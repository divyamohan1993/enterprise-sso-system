#![deny(unsafe_code)]
//! Cluster coordination layer.
//!
//! Wraps the Raft engine into an async service that handles:
//! - Network transport for Raft messages (over TCP + postcard)
//! - Periodic ticking of the Raft state machine
//! - Applying committed log entries to cluster state
//! - Exposing leader/follower status to the service

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha512;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch, Mutex, RwLock};
use tracing::{debug, error, info, warn};

type HmacSha512 = Hmac<Sha512>;

/// HKDF info string for deriving the Raft transport HMAC key from the master KEK.
const RAFT_HMAC_INFO: &[u8] = b"MILNET-RAFT-HMAC-v1";

/// Length of HMAC-SHA512 tag appended to each Raft message.
const HMAC_TAG_LEN: usize = 64;

/// Domain separator prefixed to every Raft control-plane message before the
/// per-node ML-DSA-87 signature is computed. Prevents a signature produced for
/// some other purpose (entry signing, attestation, snapshot) from ever being
/// replayed as a transport-message signature.
const RAFT_TRANSPORT_SIG_DOMAIN: &[u8] = b"MILNET-RAFT-TRANSPORT-ML-DSA-87-v1";

use super::raft::{
    ClusterCommand, LogEntry, LogIndex, NodeId, RaftConfig, RaftMessage, RaftRole, RaftState,
};
#[cfg(test)]
use super::raft::Term;


// ── ServiceType ──

/// The type of MILNET service running on a cluster node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ServiceType {
    Orchestrator,
    TssCoordinator,
    Opaque,
    Gateway,
    Audit,
}

impl fmt::Display for ServiceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServiceType::Orchestrator => write!(f, "orchestrator"),
            ServiceType::TssCoordinator => write!(f, "tss-coordinator"),
            ServiceType::Opaque => write!(f, "opaque"),
            ServiceType::Gateway => write!(f, "gateway"),
            ServiceType::Audit => write!(f, "audit"),
        }
    }
}

impl FromStr for ServiceType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "orchestrator" => Ok(ServiceType::Orchestrator),
            "tss-coordinator" | "tss_coordinator" | "tsscoordinator" => {
                Ok(ServiceType::TssCoordinator)
            }
            "opaque" => Ok(ServiceType::Opaque),
            "gateway" => Ok(ServiceType::Gateway),
            "audit" => Ok(ServiceType::Audit),
            other => Err(format!("unknown service type: {other}")),
        }
    }
}

// ── MemberInfo ──

/// Information about a cluster member, maintained by the applied state.
#[derive(Debug, Clone)]
pub struct MemberInfo {
    pub node_id: NodeId,
    /// The service-level address (e.g. gRPC or HTTP endpoint).
    pub addr: String,
    pub service_type: ServiceType,
    pub healthy: bool,
    pub last_seen: Instant,
}

// ── ClusterState ──

/// Applied state derived from committed Raft log entries.
///
/// This is the "state machine" that Raft replicates.
#[derive(Debug, Clone)]
pub struct ClusterState {
    pub members: HashMap<NodeId, MemberInfo>,
    pub leader_id: Option<NodeId>,
    pub term: u64,
    pub fencing_token: u64,
}

impl ClusterState {
    /// Create an empty cluster state.
    pub fn new() -> Self {
        Self {
            members: HashMap::new(),
            leader_id: None,
            term: 0,
            fencing_token: 0,
        }
    }

    /// Apply a committed log entry to the cluster state.
    pub fn apply(&mut self, entry: &LogEntry) {
        self.term = entry.term.0;
        match &entry.command {
            ClusterCommand::MemberJoin {
                node_id,
                addr,
                service_type,
            } => {
                let svc_type = ServiceType::from_str(service_type).unwrap_or(ServiceType::Gateway);
                self.members.insert(
                    *node_id,
                    MemberInfo {
                        node_id: *node_id,
                        addr: addr.clone(),
                        service_type: svc_type,
                        healthy: true,
                        last_seen: Instant::now(),
                    },
                );
            }
            ClusterCommand::MemberLeave { node_id } => {
                self.members.remove(node_id);
            }
            ClusterCommand::RoleAssignment { .. } => {
                // Role assignments are handled externally by the cluster_roles module.
            }
            ClusterCommand::HealthUpdate { node_id, healthy } => {
                if let Some(member) = self.members.get_mut(node_id) {
                    member.healthy = *healthy;
                    member.last_seen = Instant::now();
                }
            }
            ClusterCommand::Noop => {
                // No-op: leader authority commit, nothing to apply.
            }
            ClusterCommand::TamperDetected {
                ref node_id,
                expected_hash: _,
                actual_hash: _,
            } => {
                // Mark the tampered node as unhealthy. If it was leader,
                // the Raft engine handles step-down separately.
                if let Some(member) = self.members.get_mut(node_id) {
                    member.healthy = false;
                    tracing::error!(
                        node_id = %node_id,
                        "TAMPER DETECTED: node marked unhealthy, ineligible for leader election"
                    );
                }
                // If tampered node was leader, clear leader_id to force re-election
                if self.leader_id == Some(*node_id) {
                    tracing::error!(
                        node_id = %node_id,
                        "TAMPER DETECTED on LEADER: clearing leader, forcing re-election"
                    );
                    self.leader_id = None;
                }
            }
            ClusterCommand::TamperHealed { ref node_id } => {
                // Restore the healed node to healthy status
                if let Some(member) = self.members.get_mut(node_id) {
                    member.healthy = true;
                    tracing::info!(
                        node_id = %node_id,
                        "node healed: binary integrity restored, eligible for leader election"
                    );
                }
            }
        }
    }

    /// Get the current leader's service address, if known.
    pub fn leader_addr(&self) -> Option<&str> {
        self.leader_id
            .and_then(|id| self.members.get(&id))
            .map(|m| m.addr.as_str())
    }

    /// Return references to all healthy members.
    pub fn healthy_members(&self) -> Vec<&MemberInfo> {
        self.members.values().filter(|m| m.healthy).collect()
    }

    /// Total number of registered members.
    pub fn member_count(&self) -> usize {
        self.members.len()
    }
}

impl Default for ClusterState {
    fn default() -> Self {
        Self::new()
    }
}

// ── TamperQuorum ──

/// Distributed tamper detection that bypasses Raft leader.
///
/// Prevents a compromised leader from suppressing its own quarantine.
/// When f+1 independent peers report the same node as tampered, that node
/// is quarantined without needing the Raft leader's cooperation.
///
/// Each reporter signs the tamper evidence with its own ML-DSA-87 key.
/// The quorum check is purely local: each node maintains its own TamperQuorum
/// and acts on it independently, so no single point of failure exists.
#[derive(Debug, Clone)]
pub struct TamperQuorum {
    /// Reports received: target node_id -> set of reporter node_ids.
    reports: HashMap<NodeId, HashSet<NodeId>>,
    /// Quorum threshold: f+1 independent reports required.
    quorum_threshold: usize,
}

impl TamperQuorum {
    /// Create a new TamperQuorum with the given fault tolerance.
    /// Quorum threshold is fault_tolerance + 1.
    pub fn new(fault_tolerance: usize) -> Self {
        Self {
            reports: HashMap::new(),
            quorum_threshold: fault_tolerance + 1,
        }
    }

    /// Record a tamper report from a peer. Returns true if quorum reached.
    ///
    /// A node is quarantined when f+1 independent reporters have flagged it.
    /// The reporter must not be the target itself (self-healing bypasses this).
    pub fn report_tamper(&mut self, target: NodeId, reporter: NodeId) -> bool {
        // A node cannot clear its own tamper report.
        if target == reporter {
            tracing::warn!(
                target = %target,
                "ignoring self-reported tamper (node cannot clear its own quarantine)"
            );
            return false;
        }
        let reporters = self.reports.entry(target).or_default();
        reporters.insert(reporter);
        let quarantined = reporters.len() >= self.quorum_threshold;
        if quarantined {
            tracing::error!(
                target = %target,
                reporters = reporters.len(),
                threshold = self.quorum_threshold,
                "TAMPER QUORUM REACHED: node quarantined by peer consensus"
            );
        }
        quarantined
    }

    /// Check if a node has been quarantined by quorum.
    pub fn is_quarantined(&self, node_id: &NodeId) -> bool {
        self.reports
            .get(node_id)
            .map(|r| r.len() >= self.quorum_threshold)
            .unwrap_or(false)
    }

    /// Get the number of reporters for a given target node.
    pub fn reporter_count(&self, node_id: &NodeId) -> usize {
        self.reports.get(node_id).map(|r| r.len()).unwrap_or(0)
    }

    /// Clear quarantine reports for a node (after successful healing).
    pub fn clear_reports(&mut self, node_id: &NodeId) {
        self.reports.remove(node_id);
    }
}

// ── PeerConfig ──

/// Configuration for a single peer in the cluster.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerConfig {
    pub node_id: NodeId,
    pub raft_addr: String,
    pub service_addr: String,
}

// ── ClusterConfig ──

/// Full configuration for a cluster node.
#[derive(Debug, Clone)]
pub struct ClusterConfig {
    pub node_id: NodeId,
    pub service_type: ServiceType,
    pub service_addr: String,
    pub raft_addr: String,
    pub peers: Vec<PeerConfig>,
    pub raft_config: RaftConfig,
}

impl ClusterConfig {
    /// Parse cluster configuration from environment variables.
    ///
    /// Environment variables:
    /// - `MILNET_NODE_ID` — UUID or 128-bit hex node ID (generated if absent)
    /// - `MILNET_SERVICE_TYPE` — one of: orchestrator, tss-coordinator, opaque, gateway, audit
    /// - `MILNET_SERVICE_ADDR` — this node's service address (default `127.0.0.1:8080`)
    /// - `MILNET_RAFT_ADDR` — this node's Raft transport address (default `127.0.0.1:9090`)
    /// - `MILNET_CLUSTER_PEERS` — comma-separated peer list:
    ///   `node-id@raft-host:raft-port/svc-host:svc-port,...`
    ///   If not set, the node runs in standalone (single-node) mode.
    pub fn from_env() -> Result<Self, String> {
        let node_id: NodeId = parse_node_id_from_env()?;

        let service_type: ServiceType = match std::env::var("MILNET_SERVICE_TYPE") {
            Ok(val) => ServiceType::from_str(&val)?,
            Err(_) => ServiceType::Gateway,
        };

        let service_addr = std::env::var("MILNET_SERVICE_ADDR")
            .unwrap_or_else(|_| "127.0.0.1:8080".to_string());

        let raft_addr =
            std::env::var("MILNET_RAFT_ADDR").unwrap_or_else(|_| "127.0.0.1:9090".to_string());

        let mut peers = match std::env::var("MILNET_CLUSTER_PEERS") {
            Ok(val) if !val.trim().is_empty() => parse_peers(&val)?,
            _ => Vec::new(),
        };

        // SECURITY: Static peer fallback eliminates DNS as a single point of failure.
        // When DNS-based peer discovery fails or is unavailable (air-gapped networks),
        // MILNET_STATIC_PEERS provides a hardcoded peer list for Raft cluster formation.
        // Format: comma-separated list of node-id@raft-addr/svc-addr entries.
        if peers.is_empty() {
            if let Ok(static_val) = std::env::var("MILNET_STATIC_PEERS") {
                if !static_val.trim().is_empty() {
                    match parse_peers(&static_val) {
                        Ok(static_peers) => {
                            info!(
                                count = static_peers.len(),
                                "DNS peer discovery unavailable, using MILNET_STATIC_PEERS fallback"
                            );
                            peers = static_peers;
                        }
                        Err(e) => {
                            warn!(
                                err = %e,
                                "failed to parse MILNET_STATIC_PEERS, continuing without static peers"
                            );
                        }
                    }
                }
            }
        }

        // SECURITY: Standalone mode is forbidden in production deployments.
        // A single-node cluster has no redundancy, no failover, and no peer
        // binary attestation. Reject immediately with a SIEM CRITICAL event.
        reject_standalone_in_production(&peers)?;

        let raft_peers = peers
            .iter()
            .map(|p| (p.node_id, p.raft_addr.clone()))
            .collect();

        Ok(Self {
            node_id,
            service_type,
            service_addr,
            raft_addr,
            peers,
            raft_config: RaftConfig {
                peers: raft_peers,
                ..RaftConfig::default()
            },
        })
    }

    /// Convenience constructor with explicit service type and address.
    ///
    /// Falls back to env vars for node_id and peers, but uses the provided
    /// service type and address. This avoids requiring MILNET_SERVICE_TYPE
    /// and MILNET_SERVICE_ADDR for services that already know their identity.
    ///
    /// Returns Err only if MILNET_CLUSTER_PEERS is set but unparseable.
    /// If MILNET_CLUSTER_PEERS is unset, returns a standalone (no-peer) config.
    pub fn from_env_with_defaults(
        service_type: ServiceType,
        service_addr: &str,
    ) -> Result<Self, String> {
        let node_id: NodeId = parse_node_id_from_env()?;

        // Raft port defaults to service port + 2000
        let raft_addr = std::env::var("MILNET_RAFT_ADDR").unwrap_or_else(|_| {
            if let Some(port_str) = service_addr.rsplit(':').next() {
                if let Ok(port) = port_str.parse::<u16>() {
                    let host = service_addr.rsplitn(2, ':').nth(1).unwrap_or("127.0.0.1");
                    return format!("{}:{}", host, port + 2000);
                }
            }
            "127.0.0.1:11101".to_string()
        });

        let mut peers = match std::env::var("MILNET_CLUSTER_PEERS") {
            Ok(val) if !val.trim().is_empty() => parse_peers(&val)?,
            _ => Vec::new(),
        };

        // SECURITY: Static peer fallback eliminates DNS as a single point of failure.
        // When DNS-based peer discovery fails or is unavailable (air-gapped networks),
        // MILNET_STATIC_PEERS provides a hardcoded peer list for Raft cluster formation.
        if peers.is_empty() {
            if let Ok(static_val) = std::env::var("MILNET_STATIC_PEERS") {
                if !static_val.trim().is_empty() {
                    match parse_peers(&static_val) {
                        Ok(static_peers) => {
                            info!(
                                count = static_peers.len(),
                                "DNS peer discovery unavailable, using MILNET_STATIC_PEERS fallback"
                            );
                            peers = static_peers;
                        }
                        Err(e) => {
                            warn!(
                                err = %e,
                                "failed to parse MILNET_STATIC_PEERS, continuing without static peers"
                            );
                        }
                    }
                }
            }
        }

        // SECURITY: Standalone mode is forbidden in production deployments.
        reject_standalone_in_production(&peers)?;

        let raft_peers = peers
            .iter()
            .map(|p| (p.node_id, p.raft_addr.clone()))
            .collect();

        Ok(Self {
            node_id,
            service_type,
            service_addr: service_addr.to_string(),
            raft_addr,
            peers,
            raft_config: RaftConfig {
                peers: raft_peers,
                ..RaftConfig::default()
            },
        })
    }
}

/// Reject standalone (zero-peer) operation when production env vars are set.
///
/// If `MILNET_PRODUCTION=1` or `MILNET_MILITARY_DEPLOYMENT=1`, a node with no
/// peers is a catastrophic misconfiguration. Emit a SIEM CRITICAL event and
/// panic -- standalone mode must be impossible in production.
fn reject_standalone_in_production(peers: &[PeerConfig]) -> Result<(), String> {
    if !peers.is_empty() {
        return Ok(());
    }
    let is_production = crate::sealed_keys::is_production();
    let is_military = std::env::var("MILNET_MILITARY_DEPLOYMENT")
        .map(|v| v == "1")
        .unwrap_or(false);
    if is_production || is_military {
        let event = crate::siem::SecurityEvent {
            timestamp: crate::siem::SecurityEvent::now_iso8601(),
            category: "cluster",
            action: "standalone_mode_rejected",
            severity: crate::siem::Severity::Critical,
            outcome: "failure",
            user_id: None,
            source_ip: None,
            detail: Some(
                "FATAL: standalone mode (no cluster peers) attempted in production. \
                 Set MILNET_CLUSTER_PEERS or MILNET_STATIC_PEERS with at least 2 peers \
                 for a minimum 3-node cluster. Single-node deployment provides zero \
                 redundancy and zero tamper detection."
                    .into(),
            ),
        };
        event.emit();
        panic!(
            "SIEM CRITICAL: standalone mode forbidden in production. \
             MILNET_PRODUCTION={} MILNET_MILITARY_DEPLOYMENT={}. \
             Configure cluster peers before starting.",
            if is_production { "1" } else { "0" },
            if is_military { "1" } else { "0" },
        );
    }
    Ok(())
}

/// Fixed namespace for deriving a stable [`NodeId`] from a non-UUID
/// `MILNET_NODE_ID` string (UUIDv5). This namespace is itself a constant UUID so
/// the mapping is deterministic and identical in every process — the Raft
/// transport, the distributed-startup attestation, and the revocation layer all
/// derive the SAME NodeId from the same `MILNET_NODE_ID`, so a peer pins the
/// right per-node verifying key. (Bytes are the ASCII "MILNET-NODEID\0\0\0" —
/// any fixed 16 bytes work; they only need to be constant.)
const MILNET_NODE_ID_NAMESPACE: uuid::Uuid = uuid::Uuid::from_bytes([
    b'M', b'I', b'L', b'N', b'E', b'T', b'-', b'N', b'O', b'D', b'E', b'I', b'D', 0, 0, 0,
]);

/// Canonicalize a `MILNET_NODE_ID` string into the cluster [`NodeId`].
///
/// Resolution order:
/// 1. A UUID string → that UUID.
/// 2. A 128-bit hex value (optionally `0x`-prefixed) → `Uuid::from_u128`.
/// 3. Any other string (e.g. a deploy id like `orchestrator-0`) →
///    `Uuid::new_v5(MILNET_NODE_ID_NAMESPACE, bytes)` — a STABLE, unique UUID for
///    that string (matches the `UUIDv5(pod-name)` scheme in the k8s design).
///
/// This is THE single node-id canonicalization used cluster-wide so the Raft
/// transport, attestation, and revocation all agree on a node's [`NodeId`].
pub fn canonical_node_id(s: &str) -> NodeId {
    if let Ok(uuid) = uuid::Uuid::parse_str(s) {
        return NodeId(uuid);
    }
    if let Ok(n) = u128::from_str_radix(s.trim_start_matches("0x"), 16) {
        return NodeId(uuid::Uuid::from_u128(n));
    }
    NodeId(uuid::Uuid::new_v5(&MILNET_NODE_ID_NAMESPACE, s.as_bytes()))
}

/// Parse node ID from MILNET_NODE_ID env var, or generate a random one.
///
/// Non-UUID values (e.g. `orchestrator-0`) are canonicalized deterministically
/// via [`canonical_node_id`] (UUIDv5) rather than rejected, so existing deploy
/// configs keep a stable identity AND the attestation/transport agree.
fn parse_node_id_from_env() -> Result<NodeId, String> {
    match std::env::var("MILNET_NODE_ID") {
        Ok(val) => Ok(canonical_node_id(&val)),
        Err(_) => Ok(NodeId(uuid::Uuid::new_v4())),
    }
}

/// Parse the `MILNET_CLUSTER_PEERS` value.
///
/// Format: `node-id@raft-host:raft-port/svc-host:svc-port,...`
fn parse_peers(s: &str) -> Result<Vec<PeerConfig>, String> {
    let mut peers = Vec::new();
    for entry in s.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let (id_str, rest) = entry
            .split_once('@')
            .ok_or_else(|| format!("invalid peer entry (missing @): {entry}"))?;
        let node_id = if let Ok(uuid) = uuid::Uuid::parse_str(id_str) {
            NodeId(uuid)
        } else {
            let n = u128::from_str_radix(id_str.trim_start_matches("0x"), 16)
                .map_err(|e| format!("invalid peer node ID '{id_str}': {e}"))?;
            NodeId(uuid::Uuid::from_u128(n))
        };
        let (raft_addr, service_addr) = rest
            .split_once('/')
            .ok_or_else(|| format!("invalid peer entry (missing /): {entry}"))?;
        peers.push(PeerConfig {
            node_id,
            raft_addr: raft_addr.to_string(),
            service_addr: service_addr.to_string(),
        });
    }
    Ok(peers)
}

// ── TCP framing helpers ──

/// Send a length-prefixed frame over a TCP stream.
async fn send_framed(stream: &mut TcpStream, data: &[u8]) -> Result<(), String> {
    let len = (data.len() as u32).to_be_bytes();
    stream
        .write_all(&len)
        .await
        .map_err(|e| format!("failed to write frame length: {e}"))?;
    stream
        .write_all(data)
        .await
        .map_err(|e| format!("failed to write frame data: {e}"))?;
    stream
        .flush()
        .await
        .map_err(|e| format!("failed to flush stream: {e}"))?;
    Ok(())
}

/// Receive a length-prefixed frame from a TCP stream.
async fn recv_framed(stream: &mut TcpStream) -> Result<Vec<u8>, String> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| format!("failed to read frame length: {e}"))?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 1_048_576 {
        return Err(format!("message too large: {len} bytes (max 1 MiB)"));
    }
    let mut buf = vec![0u8; len];
    stream
        .read_exact(&mut buf)
        .await
        .map_err(|e| format!("failed to read frame data: {e}"))?;
    Ok(buf)
}

/// Derive a 64-byte HMAC key from the master KEK via HKDF-SHA512.
///
/// If no master KEK is configured (e.g. in tests), returns `None` and
/// HMAC authentication is skipped.
fn derive_raft_hmac_key() -> Option<[u8; 64]> {
    // Use the threshold-reconstructed master KEK, not raw env var.
    // get_master_kek() enforces 3-of-5 Shamir reconstruction in production.
    let kek = crate::sealed_keys::get_master_kek();

    use hkdf::Hkdf;
    let hk = Hkdf::<Sha512>::new(Some(b"MILNET-CLUSTER-SALT-v1"), kek);
    let mut okm = [0u8; 64];
    if let Err(e) = hk.expand(RAFT_HMAC_INFO, &mut okm) {
        tracing::error!("FATAL: HKDF-SHA512 expand failed for Raft HMAC key: {e}");
        std::process::exit(1);
    }
    Some(okm)
}

/// Send a length-prefixed, HMAC-authenticated frame over TCP.
///
/// Wire format: `len(4 bytes, big-endian)` || `payload` || `hmac_tag(64 bytes)`
/// where `len` = `payload.len() + 64`.
///
/// SECURITY NOTE: Raft messages are HMAC-authenticated (integrity + authenticity)
/// but the payload is NOT encrypted. An attacker on the network can observe
/// cluster topology commands (membership changes, heartbeats) but cannot forge
/// them. For full confidentiality, deploy Raft nodes behind a TLS mesh/sidecar
/// (e.g. Istio mTLS, WireGuard) or use the MILNET_RAFT_TLS=1 environment
/// variable to enable application-layer encryption of payloads.
async fn send_authenticated(
    stream: &mut TcpStream,
    data: &[u8],
    hmac_key: &[u8; 64],
) -> Result<(), String> {
    // Optionally encrypt payload for confidentiality (MILNET_RAFT_ENCRYPT=1).
    // Uses AES-256-GCM with the first 32 bytes of the HMAC key as the
    // encryption key and a random 12-byte nonce prepended to the ciphertext.
    let data = if raft_encrypt_enabled() {
        use aes_gcm::{Aes256Gcm, KeyInit, Nonce as GcmNonce};
        use aes_gcm::aead::Aead;
        let cipher = Aes256Gcm::new_from_slice(&hmac_key[..32])
            .map_err(|e| format!("AES-256-GCM key init failed: {e}"))?;
        let mut nonce_bytes = [0u8; 12];
        getrandom::getrandom(&mut nonce_bytes)
            .map_err(|e| format!("nonce generation failed: {e}"))?;
        let nonce = GcmNonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, data)
            .map_err(|e| format!("Raft payload encryption failed: {e}"))?;
        [nonce_bytes.to_vec(), ciphertext].concat()
    } else {
        data.to_vec()
    };
    let data = &data;

    let mut mac = match HmacSha512::new_from_slice(hmac_key) {
        Ok(m) => m,
        Err(e) => return Err(format!("HMAC-SHA512 key init failed: {e}")),
    };
    mac.update(data);
    let tag = mac.finalize().into_bytes();

    let total_len = data.len() + HMAC_TAG_LEN;
    let len_bytes = (total_len as u32).to_be_bytes();

    stream
        .write_all(&len_bytes)
        .await
        .map_err(|e| format!("failed to write frame length: {e}"))?;
    stream
        .write_all(data)
        .await
        .map_err(|e| format!("failed to write frame data: {e}"))?;
    stream
        .write_all(&tag)
        .await
        .map_err(|e| format!("failed to write HMAC tag: {e}"))?;
    stream
        .flush()
        .await
        .map_err(|e| format!("failed to flush stream: {e}"))?;
    Ok(())
}

/// Receive a length-prefixed, HMAC-authenticated frame from TCP.
///
/// Verifies the HMAC-SHA512 tag before returning the payload.
/// Rejects messages with invalid HMAC and emits a SIEM event.
async fn recv_authenticated(
    stream: &mut TcpStream,
    hmac_key: &[u8; 64],
) -> Result<Vec<u8>, String> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| format!("failed to read frame length: {e}"))?;
    let total_len = u32::from_be_bytes(len_buf) as usize;

    if total_len > 1_048_576 + HMAC_TAG_LEN {
        return Err(format!(
            "authenticated message too large: {total_len} bytes"
        ));
    }
    if total_len < HMAC_TAG_LEN {
        return Err("authenticated message too small to contain HMAC tag".into());
    }

    let payload_len = total_len - HMAC_TAG_LEN;
    let mut payload = vec![0u8; payload_len];
    stream
        .read_exact(&mut payload)
        .await
        .map_err(|e| format!("failed to read frame payload: {e}"))?;

    let mut tag_buf = [0u8; HMAC_TAG_LEN];
    stream
        .read_exact(&mut tag_buf)
        .await
        .map_err(|e| format!("failed to read HMAC tag: {e}"))?;

    // Verify HMAC before deserializing.
    let mut mac = match HmacSha512::new_from_slice(hmac_key) {
        Ok(m) => m,
        Err(e) => return Err(format!("HMAC-SHA512 key init failed: {e}")),
    };
    mac.update(&payload);
    if mac.verify_slice(&tag_buf).is_err() {
        // Emit SIEM event for failed authentication.
        let event = crate::siem::SecurityEvent {
            timestamp: crate::siem::SecurityEvent::now_iso8601(),
            category: "cluster",
            action: "raft_hmac_verification_failed",
            severity: crate::siem::Severity::Critical,
            outcome: "failure",
            user_id: None,
            source_ip: None,
            detail: Some("rejected Raft message with invalid HMAC-SHA512 tag".into()),
        };
        event.emit();
        return Err("HMAC verification failed — rejecting unauthenticated Raft message".into());
    }

    // Decrypt payload if Raft encryption is enabled
    if raft_encrypt_enabled() {
        use aes_gcm::{Aes256Gcm, KeyInit, Nonce as GcmNonce};
        use aes_gcm::aead::Aead;
        if payload.len() < 12 {
            return Err("encrypted Raft payload too short for nonce".into());
        }
        let (nonce_bytes, ciphertext) = payload.split_at(12);
        let cipher = Aes256Gcm::new_from_slice(&hmac_key[..32])
            .map_err(|e| format!("AES-256-GCM key init failed: {e}"))?;
        let nonce = GcmNonce::from_slice(nonce_bytes);
        let plaintext = cipher.decrypt(nonce, ciphertext)
            .map_err(|e| format!("Raft payload decryption failed: {e}"))?;
        return Ok(plaintext);
    }

    Ok(payload)
}

/// Returns true if Raft payload encryption is enabled.
///
/// When `MILNET_RAFT_ENCRYPT=1` is set, all Raft consensus messages are
/// AES-256-GCM encrypted in addition to HMAC-SHA512 authentication.
/// This prevents network observers from reading cluster topology commands.
fn raft_encrypt_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| {
        std::env::var("MILNET_RAFT_ENCRYPT").as_deref() == Ok("1")
    })
}

// ── Per-node ML-DSA-87 Raft message authentication ──
//
// SECURITY (closes the CRITICAL consensus-BFT finding):
// The legacy transport authenticated every Raft message with a CLUSTER-WIDE
// SHARED HMAC key (HKDF of the master KEK with a fixed salt/info). Because the
// key is identical on every node, ONE compromised node could forge a
// RequestVote / AppendEntries / vote-response attributed to ANY NodeId,
// manufacture a quorum, and install itself leader. The HMAC binds a message to
// *the cluster*, not to *a node*.
//
// Here every control-plane message additionally carries a per-node ML-DSA-87
// signature over (domain || sender_id || serialized RaftMessage), verified
// against the sender's verifying key PINNED at cluster join. A compromised node
// can therefore only forge AS ITSELF — it cannot sign as another NodeId. The
// HMAC is retained ONLY as a cheap first factor (it rejects random/garbage
// frames before the expensive lattice verify); security now rests on the
// asymmetric per-node signature.
//
// PERFORMANCE TRADEOFF: ML-DSA-87 sign+verify per message is dramatically
// heavier than HMAC-SHA512 (lattice arithmetic; ~4.6 KB signatures added to
// every heartbeat). At the default 500ms heartbeat across a small cluster this
// is acceptable; for very large clusters the heartbeat interval should be tuned.
// This cost is the audit-mandated price of per-node authenticity: security > perf.
//
// RESIDUAL (documented, not closed here): the per-node ML-DSA seed is derived
// from the shared master KEK + NodeId (see distributed_startup::NodeIdentity).
// A root attacker who exfiltrates the cached KEK could re-derive any node's seed
// and forge as it. Eliminating that requires an INDEPENDENT per-node signing key
// (e.g. generated once and sealed to each node's TPM, only the verifying key
// shared). The pinned registry below is `NodeId -> VK bytes`, agnostic to how
// the VK was produced, so such keys drop in with no API change. This matches the
// codebase's documented anti-clone-not-anti-root boundary.

use crate::binary_attestation_mesh::BinaryHash;
use crate::distributed_startup::{
    verify_node_sig, DistributedStartupVerifier, NodeIdentity, NodeIdentityRegistry,
    PeerAttestation,
};

/// A Raft control-plane message bound to its sender by a per-node ML-DSA-87
/// signature. Serialized with postcard and carried inside the HMAC frame.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NodeAuthenticatedRaftMessage {
    /// The node that produced this message (the *claimed* sender).
    sender_id: NodeId,
    /// The Raft protocol message.
    message: RaftMessage,
    /// ML-DSA-87 signature over
    /// (RAFT_TRANSPORT_SIG_DOMAIN || sender_id_bytes || postcard(message))
    /// by the sender's per-node identity key.
    ml_dsa_sig: Vec<u8>,
}

/// Build the exact byte string that is signed/verified for a transport message:
/// domain || sender_id(16) || postcard(message).
fn transport_signed_bytes(sender_id: NodeId, msg_bytes: &[u8]) -> Vec<u8> {
    let mut signed = Vec::with_capacity(
        RAFT_TRANSPORT_SIG_DOMAIN.len() + 16 + msg_bytes.len(),
    );
    signed.extend_from_slice(RAFT_TRANSPORT_SIG_DOMAIN);
    signed.extend_from_slice(sender_id.0.as_bytes());
    signed.extend_from_slice(msg_bytes);
    signed
}

/// Serialize and per-node-sign a Raft message, producing the wire bytes of a
/// [`NodeAuthenticatedRaftMessage`].
fn sign_transport_message(
    identity: &NodeIdentity,
    sender_id: NodeId,
    message: &RaftMessage,
) -> Result<Vec<u8>, String> {
    let msg_bytes = postcard::to_allocvec(message)
        .map_err(|e| format!("failed to serialize raft message for signing: {e}"))?;
    let signed = transport_signed_bytes(sender_id, &msg_bytes);
    let ml_dsa_sig = identity.node_sign(&signed);
    let envelope = NodeAuthenticatedRaftMessage {
        sender_id,
        message: message.clone(),
        ml_dsa_sig,
    };
    postcard::to_allocvec(&envelope)
        .map_err(|e| format!("failed to serialize authenticated raft envelope: {e}"))
}

/// Deserialize and verify a per-node-signed Raft message.
///
/// FAIL-CLOSED: returns `Err` if the envelope can't be parsed, the sender is not
/// in the pinned verifying-key registry, or the ML-DSA-87 signature does not
/// verify. On success returns the inner `(sender_id, message)`.
fn verify_transport_message(
    data: &[u8],
    registry: &NodeIdentityRegistry,
) -> Result<(NodeId, RaftMessage), String> {
    let envelope: NodeAuthenticatedRaftMessage = postcard::from_bytes(data)
        .map_err(|e| format!("failed to deserialize authenticated raft envelope: {e}"))?;

    // Look up the sender's PINNED verifying key. Unknown sender => reject.
    let vk = registry.verifying_key(&envelope.sender_id).ok_or_else(|| {
        let event = crate::siem::SecurityEvent {
            timestamp: crate::siem::SecurityEvent::now_iso8601(),
            category: "cluster",
            action: "raft_unpinned_sender_rejected",
            severity: crate::siem::Severity::Critical,
            outcome: "failure",
            user_id: None,
            source_ip: None,
            detail: Some(format!(
                "rejected Raft message from unpinned/unknown sender {} — \
                 no verifying key pinned at cluster join",
                envelope.sender_id
            )),
        };
        event.emit();
        format!(
            "unpinned Raft sender {} — rejecting (fail-closed)",
            envelope.sender_id
        )
    })?;

    let msg_bytes = postcard::to_allocvec(&envelope.message)
        .map_err(|e| format!("failed to re-serialize raft message for verify: {e}"))?;
    let signed = transport_signed_bytes(envelope.sender_id, &msg_bytes);

    if !verify_node_sig(vk, &signed, &envelope.ml_dsa_sig) {
        let event = crate::siem::SecurityEvent {
            timestamp: crate::siem::SecurityEvent::now_iso8601(),
            category: "cluster",
            action: "raft_ml_dsa_verification_failed",
            severity: crate::siem::Severity::Critical,
            outcome: "failure",
            user_id: None,
            source_ip: None,
            detail: Some(format!(
                "rejected Raft message: ML-DSA-87 signature invalid for claimed \
                 sender {} — possible Byzantine forgery (a node signing as another)",
                envelope.sender_id
            )),
        };
        event.emit();
        return Err(format!(
            "ML-DSA-87 transport signature verification failed for sender {} \
             — rejecting forged Raft message",
            envelope.sender_id
        ));
    }

    Ok((envelope.sender_id, envelope.message))
}

// ── Transport frame multiplexing (Raft messages + attestation handshake) ─────
//
// SECURITY (closes the LIVE-WIRING gap of the per-node ML-DSA-87 transport):
// The per-node-signed Raft transport above authenticates a peer ONLY against a
// verifying key PINNED for that peer's NodeId. In MILITARY mode nothing pins
// peers locally (`build_peer_verifying_keys` pins SELF only, because each peer's
// signing seed is sealed to its OWN TPM and its VK is therefore not locally
// derivable). Until a peer's VK is pinned, EVERY Raft message from it is dropped
// fail-closed — i.e. the cluster cannot form. The missing piece is a LIVE
// exchange of each node's PUBLISHED, attestation-signed Raft VK.
//
// We carry that exchange over the SAME TCP transport the Raft RPCs use, by
// tagging every frame with a small [`TransportFrame`] discriminant so the one
// listener can tell a handshake from a Raft message. The handshake payload is a
// signed [`PeerAttestation`] (`generate_own_attestation`): its ML-DSA-87
// signature COVERS the published `raft_verifying_key`, so a man-in-the-middle
// cannot substitute a different VK, and an unverifiable attestation is never
// pinned (fail-closed). The attestation also rides INSIDE the existing HMAC
// frame, so it inherits the same cheap first-factor as Raft traffic.
//
// DEPLOYMENT REQUIREMENTS (documented, by design — do NOT weaken):
//  * SAME-VERSION CLUSTER: this `TransportFrame` outer tag changes the bytes the
//    listener deserializes, so a node on this version CANNOT exchange Raft
//    messages with a node still on the pre-handshake (raw `NodeAuthenticatedRaft
//    Message` / raw tuple) format. The transport is therefore NOT
//    rolling-compatible across this change. That is acceptable here: the
//    threshold StatefulSet / LAN fleet deploys every node at a single version
//    together (see deploy/kubernetes/threshold/). A try-TransportFrame-then-fall-
//    back-to-raw shim was considered and deliberately rejected — it adds parsing
//    ambiguity and a downgrade surface for zero benefit given whole-cluster
//    deploys.
//  * ATTESTATION FRESHNESS + BINARY HASH: a peer's attestation is rejected if it
//    is older than `attestation_max_age` (default 60s) or — outside a rolling
//    update — its binary hash differs from ours. So (a) the handshake regenerates
//    a FRESH attestation on every (re)connect (see `fresh_attestation`), and
//    (b) a genuine cross-version rollout that changes the binary needs
//    `MILNET_ROLLING_UPDATE=1` for peers to pin across the version skew, exactly
//    as full cluster verification requires.

/// A frame on the cluster TCP transport, tagging its kind so the single listener
/// can route a handshake versus a Raft control-plane message. Postcard-encoded,
/// then carried inside the HMAC (and optionally AES-GCM) frame like any payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
enum TransportFrame {
    /// A signed peer attestation exchanged at connect to publish (and pin) the
    /// sender's per-node Raft verifying key. Boxed because `PeerAttestation`
    /// carries multi-KB ML-DSA-87 material and is far larger than a Raft message,
    /// so we keep the enum's other (hot-path) variant cheap.
    Handshake(Box<PeerAttestation>),
    /// The pre-existing transport payload: either a per-node-signed
    /// [`NodeAuthenticatedRaftMessage`] (military / KEK present) or a plain
    /// `postcard((NodeId, RaftMessage))` tuple (legacy / no-KEK / tests). The
    /// bytes are EXACTLY what was carried before this multiplexing layer existed,
    /// so the `sign_transport_message` / `verify_transport_message` contract is
    /// unchanged — this only adds an outer tag.
    Raft(Vec<u8>),
}

impl TransportFrame {
    /// Serialize this frame to wire bytes.
    fn to_wire(&self) -> Result<Vec<u8>, String> {
        postcard::to_allocvec(self)
            .map_err(|e| format!("failed to serialize transport frame: {e}"))
    }

    /// Parse a transport frame from wire bytes.
    fn from_wire(data: &[u8]) -> Result<Self, String> {
        postcard::from_bytes(data)
            .map_err(|e| format!("failed to deserialize transport frame: {e}"))
    }
}

/// The attestation handshaker: produces THIS node's signed attestation and
/// verifies a peer's, then yields the `(NodeId, raft_verifying_key)` to pin.
///
/// Built once in [`ClusterNode::start`] (military mode only) and shared by the
/// connect-side handshake task and the listener's inbound-handshake path so both
/// directions of the exchange share one verifier and one published attestation.
struct AttestationHandshaker {
    verifier: DistributedStartupVerifier,
    /// This node's own binary hash, compared against a peer's before pinning.
    /// Pinning only authenticates a peer's identity key; binary consistency
    /// additionally rejects pinning a peer that is running a DIFFERENT (possibly
    /// tampered) binary — defense in depth that reuses the same policy
    /// (honoring `MILNET_ROLLING_UPDATE`) as full cluster verification. Computed
    /// once at construction (the running binary does not change).
    own_binary_hash: BinaryHash,
}

impl AttestationHandshaker {
    /// Build the handshaker, publishing EXACTLY `identity`'s verifying key in the
    /// attestation so peers pin the same key the Raft transport signs with.
    ///
    /// Returns `None` (handshake disabled) if the verifier cannot be constructed
    /// (e.g. no peers configured) — the caller treats that as "no live pinning",
    /// which keeps the transport fail-closed rather than silently trusting peers.
    fn new(identity: &NodeIdentity) -> Option<Self> {
        let verifier = match DistributedStartupVerifier::new() {
            Ok(v) => v.from_node_identity(identity),
            Err(e) => {
                warn!(
                    err = %e,
                    "attestation handshaker disabled: verifier init failed \
                     (peers remain unpinned; military Raft transport stays fail-closed)"
                );
                return None;
            }
        };
        // Compute the binary hash once (it does not change for the life of the
        // process); the attestation itself is generated FRESH per send below.
        let own_binary_hash = verifier.generate_own_attestation().binary_hash;
        Some(Self {
            verifier,
            own_binary_hash,
        })
    }

    /// Generate a FRESH signed attestation to send to a peer.
    ///
    /// Regenerated per (re)connect rather than cached so its `timestamp` is
    /// current: a peer rejects any attestation older than `attestation_max_age`
    /// (default 60s), so a stale cached attestation would fail to pin on a late
    /// join / reconnect after a long outage. Regeneration re-signs with the
    /// already-in-memory attestation seed (ML-DSA-87, off the Raft hot path — only
    /// during handshake retries), and does NOT re-unseal the TPM identity seed.
    fn fresh_attestation(&self) -> PeerAttestation {
        self.verifier.generate_own_attestation()
    }

    /// Verify a received peer attestation and, if valid, return the
    /// `(NodeId, raft_verifying_key)` to pin. FAIL-CLOSED: any verification
    /// failure (bad signature, stale, missing published VK, or — outside a
    /// rolling update — a mismatched binary hash) yields `Err` and NOTHING is
    /// pinned, so the peer's Raft messages keep being dropped.
    fn verify_and_extract(
        &self,
        att: &PeerAttestation,
    ) -> Result<(NodeId, Vec<u8>), String> {
        // Signature (covers the published raft_verifying_key) + freshness.
        self.verifier
            .verify_attestation(att)
            .map_err(|e| format!("peer attestation rejected (sig/freshness): {e}"))?;

        // Defense in depth: refuse to pin a peer running a different binary,
        // honoring MILNET_ROLLING_UPDATE exactly as full cluster verification.
        self.verifier
            .verify_binary_consistency(&self.own_binary_hash, att)
            .map_err(|e| format!("peer attestation rejected (binary consistency): {e}"))?;

        if att.raft_verifying_key.is_empty() {
            return Err(format!(
                "peer {} published no raft_verifying_key — not pinning (fail-closed)",
                att.node_id
            ));
        }
        Ok((att.node_id, att.raft_verifying_key.clone()))
    }

    /// Test-only constructor from an explicit verifier (no env / TPM dependency),
    /// so the verify+pin policy can be exercised hermetically.
    #[cfg(test)]
    fn from_verifier_for_test(
        verifier: DistributedStartupVerifier,
        own_binary_hash: BinaryHash,
    ) -> Self {
        Self {
            verifier,
            own_binary_hash,
        }
    }
}

/// Send a [`TransportFrame`] over `stream`, using the HMAC frame when a key is
/// configured (the same envelope Raft messages use) or a plain frame otherwise.
async fn send_transport_frame(
    stream: &mut TcpStream,
    frame: &TransportFrame,
    hmac_key: Option<&[u8; 64]>,
) -> Result<(), String> {
    let wire = frame.to_wire()?;
    match hmac_key {
        Some(key) => send_authenticated(stream, &wire, key).await,
        None => send_framed(stream, &wire).await,
    }
}

/// Receive and parse a [`TransportFrame`] from `stream`, verifying the HMAC frame
/// when a key is configured.
async fn recv_transport_frame(
    stream: &mut TcpStream,
    hmac_key: Option<&[u8; 64]>,
) -> Result<TransportFrame, String> {
    let data = match hmac_key {
        Some(key) => recv_authenticated(stream, key).await?,
        None => recv_framed(stream).await?,
    };
    TransportFrame::from_wire(&data)
}

/// Emit a SIEM event for a REJECTED peer attestation during the handshake.
/// A rejected attestation means an unverifiable/forged/tampered/stale claim, or
/// a peer running a different binary — all security-relevant.
fn emit_handshake_rejected(peer_addr: &str, reason: &str) {
    let event = crate::siem::SecurityEvent {
        timestamp: crate::siem::SecurityEvent::now_iso8601(),
        category: "cluster",
        action: "raft_attestation_handshake_rejected",
        severity: crate::siem::Severity::Critical,
        outcome: "failure",
        user_id: None,
        source_ip: Some(peer_addr.to_string()),
        detail: Some(format!(
            "rejected peer attestation during Raft VK handshake — peer NOT pinned \
             (its Raft messages stay dropped, fail-closed): {reason}"
        )),
    };
    event.emit();
}

/// Verify a received attestation and pin the peer's per-node Raft VK into the
/// shared registry. Shared by both handshake directions. FAIL-CLOSED: returns
/// without pinning on any verification failure (and emits a SIEM Critical).
///
/// On a successful (or already-present) pin, publishes the new pinned-PEER count
/// (registry size minus self) to `pinned_peers_tx` so readiness consumers learn
/// when peers are pinned. `watch::Sender::send_if_modified` is used so a
/// duplicate pin (same peer re-handshaking) does not spuriously notify.
async fn verify_and_pin(
    att: PeerAttestation,
    peer_addr: &str,
    handshaker: &AttestationHandshaker,
    peer_vks: &Arc<RwLock<NodeIdentityRegistry>>,
    pinned_peers_tx: Option<&watch::Sender<usize>>,
) {
    match handshaker.verify_and_extract(&att) {
        Ok((node_id, vk)) => {
            // Pin under the write lock and read back the peer count atomically so
            // the published count never races a concurrent pin.
            let peer_count = {
                let mut reg = peer_vks.write().await;
                reg.pin(node_id, vk);
                // Peers = all pinned identities minus self (self is always pinned).
                reg.len().saturating_sub(1)
            };
            info!(
                peer = %node_id,
                peer_addr = %peer_addr,
                pinned_peers = peer_count,
                "pinned peer per-node Raft verifying key from verified attestation \
                 (handshake) — peer's Raft messages now authenticated"
            );
            if let Some(tx) = pinned_peers_tx {
                // Only notify when the count actually advances (idempotent pins
                // of an already-known peer must not wake waiters needlessly).
                tx.send_if_modified(|cur| {
                    if peer_count > *cur {
                        *cur = peer_count;
                        true
                    } else {
                        false
                    }
                });
            }
        }
        Err(e) => {
            warn!(peer_addr = %peer_addr, err = %e, "REJECTING peer attestation: not pinning");
            emit_handshake_rejected(peer_addr, &e);
        }
    }
}

/// Connect-side handshake: dial a peer's raft transport, send our attestation,
/// read the peer's reply attestation, verify it, and pin the peer's Raft VK.
///
/// FAIL-CLOSED throughout: a connect failure, a frame error, or an unverifiable
/// attestation simply leaves the peer unpinned (the loop in Task 5 retries on the
/// next tick), so the transport never trusts a peer it has not authenticated.
async fn outbound_handshake(
    peer: &PeerConfig,
    handshaker: &AttestationHandshaker,
    peer_vks: &Arc<RwLock<NodeIdentityRegistry>>,
    hmac_key: Option<&[u8; 64]>,
    pinned_peers_tx: Option<&watch::Sender<usize>>,
) {
    let mut stream = match TcpStream::connect(&peer.raft_addr).await {
        Ok(s) => s,
        Err(e) => {
            debug!(
                addr = %peer.raft_addr,
                err = %e,
                "handshake: failed to connect to peer (will retry)"
            );
            return;
        }
    };

    // Send our own freshly-signed attestation (publishes our per-node Raft VK).
    let own = TransportFrame::Handshake(Box::new(handshaker.fresh_attestation()));
    if let Err(e) = send_transport_frame(&mut stream, &own, hmac_key).await {
        debug!(addr = %peer.raft_addr, err = %e, "handshake: failed to send own attestation");
        return;
    }

    // Read the peer's reply attestation.
    let frame = match recv_transport_frame(&mut stream, hmac_key).await {
        Ok(f) => f,
        Err(e) => {
            debug!(addr = %peer.raft_addr, err = %e, "handshake: failed to read peer attestation");
            return;
        }
    };
    match frame {
        TransportFrame::Handshake(att) => {
            verify_and_pin(*att, &peer.raft_addr, handshaker, peer_vks, pinned_peers_tx).await;
        }
        TransportFrame::Raft(_) => {
            warn!(
                addr = %peer.raft_addr,
                "handshake: expected attestation reply but got a Raft frame — ignoring"
            );
        }
    }
}

/// Listener-side handshake: a peer connected to US and sent its attestation.
/// Verify + pin it, then reply with OUR attestation so the peer pins us too
/// (symmetric exchange — completes regardless of who connected first).
///
/// `handshaker` is `None` if this node has no handshaker (non-military): in that
/// case we received a handshake we cannot process, so we drop it (fail-closed).
async fn handle_inbound_handshake(
    stream: &mut TcpStream,
    att: PeerAttestation,
    peer_addr: &str,
    handshaker: Option<&AttestationHandshaker>,
    peer_vks: Option<&Arc<RwLock<NodeIdentityRegistry>>>,
    hmac_key: Option<&[u8; 64]>,
    pinned_peers_tx: Option<&watch::Sender<usize>>,
) {
    let (handshaker, peer_vks) = match (handshaker, peer_vks) {
        (Some(h), Some(v)) => (h, v),
        _ => {
            warn!(
                peer_addr = %peer_addr,
                "received attestation handshake but per-node auth/handshake is disabled — dropping"
            );
            return;
        }
    };

    // Verify + pin the inbound peer's VK.
    verify_and_pin(att, peer_addr, handshaker, peer_vks, pinned_peers_tx).await;

    // Reply with our own freshly-signed attestation so the initiating peer pins
    // us as well (symmetric exchange).
    let own = TransportFrame::Handshake(Box::new(handshaker.fresh_attestation()));
    if let Err(e) = send_transport_frame(stream, &own, hmac_key).await {
        debug!(peer_addr = %peer_addr, err = %e, "handshake: failed to send reply attestation");
    }
}

/// Build the initial pinned [`NodeIdentityRegistry`] for the transport.
///
/// SELF is always pinned from this node's own identity VK (`self_vk`).
///
/// PEER pinning depends on the deployment:
/// * MILITARY mode: peers are NOT pinned here. Each node's signing seed is
///   sealed to its OWN TPM (anti-root), so a peer's verifying key is NOT locally
///   derivable — it MUST be distributed (published by the peer) and pinned at
///   cluster join via [`ClusterNode::pin_peer_verifying_key`]. Deriving peer VKs
///   locally is precisely the shared-single-point anti-pattern this audit
///   closes, so it is refused here.
/// * NON-MILITARY (dev/test): there is no TPM and every node's identity is the
///   KEK-bound derivation, so peer VKs ARE locally derivable and we pin them for
///   convenience (keeps dev clusters working without a VK-exchange step).
///
/// This is the SAME registry type the session/revocation layer pins, so the
/// cluster shares ONE per-node identity registry keyed on [`NodeId`].
fn build_peer_verifying_keys(
    config: &ClusterConfig,
    self_vk: Vec<u8>,
    military: bool,
) -> NodeIdentityRegistry {
    let mut registry = NodeIdentityRegistry::new();
    // Pin self from the already-built identity VK.
    registry.pin(config.node_id, self_vk);

    if !military {
        // DEV ONLY: KEK-derived identities are locally derivable, so pin peers.
        for peer in &config.peers {
            registry.pin(
                peer.node_id,
                NodeIdentity::for_node(peer.node_id.0).verifying_key(),
            );
        }
    }
    // MILITARY: peers are pinned at join from PUBLISHED VKs (see doc above).
    registry
}

// ── ClusterNode ──

/// The main async coordination handle.
///
/// Embeds a Raft state machine and manages background tasks for network
/// transport, periodic ticking, and state application.
///
/// LOCK ORDERING: Always acquire `raft` before `state` to prevent deadlock.
/// All code paths that need both locks MUST follow this order.
pub struct ClusterNode {
    raft: Arc<Mutex<RaftState>>,
    state: Arc<RwLock<ClusterState>>,
    config: Arc<ClusterConfig>,
    shutdown_tx: watch::Sender<bool>,
    leader_tx: Arc<watch::Sender<Option<NodeId>>>,
    /// Pinned per-node verifying-key registry used by the Raft transport.
    /// `None` when per-node auth is disabled (non-military, no KEK). The cluster
    /// join flow pins PUBLISHED peer VKs here via [`Self::pin_peer_verifying_key`].
    peer_vks: Option<Arc<RwLock<NodeIdentityRegistry>>>,
    /// Watch carrying the number of PEERS currently pinned via the attestation
    /// handshake (excludes self). Updated after each successful pin. `None` when
    /// the handshake is disabled (non-military / no KEK). Consumers (e.g. the
    /// revocation layer) use [`Self::pinned_peers_watch`] to know WHEN it is safe
    /// to snapshot the registry — pinning is asynchronous and ongoing after
    /// `start` returns, so a snapshot taken too early would miss peers.
    pinned_peers_tx: Option<watch::Sender<usize>>,
}

impl ClusterNode {
    /// Create and start the cluster node.
    ///
    /// Spawns background tasks for:
    /// - Raft tick loop (every 100ms, checks timers)
    /// - Raft message listener (TCP server for incoming Raft messages)
    /// - Raft message sender (sends outgoing messages to peers)
    /// - State applier (applies committed entries to `ClusterState`)
    pub async fn start(config: ClusterConfig) -> Result<Self, String> {
        let raft = RaftState::new(config.node_id, config.raft_config.clone());

        let standalone = config.peers.is_empty();
        if standalone {
            // Standalone mode is FORBIDDEN — no SPOF allowed.
            // A single-node deployment has no redundancy, no failover, and no
            // peer-to-peer binary attestation. The entire system becomes a SPOF.
            return Err(
                "FATAL: standalone mode (no cluster peers) is forbidden. \
                 Set MILNET_CLUSTER_PEERS with at least 2 peers for a minimum 3-node cluster. \
                 Single-node deployment provides zero redundancy and zero tamper detection."
                    .to_string(),
            );
        } else {
            // Enforce minimum 3-node cluster (tolerates 1 failure)
            let cluster_size = config.peers.len() + 1; // peers + self
            if cluster_size < 3 {
                return Err(format!(
                    "FATAL: cluster size {} is too small. \
                     Minimum 3 nodes required (tolerates 1 failure). \
                     Add at least {} more peers to MILNET_CLUSTER_PEERS.",
                    cluster_size,
                    3 - cluster_size,
                ));
            }
            info!(
                node_id = %config.node_id,
                peers = config.peers.len(),
                cluster_size = cluster_size,
                "starting cluster node (quorum = {})",
                cluster_size / 2 + 1
            );
        }

        let raft = Arc::new(Mutex::new(raft));
        let state = Arc::new(RwLock::new(ClusterState::new()));
        let config = Arc::new(config);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (leader_tx, _leader_rx) = watch::channel::<Option<NodeId>>(None);
        let leader_tx = Arc::new(leader_tx);

        // Derive HMAC key for Raft transport authentication (cheap first factor).
        let hmac_key: Option<Arc<[u8; 64]>> = derive_raft_hmac_key().map(Arc::new);
        if hmac_key.is_some() {
            info!("raft transport HMAC-SHA512 first-factor authentication enabled");
        } else {
            warn!("MILNET_MASTER_KEK not set — raft transport HMAC authentication DISABLED");
        }

        // Per-node ML-DSA-87 authentication: bind every Raft message to its
        // sender's pinned verifying key. This is the PRIMARY transport security
        // factor (the HMAC is only a cheap pre-filter). Built when the master KEK
        // is available (same precondition as the HMAC key).
        let military = std::env::var("MILNET_MILITARY_DEPLOYMENT").as_deref() == Ok("1");
        // The peer registry is wrapped in an RwLock so the cluster-join flow can
        // pin PUBLISHED peer verifying keys after start (military mode), where
        // peer VKs are NOT locally derivable. See `pin_peer_verifying_key`.
        let (node_identity, peer_vks): (
            Option<Arc<NodeIdentity>>,
            Option<Arc<RwLock<NodeIdentityRegistry>>>,
        ) = if hmac_key.is_some() {
            // Build THIS node's identity once. In military mode this unseals (or
            // first-boot generates+seals) the per-node seed from the TPM and
            // fail-closes inside `for_node` if the TPM is unavailable.
            let identity = Arc::new(NodeIdentity::for_node(config.node_id.0));
            let registry = build_peer_verifying_keys(&config, identity.verifying_key(), military);
            let pinned = registry.len();
            if military {
                info!(
                    pinned_nodes = pinned,
                    "raft transport per-node ML-DSA-87 auth enabled (TPM-sealed identity); \
                     PEER verifying keys must be pinned at join via pin_peer_verifying_key"
                );
            } else {
                info!(
                    pinned_nodes = pinned,
                    "raft transport per-node ML-DSA-87 auth enabled (dev KEK-derived; peers pinned)"
                );
            }
            (Some(identity), Some(Arc::new(RwLock::new(registry))))
        } else {
            // FAIL-CLOSED: military mode must never run the Raft control plane
            // without per-node authentication. Without it, a single compromised
            // node can forge consensus messages as any peer.
            if military {
                return Err(
                    "FATAL: MILNET_MILITARY_DEPLOYMENT=1 but no master KEK available — \
                     per-node ML-DSA-87 Raft authentication cannot be established. \
                     Seal the master KEK to this node's TPM before starting."
                        .to_string(),
                );
            }
            warn!("master KEK absent — raft transport per-node ML-DSA authentication DISABLED (non-military)");
            (None, None)
        };

        // Attestation handshaker — LIVE peer verifying-key exchange.
        //
        // Built ONLY in military mode, where `build_peer_verifying_keys` pinned
        // SELF only and peer VKs are not locally derivable (each peer's seed is
        // sealed to its own TPM). Outside military mode every peer is already
        // pinned from the KEK-derived identity, so no exchange is needed and we
        // skip the handshake entirely. The handshaker publishes EXACTLY this
        // node's identity VK (`from_node_identity`) so peers pin the same key the
        // Raft transport signs with.
        let handshaker: Option<Arc<AttestationHandshaker>> =
            match (military, node_identity.as_ref()) {
                (true, Some(identity)) => match AttestationHandshaker::new(identity) {
                    Some(h) => {
                        info!(
                            "attestation handshake ENABLED: publishing this node's \
                             per-node Raft VK to peers and pinning theirs at connect"
                        );
                        Some(Arc::new(h))
                    }
                    None => {
                        // FAIL-CLOSED posture preserved: without a handshaker no
                        // peer is ever pinned, so the transport keeps dropping all
                        // peer Raft messages rather than trusting an unpinned peer.
                        warn!(
                            "attestation handshake DISABLED (verifier unavailable) — \
                             peers will NOT be pinned and their Raft messages stay dropped"
                        );
                        None
                    }
                },
                _ => None,
            };

        // Readiness watch: number of PEERS pinned via the handshake (excludes
        // self). Only meaningful when the handshake is active; consumers await it
        // before snapshotting the registry (see `pinned_peers_watch`). Built only
        // when the handshake is enabled so a `None` here is an unambiguous "no
        // live pinning happens on this node".
        let pinned_peers_tx: Option<watch::Sender<usize>> = if handshaker.is_some() {
            let (tx, _rx) = watch::channel::<usize>(0);
            Some(tx)
        } else {
            None
        };

        // Channel for outgoing Raft messages.
        let (send_tx, send_rx) = mpsc::unbounded_channel::<(NodeId, RaftMessage)>();

        // Task 1: Raft Tick Loop
        {
            let raft = Arc::clone(&raft);
            let send_tx = send_tx.clone();
            let mut shutdown_rx = shutdown_rx.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_millis(100));
                loop {
                    tokio::select! {
                        _ = interval.tick() => {},
                        _ = shutdown_rx.changed() => break,
                    }
                    let messages = raft.lock().await.tick();
                    for (target, msg) in messages {
                        if send_tx.send((target, msg)).is_err() {
                            break;
                        }
                    }
                }
                debug!("raft tick loop shut down");
            });
        }

        // Task 2: Message Listener (TCP)
        {
            let raft = Arc::clone(&raft);
            let send_tx = send_tx.clone();
            let raft_addr = config.raft_addr.clone();
            let mut shutdown_rx = shutdown_rx.clone();
            let hmac_key = hmac_key.clone();
            let peer_vks = peer_vks.clone();
            let handshaker = handshaker.clone();
            let pinned_peers_tx = pinned_peers_tx.clone();
            tokio::spawn(async move {
                let listener = match TcpListener::bind(&raft_addr).await {
                    Ok(l) => l,
                    Err(e) => {
                        error!(addr = %raft_addr, err = %e, "failed to bind raft listener");
                        return;
                    }
                };
                info!(addr = %raft_addr, "raft listener started");
                loop {
                    let (mut stream, peer_addr) = tokio::select! {
                        result = listener.accept() => {
                            match result {
                                Ok(v) => v,
                                Err(e) => {
                                    warn!(err = %e, "failed to accept raft connection");
                                    continue;
                                }
                            }
                        }
                        _ = shutdown_rx.changed() => break,
                    };
                    debug!(peer = %peer_addr, "accepted raft connection");

                    let raft = Arc::clone(&raft);
                    let send_tx = send_tx.clone();
                    let hmac_key = hmac_key.clone();
                    let peer_vks = peer_vks.clone();
                    let handshaker = handshaker.clone();
                    let pinned_peers_tx = pinned_peers_tx.clone();
                    tokio::spawn(async move {
                        // First factor: HMAC frame (cheap, rejects garbage). The
                        // attestation handshake rides inside this same frame, so it
                        // inherits the HMAC pre-filter too.
                        let data = if let Some(ref key) = hmac_key {
                            match recv_authenticated(&mut stream, key).await {
                                Ok(d) => d,
                                Err(e) => {
                                    warn!(peer = %peer_addr, err = %e, "failed to receive authenticated raft message");
                                    return;
                                }
                            }
                        } else {
                            match recv_framed(&mut stream).await {
                                Ok(d) => d,
                                Err(e) => {
                                    warn!(err = %e, "failed to receive raft message");
                                    return;
                                }
                            }
                        };

                        // Demultiplex: a handshake (attestation exchange) or a
                        // Raft control-plane message. A parse error drops the
                        // connection (fail-closed).
                        let frame = match TransportFrame::from_wire(&data) {
                            Ok(f) => f,
                            Err(e) => {
                                warn!(peer = %peer_addr, err = %e, "failed to parse transport frame");
                                return;
                            }
                        };

                        let raft_payload = match frame {
                            TransportFrame::Handshake(att) => {
                                // Inbound peer attestation: verify (sig covers the
                                // published VK + freshness + binary consistency)
                                // and pin the peer's per-node Raft VK. FAIL-CLOSED:
                                // an unverifiable attestation pins nothing, so the
                                // peer's Raft messages keep being dropped.
                                handle_inbound_handshake(
                                    &mut stream,
                                    *att,
                                    &peer_addr.to_string(),
                                    handshaker.as_deref(),
                                    peer_vks.as_ref(),
                                    hmac_key.as_deref(),
                                    pinned_peers_tx.as_ref(),
                                )
                                .await;
                                return;
                            }
                            TransportFrame::Raft(payload) => payload,
                        };

                        // Primary factor: per-node ML-DSA-87 signature bound to
                        // the claimed sender's pinned verifying key. FAIL-CLOSED:
                        // a parse error, an unpinned sender, or a bad signature
                        // drops the message (a node can only sign AS ITSELF).
                        let (from, msg): (NodeId, RaftMessage) =
                            if let Some(ref vks) = peer_vks {
                                let registry = vks.read().await;
                                match verify_transport_message(&raft_payload, &registry) {
                                    Ok(v) => v,
                                    Err(e) => {
                                        warn!(peer = %peer_addr, err = %e, "REJECTING raft message: per-node authentication failed");
                                        return;
                                    }
                                }
                            } else {
                                // Legacy/no-KEK path (non-military, tests):
                                // plain (NodeId, RaftMessage) tuple.
                                match postcard::from_bytes(&raft_payload) {
                                    Ok(v) => v,
                                    Err(e) => {
                                        warn!(err = %e, "failed to deserialize raft message");
                                        return;
                                    }
                                }
                            };
                        let responses = raft.lock().await.handle_message(from, msg);
                        for (target, resp) in responses {
                            if send_tx.send((target, resp)).is_err() {
                                break;
                            }
                        }
                    });
                }
                debug!("raft listener shut down");
            });
        }

        // Task 3: Message Sender
        {
            let config = Arc::clone(&config);
            let mut send_rx = send_rx;
            let mut shutdown_rx = shutdown_rx.clone();
            let hmac_key = hmac_key.clone();
            let node_identity = node_identity.clone();
            tokio::spawn(async move {
                loop {
                    let (target, msg) = tokio::select! {
                        item = send_rx.recv() => {
                            match item {
                                Some(v) => v,
                                None => break,
                            }
                        }
                        _ = shutdown_rx.changed() => break,
                    };

                    // Look up peer address
                    let peer_addr = match config.peers.iter().find(|p| p.node_id == target) {
                        Some(p) => p.raft_addr.clone(),
                        None => {
                            warn!(target = %target, "unknown peer, dropping message");
                            continue;
                        }
                    };

                    // Spawn a short-lived task so we don't block the sender loop
                    let node_id = config.node_id;
                    let hmac_key = hmac_key.clone();
                    let node_identity = node_identity.clone();
                    tokio::spawn(async move {
                        let mut stream = match TcpStream::connect(&peer_addr).await {
                            Ok(s) => s,
                            Err(e) => {
                                debug!(
                                    addr = %peer_addr,
                                    err = %e,
                                    "failed to connect to peer (raft will retry)"
                                );
                                return;
                            }
                        };
                        // Sign with this node's per-node ML-DSA-87 identity when
                        // available; otherwise fall back to the plain tuple
                        // (legacy/no-KEK path). The signature binds the message
                        // to THIS node — a peer cannot replay it as another.
                        let data = if let Some(ref identity) = node_identity {
                            match sign_transport_message(identity, node_id, &msg) {
                                Ok(d) => d,
                                Err(e) => {
                                    warn!(err = %e, "failed to sign raft message");
                                    return;
                                }
                            }
                        } else {
                            let payload: (NodeId, RaftMessage) = (node_id, msg);
                            match postcard::to_allocvec(&payload) {
                                Ok(d) => d,
                                Err(e) => {
                                    warn!(err = %e, "failed to serialize raft message");
                                    return;
                                }
                            }
                        };
                        // Tag as a Raft frame so the peer's listener demultiplexes
                        // it from an attestation handshake. The inner `data` bytes
                        // are unchanged from before this multiplexing layer.
                        let framed = match (TransportFrame::Raft(data)).to_wire() {
                            Ok(f) => f,
                            Err(e) => {
                                warn!(err = %e, "failed to frame raft message");
                                return;
                            }
                        };
                        if let Some(ref key) = hmac_key {
                            if let Err(e) = send_authenticated(&mut stream, &framed, key).await {
                                debug!(addr = %peer_addr, err = %e, "failed to send authenticated raft message");
                            }
                        } else {
                            if let Err(e) = send_framed(&mut stream, &framed).await {
                                debug!(addr = %peer_addr, err = %e, "failed to send raft message");
                            }
                        }
                    });
                }
                debug!("raft sender shut down");
            });
        }

        // Task 4: State Applier
        {
            let raft = Arc::clone(&raft);
            let state = Arc::clone(&state);
            let leader_tx = Arc::clone(&leader_tx);
            let config_clone = Arc::clone(&config);
            let mut shutdown_rx = shutdown_rx.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_millis(100));
                let mut prev_leader: Option<NodeId> = None;
                loop {
                    tokio::select! {
                        _ = interval.tick() => {},
                        _ = shutdown_rx.changed() => break,
                    }

                    let entries = raft.lock().await.take_committed();
                    if !entries.is_empty() {
                        let mut st = state.write().await;
                        for entry in &entries {
                            st.apply(entry);
                        }
                    }

                    // Detect leader changes from the Raft engine
                    let current_role = {
                        let r = raft.lock().await;
                        r.role().clone()
                    };

                    let new_leader = match current_role {
                        RaftRole::Leader => Some(config_clone.node_id),
                        _ => {
                            // Keep what's in cluster state.
                            state.read().await.leader_id
                        }
                    };

                    if new_leader != prev_leader {
                        prev_leader = new_leader;
                        let mut st = state.write().await;
                        st.leader_id = new_leader;
                        let _ = leader_tx.send(new_leader);
                        if let Some(id) = new_leader {
                            info!(
                                leader = %id,
                                "leader changed"
                            );
                        }
                    }
                }
                debug!("state applier shut down");
            });
        }

        // Task 5: Attestation Handshake (LIVE peer verifying-key exchange).
        //
        // Military mode only (handshaker is None otherwise). For each configured
        // peer that is NOT yet pinned, connect over the SAME raft transport, send
        // our signed attestation (TransportFrame::Handshake), read the peer's
        // reply attestation, verify it, and pin the peer's per-node Raft VK. The
        // loop re-runs so a peer that is initially down / restarting / rejoining
        // gets pinned once it answers (dynamic membership). Once every peer is
        // pinned the loop idles cheaply. The listener performs the symmetric pin
        // when a peer connects to US first, so the exchange completes regardless
        // of who initiates.
        if let (Some(handshaker), Some(peer_vks)) = (handshaker.clone(), peer_vks.clone()) {
            let config = Arc::clone(&config);
            let hmac_key = hmac_key.clone();
            let mut shutdown_rx = shutdown_rx.clone();
            let pinned_peers_tx = pinned_peers_tx.clone();
            tokio::spawn(async move {
                // Retry every 2s. tokio's interval fires its FIRST tick
                // immediately, so the first dial may race peers' listeners binding;
                // that just fails and self-heals on the next tick (fail-closed:
                // until a peer answers and verifies, it is never pinned).
                let mut interval = tokio::time::interval(Duration::from_secs(2));
                loop {
                    tokio::select! {
                        _ = interval.tick() => {},
                        _ = shutdown_rx.changed() => break,
                    }

                    // Snapshot which peers still need pinning (cheap read lock).
                    let unpinned: Vec<PeerConfig> = {
                        let reg = peer_vks.read().await;
                        config
                            .peers
                            .iter()
                            .filter(|p| !reg.contains(&p.node_id))
                            .cloned()
                            .collect()
                    };
                    if unpinned.is_empty() {
                        // All peers pinned; nothing to do until membership changes.
                        continue;
                    }

                    for peer in unpinned {
                        let handshaker = handshaker.clone();
                        let peer_vks = peer_vks.clone();
                        let hmac_key = hmac_key.clone();
                        let pinned_peers_tx = pinned_peers_tx.clone();
                        // One short-lived task per peer so a slow/unreachable peer
                        // never blocks the others.
                        tokio::spawn(async move {
                            outbound_handshake(
                                &peer,
                                handshaker.as_ref(),
                                &peer_vks,
                                hmac_key.as_deref(),
                                pinned_peers_tx.as_ref(),
                            )
                            .await;
                        });
                    }
                }
                debug!("attestation handshake task shut down");
            });
        }

        Ok(Self {
            raft,
            state,
            config,
            shutdown_tx,
            leader_tx,
            peer_vks,
            pinned_peers_tx,
        })
    }

    /// Is this node currently the Raft leader?
    pub fn is_leader(&self) -> bool {
        match self.raft.try_lock() {
            Ok(guard) => guard.is_leader(),
            Err(_) => false,
        }
    }

    /// Get the current leader's service address (for request proxying).
    pub fn leader_addr(&self) -> Option<String> {
        let st = self.state.try_read().ok()?;
        st.leader_addr().map(|s| s.to_string())
    }

    /// Get this node's ID.
    pub fn node_id(&self) -> NodeId {
        self.config.node_id
    }

    /// Pin a peer's PUBLISHED ML-DSA-87 verifying key into the Raft transport's
    /// identity registry (the cluster-join step).
    ///
    /// In military mode each node's signing seed is sealed to its OWN TPM, so a
    /// peer's verifying key is NOT locally derivable — the peer publishes it and
    /// the join flow pins it here. After pinning, the transport will accept that
    /// peer's per-node-signed Raft messages; until then they are dropped
    /// (fail-closed). Returns `false` if per-node auth is disabled on this node.
    ///
    /// SECURITY: the caller MUST have authenticated the published VK before
    /// pinning (e.g. it arrived inside an ML-DSA-signed `PeerAttestation` whose
    /// signature was verified during distributed startup). Pinning an
    /// unauthenticated VK would defeat the whole scheme.
    pub async fn pin_peer_verifying_key(&self, node_id: NodeId, verifying_key: Vec<u8>) -> bool {
        match &self.peer_vks {
            Some(reg) => {
                reg.write().await.pin(node_id, verifying_key);
                info!(peer = %node_id, "pinned published peer verifying key into raft transport registry");
                true
            }
            None => {
                warn!(
                    peer = %node_id,
                    "pin_peer_verifying_key called but per-node auth is disabled (non-military, no KEK)"
                );
                false
            }
        }
    }

    /// This node's own ML-DSA-87 verifying key, to be PUBLISHED to peers for
    /// pinning at join. `None` when per-node auth is disabled.
    ///
    /// In military mode this is the verifying key of the node's TPM-sealed
    /// identity; peers pin it via [`Self::pin_peer_verifying_key`].
    pub async fn self_verifying_key(&self) -> Option<Vec<u8>> {
        let reg = self.peer_vks.as_ref()?;
        reg.read().await.verifying_key(&self.config.node_id).map(|vk| vk.to_vec())
    }

    /// The LIVE shared per-node identity registry handle, so OTHER subsystems
    /// (e.g. session-revocation propagation) authenticate against the SAME pinned
    /// `NodeId -> VK` set the Raft transport uses — one registry, no duplication.
    ///
    /// Returns `None` when per-node auth is disabled (non-military, no KEK). The
    /// registry is mutated by [`Self::pin_peer_verifying_key`] at cluster join, so
    /// a holder of this `Arc<RwLock<..>>` always sees the current pinned set
    /// (including peers pinned AFTER this call — correct for dynamic membership).
    /// Read through it with `.read().await` then `registry.verify(node_id, ..)`.
    pub fn identity_registry(&self) -> Option<Arc<RwLock<NodeIdentityRegistry>>> {
        self.peer_vks.clone()
    }

    /// A point-in-time CLONE of the current pinned identity registry, for callers
    /// whose API wants an owned / `Arc<NodeIdentityRegistry>` (e.g. a revocation
    /// signer built via `NodeDsaSigner::from_node_identity`).
    ///
    /// IMPORTANT: this is a SNAPSHOT — peers pinned AFTER this call are NOT
    /// reflected. Take it AFTER cluster-join pinning completes, or prefer
    /// [`Self::identity_registry`] for a live view. Returns `None` when per-node
    /// auth is disabled.
    pub async fn identity_registry_snapshot(&self) -> Option<NodeIdentityRegistry> {
        let reg = self.peer_vks.as_ref()?;
        Some(reg.read().await.clone())
    }

    /// The number of cluster PEERS configured for this node (excludes self).
    ///
    /// A readiness consumer waits until [`Self::pinned_peers_watch`] reports this
    /// many pinned peers before treating an `identity_registry_snapshot()` as
    /// complete. (Note: this is the CONFIGURED peer count; if a peer is down at
    /// startup the count may never reach it, so consumers should also accept
    /// quorum-sized progress, not strictly all peers.)
    pub fn expected_peer_count(&self) -> usize {
        self.config.peers.len()
    }

    /// Subscribe to the count of PEERS pinned via the attestation handshake
    /// (excludes self), so a consumer learns WHEN peers are pinned.
    ///
    /// SNAPSHOT-TIMING CONTRACT (for the revocation layer and any other registry
    /// consumer): peer pinning is ASYNCHRONOUS and ONGOING after [`Self::start`]
    /// returns — a peer is pinned only once its signed attestation has been
    /// exchanged and verified, which for a slow/restarting peer can be seconds
    /// later. Therefore an [`Self::identity_registry_snapshot`] taken immediately
    /// after `start` will MISS peers. To snapshot safely:
    ///
    /// ```ignore
    /// if let Some(mut rx) = node.pinned_peers_watch() {
    ///     // wait until at least a quorum of peers is pinned (or all):
    ///     let want = node.expected_peer_count();
    ///     let _ = rx.wait_for(|&n| n >= want).await;
    /// }
    /// let snap = node.identity_registry_snapshot().await; // now complete
    /// ```
    ///
    /// PREFERRED ALTERNATIVE: hold the LIVE [`Self::identity_registry`] handle and
    /// read through it at verification time — it always reflects the current
    /// pinned set (including peers pinned later / after a reconnect), so no
    /// barrier is needed. Use the snapshot+watch only if your API requires an
    /// owned registry.
    ///
    /// Returns `None` when no ASYNCHRONOUS pinning happens on this node:
    ///  * NON-MILITARY (dev/test): peers are pinned SYNCHRONOUSLY at `start`
    ///    (locally KEK-derived, see `build_peer_verifying_keys`), so an
    ///    `identity_registry_snapshot()` is already complete the instant `start`
    ///    returns — no barrier is needed and `None` means "snapshot anytime".
    ///  * NO KEK: per-node auth is fully disabled; there is no registry to snapshot.
    /// `Some(rx)` is returned ONLY in military mode, where pinning is async and the
    /// barrier above is required.
    pub fn pinned_peers_watch(&self) -> Option<watch::Receiver<usize>> {
        self.pinned_peers_tx.as_ref().map(|tx| tx.subscribe())
    }

    /// Get a snapshot of the current cluster state.
    pub fn cluster_state(&self) -> ClusterState {
        match self.state.try_read() {
            Ok(guard) => guard.clone(),
            Err(_) => ClusterState::new(),
        }
    }

    /// Get the current fencing token.
    pub fn fencing_token(&self) -> u64 {
        match self.state.try_read() {
            Ok(guard) => guard.fencing_token,
            Err(_) => 0,
        }
    }

    /// Propose a command to the cluster (leader only).
    ///
    /// Returns the log index assigned to the command if this node is the leader.
    pub fn propose(&self, cmd: ClusterCommand) -> Result<LogIndex, String> {
        match self.raft.try_lock() {
            Ok(mut guard) => guard.propose(cmd),
            Err(_) => Err("raft lock contended, try again".into()),
        }
    }

    /// Shutdown the cluster node gracefully.
    pub async fn shutdown(&self) {
        info!(node_id = %self.config.node_id, "shutting down cluster node");
        let _ = self.shutdown_tx.send(true);
        // Give background tasks a moment to exit.
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    /// Subscribe to leader change events.
    pub fn leader_watch(&self) -> watch::Receiver<Option<NodeId>> {
        self.leader_tx.subscribe()
    }
}

/// Start a cluster node. In production mode, cluster membership is MANDATORY.
/// The service will panic if it cannot join the cluster.
pub async fn require_cluster(
    service_type: ServiceType,
    listen_addr: &str,
) -> Option<std::sync::Arc<ClusterNode>> {
    match ClusterConfig::from_env_with_defaults(service_type, listen_addr) {
        Ok(config) => {
            tracing::info!(
                node_id = %config.node_id,
                peers = config.peers.len(),
                "starting cluster node"
            );
            match ClusterNode::start(config).await {
                Ok(node) => Some(std::sync::Arc::new(node)),
                Err(e) => {
                    panic!("FATAL: cluster start failed: {e}. \
                           Set MILNET_CLUSTER_PEERS for distributed operation.");
                }
            }
        }
        Err(e) => {
            panic!("FATAL: no cluster config: {e}. \
                   Set MILNET_CLUSTER_PEERS for distributed operation.");
        }
    }
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;

    fn test_node_id(n: u8) -> NodeId {
        NodeId(uuid::Uuid::from_bytes([n; 16]))
    }

    #[test]
    fn service_type_display_roundtrip() {
        let types = [
            ServiceType::Orchestrator,
            ServiceType::TssCoordinator,
            ServiceType::Opaque,
            ServiceType::Gateway,
            ServiceType::Audit,
        ];
        for st in &types {
            let s = st.to_string();
            let parsed: ServiceType = s.parse().expect("roundtrip failed");
            assert_eq!(*st, parsed);
        }
    }

    #[test]
    fn service_type_parse_variants() {
        assert_eq!(
            "tss_coordinator".parse::<ServiceType>().unwrap(),
            ServiceType::TssCoordinator
        );
        assert_eq!(
            "tsscoordinator".parse::<ServiceType>().unwrap(),
            ServiceType::TssCoordinator
        );
        assert!("invalid".parse::<ServiceType>().is_err());
    }

    #[test]
    fn parse_peers_valid() {
        let input = "1a@10.0.0.1:9090/10.0.0.1:8080,2b@10.0.0.2:9090/10.0.0.2:8080";
        let peers = parse_peers(input).unwrap();
        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0].node_id, NodeId(uuid::Uuid::from_u128(0x1a)));
        assert_eq!(peers[0].raft_addr, "10.0.0.1:9090");
        assert_eq!(peers[0].service_addr, "10.0.0.1:8080");
        assert_eq!(peers[1].node_id, NodeId(uuid::Uuid::from_u128(0x2b)));
    }

    #[test]
    fn canonical_node_id_uuid_hex_and_v5() {
        // UUID string round-trips.
        let u = uuid::Uuid::from_u128(0x2a);
        assert_eq!(canonical_node_id(&u.to_string()), NodeId(u));
        // Hex (with/without 0x) → from_u128.
        assert_eq!(canonical_node_id("0x2a"), NodeId(uuid::Uuid::from_u128(0x2a)));
        assert_eq!(canonical_node_id("2a"), NodeId(uuid::Uuid::from_u128(0x2a)));
        // Non-UUID deploy id → STABLE, distinct UUIDv5 (not rejected).
        let a = canonical_node_id("orchestrator-0");
        assert_eq!(a, canonical_node_id("orchestrator-0"), "deterministic");
        assert_ne!(a, canonical_node_id("orchestrator-1"), "distinct per id");
        assert_ne!(a, canonical_node_id("tss-coordinator-0"));
    }

    #[test]
    fn parse_peers_empty() {
        let peers = parse_peers("").unwrap();
        assert!(peers.is_empty());
    }

    #[test]
    fn parse_peers_invalid_no_at() {
        assert!(parse_peers("1a-10.0.0.1:9090/10.0.0.1:8080").is_err());
    }

    #[test]
    fn parse_peers_invalid_no_slash() {
        assert!(parse_peers("1a@10.0.0.1:9090-10.0.0.1:8080").is_err());
    }

    #[test]
    #[should_panic(expected = "standalone mode forbidden in production")]
    fn cluster_config_from_env_rejects_standalone_in_production() {
        // Production mode correctly rejects zero-peer (standalone) configuration.
        // This is a security invariant: no single-node deployment in production.
        std::env::remove_var("MILNET_NODE_ID");
        std::env::remove_var("MILNET_SERVICE_TYPE");
        std::env::remove_var("MILNET_SERVICE_ADDR");
        std::env::remove_var("MILNET_RAFT_ADDR");
        std::env::remove_var("MILNET_CLUSTER_PEERS");
        std::env::remove_var("MILNET_STATIC_PEERS");

        let _ = ClusterConfig::from_env();
    }

    #[test]
    fn cluster_config_from_env_with_peers() {
        // Production mode accepts properly configured cluster peers.
        // Peer format: UUID@raft_addr/service_addr
        std::env::set_var(
            "MILNET_CLUSTER_PEERS",
            "00000000-0000-0000-0000-000000000002@10.0.0.2:9090/10.0.0.2:8080,\
             00000000-0000-0000-0000-000000000003@10.0.0.3:9090/10.0.0.3:8080",
        );
        std::env::remove_var("MILNET_NODE_ID");
        std::env::remove_var("MILNET_SERVICE_TYPE");
        std::env::remove_var("MILNET_SERVICE_ADDR");
        std::env::remove_var("MILNET_RAFT_ADDR");

        let cfg = ClusterConfig::from_env().unwrap();
        assert_eq!(cfg.service_type, ServiceType::Gateway);
        assert!(!cfg.peers.is_empty(), "peers must be configured in production");
        std::env::remove_var("MILNET_CLUSTER_PEERS");
    }

    #[test]
    fn cluster_state_apply_member_join() {
        let mut state = ClusterState::new();
        let entry = LogEntry {
            term: Term(1),
            index: LogIndex(1),
            command: ClusterCommand::MemberJoin {
                node_id: test_node_id(42),
                addr: "10.0.0.1:8080".to_string(),
                service_type: "orchestrator".to_string(),
            },
            entry_signature: None,
        };
        state.apply(&entry);
        assert_eq!(state.member_count(), 1);
        let member = state.members.get(&test_node_id(42)).unwrap();
        assert_eq!(member.addr, "10.0.0.1:8080");
        assert_eq!(member.service_type, ServiceType::Orchestrator);
        assert!(member.healthy);
    }

    #[test]
    fn cluster_state_apply_member_leave() {
        let mut state = ClusterState::new();
        state.apply(&LogEntry {
            term: Term(1),
            index: LogIndex(1),
            command: ClusterCommand::MemberJoin {
                node_id: test_node_id(42),
                addr: "10.0.0.1:8080".to_string(),
                service_type: "gateway".to_string(),
            },
            entry_signature: None,
        });
        assert_eq!(state.member_count(), 1);

        state.apply(&LogEntry {
            term: Term(1),
            index: LogIndex(2),
            command: ClusterCommand::MemberLeave {
                node_id: test_node_id(42),
            },
            entry_signature: None,
        });
        assert_eq!(state.member_count(), 0);
    }

    #[test]
    fn cluster_state_apply_health_update() {
        let mut state = ClusterState::new();
        state.apply(&LogEntry {
            term: Term(1),
            index: LogIndex(1),
            command: ClusterCommand::MemberJoin {
                node_id: test_node_id(7),
                addr: "10.0.0.1:8080".to_string(),
                service_type: "audit".to_string(),
            },
            entry_signature: None,
        });
        let before = state.members.get(&test_node_id(7)).unwrap().last_seen;

        // Small delay so Instant differs
        std::thread::sleep(std::time::Duration::from_millis(1));

        state.apply(&LogEntry {
            term: Term(1),
            index: LogIndex(2),
            command: ClusterCommand::HealthUpdate {
                node_id: test_node_id(7),
                healthy: true,
            },
            entry_signature: None,
        });
        let after = state.members.get(&test_node_id(7)).unwrap().last_seen;
        assert!(after >= before);
    }

    #[test]
    fn cluster_state_apply_noop() {
        let mut state = ClusterState::new();
        state.apply(&LogEntry {
            term: Term(1),
            index: LogIndex(1),
            command: ClusterCommand::Noop,
            entry_signature: None,
        });
        assert_eq!(state.member_count(), 0);
        assert_eq!(state.fencing_token, 0);
    }

    #[test]
    fn cluster_state_leader_addr() {
        let mut state = ClusterState::new();
        assert!(state.leader_addr().is_none());

        let nid = test_node_id(1);
        state.apply(&LogEntry {
            term: Term(1),
            index: LogIndex(1),
            command: ClusterCommand::MemberJoin {
                node_id: nid,
                addr: "leader.milnet:8080".to_string(),
                service_type: "orchestrator".to_string(),
            },
            entry_signature: None,
        });
        state.leader_id = Some(nid);
        assert_eq!(state.leader_addr(), Some("leader.milnet:8080"));
    }

    #[test]
    fn cluster_state_healthy_members() {
        let mut state = ClusterState::new();
        let n1 = test_node_id(1);
        let n2 = test_node_id(2);
        state.apply(&LogEntry {
            term: Term(1),
            index: LogIndex(1),
            command: ClusterCommand::MemberJoin {
                node_id: n1,
                addr: "a:8080".to_string(),
                service_type: "gateway".to_string(),
            },
            entry_signature: None,
        });
        state.apply(&LogEntry {
            term: Term(1),
            index: LogIndex(2),
            command: ClusterCommand::MemberJoin {
                node_id: n2,
                addr: "b:8080".to_string(),
                service_type: "gateway".to_string(),
            },
            entry_signature: None,
        });
        // Mark one unhealthy
        state.members.get_mut(&n2).unwrap().healthy = false;

        let healthy = state.healthy_members();
        assert_eq!(healthy.len(), 1);
        assert_eq!(healthy[0].node_id, n1);
    }

    #[tokio::test]
    async fn standalone_node_is_rejected() {
        let nid = NodeId(uuid::Uuid::from_u128(0xCAFE));
        let config = ClusterConfig {
            node_id: nid,
            service_type: ServiceType::Orchestrator,
            service_addr: "127.0.0.1:0".to_string(),
            raft_addr: "127.0.0.1:0".to_string(),
            peers: vec![],
            raft_config: RaftConfig::default(),
        };

        let result = ClusterNode::start(config).await;
        match result {
            Err(err) => {
                assert!(
                    err.contains("standalone") && err.contains("forbidden"),
                    "error must mention standalone mode is forbidden, got: {err}"
                );
            }
            Ok(_) => panic!("standalone mode must be rejected, but start() succeeded"),
        }
    }

    // ── Per-node ML-DSA-87 Raft transport authentication (CRITICAL fix) ──────
    //
    // These exercise the transport sign/verify primitives directly with
    // explicit-seed identities (no KEK needed). ML-DSA-87 keys are large, so the
    // tests run on a thread with extra stack (matches RUST_MIN_STACK on OCI).

    fn run_with_large_stack<F: FnOnce() + Send + 'static>(f: F) {
        std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(f)
            .expect("thread spawn failed")
            .join()
            .expect("test thread panicked");
    }

    fn test_identity(n: u8) -> crate::distributed_startup::NodeIdentity {
        crate::distributed_startup::NodeIdentity::from_seed(
            uuid::Uuid::from_bytes([n; 16]),
            [n; 32],
        )
    }

    fn registry_with(
        identities: &[&crate::distributed_startup::NodeIdentity],
    ) -> NodeIdentityRegistry {
        let mut reg = NodeIdentityRegistry::new();
        for id in identities {
            reg.pin(id.node_id(), id.verifying_key());
        }
        reg
    }

    fn sample_request_vote(candidate: NodeId) -> RaftMessage {
        RaftMessage::RequestVote {
            term: Term(7),
            candidate_id: candidate,
            last_log_index: LogIndex(3),
            last_log_term: Term(6),
        }
    }

    /// A valid per-node-signed message verifies and round-trips its contents.
    #[test]
    fn transport_valid_signature_verifies() {
        run_with_large_stack(|| {
            let id_a = test_identity(1);
            let node_a = id_a.node_id();
            let registry = registry_with(&[&id_a]);

            let msg = sample_request_vote(node_a);
            let wire = sign_transport_message(&id_a, node_a, &msg).unwrap();
            let (from, got) = verify_transport_message(&wire, &registry).unwrap();
            assert_eq!(from, node_a);
            assert_eq!(got, msg);
        });
    }

    /// CORE ANTI-FORGERY PROPERTY (the CRITICAL finding): a compromised node A
    /// cannot forge a message attributed to node B. Even though A controls the
    /// `sender_id` field and signs over B's id, A signs with A's key, which does
    /// not verify under B's pinned verifying key.
    #[test]
    fn transport_node_cannot_forge_as_another_node() {
        run_with_large_stack(|| {
            let id_a = test_identity(1); // compromised node
            let id_b = test_identity(2); // victim identity A wants to impersonate
            let node_b = id_b.node_id();

            // Both A and B are pinned (their VKs known at join).
            let registry = registry_with(&[&id_a, &id_b]);

            // A crafts a RequestVote claiming to be B, signing (domain||B||msg)
            // with A's OWN key (A does not have B's signing seed).
            let forged_msg = sample_request_vote(node_b);
            let msg_bytes = postcard::to_allocvec(&forged_msg).unwrap();
            let signed = transport_signed_bytes(node_b, &msg_bytes);
            let forged_sig = id_a.node_sign(&signed);
            let forged_envelope = NodeAuthenticatedRaftMessage {
                sender_id: node_b, // LIE: claims to be B
                message: forged_msg,
                ml_dsa_sig: forged_sig,
            };
            let wire = postcard::to_allocvec(&forged_envelope).unwrap();

            // Verifier reconstructs (domain||B||msg) and checks against B's
            // pinned key → A's signature fails. Forgery rejected.
            let result = verify_transport_message(&wire, &registry);
            assert!(
                result.is_err(),
                "node A must NOT be able to forge a message as node B"
            );
        });
    }

    /// A tampered message body is rejected (signature no longer matches).
    #[test]
    fn transport_tampered_message_rejected() {
        run_with_large_stack(|| {
            let id_a = test_identity(1);
            let node_a = id_a.node_id();
            let registry = registry_with(&[&id_a]);

            let msg = sample_request_vote(node_a);
            let wire = sign_transport_message(&id_a, node_a, &msg).unwrap();

            // Tamper: parse, swap the message for a different term, re-serialize
            // WITHOUT re-signing.
            let mut env: NodeAuthenticatedRaftMessage =
                postcard::from_bytes(&wire).unwrap();
            env.message = RaftMessage::RequestVote {
                term: Term(999), // attacker bumps term to win election
                candidate_id: node_a,
                last_log_index: LogIndex(3),
                last_log_term: Term(6),
            };
            let tampered_wire = postcard::to_allocvec(&env).unwrap();

            assert!(
                verify_transport_message(&tampered_wire, &registry).is_err(),
                "tampered Raft message must be rejected"
            );
        });
    }

    /// A tampered signature is rejected.
    #[test]
    fn transport_tampered_signature_rejected() {
        run_with_large_stack(|| {
            let id_a = test_identity(1);
            let node_a = id_a.node_id();
            let registry = registry_with(&[&id_a]);

            let msg = sample_request_vote(node_a);
            let wire = sign_transport_message(&id_a, node_a, &msg).unwrap();

            let mut env: NodeAuthenticatedRaftMessage =
                postcard::from_bytes(&wire).unwrap();
            if !env.ml_dsa_sig.is_empty() {
                env.ml_dsa_sig[0] ^= 0xFF;
            }
            let tampered_wire = postcard::to_allocvec(&env).unwrap();

            assert!(
                verify_transport_message(&tampered_wire, &registry).is_err(),
                "message with tampered ML-DSA signature must be rejected"
            );
        });
    }

    /// FAIL-CLOSED: a message from an unpinned / unknown sender is rejected even
    /// if its own self-consistent signature is valid.
    #[test]
    fn transport_unpinned_sender_rejected() {
        run_with_large_stack(|| {
            let id_a = test_identity(1);
            let node_a = id_a.node_id();

            // Registry that does NOT contain node_a (never pinned at join).
            let id_b = test_identity(2);
            let registry = registry_with(&[&id_b]);

            // A produces a perfectly valid self-signed message.
            let msg = sample_request_vote(node_a);
            let wire = sign_transport_message(&id_a, node_a, &msg).unwrap();

            assert!(
                verify_transport_message(&wire, &registry).is_err(),
                "message from an unpinned sender must be rejected (fail-closed)"
            );
        });
    }

    /// The pinned registry built from config derives the SAME verifying key that
    /// each node's own identity produces (so legitimate peers verify).
    #[test]
    fn transport_registry_consistent_for_same_kek() {
        run_with_large_stack(|| {
            // Same explicit seed on both sides simulates the shared-KEK
            // derivation agreeing on a peer's verifying key.
            let seed = [0x5Au8; 32];
            let uuid_val = uuid::Uuid::from_u128(0xABCD);
            let node = NodeId(uuid_val);
            let signer = crate::distributed_startup::NodeIdentity::from_seed(uuid_val, seed);
            let pinned = crate::distributed_startup::NodeIdentity::from_seed(uuid_val, seed);
            let registry = registry_with(&[&pinned]);

            let msg = sample_request_vote(node);
            let wire = sign_transport_message(&signer, node, &msg).unwrap();
            assert!(
                verify_transport_message(&wire, &registry).is_ok(),
                "a peer signing with the KEK-derived key must verify against the pinned key"
            );
        });
    }

    // ── Attestation handshake (LIVE peer verifying-key exchange) ─────────────
    //
    // These exercise the multiplexing frame and the verify+pin policy that turns
    // a peer's signed attestation into a pinned per-node Raft verifying key. The
    // handshaker is built from an explicit verifier (no env/TPM) via the
    // test-only constructor. ML-DSA-87 keys are large → run on a big stack.

    use std::time::{SystemTime, UNIX_EPOCH};

    fn now_secs_for_test() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    /// A handshaker whose verifier has 2 configured peers, 60s max age, no
    /// rolling update, and an own binary hash of all-zero (matches the test-env
    /// `compute_own_binary_hash` fallback, so binary consistency passes against
    /// peers that also use [0;64]).
    fn test_handshaker() -> AttestationHandshaker {
        let verifier = crate::distributed_startup::DistributedStartupVerifier::with_config(
            2,
            std::time::Duration::from_secs(30),
            std::time::Duration::from_secs(60),
            vec!["10.0.0.1:9090".to_string(), "10.0.0.2:9090".to_string()],
            [0xA1u8; 32], // attestation signing seed (this node) — unused for peer verify
            "self-node".to_string(),
            false,
        );
        AttestationHandshaker::from_verifier_for_test(verifier, [0u8; 64])
    }

    /// Build a peer's per-node Raft identity VK from an explicit seed.
    fn peer_raft_vk(seed: u8) -> Vec<u8> {
        crate::distributed_startup::NodeIdentity::from_seed(
            uuid::Uuid::from_bytes([seed; 16]),
            [seed; 32],
        )
        .verifying_key()
    }

    /// TransportFrame round-trips for both variants (the multiplexing contract).
    #[test]
    fn transport_frame_roundtrip() {
        run_with_large_stack(|| {
            // Raft variant: arbitrary inner bytes survive the outer tag.
            let raft = TransportFrame::Raft(vec![1, 2, 3, 4, 5]);
            let wire = raft.to_wire().unwrap();
            match TransportFrame::from_wire(&wire).unwrap() {
                TransportFrame::Raft(b) => assert_eq!(b, vec![1, 2, 3, 4, 5]),
                _ => panic!("expected Raft variant"),
            }

            // Handshake variant: a signed attestation round-trips intact.
            let att = crate::distributed_startup::create_test_attestation_with_raft_vk(
                "peer-1",
                &[0xB2u8; 32],
                &[0u8; 64],
                "boot",
                now_secs_for_test(),
                &peer_raft_vk(2),
            );
            let hs = TransportFrame::Handshake(Box::new(att.clone()));
            let wire = hs.to_wire().unwrap();
            match TransportFrame::from_wire(&wire).unwrap() {
                TransportFrame::Handshake(got) => {
                    assert_eq!(got.node_id, att.node_id);
                    assert_eq!(got.raft_verifying_key, att.raft_verifying_key);
                }
                _ => panic!("expected Handshake variant"),
            }
        });
    }

    /// A valid attestation is accepted and yields the correct (NodeId, raft VK).
    #[test]
    fn handshake_valid_attestation_pins_peer_vk() {
        run_with_large_stack(|| {
            let hs = test_handshaker();
            let vk = peer_raft_vk(2);
            let att = crate::distributed_startup::create_test_attestation_with_raft_vk(
                "peer-1",
                &[0xB2u8; 32],
                &[0u8; 64],
                "boot",
                now_secs_for_test(),
                &vk,
            );
            let (node_id, got_vk) = hs
                .verify_and_extract(&att)
                .expect("valid attestation must verify");
            assert_eq!(node_id, canonical_node_id("peer-1"));
            assert_eq!(got_vk, vk);

            // The pinned VK must actually authenticate that peer's Raft messages.
            let mut registry = NodeIdentityRegistry::new();
            registry.pin(node_id, got_vk);
            let peer_identity = crate::distributed_startup::NodeIdentity::from_seed(
                canonical_node_id("peer-1").0,
                [2u8; 32],
            );
            let msg = sample_request_vote(node_id);
            let wire = sign_transport_message(&peer_identity, node_id, &msg).unwrap();
            assert!(
                verify_transport_message(&wire, &registry).is_ok(),
                "after pinning from the attestation, the peer's Raft msg must verify"
            );
        });
    }

    /// A tampered attestation signature is rejected → nothing pinned.
    #[test]
    fn handshake_tampered_signature_rejected() {
        run_with_large_stack(|| {
            let hs = test_handshaker();
            let mut att = crate::distributed_startup::create_test_attestation_with_raft_vk(
                "peer-1",
                &[0xB2u8; 32],
                &[0u8; 64],
                "boot",
                now_secs_for_test(),
                &peer_raft_vk(2),
            );
            att.signature[0] ^= 0xFF;
            assert!(
                hs.verify_and_extract(&att).is_err(),
                "tampered attestation signature must be rejected (fail-closed)"
            );
        });
    }

    /// Swapping the published raft_verifying_key after signing is rejected: the
    /// attestation signature COVERS the VK, so the swap invalidates the signature.
    /// This is the core anti-MITM property (a peer's VK cannot be substituted).
    #[test]
    fn handshake_swapped_raft_vk_rejected() {
        run_with_large_stack(|| {
            let hs = test_handshaker();
            let mut att = crate::distributed_startup::create_test_attestation_with_raft_vk(
                "peer-1",
                &[0xB2u8; 32],
                &[0u8; 64],
                "boot",
                now_secs_for_test(),
                &peer_raft_vk(2),
            );
            // Attacker swaps in a DIFFERENT VK (e.g. their own) without re-signing.
            att.raft_verifying_key = peer_raft_vk(9);
            assert!(
                hs.verify_and_extract(&att).is_err(),
                "a swapped raft_verifying_key must invalidate the attestation signature"
            );
        });
    }

    /// An expired attestation (older than max_age) is rejected.
    #[test]
    fn handshake_expired_attestation_rejected() {
        run_with_large_stack(|| {
            let hs = test_handshaker();
            let att = crate::distributed_startup::create_test_attestation_with_raft_vk(
                "peer-1",
                &[0xB2u8; 32],
                &[0u8; 64],
                "boot",
                now_secs_for_test() - 200, // 200s old > 60s max
                &peer_raft_vk(2),
            );
            assert!(
                hs.verify_and_extract(&att).is_err(),
                "an expired attestation must be rejected"
            );
        });
    }

    /// A peer running a DIFFERENT binary is not pinned (binary consistency),
    /// when not in a rolling update.
    #[test]
    fn handshake_binary_mismatch_rejected() {
        run_with_large_stack(|| {
            let hs = test_handshaker(); // own_binary_hash = [0;64], rolling_update=false
            let mut different = [0u8; 64];
            different[0] = 0xFF;
            let att = crate::distributed_startup::create_test_attestation_with_raft_vk(
                "peer-1",
                &[0xB2u8; 32],
                &different,
                "boot",
                now_secs_for_test(),
                &peer_raft_vk(2),
            );
            assert!(
                hs.verify_and_extract(&att).is_err(),
                "a peer with a mismatched binary hash must not be pinned"
            );
        });
    }

    /// An attestation with no published raft_verifying_key is not pinned
    /// (fail-closed: an unpinned peer's Raft messages are dropped, not trusted).
    #[test]
    fn handshake_missing_raft_vk_rejected() {
        run_with_large_stack(|| {
            let hs = test_handshaker();
            let att = crate::distributed_startup::create_test_attestation_with_raft_vk(
                "peer-1",
                &[0xB2u8; 32],
                &[0u8; 64],
                "boot",
                now_secs_for_test(),
                &[], // legacy peer: no published VK
            );
            assert!(
                hs.verify_and_extract(&att).is_err(),
                "an attestation with no raft_verifying_key must not be pinned"
            );
        });
    }
}
