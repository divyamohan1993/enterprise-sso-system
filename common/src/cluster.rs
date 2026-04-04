#![deny(unsafe_code)]
//! Cluster coordination layer.
//!
//! Wraps the Raft engine into an async service that handles:
//! - Network transport for Raft messages (over TCP + postcard)
//! - Periodic ticking of the Raft state machine
//! - Applying committed log entries to cluster state
//! - Exposing leader/follower status to the service

use std::collections::HashMap;
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

// ── PeerConfig ──

/// Configuration for a single peer in the cluster.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    let is_production = std::env::var("MILNET_PRODUCTION")
        .map(|v| v == "1")
        .unwrap_or(false);
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

/// Parse node ID from MILNET_NODE_ID env var, or generate a random one.
fn parse_node_id_from_env() -> Result<NodeId, String> {
    match std::env::var("MILNET_NODE_ID") {
        Ok(val) => {
            if let Ok(uuid) = uuid::Uuid::parse_str(&val) {
                Ok(NodeId(uuid))
            } else {
                let n = u128::from_str_radix(val.trim_start_matches("0x"), 16)
                    .map_err(|e| format!("invalid MILNET_NODE_ID: {e}"))?;
                Ok(NodeId(uuid::Uuid::from_u128(n)))
            }
        }
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
    use zeroize::Zeroize;
    let mut kek_hex = std::env::var("MILNET_MASTER_KEK").ok()?;
    let mut kek_bytes = hex::decode(kek_hex.trim()).ok()?;
    kek_hex.zeroize();
    if kek_bytes.is_empty() {
        return None;
    }

    use hkdf::Hkdf;
    let hk = Hkdf::<Sha512>::new(None, &kek_bytes);
    kek_bytes.zeroize();
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

// ── ClusterNode ──

/// The main async coordination handle.
///
/// Embeds a Raft state machine and manages background tasks for network
/// transport, periodic ticking, and state application.
pub struct ClusterNode {
    raft: Arc<Mutex<RaftState>>,
    state: Arc<RwLock<ClusterState>>,
    config: Arc<ClusterConfig>,
    shutdown_tx: watch::Sender<bool>,
    leader_tx: Arc<watch::Sender<Option<NodeId>>>,
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

        // Derive HMAC key for Raft transport authentication.
        let hmac_key: Option<Arc<[u8; 64]>> = derive_raft_hmac_key().map(Arc::new);
        if hmac_key.is_some() {
            info!("raft transport HMAC-SHA512 authentication enabled");
        } else {
            warn!("MILNET_MASTER_KEK not set — raft transport HMAC authentication DISABLED");
        }

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
                    tokio::spawn(async move {
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
                        let (from, msg): (NodeId, RaftMessage) =
                            match postcard::from_bytes(&data) {
                                Ok(v) => v,
                                Err(e) => {
                                    warn!(err = %e, "failed to deserialize raft message");
                                    return;
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
                        let payload: (NodeId, RaftMessage) = (node_id, msg);
                        let data = match postcard::to_allocvec(&payload) {
                            Ok(d) => d,
                            Err(e) => {
                                warn!(err = %e, "failed to serialize raft message");
                                return;
                            }
                        };
                        if let Some(ref key) = hmac_key {
                            if let Err(e) = send_authenticated(&mut stream, &data, key).await {
                                debug!(addr = %peer_addr, err = %e, "failed to send authenticated raft message");
                            }
                        } else {
                            if let Err(e) = send_framed(&mut stream, &data).await {
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

        Ok(Self {
            raft,
            state,
            config,
            shutdown_tx,
            leader_tx,
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
    fn cluster_config_from_env_defaults() {
        // Clear relevant env vars to ensure defaults
        std::env::remove_var("MILNET_NODE_ID");
        std::env::remove_var("MILNET_SERVICE_TYPE");
        std::env::remove_var("MILNET_SERVICE_ADDR");
        std::env::remove_var("MILNET_RAFT_ADDR");
        std::env::remove_var("MILNET_CLUSTER_PEERS");

        let cfg = ClusterConfig::from_env().unwrap();
        assert_eq!(cfg.service_type, ServiceType::Gateway);
        assert_eq!(cfg.service_addr, "127.0.0.1:8080");
        assert_eq!(cfg.raft_addr, "127.0.0.1:9090");
        assert!(cfg.peers.is_empty());
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
        });
        assert_eq!(state.member_count(), 1);

        state.apply(&LogEntry {
            term: Term(1),
            index: LogIndex(2),
            command: ClusterCommand::MemberLeave {
                node_id: test_node_id(42),
            },
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
        });
        state.apply(&LogEntry {
            term: Term(1),
            index: LogIndex(2),
            command: ClusterCommand::MemberJoin {
                node_id: n2,
                addr: "b:8080".to_string(),
                service_type: "gateway".to_string(),
            },
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
}
