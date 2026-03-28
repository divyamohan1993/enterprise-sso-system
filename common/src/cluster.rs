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

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch, Mutex, RwLock};
use tracing::{debug, error, info, warn};

use super::raft::{
    ClusterCommand, LogEntry, LogIndex, NodeId, RaftConfig, RaftMessage, RaftRole, RaftState, Term,
};

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
    /// The Raft transport address.
    pub raft_addr: String,
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
    pub term: Term,
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
        self.term = entry.term;
        match &entry.command {
            ClusterCommand::RegisterNode {
                node_id,
                service_addr,
                raft_addr,
                service_type,
            } => {
                let svc_type = ServiceType::from_str(service_type).unwrap_or(ServiceType::Gateway);
                self.members.insert(
                    *node_id,
                    MemberInfo {
                        node_id: *node_id,
                        addr: service_addr.clone(),
                        raft_addr: raft_addr.clone(),
                        service_type: svc_type,
                        healthy: true,
                        last_seen: Instant::now(),
                    },
                );
            }
            ClusterCommand::DeregisterNode { node_id } => {
                self.members.remove(node_id);
            }
            ClusterCommand::Heartbeat { node_id } => {
                if let Some(member) = self.members.get_mut(node_id) {
                    member.healthy = true;
                    member.last_seen = Instant::now();
                }
            }
            ClusterCommand::BumpFencingToken => {
                self.fencing_token += 1;
            }
            ClusterCommand::Application { .. } => {
                // Application-level commands are handled by the embedding service,
                // not by the cluster state machine.
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    /// - `MILNET_NODE_ID` — 128-bit hex node ID (generated if absent)
    /// - `MILNET_SERVICE_TYPE` — one of: orchestrator, tss-coordinator, opaque, gateway, audit
    /// - `MILNET_SERVICE_ADDR` — this node's service address (default `127.0.0.1:8080`)
    /// - `MILNET_RAFT_ADDR` — this node's Raft transport address (default `127.0.0.1:9090`)
    /// - `MILNET_CLUSTER_PEERS` — comma-separated peer list:
    ///   `node-id@raft-host:raft-port/svc-host:svc-port,...`
    ///   If not set, the node runs in standalone (single-node) mode.
    pub fn from_env() -> Result<Self, String> {
        let node_id: NodeId = match std::env::var("MILNET_NODE_ID") {
            Ok(val) => {
                if let Ok(uuid) = uuid::Uuid::parse_str(&val) {
                    NodeId(uuid)
                } else {
                    let n = u128::from_str_radix(val.trim_start_matches("0x"), 16)
                        .map_err(|e| format!("invalid MILNET_NODE_ID: {e}"))?;
                    NodeId(uuid::Uuid::from_u128(n))
                }
            }
            Err(_) => NodeId(uuid::Uuid::new_v4()),
        };

        let service_type: ServiceType = match std::env::var("MILNET_SERVICE_TYPE") {
            Ok(val) => ServiceType::from_str(&val)?,
            Err(_) => ServiceType::Gateway,
        };

        let service_addr = std::env::var("MILNET_SERVICE_ADDR")
            .unwrap_or_else(|_| "127.0.0.1:8080".to_string());

        let raft_addr =
            std::env::var("MILNET_RAFT_ADDR").unwrap_or_else(|_| "127.0.0.1:9090".to_string());

        let peers = match std::env::var("MILNET_CLUSTER_PEERS") {
            Ok(val) if !val.trim().is_empty() => parse_peers(&val)?,
            _ => Vec::new(),
        };

        Ok(Self {
            node_id,
            service_type,
            service_addr,
            raft_addr,
            peers,
            raft_config: RaftConfig::default(),
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
        let node_id: NodeId = match std::env::var("MILNET_NODE_ID") {
            Ok(val) => {
                // Accept UUID format or hex u128
                if let Ok(uuid) = uuid::Uuid::parse_str(&val) {
                    NodeId(uuid)
                } else {
                    let n = u128::from_str_radix(val.trim_start_matches("0x"), 16)
                        .map_err(|e| format!("invalid MILNET_NODE_ID: {e}"))?;
                    NodeId(uuid::Uuid::from_u128(n))
                }
            }
            Err(_) => NodeId(uuid::Uuid::new_v4()),
        };

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

        let peers = match std::env::var("MILNET_CLUSTER_PEERS") {
            Ok(val) if !val.trim().is_empty() => parse_peers(&val)?,
            _ => Vec::new(),
        };

        Ok(Self {
            node_id,
            service_type,
            service_addr: service_addr.to_string(),
            raft_addr,
            peers,
            raft_config: RaftConfig::default(),
        })
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
        let peer_ids: Vec<NodeId> = config.peers.iter().map(|p| p.node_id).collect();
        let mut raft = RaftState::new(config.node_id, peer_ids, config.raft_config.clone());

        let standalone = config.peers.is_empty();
        if standalone {
            info!(
                node_id = %format!("{:032x}", config.node_id),
                "starting in standalone mode — becoming leader immediately"
            );
            raft.become_leader_standalone();
        } else {
            info!(
                node_id = %format!("{:032x}", config.node_id),
                peers = config.peers.len(),
                "starting cluster node"
            );
        }

        let raft = Arc::new(Mutex::new(raft));
        let state = Arc::new(RwLock::new(ClusterState::new()));
        let config = Arc::new(config);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (leader_tx, _leader_rx) = watch::channel::<Option<NodeId>>(None);
        let leader_tx = Arc::new(leader_tx);

        // Channel for outgoing Raft messages.
        let (send_tx, send_rx) = mpsc::unbounded_channel::<(NodeId, RaftMessage)>();

        // If standalone, set initial leader state.
        if standalone {
            let mut st = state.write().await;
            st.leader_id = Some(config.node_id);
            let _ = leader_tx.send(Some(config.node_id));
        }

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
                    tokio::spawn(async move {
                        let data = match recv_framed(&mut stream).await {
                            Ok(d) => d,
                            Err(e) => {
                                warn!(err = %e, "failed to receive raft message");
                                return;
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
                            warn!(target = %format!("{:032x}", target), "unknown peer, dropping message");
                            continue;
                        }
                    };

                    // Spawn a short-lived task so we don't block the sender loop
                    let node_id = config.node_id;
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
                        if let Err(e) = send_framed(&mut stream, &data).await {
                            debug!(addr = %peer_addr, err = %e, "failed to send raft message");
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
                    let (current_role, current_term) = {
                        let r = raft.lock().await;
                        (r.role, r.current_term)
                    };

                    let new_leader = match current_role {
                        RaftRole::Leader => Some(config_clone.node_id),
                        _ => {
                            // We don't know who the leader is from follower state alone;
                            // keep what's in cluster state.
                            state.read().await.leader_id
                        }
                    };

                    if new_leader != prev_leader {
                        prev_leader = new_leader;
                        let mut st = state.write().await;
                        st.leader_id = new_leader;
                        st.term = current_term;
                        let _ = leader_tx.send(new_leader);
                        if let Some(id) = new_leader {
                            info!(
                                leader = %format!("{:032x}", id),
                                term = current_term,
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
        // Fast path: try_lock to avoid blocking. If contended, fall back to false.
        match self.raft.try_lock() {
            Ok(guard) => guard.role == RaftRole::Leader,
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
        info!(node_id = %format!("{:032x}", self.config.node_id), "shutting down cluster node");
        let _ = self.shutdown_tx.send(true);
        // Give background tasks a moment to exit.
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    /// Subscribe to leader change events.
    pub fn leader_watch(&self) -> watch::Receiver<Option<NodeId>> {
        self.leader_tx.subscribe()
    }
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(peers[0].node_id, 0x1a);
        assert_eq!(peers[0].raft_addr, "10.0.0.1:9090");
        assert_eq!(peers[0].service_addr, "10.0.0.1:8080");
        assert_eq!(peers[1].node_id, 0x2b);
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
    fn cluster_config_from_env_with_peers() {
        std::env::set_var("MILNET_NODE_ID", "0xdeadbeef");
        std::env::set_var("MILNET_SERVICE_TYPE", "orchestrator");
        std::env::set_var("MILNET_SERVICE_ADDR", "10.0.0.1:8080");
        std::env::set_var("MILNET_RAFT_ADDR", "10.0.0.1:9090");
        std::env::set_var(
            "MILNET_CLUSTER_PEERS",
            "aa@10.0.0.2:9090/10.0.0.2:8080,bb@10.0.0.3:9090/10.0.0.3:8080",
        );

        let cfg = ClusterConfig::from_env().unwrap();
        assert_eq!(cfg.node_id, 0xdeadbeef);
        assert_eq!(cfg.service_type, ServiceType::Orchestrator);
        assert_eq!(cfg.peers.len(), 2);

        // Clean up
        std::env::remove_var("MILNET_NODE_ID");
        std::env::remove_var("MILNET_SERVICE_TYPE");
        std::env::remove_var("MILNET_SERVICE_ADDR");
        std::env::remove_var("MILNET_RAFT_ADDR");
        std::env::remove_var("MILNET_CLUSTER_PEERS");
    }

    #[test]
    fn cluster_state_apply_register() {
        let mut state = ClusterState::new();
        let entry = LogEntry {
            term: 1,
            index: 1,
            command: ClusterCommand::RegisterNode {
                node_id: 42,
                service_addr: "10.0.0.1:8080".to_string(),
                raft_addr: "10.0.0.1:9090".to_string(),
                service_type: "orchestrator".to_string(),
            },
        };
        state.apply(&entry);
        assert_eq!(state.member_count(), 1);
        let member = state.members.get(&42).unwrap();
        assert_eq!(member.addr, "10.0.0.1:8080");
        assert_eq!(member.service_type, ServiceType::Orchestrator);
        assert!(member.healthy);
    }

    #[test]
    fn cluster_state_apply_deregister() {
        let mut state = ClusterState::new();
        state.apply(&LogEntry {
            term: 1,
            index: 1,
            command: ClusterCommand::RegisterNode {
                node_id: 42,
                service_addr: "10.0.0.1:8080".to_string(),
                raft_addr: "10.0.0.1:9090".to_string(),
                service_type: "gateway".to_string(),
            },
        });
        assert_eq!(state.member_count(), 1);

        state.apply(&LogEntry {
            term: 1,
            index: 2,
            command: ClusterCommand::DeregisterNode { node_id: 42 },
        });
        assert_eq!(state.member_count(), 0);
    }

    #[test]
    fn cluster_state_apply_heartbeat() {
        let mut state = ClusterState::new();
        state.apply(&LogEntry {
            term: 1,
            index: 1,
            command: ClusterCommand::RegisterNode {
                node_id: 7,
                service_addr: "10.0.0.1:8080".to_string(),
                raft_addr: "10.0.0.1:9090".to_string(),
                service_type: "audit".to_string(),
            },
        });
        let before = state.members.get(&7).unwrap().last_seen;

        // Small delay so Instant differs
        std::thread::sleep(std::time::Duration::from_millis(1));

        state.apply(&LogEntry {
            term: 1,
            index: 2,
            command: ClusterCommand::Heartbeat { node_id: 7 },
        });
        let after = state.members.get(&7).unwrap().last_seen;
        assert!(after >= before);
    }

    #[test]
    fn cluster_state_apply_bump_fencing_token() {
        let mut state = ClusterState::new();
        assert_eq!(state.fencing_token, 0);
        state.apply(&LogEntry {
            term: 1,
            index: 1,
            command: ClusterCommand::BumpFencingToken,
        });
        assert_eq!(state.fencing_token, 1);
        state.apply(&LogEntry {
            term: 1,
            index: 2,
            command: ClusterCommand::BumpFencingToken,
        });
        assert_eq!(state.fencing_token, 2);
    }

    #[test]
    fn cluster_state_apply_application_is_noop() {
        let mut state = ClusterState::new();
        state.apply(&LogEntry {
            term: 1,
            index: 1,
            command: ClusterCommand::Application {
                payload: vec![1, 2, 3],
            },
        });
        assert_eq!(state.member_count(), 0);
        assert_eq!(state.fencing_token, 0);
    }

    #[test]
    fn cluster_state_leader_addr() {
        let mut state = ClusterState::new();
        assert!(state.leader_addr().is_none());

        state.apply(&LogEntry {
            term: 1,
            index: 1,
            command: ClusterCommand::RegisterNode {
                node_id: 1,
                service_addr: "leader.milnet:8080".to_string(),
                raft_addr: "leader.milnet:9090".to_string(),
                service_type: "orchestrator".to_string(),
            },
        });
        state.leader_id = Some(1);
        assert_eq!(state.leader_addr(), Some("leader.milnet:8080"));
    }

    #[test]
    fn cluster_state_healthy_members() {
        let mut state = ClusterState::new();
        state.apply(&LogEntry {
            term: 1,
            index: 1,
            command: ClusterCommand::RegisterNode {
                node_id: 1,
                service_addr: "a:8080".to_string(),
                raft_addr: "a:9090".to_string(),
                service_type: "gateway".to_string(),
            },
        });
        state.apply(&LogEntry {
            term: 1,
            index: 2,
            command: ClusterCommand::RegisterNode {
                node_id: 2,
                service_addr: "b:8080".to_string(),
                raft_addr: "b:9090".to_string(),
                service_type: "gateway".to_string(),
            },
        });
        // Mark one unhealthy
        state.members.get_mut(&2).unwrap().healthy = false;

        let healthy = state.healthy_members();
        assert_eq!(healthy.len(), 1);
        assert_eq!(healthy[0].node_id, 1);
    }

    #[tokio::test]
    async fn standalone_node_becomes_leader() {
        let config = ClusterConfig {
            node_id: 0xCAFE,
            service_type: ServiceType::Orchestrator,
            service_addr: "127.0.0.1:0".to_string(),
            raft_addr: "127.0.0.1:0".to_string(),
            peers: vec![],
            raft_config: RaftConfig::default(),
        };

        let node = ClusterNode::start(config).await.unwrap();
        assert!(node.is_leader());
        assert_eq!(node.node_id(), 0xCAFE);

        let state = node.cluster_state();
        assert_eq!(state.leader_id, Some(0xCAFE));

        // Propose should work on standalone leader
        let idx = node.propose(ClusterCommand::BumpFencingToken).unwrap();
        assert_eq!(idx, 1);

        node.shutdown().await;
    }

    #[tokio::test]
    async fn standalone_leader_watch() {
        let config = ClusterConfig {
            node_id: 0xBEEF,
            service_type: ServiceType::Gateway,
            service_addr: "127.0.0.1:0".to_string(),
            raft_addr: "127.0.0.1:0".to_string(),
            peers: vec![],
            raft_config: RaftConfig::default(),
        };

        let node = ClusterNode::start(config).await.unwrap();
        let rx = node.leader_watch();
        assert_eq!(*rx.borrow(), Some(0xBEEF));

        node.shutdown().await;
    }
}
