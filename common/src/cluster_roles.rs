//! Cluster role registry and request routing.
//!
//! Tracks which node holds each role (leader/follower) per service type,
//! and provides transparent request proxying from followers to leaders.
//! Callers (e.g., gateway) don't need to know cluster topology.

use crate::raft::NodeId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

// ---------------------------------------------------------------------------
// Role types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InstanceRole {
    /// Handles all incoming requests for this service type.
    Leader,
    /// Hot standby. Proxies requests to leader transparently.
    Follower,
    /// Unhealthy or draining. Rejects new requests.
    Standby,
}

impl std::fmt::Display for InstanceRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Leader => write!(f, "leader"),
            Self::Follower => write!(f, "follower"),
            Self::Standby => write!(f, "standby"),
        }
    }
}

// ---------------------------------------------------------------------------
// Role registry
// ---------------------------------------------------------------------------

/// Tracks the current role assignment for each node in the cluster.
/// Updated by applying Raft log entries (via ClusterState).
#[derive(Debug, Clone)]
pub struct RoleRegistry {
    /// This node's ID.
    pub node_id: NodeId,
    /// Current role of this node.
    pub role: InstanceRole,
    /// Current leader's node ID (if known).
    pub leader_id: Option<NodeId>,
    /// Map of node_id -> service address (host:port) for all known members.
    pub member_addrs: HashMap<NodeId, String>,
    /// Current fencing token (from Raft leader election).
    pub fencing_token: u64,
}

impl RoleRegistry {
    pub fn new(node_id: NodeId) -> Self {
        Self {
            node_id,
            role: InstanceRole::Follower,
            leader_id: None,
            member_addrs: HashMap::new(),
            fencing_token: 0,
        }
    }

    /// Update role based on Raft state changes.
    pub fn update_from_raft(&mut self, is_leader: bool, leader_id: Option<NodeId>, fencing_token: u64) {
        self.role = if is_leader {
            InstanceRole::Leader
        } else {
            InstanceRole::Follower
        };
        self.leader_id = leader_id;
        self.fencing_token = fencing_token;
    }

    /// Register or update a member's service address.
    pub fn set_member_addr(&mut self, node_id: NodeId, addr: String) {
        self.member_addrs.insert(node_id, addr);
    }

    /// Remove a member (left or dead).
    pub fn remove_member(&mut self, node_id: &NodeId) {
        self.member_addrs.remove(node_id);
    }

    /// Get the current leader's service address for proxying.
    pub fn leader_service_addr(&self) -> Option<&str> {
        self.leader_id
            .as_ref()
            .and_then(|lid| self.member_addrs.get(lid))
            .map(|s| s.as_str())
    }

    /// Is this node the leader?
    pub fn is_leader(&self) -> bool {
        self.role == InstanceRole::Leader
    }

    /// How many members are known?
    pub fn member_count(&self) -> usize {
        self.member_addrs.len()
    }
}

// ---------------------------------------------------------------------------
// Request proxy (follower -> leader)
// ---------------------------------------------------------------------------

/// Maximum proxy payload size: 16 MB.
const MAX_PROXY_PAYLOAD: usize = 16 * 1024 * 1024;

/// Proxy a raw request to the current leader.
///
/// Sends the payload to the leader's service address with a fencing token
/// header, waits for the response, and returns it. The caller sees this
/// as if the request was handled locally.
///
/// Returns Err if no leader is known or the connection fails.
pub async fn proxy_to_leader(
    registry: &RoleRegistry,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    let leader_addr = registry
        .leader_service_addr()
        .ok_or("no leader known — cannot proxy request")?;

    let mut stream = TcpStream::connect(leader_addr)
        .await
        .map_err(|e| format!("failed to connect to leader at {}: {}", leader_addr, e))?;

    // Send: [4-byte len][8-byte fencing_token][payload]
    let total_len = (8 + payload.len()) as u32;
    stream
        .write_all(&total_len.to_be_bytes())
        .await
        .map_err(|e| format!("proxy write len: {e}"))?;
    stream
        .write_all(&registry.fencing_token.to_be_bytes())
        .await
        .map_err(|e| format!("proxy write fencing token: {e}"))?;
    stream
        .write_all(payload)
        .await
        .map_err(|e| format!("proxy write payload: {e}"))?;

    // Read response: [4-byte len][response]
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| format!("proxy read response len: {e}"))?;
    let resp_len = u32::from_be_bytes(len_buf) as usize;
    if resp_len > MAX_PROXY_PAYLOAD {
        return Err(format!(
            "leader response too large: {} bytes (max {})",
            resp_len, MAX_PROXY_PAYLOAD
        ));
    }
    let mut resp = vec![0u8; resp_len];
    stream
        .read_exact(&mut resp)
        .await
        .map_err(|e| format!("proxy read response: {e}"))?;

    Ok(resp)
}

// ---------------------------------------------------------------------------
// Shared role registry handle
// ---------------------------------------------------------------------------

/// Thread-safe handle to the role registry, shared across async tasks.
#[derive(Clone)]
pub struct SharedRoleRegistry {
    inner: Arc<RwLock<RoleRegistry>>,
}

impl SharedRoleRegistry {
    pub fn new(node_id: NodeId) -> Self {
        Self {
            inner: Arc::new(RwLock::new(RoleRegistry::new(node_id))),
        }
    }

    pub fn read(&self) -> std::sync::RwLockReadGuard<'_, RoleRegistry> {
        self.inner.read().unwrap_or_else(|e| {
                    tracing::warn!(target: "siem", "SIEM:WARNING mutex poisoned in cluster_roles - recovering: thread panicked while holding lock");
                    e.into_inner()
                })
    }

    pub fn write(&self) -> std::sync::RwLockWriteGuard<'_, RoleRegistry> {
        self.inner.write().unwrap_or_else(|e| {
                    tracing::warn!(target: "siem", "SIEM:WARNING mutex poisoned in cluster_roles - recovering: thread panicked while holding lock");
                    e.into_inner()
                })
    }

    pub fn is_leader(&self) -> bool {
        self.read().is_leader()
    }

    pub fn leader_service_addr(&self) -> Option<String> {
        self.read().leader_service_addr().map(|s| s.to_string())
    }

    pub fn fencing_token(&self) -> u64 {
        self.read().fencing_token
    }
}

// ---------------------------------------------------------------------------
// Fencing token validation
// ---------------------------------------------------------------------------

/// Validate that a request's fencing token is current.
/// Stale leaders (with old fencing tokens) are rejected.
pub fn validate_fencing_token(expected: u64, received: u64) -> Result<(), String> {
    if received < expected {
        Err(format!(
            "stale fencing token: received {} but current is {} — request from old leader rejected",
            received, expected
        ))
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_node_id(n: u8) -> NodeId {
        NodeId(uuid::Uuid::from_bytes([n; 16]))
    }

    #[test]
    fn role_registry_initial_state() {
        let reg = RoleRegistry::new(test_node_id(1));
        assert!(!reg.is_leader());
        assert!(reg.leader_id.is_none());
        assert!(reg.leader_service_addr().is_none());
        assert_eq!(reg.member_count(), 0);
    }

    #[test]
    fn role_registry_become_leader() {
        let mut reg = RoleRegistry::new(test_node_id(1));
        reg.set_member_addr(test_node_id(1), "10.0.0.1:9101".into());
        reg.update_from_raft(true, Some(test_node_id(1)), 1);
        assert!(reg.is_leader());
        assert_eq!(reg.fencing_token, 1);
        assert_eq!(reg.leader_service_addr(), Some("10.0.0.1:9101"));
    }

    #[test]
    fn role_registry_follower_knows_leader() {
        let mut reg = RoleRegistry::new(test_node_id(2));
        reg.set_member_addr(test_node_id(1), "10.0.0.1:9101".into());
        reg.set_member_addr(test_node_id(2), "10.0.0.2:9101".into());
        reg.update_from_raft(false, Some(test_node_id(1)), 5);
        assert!(!reg.is_leader());
        assert_eq!(reg.leader_service_addr(), Some("10.0.0.1:9101"));
        assert_eq!(reg.fencing_token, 5);
    }

    #[test]
    fn role_registry_remove_member() {
        let mut reg = RoleRegistry::new(test_node_id(1));
        reg.set_member_addr(test_node_id(2), "10.0.0.2:9101".into());
        assert_eq!(reg.member_count(), 1);
        reg.remove_member(&test_node_id(2));
        assert_eq!(reg.member_count(), 0);
    }

    #[test]
    fn fencing_token_validation() {
        assert!(validate_fencing_token(5, 5).is_ok());
        assert!(validate_fencing_token(5, 6).is_ok());
        assert!(validate_fencing_token(5, 4).is_err());
        assert!(validate_fencing_token(0, 0).is_ok());
    }

    #[test]
    fn instance_role_display() {
        assert_eq!(InstanceRole::Leader.to_string(), "leader");
        assert_eq!(InstanceRole::Follower.to_string(), "follower");
        assert_eq!(InstanceRole::Standby.to_string(), "standby");
    }

    #[test]
    fn shared_registry_thread_safe() {
        let shared = SharedRoleRegistry::new(test_node_id(1));
        {
            let mut w = shared.write();
            w.update_from_raft(true, Some(test_node_id(1)), 42);
        }
        assert!(shared.is_leader());
        assert_eq!(shared.fencing_token(), 42);
    }
}
