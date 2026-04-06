//! Network-level quarantine that severs TLS connections from compromised nodes.
//! Unlike logical quarantine (Raft membership), this operates at the transport
//! layer and does not require cluster consensus.
//!
//! Usage in the TLS acceptor path:
//! 1. Extract client certificate from the TLS handshake
//! 2. Compute SHA-512 fingerprint of the DER-encoded certificate
//! 3. Check `is_cert_blocked()` before processing any application data
//! 4. If blocked, drop the connection immediately (no error response)
//!
//! This provides defense-in-depth: even if a compromised node bypasses Raft
//! membership checks, the TLS layer will refuse its connections.

use crate::siem::{PanelSiemEvent, SiemPanel, SiemSeverity};
use std::collections::HashSet;
use std::sync::Mutex;

// ---------------------------------------------------------------------------
// NetworkQuarantine
// ---------------------------------------------------------------------------

/// Transport-layer blocklist for compromised node IDs and certificate fingerprints.
///
/// Thread-safe via `Mutex`. The critical path (`is_blocked` / `is_cert_blocked`)
/// acquires the lock briefly for a HashSet lookup, which is O(1) amortized.
pub struct NetworkQuarantine {
    /// Blocked node identifiers (logical IDs like "node-3" or UUIDs).
    blocked_nodes: Mutex<HashSet<String>>,
    /// Blocked certificate fingerprints (SHA-512 of DER-encoded cert).
    blocked_fingerprints: Mutex<HashSet<[u8; 64]>>,
}

impl NetworkQuarantine {
    /// Create a new empty quarantine.
    pub fn new() -> Self {
        Self {
            blocked_nodes: Mutex::new(HashSet::new()),
            blocked_fingerprints: Mutex::new(HashSet::new()),
        }
    }

    /// Block a node by ID and certificate fingerprint.
    ///
    /// Both the node ID and certificate fingerprint are added to the blocklist.
    /// This ensures the node cannot reconnect even if it obtains a new logical
    /// identity (the cert fingerprint still matches).
    pub fn block_node(&self, node_id: &str, cert_fingerprint: &[u8; 64]) {
        {
            let mut nodes = self.blocked_nodes.lock().unwrap_or_else(|e| {
                    tracing::warn!(target: "siem", "SIEM:WARNING mutex poisoned in network_quarantine - recovering: thread panicked while holding lock");
                    e.into_inner()
                });
            nodes.insert(node_id.to_string());
        }
        {
            let mut fps = self
                .blocked_fingerprints
                .lock()
                .unwrap_or_else(|e| {
                    tracing::warn!(target: "siem", "SIEM:WARNING mutex poisoned in network_quarantine - recovering: thread panicked while holding lock");
                    e.into_inner()
                });
            fps.insert(*cert_fingerprint);
        }

        PanelSiemEvent::new(
            SiemPanel::NetworkAnomalies,
            SiemSeverity::Critical,
            "network_quarantine_block",
            format!(
                "Node blocked at transport layer: node_id={}, cert_fp={}",
                node_id,
                hex::encode(&cert_fingerprint[..8]), // log first 8 bytes only
            ),
            file!(),
            line!(),
            module_path!(),
        )
        .emit();

        tracing::warn!(
            node_id = %node_id,
            "network quarantine: node blocked at TLS layer"
        );
    }

    /// Check if a node ID is blocked.
    pub fn is_blocked(&self, node_id: &str) -> bool {
        let nodes = self.blocked_nodes.lock().unwrap_or_else(|e| {
                    tracing::warn!(target: "siem", "SIEM:WARNING mutex poisoned in network_quarantine - recovering: thread panicked while holding lock");
                    e.into_inner()
                });
        nodes.contains(node_id)
    }

    /// Check if a certificate fingerprint is blocked.
    pub fn is_cert_blocked(&self, fingerprint: &[u8; 64]) -> bool {
        let fps = self
            .blocked_fingerprints
            .lock()
            .unwrap_or_else(|e| {
                    tracing::warn!(target: "siem", "SIEM:WARNING mutex poisoned in network_quarantine - recovering: thread panicked while holding lock");
                    e.into_inner()
                });
        fps.contains(fingerprint)
    }

    /// Number of blocked nodes.
    pub fn blocked_count(&self) -> usize {
        let nodes = self.blocked_nodes.lock().unwrap_or_else(|e| {
                    tracing::warn!(target: "siem", "SIEM:WARNING mutex poisoned in network_quarantine - recovering: thread panicked while holding lock");
                    e.into_inner()
                });
        nodes.len()
    }

    /// List all blocked node IDs (for admin dashboard).
    pub fn blocked_node_ids(&self) -> Vec<String> {
        let nodes = self.blocked_nodes.lock().unwrap_or_else(|e| {
                    tracing::warn!(target: "siem", "SIEM:WARNING mutex poisoned in network_quarantine - recovering: thread panicked while holding lock");
                    e.into_inner()
                });
        nodes.iter().cloned().collect()
    }

    /// Remove a node from the blocklist (after verified remediation).
    ///
    /// Only removes the node ID. The certificate fingerprint stays blocked
    /// permanently, forcing the remediated node to use a new certificate.
    pub fn unblock_node(&self, node_id: &str) {
        let mut nodes = self.blocked_nodes.lock().unwrap_or_else(|e| {
                    tracing::warn!(target: "siem", "SIEM:WARNING mutex poisoned in network_quarantine - recovering: thread panicked while holding lock");
                    e.into_inner()
                });
        nodes.remove(node_id);

        PanelSiemEvent::new(
            SiemPanel::NetworkAnomalies,
            SiemSeverity::Warning,
            "network_quarantine_unblock",
            format!("Node unblocked at transport layer: node_id={node_id} (cert fingerprint remains blocked)"),
            file!(),
            line!(),
            module_path!(),
        )
        .emit();
    }
}

impl Default for NetworkQuarantine {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_fingerprint(fill: u8) -> [u8; 64] {
        [fill; 64]
    }

    #[test]
    fn new_quarantine_is_empty() {
        let nq = NetworkQuarantine::new();
        assert_eq!(nq.blocked_count(), 0);
        assert!(!nq.is_blocked("node-1"));
        assert!(!nq.is_cert_blocked(&make_fingerprint(0xAA)));
    }

    #[test]
    fn block_node_adds_to_both_lists() {
        let nq = NetworkQuarantine::new();
        let fp = make_fingerprint(0xBB);
        nq.block_node("node-3", &fp);

        assert!(nq.is_blocked("node-3"));
        assert!(nq.is_cert_blocked(&fp));
        assert_eq!(nq.blocked_count(), 1);
    }

    #[test]
    fn block_multiple_nodes() {
        let nq = NetworkQuarantine::new();
        nq.block_node("node-1", &make_fingerprint(0x01));
        nq.block_node("node-2", &make_fingerprint(0x02));
        nq.block_node("node-3", &make_fingerprint(0x03));

        assert_eq!(nq.blocked_count(), 3);
        assert!(nq.is_blocked("node-1"));
        assert!(nq.is_blocked("node-2"));
        assert!(nq.is_blocked("node-3"));
        assert!(!nq.is_blocked("node-4"));
    }

    #[test]
    fn duplicate_block_is_idempotent() {
        let nq = NetworkQuarantine::new();
        let fp = make_fingerprint(0xCC);
        nq.block_node("node-1", &fp);
        nq.block_node("node-1", &fp);
        assert_eq!(nq.blocked_count(), 1);
    }

    #[test]
    fn cert_fingerprint_matching_exact() {
        let nq = NetworkQuarantine::new();
        let fp = make_fingerprint(0xDD);
        nq.block_node("node-1", &fp);

        // Exact match
        assert!(nq.is_cert_blocked(&fp));
        // Different fingerprint
        assert!(!nq.is_cert_blocked(&make_fingerprint(0xEE)));
        // One byte different
        let mut almost = fp;
        almost[63] = 0x00;
        assert!(!nq.is_cert_blocked(&almost));
    }

    #[test]
    fn unblock_node_removes_id_keeps_cert() {
        let nq = NetworkQuarantine::new();
        let fp = make_fingerprint(0xFF);
        nq.block_node("node-5", &fp);

        assert!(nq.is_blocked("node-5"));
        assert!(nq.is_cert_blocked(&fp));

        nq.unblock_node("node-5");
        assert!(!nq.is_blocked("node-5"));
        // Certificate fingerprint remains blocked (node must get new cert)
        assert!(nq.is_cert_blocked(&fp));
        assert_eq!(nq.blocked_count(), 0);
    }

    #[test]
    fn blocked_node_ids_list() {
        let nq = NetworkQuarantine::new();
        nq.block_node("alpha", &make_fingerprint(0x01));
        nq.block_node("beta", &make_fingerprint(0x02));

        let mut ids = nq.blocked_node_ids();
        ids.sort();
        assert_eq!(ids, vec!["alpha", "beta"]);
    }

    #[test]
    fn unblock_nonexistent_is_noop() {
        let nq = NetworkQuarantine::new();
        nq.unblock_node("ghost");
        assert_eq!(nq.blocked_count(), 0);
    }

    #[test]
    fn default_impl() {
        let nq: NetworkQuarantine = Default::default();
        assert_eq!(nq.blocked_count(), 0);
    }

    #[test]
    fn different_nodes_same_fingerprint() {
        let nq = NetworkQuarantine::new();
        let fp = make_fingerprint(0xAA);
        nq.block_node("node-a", &fp);
        nq.block_node("node-b", &fp);

        assert_eq!(nq.blocked_count(), 2);
        assert!(nq.is_blocked("node-a"));
        assert!(nq.is_blocked("node-b"));
        // Only one fingerprint entry (same fingerprint)
        assert!(nq.is_cert_blocked(&fp));
    }
}
