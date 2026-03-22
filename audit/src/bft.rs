//! Simplified BFT audit replication.
//!
//! Models a cluster of 7 audit nodes that tolerates up to 2 Byzantine faults.
//! An entry is considered committed when a quorum (2f + 1 = 5) of nodes accept it.
//! Byzantine nodes that produce conflicting entries are detectable via chain
//! divergence checks.

use crate::log::{hash_entry, AuditLog};
use common::types::{AuditEntry, AuditEventType, Receipt};
use crypto::pq_sign;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// A single audit replica node.
pub struct AuditNode {
    pub node_id: u8,
    pub log: AuditLog,
    pub is_byzantine: bool,
}

impl AuditNode {
    pub fn new(node_id: u8) -> Self {
        Self {
            node_id,
            log: AuditLog::new(),
            is_byzantine: false,
        }
    }

    /// Accept an entry proposal. Returns the entry hash if accepted.
    pub fn accept_entry(&mut self, entry: &AuditEntry) -> Option<[u8; 64]> {
        if self.is_byzantine {
            return None; // Byzantine node refuses
        }
        // Verify the entry's prev_hash matches our last hash
        let our_last = if self.log.is_empty() {
            [0u8; 64]
        } else {
            hash_entry(&self.log.entries()[self.log.len() - 1])
        };
        if entry.prev_hash != our_last {
            return None; // Chain mismatch
        }
        self.log.append_raw(entry.clone());
        Some(hash_entry(entry))
    }
}

/// BFT audit cluster.
pub struct BftAuditCluster {
    pub nodes: Vec<AuditNode>,
    /// Minimum number of nodes that must accept for an entry to be committed.
    pub quorum_size: usize,
    /// Optional ML-DSA-65 signing key for signing audit entries.
    pq_signing_key: Option<pq_sign::PqSigningKey>,
}

impl BftAuditCluster {
    /// Create a new cluster. `node_count` should be >= 4 for meaningful BFT
    /// (3f + 1). For 7 nodes: f = 2, quorum = 2f + 1 = 5.
    pub fn new(node_count: usize) -> Self {
        let f = (node_count - 1) / 3; // max Byzantine faults tolerated
        let quorum = 2 * f + 1; // minimum for consensus
        let nodes: Vec<AuditNode> = (0..node_count as u8).map(AuditNode::new).collect();
        Self {
            nodes,
            quorum_size: quorum,
            pq_signing_key: None,
        }
    }

    /// Create a new cluster with an ML-DSA-65 signing key for entry signing.
    pub fn new_with_signing_key(node_count: usize, signing_key: pq_sign::PqSigningKey) -> Self {
        let f = (node_count - 1) / 3;
        let quorum = 2 * f + 1;
        let nodes: Vec<AuditNode> = (0..node_count as u8).map(AuditNode::new).collect();
        Self {
            nodes,
            quorum_size: quorum,
            pq_signing_key: Some(signing_key),
        }
    }

    /// Propose an entry to all nodes. Returns `Ok(entry_hash)` if quorum accepts.
    pub fn propose_entry(
        &mut self,
        event_type: AuditEventType,
        user_ids: Vec<Uuid>,
        device_ids: Vec<Uuid>,
        risk_score: f64,
        ceremony_receipts: Vec<Receipt>,
    ) -> Result<[u8; 64], String> {
        // Build the entry using the first honest node's state for prev_hash.
        let prev_hash = self
            .nodes
            .iter()
            .find(|n| !n.is_byzantine)
            .map(|n| {
                if n.log.is_empty() {
                    [0u8; 64]
                } else {
                    hash_entry(&n.log.entries()[n.log.len() - 1])
                }
            })
            .unwrap_or([0u8; 64]);

        let mut entry = AuditEntry {
            event_id: Uuid::new_v4(),
            event_type,
            user_ids,
            device_ids,
            ceremony_receipts,
            risk_score,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_micros() as i64,
            prev_hash,
            signature: Vec::new(),
        };

        if let Some(ref key) = self.pq_signing_key {
            let hash = hash_entry(&entry);
            entry.signature = pq_sign::pq_sign_raw(key, &hash);
        }

        // Propose to all nodes, count acceptances.
        let mut accept_count = 0usize;
        let mut entry_hash = [0u8; 64];

        for node in &mut self.nodes {
            if let Some(hash) = node.accept_entry(&entry) {
                accept_count += 1;
                entry_hash = hash;
            }
        }

        if accept_count >= self.quorum_size {
            Ok(entry_hash)
        } else {
            Err(format!(
                "quorum not met: {}/{} accepted (need {})",
                accept_count,
                self.nodes.len(),
                self.quorum_size
            ))
        }
    }

    /// Verify all honest nodes have consistent chains.
    pub fn verify_consistency(&self) -> bool {
        let honest_nodes: Vec<&AuditNode> = self.nodes.iter().filter(|n| !n.is_byzantine).collect();

        if honest_nodes.is_empty() {
            return true;
        }

        let reference = &honest_nodes[0].log;
        for node in &honest_nodes[1..] {
            if node.log.len() != reference.len() {
                return false;
            }
            // Compare hashes of last entry
            if !node.log.is_empty() && !reference.is_empty() {
                let node_hash = hash_entry(&node.log.entries()[node.log.len() - 1]);
                let ref_hash = hash_entry(&reference.entries()[reference.len() - 1]);
                if node_hash != ref_hash {
                    return false;
                }
            }
        }
        true
    }

    /// Mark a node as Byzantine (for testing).
    pub fn set_byzantine(&mut self, node_id: u8) {
        if let Some(node) = self.nodes.iter_mut().find(|n| n.node_id == node_id) {
            node.is_byzantine = true;
        }
    }
}
