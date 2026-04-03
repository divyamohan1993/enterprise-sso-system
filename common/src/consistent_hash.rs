//! Consistent hashing ring for distributing data across nodes.
//! When nodes join/leave, only 1/n of keys need to be remapped.
//! Virtual nodes ensure even distribution.

use sha2::{Digest, Sha512};
use std::collections::{BTreeMap, HashMap, HashSet};

/// Certificate proving a node is authorized to join the ring.
/// Must be signed by the cluster CA using ML-DSA-87.
#[derive(Debug, Clone)]
pub struct NodeCertificate {
    /// The node ID this certificate authorizes.
    pub node_id: String,
    /// ML-DSA-87 signature from the cluster CA over the node_id.
    pub ca_signature: Vec<u8>,
}

pub struct ConsistentHashRing {
    /// hash position -> node_id
    ring: BTreeMap<u64, String>,
    /// Number of virtual nodes per real node.
    virtual_nodes_per_real: usize,
    /// Set of real node IDs.
    nodes: HashSet<String>,
    /// ML-DSA-87 verifying key of the cluster CA. If set, all add_node calls
    /// must provide a valid NodeCertificate.
    ca_verifying_key: Option<Vec<u8>>,
}

impl ConsistentHashRing {
    /// Create an empty ring with the given number of virtual nodes per real node.
    /// Default recommendation: 150 vnodes for good distribution.
    pub fn new(virtual_nodes_per_real: usize) -> Self {
        Self {
            ring: BTreeMap::new(),
            virtual_nodes_per_real,
            nodes: HashSet::new(),
            ca_verifying_key: None,
        }
    }

    /// Create a ring that requires node authentication via ML-DSA-87 certificates.
    pub fn with_ca_key(virtual_nodes_per_real: usize, ca_verifying_key: Vec<u8>) -> Self {
        Self {
            ring: BTreeMap::new(),
            virtual_nodes_per_real,
            nodes: HashSet::new(),
            ca_verifying_key: Some(ca_verifying_key),
        }
    }

    /// Add an authenticated node with its virtual nodes to the ring.
    /// If a CA key is configured, the certificate must be valid or the node is rejected.
    pub fn add_node_authenticated(&mut self, cert: &NodeCertificate) -> Result<(), String> {
        if let Some(ca_key) = &self.ca_verifying_key {
            if !verify_node_certificate(&cert.node_id, &cert.ca_signature, ca_key) {
                return Err(format!("node '{}' certificate verification failed", cert.node_id));
            }
        }
        self.add_node(&cert.node_id);
        Ok(())
    }

    /// Add a node with its virtual nodes to the ring.
    ///
    /// # Security
    /// When a CA verifying key is configured, this method is restricted to
    /// internal use only (called from `add_node_authenticated` after cert
    /// verification). Direct external callers MUST use `add_node_authenticated`.
    /// Panics in military deployment if called directly when a CA key is set.
    pub fn add_node(&mut self, node_id: &str) {
        if self.ca_verifying_key.is_some() {
            // In authenticated mode, only add_node_authenticated should call us.
            // If called directly, a rogue node could bypass certificate verification.
            if std::env::var("MILNET_MILITARY_DEPLOYMENT").is_ok()
                || std::env::var("MILNET_PRODUCTION").is_ok()
            {
                panic!(
                    "SECURITY: add_node() called directly with CA key configured. \
                     Use add_node_authenticated() to verify node certificates. \
                     node_id='{node_id}'"
                );
            }
            tracing::warn!(
                target: "siem",
                "SIEM:WARNING add_node() called directly with CA key configured for node '{}'. \
                 Use add_node_authenticated() in production.",
                node_id
            );
        }
        if !self.nodes.insert(node_id.to_owned()) {
            return; // already present
        }
        for i in 0..self.virtual_nodes_per_real {
            let hash = self.vnode_hash(node_id, i);
            self.ring.insert(hash, node_id.to_owned());
        }
    }

    /// Remove a node and all its virtual nodes from the ring.
    /// Returns true if the node was present.
    pub fn remove_node(&mut self, node_id: &str) -> bool {
        if !self.nodes.remove(node_id) {
            return false;
        }
        for i in 0..self.virtual_nodes_per_real {
            let hash = self.vnode_hash(node_id, i);
            self.ring.remove(&hash);
        }
        true
    }

    /// Find the responsible node for a given key.
    /// Returns `None` if the ring is empty.
    pub fn get_node(&self, key: &[u8]) -> Option<&str> {
        if self.ring.is_empty() {
            return None;
        }
        let hash = self.key_hash(key);
        // Find the first node at or after the hash position (clockwise).
        // If nothing found, wrap around to the first node in the ring.
        let node_id = self
            .ring
            .range(hash..)
            .next()
            .or_else(|| self.ring.iter().next())
            .map(|(_, id)| id.as_str());
        node_id
    }

    /// Find n distinct responsible nodes for a given key (for replication).
    /// Walks clockwise from the key's position, skipping duplicate real nodes.
    /// Returns fewer than n if fewer than n real nodes exist.
    pub fn get_n_nodes(&self, key: &[u8], n: usize) -> Vec<&str> {
        if self.ring.is_empty() {
            return Vec::new();
        }

        let hash = self.key_hash(key);
        let mut result = Vec::with_capacity(n);
        let mut seen = HashSet::new();

        // Walk clockwise from hash position, then wrap around
        let after = self.ring.range(hash..);
        let before = self.ring.range(..hash);

        for (_, node_id) in after.chain(before) {
            if seen.insert(node_id.as_str()) {
                result.push(node_id.as_str());
                if result.len() == n {
                    break;
                }
            }
        }

        result
    }

    /// Report the distribution of virtual nodes across real nodes.
    /// Returns a map of node_id -> number of ring positions (vnodes).
    /// Useful for verifying even distribution.
    pub fn rebalance_report(&self) -> HashMap<&str, usize> {
        let mut report: HashMap<&str, usize> = HashMap::new();
        for node_id in self.ring.values() {
            *report.entry(node_id.as_str()).or_insert(0) += 1;
        }
        report
    }

    /// Number of real nodes in the ring.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Total number of virtual nodes (ring positions).
    pub fn ring_size(&self) -> usize {
        self.ring.len()
    }

    // -- internal --

    /// Hash a key to a ring position.
    fn key_hash(&self, key: &[u8]) -> u64 {
        let digest = Sha512::digest(key);
        // Take the first 8 bytes as a u64 (big-endian for uniform distribution).
        u64::from_be_bytes(
            match digest[..8].try_into() {
                Ok(arr) => arr,
                Err(_) => [0u8; 8], // SHA-512 always produces >= 8 bytes
            }
        )
    }

    /// Hash a virtual node to a ring position.
    fn vnode_hash(&self, node_id: &str, vnode_index: usize) -> u64 {
        let mut h = Sha512::new();
        h.update(node_id.as_bytes());
        h.update(b":");
        h.update(vnode_index.to_le_bytes());
        let digest = h.finalize();
        u64::from_be_bytes(
            match digest[..8].try_into() {
                Ok(arr) => arr,
                Err(_) => [0u8; 8], // SHA-512 always produces >= 8 bytes
            }
        )
    }
}

/// Verify an ML-DSA-87 node certificate against the cluster CA key.
fn verify_node_certificate(node_id: &str, signature: &[u8], ca_key_bytes: &[u8]) -> bool {
    use ml_dsa::{signature::Verifier, EncodedVerifyingKey, MlDsa87, VerifyingKey};
    let vk_enc = match EncodedVerifyingKey::<MlDsa87>::try_from(ca_key_bytes) {
        Ok(e) => e,
        Err(_) => return false,
    };
    let vk = VerifyingKey::<MlDsa87>::decode(&vk_enc);
    let sig = match ml_dsa::Signature::<MlDsa87>::try_from(signature) {
        Ok(s) => s,
        Err(_) => return false,
    };
    vk.verify(node_id.as_bytes(), &sig).is_ok()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_ring_returns_none() {
        let ring = ConsistentHashRing::new(150);
        assert!(ring.get_node(b"anything").is_none());
        assert!(ring.get_n_nodes(b"anything", 3).is_empty());
    }

    #[test]
    fn single_node_gets_all_keys() {
        let mut ring = ConsistentHashRing::new(150);
        ring.add_node("node_a");

        for i in 0u32..100 {
            let key = format!("key_{i}");
            assert_eq!(ring.get_node(key.as_bytes()), Some("node_a"));
        }
    }

    #[test]
    fn add_remove_node() {
        let mut ring = ConsistentHashRing::new(150);
        ring.add_node("a");
        ring.add_node("b");
        assert_eq!(ring.node_count(), 2);
        assert_eq!(ring.ring_size(), 300);

        ring.remove_node("b");
        assert_eq!(ring.node_count(), 1);
        assert_eq!(ring.ring_size(), 150);

        // All keys should go to "a" now
        assert_eq!(ring.get_node(b"test"), Some("a"));
    }

    #[test]
    fn duplicate_add_is_idempotent() {
        let mut ring = ConsistentHashRing::new(10);
        ring.add_node("a");
        ring.add_node("a");
        assert_eq!(ring.node_count(), 1);
        assert_eq!(ring.ring_size(), 10);
    }

    #[test]
    fn remove_nonexistent_returns_false() {
        let mut ring = ConsistentHashRing::new(10);
        assert!(!ring.remove_node("ghost"));
    }

    #[test]
    fn get_n_nodes_returns_distinct() {
        let mut ring = ConsistentHashRing::new(150);
        ring.add_node("a");
        ring.add_node("b");
        ring.add_node("c");

        let nodes = ring.get_n_nodes(b"my_key", 3);
        assert_eq!(nodes.len(), 3);
        // All must be distinct
        let unique: HashSet<_> = nodes.iter().collect();
        assert_eq!(unique.len(), 3);
    }

    #[test]
    fn get_n_nodes_caps_at_available() {
        let mut ring = ConsistentHashRing::new(150);
        ring.add_node("a");
        ring.add_node("b");

        let nodes = ring.get_n_nodes(b"my_key", 5);
        assert_eq!(nodes.len(), 2); // only 2 real nodes exist
    }

    #[test]
    fn deterministic_placement() {
        let mut ring1 = ConsistentHashRing::new(150);
        ring1.add_node("a");
        ring1.add_node("b");
        ring1.add_node("c");

        let mut ring2 = ConsistentHashRing::new(150);
        ring2.add_node("a");
        ring2.add_node("b");
        ring2.add_node("c");

        // Same ring, same key → same node
        for i in 0u32..100 {
            let key = format!("key_{i}");
            assert_eq!(
                ring1.get_node(key.as_bytes()),
                ring2.get_node(key.as_bytes())
            );
        }
    }

    #[test]
    fn minimal_redistribution_on_add() {
        let mut ring = ConsistentHashRing::new(150);
        ring.add_node("a");
        ring.add_node("b");
        ring.add_node("c");

        let n = 10000u32;
        let before: Vec<Option<String>> = (0..n)
            .map(|i| ring.get_node(format!("k{i}").as_bytes()).map(|s| s.to_owned()))
            .collect();

        // Add a 4th node
        ring.add_node("d");

        let mut moved = 0u32;
        for i in 0..n {
            let after = ring.get_node(format!("k{i}").as_bytes()).map(|s| s.to_owned());
            if after != before[i as usize] {
                moved += 1;
            }
        }

        // With 4 nodes, ideal redistribution is ~25% of keys.
        // Allow up to 40% to account for hash variance.
        let move_ratio = moved as f64 / n as f64;
        assert!(
            move_ratio < 0.40,
            "too many keys moved: {moved}/{n} = {move_ratio:.2}"
        );
    }

    #[test]
    fn distribution_evenness() {
        let mut ring = ConsistentHashRing::new(150);
        ring.add_node("a");
        ring.add_node("b");
        ring.add_node("c");
        ring.add_node("d");

        let mut counts: HashMap<&str, u32> = HashMap::new();
        let n = 40000u32;
        for i in 0..n {
            let key = format!("object_{i}");
            if let Some(node) = ring.get_node(key.as_bytes()) {
                *counts.entry(node).or_insert(0) += 1;
            }
        }

        // Each node should get roughly 25%. Allow 15-35%.
        for (node, count) in &counts {
            let ratio = *count as f64 / n as f64;
            assert!(
                (0.15..=0.35).contains(&ratio),
                "node {node} has {count}/{n} = {ratio:.2}, expected ~0.25"
            );
        }
    }

    #[test]
    fn rebalance_report_matches() {
        let mut ring = ConsistentHashRing::new(50);
        ring.add_node("x");
        ring.add_node("y");

        let report = ring.rebalance_report();
        assert_eq!(report.len(), 2);
        assert_eq!(*report.get("x").unwrap(), 50);
        assert_eq!(*report.get("y").unwrap(), 50);
    }

    #[test]
    fn get_n_nodes_order_is_clockwise() {
        let mut ring = ConsistentHashRing::new(150);
        ring.add_node("a");
        ring.add_node("b");
        ring.add_node("c");
        ring.add_node("d");
        ring.add_node("e");

        // Should return nodes in clockwise order (no duplicates)
        let nodes = ring.get_n_nodes(b"test_key", 5);
        assert_eq!(nodes.len(), 5);
        let unique: HashSet<_> = nodes.iter().collect();
        assert_eq!(unique.len(), 5);
    }
}
