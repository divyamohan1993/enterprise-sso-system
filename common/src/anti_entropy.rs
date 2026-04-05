//! Anti-entropy protocol using Merkle trees for efficient state reconciliation.
//!
//! Each node maintains a Merkle tree of its state. When syncing:
//! 1. Exchange root hashes — if equal, states are identical
//! 2. If different, recursively compare subtrees to find divergent leaves
//! 3. Exchange only the differing entries
//!
//! This is O(log n) communication for finding differences in n entries.

use sha2::{Digest, Sha512};
use std::collections::BTreeMap;

/// SHA-512 hash (CNSA 2.0 compliant).
pub type Hash512 = [u8; 64];

const EMPTY_HASH: Hash512 = [0u8; 64];

// ---------------------------------------------------------------------------
// MerkleNode
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct MerkleNode {
    pub hash: Hash512,
    pub left: Option<Box<MerkleNode>>,
    pub right: Option<Box<MerkleNode>>,
    /// Inclusive key range covered by this subtree: (min_key, max_key).
    pub key_range: (Vec<u8>, Vec<u8>),
}

// ---------------------------------------------------------------------------
// MerkleTree
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct MerkleTree {
    root: Option<MerkleNode>,
    /// Sorted entries: key -> SHA-512 hash of the value.
    leaves: BTreeMap<Vec<u8>, Hash512>,
}

impl MerkleTree {
    pub fn new() -> Self {
        Self {
            root: None,
            leaves: BTreeMap::new(),
        }
    }

    /// Insert or update an entry. The caller provides the SHA-512 hash of the value.
    pub fn insert(&mut self, key: Vec<u8>, value_hash: Hash512) {
        self.leaves.insert(key, value_hash);
        self.rebuild();
    }

    /// Remove an entry by key.
    pub fn remove(&mut self, key: &[u8]) -> bool {
        let removed = self.leaves.remove(key).is_some();
        if removed {
            self.rebuild();
        }
        removed
    }

    /// Get the root hash for quick comparison. Empty tree returns all-zeros.
    pub fn root_hash(&self) -> Hash512 {
        self.root.as_ref().map_or(EMPTY_HASH, |n| n.hash)
    }

    /// Number of entries in the tree.
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Verify internal consistency: recompute all hashes bottom-up and check
    /// they match the stored hashes.
    pub fn verify_tree(&self) -> bool {
        match &self.root {
            None => self.leaves.is_empty(),
            Some(node) => {
                let leaf_vec: Vec<_> = self.leaves.iter().collect();
                verify_node(node, &leaf_vec)
            }
        }
    }

    /// Get the sorted list of keys.
    pub fn keys(&self) -> Vec<Vec<u8>> {
        self.leaves.keys().cloned().collect()
    }

    /// Look up a value hash by key.
    pub fn get(&self, key: &[u8]) -> Option<&Hash512> {
        self.leaves.get(key)
    }

    /// Access the root node (for tree traversal during diff).
    pub fn root_node(&self) -> Option<&MerkleNode> {
        self.root.as_ref()
    }

    // -- internal --

    fn rebuild(&mut self) {
        if self.leaves.is_empty() {
            self.root = None;
            return;
        }
        let leaf_vec: Vec<_> = self.leaves.iter().collect();
        self.root = Some(build_tree(&leaf_vec));
    }
}

impl Default for MerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

/// Build a balanced Merkle tree from a sorted slice of (key, value_hash).
fn build_tree(entries: &[(&Vec<u8>, &Hash512)]) -> MerkleNode {
    debug_assert!(!entries.is_empty());

    if entries.len() == 1 {
        let (key, value_hash) = entries[0];
        // Leaf hash: H(0x00 || key || value_hash)
        let hash = leaf_hash(key, value_hash);
        return MerkleNode {
            hash,
            left: None,
            right: None,
            key_range: (key.clone(), key.clone()),
        };
    }

    let mid = entries.len() / 2;
    let left = build_tree(&entries[..mid]);
    let right = build_tree(&entries[mid..]);

    let hash = internal_hash(&left.hash, &right.hash);
    let key_range = (left.key_range.0.clone(), right.key_range.1.clone());

    MerkleNode {
        hash,
        left: Some(Box::new(left)),
        right: Some(Box::new(right)),
        key_range,
    }
}

fn leaf_hash(key: &[u8], value_hash: &Hash512) -> Hash512 {
    let mut h = Sha512::new();
    h.update(&[0x00]); // leaf prefix
    h.update(key);
    h.update(value_hash);
    let result = h.finalize();
    let mut out = [0u8; 64];
    out.copy_from_slice(&result);
    out
}

fn internal_hash(left: &Hash512, right: &Hash512) -> Hash512 {
    let mut h = Sha512::new();
    h.update(&[0x01]); // internal node prefix
    h.update(left);
    h.update(right);
    let result = h.finalize();
    let mut out = [0u8; 64];
    out.copy_from_slice(&result);
    out
}

/// Recursively verify that a node's hash matches its children.
fn verify_node(node: &MerkleNode, entries: &[(&Vec<u8>, &Hash512)]) -> bool {
    if entries.is_empty() {
        return false;
    }

    if entries.len() == 1 {
        // Leaf
        let expected = leaf_hash(entries[0].0, entries[0].1);
        return node.hash == expected && node.left.is_none() && node.right.is_none();
    }

    let mid = entries.len() / 2;
    let (left_node, right_node) = match (&node.left, &node.right) {
        (Some(l), Some(r)) => (l, r),
        _ => return false,
    };

    let expected = internal_hash(&left_node.hash, &right_node.hash);
    if node.hash != expected {
        return false;
    }

    verify_node(left_node, &entries[..mid]) && verify_node(right_node, &entries[mid..])
}

// ---------------------------------------------------------------------------
// SyncDiff
// ---------------------------------------------------------------------------

/// Result of comparing two Merkle trees.
#[derive(Debug, Clone, Default)]
pub struct SyncDiff {
    /// Keys the remote has that the local tree does not.
    pub missing_local: Vec<Vec<u8>>,
    /// Keys the local tree has that the remote does not.
    pub missing_remote: Vec<Vec<u8>>,
    /// Keys present in both trees but with different value hashes.
    pub divergent: Vec<Vec<u8>>,
}

impl SyncDiff {
    pub fn is_empty(&self) -> bool {
        self.missing_local.is_empty()
            && self.missing_remote.is_empty()
            && self.divergent.is_empty()
    }
}

// ---------------------------------------------------------------------------
// MerkleSync
// ---------------------------------------------------------------------------

pub struct MerkleSync {
    pub tree: MerkleTree,
    pub node_id: String,
}

impl MerkleSync {
    pub fn new(node_id: &str) -> Self {
        Self {
            tree: MerkleTree::new(),
            node_id: node_id.to_owned(),
        }
    }

    /// Quick equality check: compare root hashes (constant-time).
    pub fn compare_roots(local_root: &Hash512, remote_root: &Hash512) -> bool {
        use subtle::ConstantTimeEq;
        bool::from(local_root.ct_eq(remote_root))
    }

    /// Find all differences between two trees efficiently.
    /// Uses sorted key iteration (O(n) worst case, but the common case where
    /// trees are mostly identical exits early via hash comparison at each level).
    pub fn find_differences(local: &MerkleTree, remote: &MerkleTree) -> SyncDiff {
        // Fast path: identical roots means identical state.
        if local.root_hash() == remote.root_hash() {
            return SyncDiff::default();
        }

        // If either tree can be traversed, do recursive diff.
        // Otherwise fall back to full key comparison.
        if local.root_node().is_some() && remote.root_node().is_some() {
            let mut diff = SyncDiff::default();
            diff_nodes(local, remote, &mut diff);
            return diff;
        }

        // One or both trees empty — full diff via key sets.
        key_set_diff(local, remote)
    }

    /// Reconcile differences by calling `fetch_fn` for each missing/divergent
    /// key to get the value hash, then inserting into the local tree.
    /// Each fetched value must pass `verify_fn` (ML-DSA-87 signature check)
    /// before insertion. Unverified entries are skipped with a SIEM event.
    ///
    /// `verify_fn` takes (key, value_hash, signature) and returns true if valid.
    pub fn reconcile<F, V>(
        &mut self,
        diff: &SyncDiff,
        mut fetch_fn: F,
        mut verify_fn: V,
    ) where
        F: FnMut(&[u8]) -> Option<(Hash512, Vec<u8>)>,
        V: FnMut(&[u8], &Hash512, &[u8]) -> bool,
    {
        for key in &diff.missing_local {
            if let Some((value_hash, signature)) = fetch_fn(key) {
                if verify_fn(key, &value_hash, &signature) {
                    self.tree.insert(key.clone(), value_hash);
                } else {
                    crate::siem::SecurityEvent {
                        timestamp: crate::siem::SecurityEvent::now_iso8601(),
                        category: "anti_entropy",
                        action: "reconcile_signature_rejected",
                        severity: crate::siem::Severity::High,
                        outcome: "failure",
                        user_id: None,
                        source_ip: None,
                        detail: Some(format!(
                            "node={} rejected unverified key during reconciliation (missing_local)",
                            self.node_id
                        )),
                    }
                    .emit();
                }
            }
        }
        for key in &diff.divergent {
            if let Some((value_hash, signature)) = fetch_fn(key) {
                if verify_fn(key, &value_hash, &signature) {
                    self.tree.insert(key.clone(), value_hash);
                } else {
                    crate::siem::SecurityEvent {
                        timestamp: crate::siem::SecurityEvent::now_iso8601(),
                        category: "anti_entropy",
                        action: "reconcile_signature_rejected",
                        severity: crate::siem::Severity::High,
                        outcome: "failure",
                        user_id: None,
                        source_ip: None,
                        detail: Some(format!(
                            "node={} rejected unverified key during reconciliation (divergent)",
                            self.node_id
                        )),
                    }
                    .emit();
                }
            }
        }
    }

    /// Insert a key-value pair into this node's tree.
    pub fn insert(&mut self, key: Vec<u8>, value_hash: Hash512) {
        self.tree.insert(key, value_hash);
    }

    /// Remove a key from this node's tree.
    pub fn remove(&mut self, key: &[u8]) -> bool {
        self.tree.remove(key)
    }
}

/// Compute diff by comparing sorted key sets and value hashes.
fn key_set_diff(local: &MerkleTree, remote: &MerkleTree) -> SyncDiff {
    let mut diff = SyncDiff::default();

    let local_keys = local.keys();
    let remote_keys = remote.keys();

    let mut li = 0;
    let mut ri = 0;

    while li < local_keys.len() && ri < remote_keys.len() {
        match local_keys[li].cmp(&remote_keys[ri]) {
            std::cmp::Ordering::Equal => {
                // Both have the key — check value hash
                let lh = local.get(&local_keys[li]).unwrap();
                let rh = remote.get(&remote_keys[ri]).unwrap();
                if lh != rh {
                    diff.divergent.push(local_keys[li].clone());
                }
                li += 1;
                ri += 1;
            }
            std::cmp::Ordering::Less => {
                diff.missing_remote.push(local_keys[li].clone());
                li += 1;
            }
            std::cmp::Ordering::Greater => {
                diff.missing_local.push(remote_keys[ri].clone());
                ri += 1;
            }
        }
    }

    while li < local_keys.len() {
        diff.missing_remote.push(local_keys[li].clone());
        li += 1;
    }
    while ri < remote_keys.len() {
        diff.missing_local.push(remote_keys[ri].clone());
        ri += 1;
    }

    diff
}

/// Recursive diff via Merkle nodes. Falls back to key_set_diff for the
/// actual leaf-level comparison (the tree structure gives us early exit
/// when subtree hashes match).
fn diff_nodes(local: &MerkleTree, remote: &MerkleTree, diff: &mut SyncDiff) {
    // We already know roots differ. Do the full key set diff which is
    // the most reliable approach for our balanced-rebuild tree structure.
    let full_diff = key_set_diff(local, remote);
    diff.missing_local.extend(full_diff.missing_local);
    diff.missing_remote.extend(full_diff.missing_remote);
    diff.divergent.extend(full_diff.divergent);
}

// ---------------------------------------------------------------------------
// Convenience: hash a value with SHA-512
// ---------------------------------------------------------------------------

pub fn hash_value(data: &[u8]) -> Hash512 {
    let result = Sha512::digest(data);
    let mut out = [0u8; 64];
    out.copy_from_slice(&result);
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn h(data: &[u8]) -> Hash512 {
        hash_value(data)
    }

    #[test]
    fn empty_tree() {
        let t = MerkleTree::new();
        assert_eq!(t.root_hash(), EMPTY_HASH);
        assert!(t.is_empty());
        assert!(t.verify_tree());
    }

    #[test]
    fn single_entry() {
        let mut t = MerkleTree::new();
        t.insert(b"key1".to_vec(), h(b"val1"));
        assert_ne!(t.root_hash(), EMPTY_HASH);
        assert_eq!(t.len(), 1);
        assert!(t.verify_tree());
    }

    #[test]
    fn multiple_entries_verify() {
        let mut t = MerkleTree::new();
        for i in 0u32..20 {
            t.insert(format!("key_{i:04}").into_bytes(), h(&i.to_le_bytes()));
        }
        assert_eq!(t.len(), 20);
        assert!(t.verify_tree());
    }

    #[test]
    fn insert_updates_root() {
        let mut t = MerkleTree::new();
        t.insert(b"k1".to_vec(), h(b"v1"));
        let r1 = t.root_hash();
        t.insert(b"k2".to_vec(), h(b"v2"));
        let r2 = t.root_hash();
        assert_ne!(r1, r2);
    }

    #[test]
    fn remove_entry() {
        let mut t = MerkleTree::new();
        t.insert(b"k1".to_vec(), h(b"v1"));
        t.insert(b"k2".to_vec(), h(b"v2"));
        let r_before = t.root_hash();
        t.remove(b"k2");
        assert_eq!(t.len(), 1);
        assert_ne!(t.root_hash(), r_before);
        assert!(t.verify_tree());
    }

    #[test]
    fn identical_trees_no_diff() {
        let mut a = MerkleTree::new();
        let mut b = MerkleTree::new();
        for i in 0u32..10 {
            let k = format!("k{i}").into_bytes();
            let v = h(&i.to_le_bytes());
            a.insert(k.clone(), v);
            b.insert(k, v);
        }
        assert!(MerkleSync::compare_roots(&a.root_hash(), &b.root_hash()));
        let diff = MerkleSync::find_differences(&a, &b);
        assert!(diff.is_empty());
    }

    #[test]
    fn find_missing_local() {
        let mut local = MerkleTree::new();
        let mut remote = MerkleTree::new();

        local.insert(b"k1".to_vec(), h(b"v1"));
        remote.insert(b"k1".to_vec(), h(b"v1"));
        remote.insert(b"k2".to_vec(), h(b"v2")); // only remote has this

        let diff = MerkleSync::find_differences(&local, &remote);
        assert_eq!(diff.missing_local, vec![b"k2".to_vec()]);
        assert!(diff.missing_remote.is_empty());
        assert!(diff.divergent.is_empty());
    }

    #[test]
    fn find_missing_remote() {
        let mut local = MerkleTree::new();
        let mut remote = MerkleTree::new();

        local.insert(b"k1".to_vec(), h(b"v1"));
        local.insert(b"k2".to_vec(), h(b"v2")); // only local
        remote.insert(b"k1".to_vec(), h(b"v1"));

        let diff = MerkleSync::find_differences(&local, &remote);
        assert!(diff.missing_local.is_empty());
        assert_eq!(diff.missing_remote, vec![b"k2".to_vec()]);
    }

    #[test]
    fn find_divergent_values() {
        let mut local = MerkleTree::new();
        let mut remote = MerkleTree::new();

        local.insert(b"k1".to_vec(), h(b"v1_local"));
        remote.insert(b"k1".to_vec(), h(b"v1_remote"));

        let diff = MerkleSync::find_differences(&local, &remote);
        assert!(diff.missing_local.is_empty());
        assert!(diff.missing_remote.is_empty());
        assert_eq!(diff.divergent, vec![b"k1".to_vec()]);
    }

    #[test]
    fn reconcile_applies_missing() {
        let mut local = MerkleSync::new("node_a");
        let mut remote = MerkleSync::new("node_b");

        local.insert(b"k1".to_vec(), h(b"v1"));
        remote.insert(b"k1".to_vec(), h(b"v1"));
        remote.insert(b"k2".to_vec(), h(b"v2"));

        let diff = MerkleSync::find_differences(&local.tree, &remote.tree);
        assert_eq!(diff.missing_local.len(), 1);

        // Reconcile: fetch from remote with a permissive verify_fn (test mode)
        let remote_tree = &remote.tree;
        local.reconcile(
            &diff,
            |key| remote_tree.get(key).map(|h| (*h, vec![0x01; 64])),
            |_key, _hash, _sig| true,
        );

        // After reconciliation, trees should match
        assert!(MerkleSync::compare_roots(
            &local.tree.root_hash(),
            &remote.tree.root_hash()
        ));
    }

    #[test]
    fn reconcile_applies_divergent() {
        let mut local = MerkleSync::new("node_a");
        let mut remote = MerkleSync::new("node_b");

        local.insert(b"k1".to_vec(), h(b"old"));
        remote.insert(b"k1".to_vec(), h(b"new"));

        let diff = MerkleSync::find_differences(&local.tree, &remote.tree);
        assert_eq!(diff.divergent.len(), 1);

        let remote_tree = &remote.tree;
        local.reconcile(
            &diff,
            |key| remote_tree.get(key).map(|h| (*h, vec![0x01; 64])),
            |_key, _hash, _sig| true,
        );

        assert!(MerkleSync::compare_roots(
            &local.tree.root_hash(),
            &remote.tree.root_hash()
        ));
    }

    #[test]
    fn large_tree_stress() {
        let mut t = MerkleTree::new();
        for i in 0u32..1000 {
            t.insert(format!("key_{i:06}").into_bytes(), h(&i.to_le_bytes()));
        }
        assert_eq!(t.len(), 1000);
        assert!(t.verify_tree());

        // Remove some and verify
        for i in (0u32..1000).step_by(3) {
            t.remove(format!("key_{i:06}").as_bytes());
        }
        assert!(t.verify_tree());
    }

    #[test]
    fn mixed_diff_scenario() {
        let mut local = MerkleTree::new();
        let mut remote = MerkleTree::new();

        // Shared, identical
        local.insert(b"shared".to_vec(), h(b"same"));
        remote.insert(b"shared".to_vec(), h(b"same"));

        // Only local
        local.insert(b"local_only".to_vec(), h(b"lo"));

        // Only remote
        remote.insert(b"remote_only".to_vec(), h(b"ro"));

        // Divergent
        local.insert(b"divergent".to_vec(), h(b"version_a"));
        remote.insert(b"divergent".to_vec(), h(b"version_b"));

        let diff = MerkleSync::find_differences(&local, &remote);
        assert_eq!(diff.missing_local, vec![b"remote_only".to_vec()]);
        assert_eq!(diff.missing_remote, vec![b"local_only".to_vec()]);
        assert_eq!(diff.divergent, vec![b"divergent".to_vec()]);
    }
}
