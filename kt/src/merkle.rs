use common::domain;
use sha3::{Digest, Sha3_256};
use uuid::Uuid;

pub struct MerkleTree {
    leaves: Vec<[u8; 32]>,
}

impl MerkleTree {
    pub fn new() -> Self {
        Self { leaves: Vec::new() }
    }

    pub fn append_credential_op(
        &mut self,
        user_id: &Uuid,
        operation: &str,
        credential_hash: &[u8; 32],
        timestamp: i64,
    ) -> [u8; 32] {
        let leaf = compute_leaf(user_id, operation, credential_hash, timestamp);
        self.leaves.push(leaf);
        leaf
    }

    pub fn root(&self) -> [u8; 32] {
        if self.leaves.is_empty() {
            return [0u8; 32];
        }
        compute_root(&self.leaves)
    }

    pub fn inclusion_proof(&self, index: usize) -> Option<Vec<[u8; 32]>> {
        if index >= self.leaves.len() {
            return None;
        }
        Some(build_proof(&self.leaves, index))
    }

    pub fn verify_inclusion(
        root: &[u8; 32],
        leaf: &[u8; 32],
        proof: &[[u8; 32]],
        index: usize,
    ) -> bool {
        let mut current = *leaf;
        let mut idx = index;
        for sibling in proof {
            current = if idx.is_multiple_of(2) {
                hash_pair(&current, sibling)
            } else {
                hash_pair(sibling, &current)
            };
            idx /= 2;
        }
        crypto::ct::ct_eq(&current, root)
    }

    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }
}

impl Default for MerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

/// Signed Tree Head — ML-DSA-65 signature over the Merkle root
#[derive(Debug, Clone)]
pub struct SignedTreeHead {
    pub root: [u8; 32],
    pub timestamp: i64,
    pub tree_size: usize,
    pub signature: Vec<u8>, // ML-DSA-65
}

impl MerkleTree {
    pub fn signed_tree_head(
        &self,
        signing_key: &crypto::pq_sign::PqSigningKey,
    ) -> SignedTreeHead {
        let root = self.root();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros() as i64;
        let mut data = Vec::new();
        data.extend_from_slice(&root);
        data.extend_from_slice(&timestamp.to_le_bytes());
        data.extend_from_slice(&(self.len() as u64).to_le_bytes());
        let signature = crypto::pq_sign::pq_sign_raw(signing_key, &data);
        SignedTreeHead {
            root,
            timestamp,
            tree_size: self.len(),
            signature,
        }
    }

    pub fn verify_tree_head(
        sth: &SignedTreeHead,
        verifying_key: &crypto::pq_sign::PqVerifyingKey,
    ) -> bool {
        let mut data = Vec::new();
        data.extend_from_slice(&sth.root);
        data.extend_from_slice(&sth.timestamp.to_le_bytes());
        data.extend_from_slice(&(sth.tree_size as u64).to_le_bytes());
        crypto::pq_sign::pq_verify_raw(verifying_key, &data, &sth.signature)
    }
}

fn compute_leaf(
    user_id: &Uuid,
    operation: &str,
    credential_hash: &[u8; 32],
    timestamp: i64,
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(domain::KT_LEAF);
    hasher.update(user_id.as_bytes());
    hasher.update(operation.as_bytes());
    hasher.update(credential_hash);
    hasher.update(timestamp.to_le_bytes());
    hasher.finalize().into()
}

fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

fn compute_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.len() == 1 {
        return leaves[0];
    }
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::new();
        for chunk in level.chunks(2) {
            if chunk.len() == 2 {
                next.push(hash_pair(&chunk[0], &chunk[1]));
            } else {
                next.push(hash_pair(&chunk[0], &chunk[0])); // duplicate for odd
            }
        }
        level = next;
    }
    level[0]
}

fn build_proof(leaves: &[[u8; 32]], index: usize) -> Vec<[u8; 32]> {
    let mut proof = Vec::new();
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    let mut idx = index;
    while level.len() > 1 {
        let sibling_idx = if idx.is_multiple_of(2) {
            idx + 1
        } else {
            idx - 1
        };
        let sibling = if sibling_idx < level.len() {
            level[sibling_idx]
        } else {
            level[idx]
        };
        proof.push(sibling);
        let mut next = Vec::new();
        for chunk in level.chunks(2) {
            if chunk.len() == 2 {
                next.push(hash_pair(&chunk[0], &chunk[1]));
            } else {
                next.push(hash_pair(&chunk[0], &chunk[0]));
            }
        }
        level = next;
        idx /= 2;
    }
    proof
}
