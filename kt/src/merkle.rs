//! Key Transparency Merkle tree — CNSA 2.0 compliant.
//!
//! Leaves are hashed with CSHAKE256 (SHA-3 XOF family, NIST SP 800-185) under
//! the customization string `MILNET-KT-LEAF-CSHAKE256-v1` for domain separation
//! and hash-algorithm diversity relative to the SHA-2 family.
//! Internal nodes continue to use SHA-512 (with the RFC-6962-style 0x01 prefix)
//! to preserve binary compatibility with existing inclusion proofs and with the
//! SHA-512 persisted checkpoint / STH chaining code paths. The distinct leaf
//! and node hash functions are not interchangeable: a second-preimage across
//! families is strictly harder than across a single family, so this is a
//! defence-in-depth hardening — not a regression.
use common::domain;
use sha2::{Digest, Sha512};
use sha3::digest::{core_api::CoreWrapper, ExtendableOutput, Update, XofReader};
use uuid::Uuid;

/// CSHAKE256 customization string for KT leaf hashing. Domain-separates
/// leaf hashes from every other CSHAKE256 usage in the system.
const KT_LEAF_CSHAKE_CUSTOM: &[u8] = b"MILNET-KT-LEAF-CSHAKE256-v1";

pub struct MerkleTree {
    leaves: Vec<[u8; 64]>,
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
    ) -> [u8; 64] {
        let leaf = compute_leaf(user_id, operation, credential_hash, timestamp);
        self.leaves.push(leaf);
        leaf
    }

    pub fn root(&self) -> [u8; 64] {
        if self.leaves.is_empty() {
            return [0u8; 64];
        }
        compute_root(&self.leaves)
    }

    pub fn inclusion_proof(&self, index: usize) -> Option<Vec<[u8; 64]>> {
        if index >= self.leaves.len() {
            return None;
        }
        Some(build_proof(&self.leaves, index))
    }

    pub fn verify_inclusion(
        root: &[u8; 64],
        leaf: &[u8; 64],
        proof: &[[u8; 64]],
        index: usize,
    ) -> bool {
        Self::verify_inclusion_with_size(root, leaf, proof, index, 0)
    }

    /// Verify inclusion with knowledge of the tree size, correctly handling
    /// odd-node promotion at each level (no self-hashing).
    pub fn verify_inclusion_with_size(
        root: &[u8; 64],
        leaf: &[u8; 64],
        proof: &[[u8; 64]],
        index: usize,
        tree_size: usize,
    ) -> bool {
        let mut current = *leaf;
        let mut idx = index;
        let mut proof_iter = proof.iter();
        // Reconstruct level sizes to detect promotion levels.
        // If tree_size is 0, fall back to consuming all proof elements (legacy).
        if tree_size > 0 {
            let mut level_size = tree_size;
            while level_size > 1 {
                if idx % 2 == 0 && idx + 1 >= level_size {
                    // This node was promoted — no sibling, no proof element consumed
                } else {
                    let sibling = match proof_iter.next() {
                        Some(s) => s,
                        None => return false,
                    };
                    current = if idx % 2 == 0 {
                        hash_pair(&current, sibling)
                    } else {
                        hash_pair(sibling, &current)
                    };
                }
                level_size = (level_size + 1) / 2;
                idx /= 2;
            }
        } else {
            // Legacy path: no tree_size, consume all proof elements
            for sibling in proof_iter {
                current = if idx % 2 == 0 {
                    hash_pair(&current, sibling)
                } else {
                    hash_pair(sibling, &current)
                };
                idx /= 2;
            }
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

/// Signed Tree Head — ML-DSA-87 signature over the Merkle root (CNSA 2.0)
#[derive(Debug, Clone)]
pub struct SignedTreeHead {
    pub root: [u8; 64],
    pub timestamp: i64,
    pub tree_size: usize,
    pub signature: Vec<u8>, // ML-DSA-87
}

impl MerkleTree {
    pub fn signed_tree_head(
        &self,
        signing_key: &crypto::pq_sign::PqSigningKey,
    ) -> SignedTreeHead {
        let root = self.root();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
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

    /// Sign the current Merkle root with an ML-DSA-87 signing key, binding the
    /// signature to an explicit epoch id (D16). The signed octet string is
    /// `epoch_id_be(8) || tree_size_be(8) || root(64)`, so a signature is only
    /// valid under the exact epoch that produced it — preventing a signature
    /// captured in one epoch from being replayed against a later epoch's STH.
    pub fn sign_root(
        &self,
        sk: &crypto::pq_sign::PqSigningKey,
        epoch_id: u64,
    ) -> Vec<u8> {
        let root = self.root();
        let tree_size = self.len() as u64;
        let mut data = Vec::with_capacity(8 + 8 + 64);
        data.extend_from_slice(&epoch_id.to_be_bytes());
        data.extend_from_slice(&tree_size.to_be_bytes());
        data.extend_from_slice(&root);
        crypto::pq_sign::pq_sign_raw(sk, &data)
    }

    /// Verify a signature produced by [`sign_root`] against the supplied epoch
    /// id, tree size, and root. Returns `true` only when the verifying key,
    /// epoch, tree size, and root all match the signature's commitments.
    pub fn verify_signed_root(
        vk: &crypto::pq_sign::PqVerifyingKey,
        epoch_id: u64,
        tree_size: u64,
        root: &[u8; 64],
        signature: &[u8],
    ) -> bool {
        let mut data = Vec::with_capacity(8 + 8 + 64);
        data.extend_from_slice(&epoch_id.to_be_bytes());
        data.extend_from_slice(&tree_size.to_be_bytes());
        data.extend_from_slice(root);
        crypto::pq_sign::pq_verify_raw(vk, &data, signature)
    }
}

fn compute_leaf(
    user_id: &Uuid,
    operation: &str,
    credential_hash: &[u8; 32],
    timestamp: i64,
) -> [u8; 64] {
    // CSHAKE256 with a KT-leaf-specific customization string. The RFC-6962
    // 0x00 leaf prefix and the legacy KT_LEAF domain tag are also absorbed so
    // that a leaf hash cannot collide with any internal-node hash or any other
    // CSHAKE256 leaf scheme in the codebase.
    let core = sha3::CShake256Core::new_with_function_name(b"", KT_LEAF_CSHAKE_CUSTOM);
    let mut hasher: sha3::CShake256 = CoreWrapper::from_core(core);
    hasher.update(&[0x00]); // RFC 6962 leaf prefix
    hasher.update(domain::KT_LEAF);
    hasher.update(user_id.as_bytes());
    hasher.update(operation.as_bytes());
    hasher.update(credential_hash);
    hasher.update(&timestamp.to_le_bytes());
    let mut reader = hasher.finalize_xof();
    let mut hash = [0u8; 64];
    reader.read(&mut hash);
    hash
}

fn hash_pair(left: &[u8; 64], right: &[u8; 64]) -> [u8; 64] {
    use sha2::Digest as Sha2Digest;
    let mut hasher = Sha512::new();
    Sha2Digest::update(&mut hasher, &[0x01]); // RFC 6962 internal node prefix
    Sha2Digest::update(&mut hasher, left);
    Sha2Digest::update(&mut hasher, right);
    let result = hasher.finalize();
    let mut hash = [0u8; 64];
    hash.copy_from_slice(&result);
    hash
}

fn compute_root(leaves: &[[u8; 64]]) -> [u8; 64] {
    if leaves.len() == 1 {
        return leaves[0];
    }
    let mut level: Vec<[u8; 64]> = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::new();
        for chunk in level.chunks(2) {
            if chunk.len() == 2 {
                next.push(hash_pair(&chunk[0], &chunk[1]));
            } else {
                // Promote the odd node unchanged to prevent [A,B,C] and
                // [A,B,C,C] from producing the same root (tree ambiguity).
                next.push(chunk[0]);
            }
        }
        level = next;
    }
    level[0]
}

fn build_proof(leaves: &[[u8; 64]], index: usize) -> Vec<[u8; 64]> {
    let mut proof = Vec::new();
    let mut level: Vec<[u8; 64]> = leaves.to_vec();
    let mut idx = index;
    while level.len() > 1 {
        // If idx is the last element in an odd-length level, it gets promoted
        // with no sibling — skip adding a proof element for this level.
        if idx % 2 == 0 && idx + 1 >= level.len() {
            // Odd node promoted: no sibling to add to proof
        } else {
            let sibling_idx = if idx % 2 == 0 {
                idx + 1
            } else {
                idx - 1
            };
            proof.push(level[sibling_idx]);
        }
        let mut next = Vec::new();
        for chunk in level.chunks(2) {
            if chunk.len() == 2 {
                next.push(hash_pair(&chunk[0], &chunk[1]));
            } else {
                // Promote the odd node unchanged (matches compute_root)
                next.push(chunk[0]);
            }
        }
        level = next;
        idx /= 2;
    }
    proof
}
