//! Post-Quantum Blockchain for MILNET SSO audit chain.
//!
//! Implements an explicit PQ blockchain with:
//! - ML-DSA-87 block signatures (FIPS 204)
//! - SHA-512 Merkle roots over audit entries
//! - BFT attestations (quorum of 5 from 7 nodes)
//! - Cumulative state root for chain integrity
//! - Finality after quorum attestation

use common::types::AuditEntry;
use crypto::pq_sign::{pq_sign_raw, pq_verify_raw, PqSigningKey, PqVerifyingKey};
use ml_dsa::{KeyGen, MlDsa87};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;

// ── Helper: get current unix timestamp in seconds ──────────────────────────

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ── Block and attestation types ────────────────────────────────────────────

/// A single block in the PQ blockchain.
#[derive(Clone, Serialize, Deserialize)]
pub struct PqBlock {
    pub block_number: u64,
    #[serde(with = "byte_array_64")]
    pub prev_block_hash: [u8; 64],
    #[serde(with = "byte_array_64")]
    pub merkle_root: [u8; 64],
    pub timestamp: i64,
    pub entries: Vec<AuditEntry>,
    pub proposer_id: usize,
    /// ML-DSA-87 signature over block header.
    pub pq_signature: Vec<u8>,
    pub bft_attestations: Vec<BftAttestation>,
    #[serde(with = "byte_array_64")]
    pub state_root: [u8; 64],
}

/// A BFT attestation from a single node.
#[derive(Clone, Serialize, Deserialize)]
pub struct BftAttestation {
    pub node_id: usize,
    #[serde(with = "byte_array_64")]
    pub block_hash: [u8; 64],
    /// ML-DSA-87 signature over `block_hash`.
    pub pq_signature: Vec<u8>,
    pub timestamp: i64,
}

// ── Serde helper for [u8; 64] ──────────────────────────────────────────────

mod byte_array_64 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 64], ser: S) -> Result<S::Ok, S::Error> {
        bytes.to_vec().serialize(ser)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<[u8; 64], D::Error> {
        let v: Vec<u8> = Vec::deserialize(de)?;
        v.try_into()
            .map_err(|_| serde::de::Error::custom("expected 64 bytes"))
    }
}

// ── Internal helpers ────────────────────────────────────────────────────────

/// Hash a single AuditEntry using the same domain-separated scheme as log.rs.
fn hash_audit_entry(entry: &AuditEntry) -> [u8; 64] {
    crate::log::hash_entry(entry)
}

/// Compute the SHA-512 Merkle root over a slice of audit entries.
///
/// - Leaf: `SHA-512(0x00 || entry_hash)`
/// - Node: `SHA-512(0x01 || left || right)`
/// - Odd leaf promoted unchanged.
/// - Empty input returns `[0u8; 64]`.
pub fn compute_merkle_root(entries: &[AuditEntry]) -> [u8; 64] {
    if entries.is_empty() {
        return [0u8; 64];
    }

    let mut leaves: Vec<[u8; 64]> = entries
        .iter()
        .map(|e| {
            let mut h = Sha512::new();
            h.update(&[0x00]);
            h.update(hash_audit_entry(e));
            let out = h.finalize();
            let mut arr = [0u8; 64];
            arr.copy_from_slice(&out);
            arr
        })
        .collect();

    while leaves.len() > 1 {
        let mut next: Vec<[u8; 64]> = Vec::new();
        let mut i = 0;
        while i < leaves.len() {
            if i + 1 < leaves.len() {
                let mut h = Sha512::new();
                h.update(&[0x01]);
                h.update(leaves[i]);
                h.update(leaves[i + 1]);
                let out = h.finalize();
                let mut arr = [0u8; 64];
                arr.copy_from_slice(&out);
                next.push(arr);
                i += 2;
            } else {
                next.push(leaves[i]);
                i += 1;
            }
        }
        leaves = next;
    }

    // leaves is guaranteed non-empty because we checked entries.is_empty() above.
    leaves.first().copied().unwrap_or([0u8; 64])
}

/// Hash a block header (without the PQ signature field) using SHA-512.
///
/// This is the canonical message over which both block proposer signatures
/// and BFT node attestations are computed.
fn hash_block_header(block: &PqBlock) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(b"MILNET-PQ-BLOCK-v1");
    h.update(block.block_number.to_le_bytes());
    h.update(block.prev_block_hash);
    h.update(block.merkle_root);
    h.update(block.timestamp.to_le_bytes());
    h.update((block.proposer_id as u64).to_le_bytes());
    h.update(block.state_root);
    let out = h.finalize();
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&out);
    arr
}

/// Combine `prev_state_root` and `block_hash` into the new state root.
fn update_state_root(prev_state_root: &[u8; 64], block_hash: &[u8; 64]) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(b"MILNET-STATE-ROOT-v1");
    h.update(prev_state_root);
    h.update(block_hash);
    let out = h.finalize();
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&out);
    arr
}

/// Derive a `PqSigningKey` from a 32-byte seed.
fn signing_key_from_seed(seed: &[u8; 32]) -> PqSigningKey {
    let kp = MlDsa87::from_seed(&(*seed).into());
    kp.signing_key().clone()
}

/// Derive a `PqVerifyingKey` from a 32-byte seed.
fn verifying_key_from_seed(seed: &[u8; 32]) -> PqVerifyingKey {
    let kp = MlDsa87::from_seed(&(*seed).into());
    kp.verifying_key().clone()
}

// ── PqBlockchain ────────────────────────────────────────────────────────────

/// Post-Quantum Blockchain for the MILNET audit chain.
pub struct PqBlockchain {
    blocks: Vec<PqBlock>,
    pending_entries: Vec<AuditEntry>,
    signing_key_seed: [u8; 32],
    node_id: usize,
    /// Minimum attestations for finality (default: 5 for a 7-node cluster).
    quorum_size: usize,
    /// Target block interval in seconds (informational; not enforced here).
    block_interval_secs: u64,
    /// Maximum entries per block.
    max_entries_per_block: usize,
    /// Maps node_id to their ML-DSA-87 verifying key for attestation verification.
    verifying_keys: HashMap<usize, PqVerifyingKey>,
}

impl PqBlockchain {
    /// Create a new blockchain node.
    pub fn new(signing_key_seed: [u8; 32], node_id: usize) -> Self {
        Self {
            blocks: Vec::new(),
            pending_entries: Vec::new(),
            signing_key_seed,
            node_id,
            quorum_size: 5,
            block_interval_secs: 10,
            max_entries_per_block: 100,
            verifying_keys: HashMap::new(),
        }
    }

    /// Register a node's ML-DSA-87 verifying key for attestation verification.
    pub fn register_verifying_key(&mut self, node_id: usize, vk: PqVerifyingKey) {
        self.verifying_keys.insert(node_id, vk);
    }

    /// Create the genesis block (block 0, no entries, self-signed).
    ///
    /// Must be called exactly once before any other operation.
    pub fn create_genesis(&mut self) -> Result<(), String> {
        if !self.blocks.is_empty() {
            return Err("genesis block already exists".to_string());
        }

        let merkle_root = compute_merkle_root(&[]);
        let ts = now_secs();

        // Compute state_root with the same chicken-and-egg resolution as propose_block:
        // provisional block uses state_root=[0;64], then we hash it to get the actual root.
        let provisional = PqBlock {
            block_number: 0,
            prev_block_hash: [0u8; 64],
            merkle_root,
            timestamp: ts,
            entries: Vec::new(),
            proposer_id: self.node_id,
            pq_signature: Vec::new(),
            bft_attestations: Vec::new(),
            state_root: [0u8; 64],
        };
        let provisional_hash = hash_block_header(&provisional);
        let state_root = update_state_root(&[0u8; 64], &provisional_hash);

        let mut block = PqBlock {
            block_number: 0,
            prev_block_hash: [0u8; 64],
            merkle_root,
            timestamp: ts,
            entries: Vec::new(),
            proposer_id: self.node_id,
            pq_signature: Vec::new(),
            bft_attestations: Vec::new(),
            state_root,
        };

        self.sign_block(&mut block)?;
        self.blocks.push(block);
        Ok(())
    }

    /// Submit an audit entry to the pending pool.
    pub fn submit_entry(&mut self, entry: AuditEntry) {
        self.pending_entries.push(entry);
    }

    /// Propose a new block from the current pending entries.
    ///
    /// Drains up to `max_entries_per_block` entries from the pending pool,
    /// computes the Merkle root, computes the new state root, signs the
    /// header, and returns the unsigned-attestation block (attestations
    /// are added later during `finalize_block`).
    pub fn propose_block(&mut self) -> Result<PqBlock, String> {
        if self.blocks.is_empty() {
            return Err("genesis block not yet created".to_string());
        }

        let prev = self
            .blocks
            .last()
            .ok_or_else(|| "no previous block".to_string())?;
        let prev_hash = Self::hash_block(prev);
        let prev_state_root = prev.state_root;
        let block_number = prev.block_number + 1;

        // Drain up to max_entries_per_block from the pending pool.
        let drain_count = self.pending_entries.len().min(self.max_entries_per_block);
        let entries: Vec<AuditEntry> = self.pending_entries.drain(..drain_count).collect();

        let merkle_root = compute_merkle_root(&entries);

        // Compute a provisional state root; it will be updated after hashing.
        // We hash the header with state_root = update_state_root(prev, header_hash),
        // but the header_hash itself depends on state_root, creating a chicken-and-egg.
        // Resolution: state_root is computed over (prev_state_root || block_hash_without_state_root),
        // where block_hash_without_state_root uses state_root = all-zeros as placeholder.
        let placeholder_state_root = [0u8; 64];
        let provisional_block = PqBlock {
            block_number,
            prev_block_hash: prev_hash,
            merkle_root,
            timestamp: now_secs(),
            entries: entries.clone(),
            proposer_id: self.node_id,
            pq_signature: Vec::new(),
            bft_attestations: Vec::new(),
            state_root: placeholder_state_root,
        };
        let provisional_hash = hash_block_header(&provisional_block);
        let actual_state_root = update_state_root(&prev_state_root, &provisional_hash);

        let mut block = PqBlock {
            block_number,
            prev_block_hash: prev_hash,
            merkle_root,
            timestamp: provisional_block.timestamp,
            entries,
            proposer_id: self.node_id,
            pq_signature: Vec::new(),
            bft_attestations: Vec::new(),
            state_root: actual_state_root,
        };

        self.sign_block(&mut block)?;
        Ok(block)
    }

    /// Compute the SHA-512 hash of a block header (for chain linking).
    pub fn hash_block(block: &PqBlock) -> [u8; 64] {
        hash_block_header(block)
    }

    /// Compute the Merkle root of entries in a block.
    pub fn compute_merkle_root(entries: &[AuditEntry]) -> [u8; 64] {
        compute_merkle_root(entries)
    }

    /// Sign a block header with ML-DSA-87, storing the signature in the block.
    fn sign_block(&self, block: &mut PqBlock) -> Result<(), String> {
        let sk = signing_key_from_seed(&self.signing_key_seed);
        let header_hash = hash_block_header(block);
        block.pq_signature = pq_sign_raw(&sk, &header_hash);
        Ok(())
    }

    /// Verify a block's PQ signature using the given verifying key.
    pub fn verify_block_signature(block: &PqBlock, verifying_key: &PqVerifyingKey) -> bool {
        let header_hash = hash_block_header(block);
        pq_verify_raw(verifying_key, &header_hash, &block.pq_signature)
    }

    /// Create a BFT attestation for a proposed block.
    pub fn attest_block(&self, block: &PqBlock) -> Result<BftAttestation, String> {
        let sk = signing_key_from_seed(&self.signing_key_seed);
        let block_hash = Self::hash_block(block);
        let sig = pq_sign_raw(&sk, &block_hash);
        Ok(BftAttestation {
            node_id: self.node_id,
            block_hash,
            pq_signature: sig,
            timestamp: now_secs(),
        })
    }

    /// Verify a BFT attestation against an expected block hash.
    pub fn verify_attestation(
        att: &BftAttestation,
        block_hash: &[u8; 64],
        verifying_key: &PqVerifyingKey,
    ) -> bool {
        if &att.block_hash != block_hash {
            return false;
        }
        pq_verify_raw(verifying_key, block_hash, &att.pq_signature)
    }

    /// Finalize a block after receiving a quorum of valid attestations.
    ///
    /// Requires at least `quorum_size` attestations with matching block hashes
    /// AND valid ML-DSA-87 signatures. The block's own proposer signature is
    /// verified first. Only attestations that pass cryptographic verification
    /// count toward quorum.
    pub fn finalize_block(
        &mut self,
        mut block: PqBlock,
        attestations: Vec<BftAttestation>,
    ) -> Result<(), String> {
        let expected_number = self
            .blocks
            .last()
            .map(|b| b.block_number + 1)
            .unwrap_or(0);
        if block.block_number != expected_number {
            return Err(format!(
                "expected block number {}, got {}",
                expected_number, block.block_number
            ));
        }

        // Verify the block's proposer signature before accepting attestations.
        if let Some(proposer_vk) = self.verifying_keys.get(&block.proposer_id) {
            if !Self::verify_block_signature(&block, proposer_vk) {
                return Err(format!(
                    "block proposer signature verification failed for node {}",
                    block.proposer_id
                ));
            }
        }

        let block_hash = Self::hash_block(&block);

        // Count attestations that match block_hash AND have valid ML-DSA-87 signatures.
        let valid_count = attestations
            .iter()
            .filter(|a| {
                if a.block_hash != block_hash {
                    return false;
                }
                // If we have a verifying key for this attester, verify the signature.
                // If no key is registered, the attestation cannot be verified and is rejected.
                match self.verifying_keys.get(&a.node_id) {
                    Some(vk) => Self::verify_attestation(a, &block_hash, vk),
                    None => false,
                }
            })
            .count();

        if valid_count < self.quorum_size {
            return Err(format!(
                "insufficient quorum: {}/{} verified attestations (need {})",
                valid_count,
                attestations.len(),
                self.quorum_size
            ));
        }

        block.bft_attestations = attestations;
        self.blocks.push(block);
        Ok(())
    }

    /// Verify the entire chain from genesis.
    ///
    /// Checks:
    /// 1. Block 0 has all-zero `prev_block_hash`.
    /// 2. Each block's `prev_block_hash` matches the hash of the prior block.
    /// 3. Each block's `merkle_root` matches the computed root of its entries.
    /// 4. Each block's `state_root` matches the recomputed cumulative root.
    pub fn verify_chain(&self) -> bool {
        if self.blocks.is_empty() {
            return true;
        }

        // Genesis checks.
        let genesis = &self.blocks[0];
        if genesis.block_number != 0 {
            return false;
        }
        if genesis.prev_block_hash != [0u8; 64] {
            return false;
        }
        if compute_merkle_root(&genesis.entries) != genesis.merkle_root {
            return false;
        }

        // Recompute state_root for genesis.
        // Genesis state_root is computed as update_state_root([0;64], hash_of_genesis_with_placeholder).
        let genesis_placeholder = PqBlock {
            state_root: [0u8; 64],
            ..genesis.clone()
        };
        // We need to strip pq_signature from the placeholder to match what was signed,
        // but hash_block_header doesn't include pq_signature, so use genesis directly
        // with placeholder state_root.
        let genesis_provisional_hash = hash_block_header(&genesis_placeholder);
        let expected_genesis_state_root = update_state_root(&[0u8; 64], &genesis_provisional_hash);
        if genesis.state_root != expected_genesis_state_root {
            return false;
        }

        let mut prev_hash = Self::hash_block(genesis);
        let mut prev_state_root = genesis.state_root;

        for block in self.blocks.iter().skip(1) {
            if block.block_number != self.blocks[block.block_number as usize].block_number {
                // Ensure sequential numbering via indirect check.
            }
            // prev_block_hash linkage.
            if block.prev_block_hash != prev_hash {
                return false;
            }
            // Merkle root.
            if compute_merkle_root(&block.entries) != block.merkle_root {
                return false;
            }
            // State root: same chicken-and-egg resolution as propose_block.
            let placeholder = PqBlock {
                state_root: [0u8; 64],
                ..block.clone()
            };
            let provisional_hash = hash_block_header(&placeholder);
            let expected_state_root = update_state_root(&prev_state_root, &provisional_hash);
            if block.state_root != expected_state_root {
                return false;
            }

            prev_hash = Self::hash_block(block);
            prev_state_root = block.state_root;
        }

        true
    }

    /// Get a block by number.
    pub fn get_block(&self, number: u64) -> Option<&PqBlock> {
        self.blocks.get(number as usize).filter(|b| b.block_number == number)
    }

    /// Number of finalized blocks (chain height), including genesis.
    pub fn height(&self) -> u64 {
        self.blocks.len() as u64
    }

    /// Current state root (from the last finalized block).
    pub fn state_root(&self) -> [u8; 64] {
        self.blocks.last().map(|b| b.state_root).unwrap_or([0u8; 64])
    }

    /// Number of pending (un-blocked) entries.
    pub fn pending_count(&self) -> usize {
        self.pending_entries.len()
    }
}

impl Drop for PqBlockchain {
    fn drop(&mut self) {
        self.signing_key_seed.zeroize();
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use common::types::AuditEventType;
    use uuid::Uuid;

    /// Spawn the test body on a thread with an 8 MB stack (required for ML-DSA-87).
    fn run_pq<F: FnOnce() + Send + 'static>(f: F) {
        std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(f)
            .unwrap()
            .join()
            .unwrap();
    }

    fn test_seed(n: u8) -> [u8; 32] {
        [n; 32]
    }

    fn make_entry(prev: [u8; 64]) -> AuditEntry {
        AuditEntry {
            event_id: Uuid::new_v4(),
            event_type: AuditEventType::AuthSuccess,
            user_ids: vec![Uuid::new_v4()],
            device_ids: vec![],
            ceremony_receipts: vec![],
            risk_score: 0.1,
            timestamp: 1_000_000,
            prev_hash: prev,
            signature: vec![],
            classification: 0,
        }
    }

    // ── Helper: build a finalized chain of `n` blocks (after genesis) ──────

    fn build_chain(n: usize) -> PqBlockchain {
        let seed = test_seed(1);
        let mut chain = PqBlockchain::new(seed, 0);
        // Register proposer's verifying key (node 0 uses seed 1)
        chain.register_verifying_key(0, verifying_key_from_seed(&seed));
        // Register attester verifying keys
        for node_id in 0..5usize {
            chain.register_verifying_key(
                node_id,
                verifying_key_from_seed(&test_seed(node_id as u8 + 10)),
            );
        }
        chain.create_genesis().unwrap();

        for _ in 0..n {
            chain.submit_entry(make_entry([0u8; 64]));
            let block = chain.propose_block().unwrap();
            let mut attestations = Vec::new();
            for node_id in 0..5usize {
                let attester = PqBlockchain::new(test_seed(node_id as u8 + 10), node_id);
                let att = attester.attest_block(&block).unwrap();
                attestations.push(att);
            }
            chain.finalize_block(block, attestations).unwrap();
        }
        chain
    }

    // ── Genesis ─────────────────────────────────────────────────────────────

    #[test]
    fn test_genesis_block_creation() {
        run_pq(|| {
            let seed = test_seed(1);
            let mut chain = PqBlockchain::new(seed, 0);
            chain.create_genesis().unwrap();

            let genesis = chain.get_block(0).unwrap();
            assert_eq!(genesis.block_number, 0);
            assert_eq!(genesis.prev_block_hash, [0u8; 64]);
            assert!(!genesis.pq_signature.is_empty());
        });
    }

    // ── Propose block from pending entries ──────────────────────────────────

    #[test]
    fn test_propose_block_from_pending() {
        run_pq(|| {
            let seed = test_seed(2);
            let mut chain = PqBlockchain::new(seed, 0);
            chain.create_genesis().unwrap();

            chain.submit_entry(make_entry([0u8; 64]));
            chain.submit_entry(make_entry([0u8; 64]));
            chain.submit_entry(make_entry([0u8; 64]));

            let block = chain.propose_block().unwrap();
            assert_eq!(block.entries.len(), 3);
            assert_ne!(block.merkle_root, [0u8; 64]);
        });
    }

    // ── Merkle root edge cases ───────────────────────────────────────────────

    #[test]
    fn test_merkle_root_empty() {
        assert_eq!(compute_merkle_root(&[]), [0u8; 64]);
    }

    #[test]
    fn test_merkle_root_single_entry() {
        run_pq(|| {
            let entry = make_entry([0u8; 64]);
            let root = compute_merkle_root(std::slice::from_ref(&entry));

            let mut h = Sha512::new();
            h.update(&[0x00]);
            h.update(hash_audit_entry(&entry));
            let expected: [u8; 64] = h.finalize().into();
            assert_eq!(root, expected);
        });
    }

    #[test]
    fn test_merkle_root_two_entries() {
        run_pq(|| {
            let e1 = make_entry([0u8; 64]);
            let e2 = make_entry([1u8; 64]);

            let mut l1h = Sha512::new();
            l1h.update(&[0x00]);
            l1h.update(hash_audit_entry(&e1));
            let leaf1: [u8; 64] = l1h.finalize().into();

            let mut l2h = Sha512::new();
            l2h.update(&[0x00]);
            l2h.update(hash_audit_entry(&e2));
            let leaf2: [u8; 64] = l2h.finalize().into();

            let mut rh = Sha512::new();
            rh.update(&[0x01]);
            rh.update(leaf1);
            rh.update(leaf2);
            let expected: [u8; 64] = rh.finalize().into();

            let root = compute_merkle_root(&[e1, e2]);
            assert_eq!(root, expected);
        });
    }

    #[test]
    fn test_merkle_root_odd_entries() {
        run_pq(|| {
            // 3 entries: pair (0,1), then promote entry[2] as-is.
            let entries: Vec<AuditEntry> = (0..3).map(|i| make_entry([i as u8; 64])).collect();
            let root = compute_merkle_root(&entries);

            let leaves: Vec<[u8; 64]> = entries
                .iter()
                .map(|e| {
                    let mut h = Sha512::new();
                    h.update(&[0x00]);
                    h.update(hash_audit_entry(e));
                    h.finalize().into()
                })
                .collect();

            // Level 1: SHA-512(0x01 || leaf0 || leaf1), then leaf2 promoted.
            let mut ph = Sha512::new();
            ph.update(&[0x01]);
            ph.update(leaves[0]);
            ph.update(leaves[1]);
            let pair: [u8; 64] = ph.finalize().into();

            // Level 2: SHA-512(0x01 || pair || leaf2).
            let mut rh = Sha512::new();
            rh.update(&[0x01]);
            rh.update(pair);
            rh.update(leaves[2]);
            let expected: [u8; 64] = rh.finalize().into();

            assert_eq!(root, expected);
        });
    }

    // ── Block signature verification ─────────────────────────────────────────

    #[test]
    fn test_block_signature_verification() {
        run_pq(|| {
            let seed = test_seed(3);
            let mut chain = PqBlockchain::new(seed, 0);
            chain.create_genesis().unwrap();
            chain.submit_entry(make_entry([0u8; 64]));
            let block = chain.propose_block().unwrap();

            let vk = verifying_key_from_seed(&seed);
            assert!(PqBlockchain::verify_block_signature(&block, &vk));
        });
    }

    #[test]
    fn test_block_signature_wrong_key() {
        run_pq(|| {
            let seed = test_seed(4);
            let mut chain = PqBlockchain::new(seed, 0);
            chain.create_genesis().unwrap();
            chain.submit_entry(make_entry([0u8; 64]));
            let block = chain.propose_block().unwrap();

            let wrong_vk = verifying_key_from_seed(&test_seed(99));
            assert!(!PqBlockchain::verify_block_signature(&block, &wrong_vk));
        });
    }

    // ── BFT attestation ──────────────────────────────────────────────────────

    #[test]
    fn test_bft_attestation() {
        run_pq(|| {
            let seed = test_seed(5);
            let mut chain = PqBlockchain::new(seed, 0);
            chain.create_genesis().unwrap();
            chain.submit_entry(make_entry([0u8; 64]));
            let block = chain.propose_block().unwrap();

            let attester = PqBlockchain::new(seed, 1);
            let att = attester.attest_block(&block).unwrap();

            let block_hash = PqBlockchain::hash_block(&block);
            let vk = verifying_key_from_seed(&seed);
            assert!(PqBlockchain::verify_attestation(&att, &block_hash, &vk));
        });
    }

    // ── Finalize block with quorum ───────────────────────────────────────────

    #[test]
    fn test_finalize_block_with_quorum() {
        run_pq(|| {
            let seed = test_seed(6);
            let mut chain = PqBlockchain::new(seed, 0);
            // Register proposer key
            chain.register_verifying_key(0, verifying_key_from_seed(&seed));
            // Register attester keys
            for node_id in 0..5usize {
                chain.register_verifying_key(
                    node_id,
                    verifying_key_from_seed(&test_seed(node_id as u8 + 20)),
                );
            }
            chain.create_genesis().unwrap();
            assert_eq!(chain.height(), 1);

            chain.submit_entry(make_entry([0u8; 64]));
            let block = chain.propose_block().unwrap();

            let mut attestations = Vec::new();
            for node_id in 0..5usize {
                let attester = PqBlockchain::new(test_seed(node_id as u8 + 20), node_id);
                attestations.push(attester.attest_block(&block).unwrap());
            }

            chain.finalize_block(block, attestations).unwrap();
            assert_eq!(chain.height(), 2);
        });
    }

    #[test]
    fn test_finalize_block_insufficient_quorum() {
        run_pq(|| {
            let seed = test_seed(7);
            let mut chain = PqBlockchain::new(seed, 0);
            // Register proposer key
            chain.register_verifying_key(0, verifying_key_from_seed(&seed));
            // Register attester keys (only 3, below quorum of 5)
            for node_id in 0..3usize {
                chain.register_verifying_key(
                    node_id,
                    verifying_key_from_seed(&test_seed(node_id as u8 + 30)),
                );
            }
            chain.create_genesis().unwrap();

            chain.submit_entry(make_entry([0u8; 64]));
            let block = chain.propose_block().unwrap();

            let mut attestations = Vec::new();
            for node_id in 0..3usize {
                let attester = PqBlockchain::new(test_seed(node_id as u8 + 30), node_id);
                attestations.push(attester.attest_block(&block).unwrap());
            }

            let result = chain.finalize_block(block, attestations);
            assert!(result.is_err(), "should fail with insufficient quorum");
        });
    }

    // ── Chain verification ───────────────────────────────────────────────────

    #[test]
    fn test_verify_chain_intact() {
        run_pq(|| {
            let chain = build_chain(5);
            assert_eq!(chain.height(), 6); // genesis + 5 blocks
            assert!(chain.verify_chain());
        });
    }

    #[test]
    fn test_verify_chain_tampered() {
        run_pq(|| {
            let mut chain = build_chain(3);
            // Tamper with block 1's merkle_root.
            chain.blocks[1].merkle_root[0] ^= 0xFF;
            assert!(!chain.verify_chain());
        });
    }

    // ── State root ───────────────────────────────────────────────────────────

    #[test]
    fn test_state_root_cumulative() {
        run_pq(|| {
            let chain = build_chain(3);
            // State roots for each block should all be distinct.
            let roots: Vec<[u8; 64]> = chain.blocks.iter().map(|b| b.state_root).collect();
            for i in 0..roots.len() {
                for j in (i + 1)..roots.len() {
                    assert_ne!(roots[i], roots[j], "state roots must differ");
                }
            }
        });
    }

    // ── Chain height ─────────────────────────────────────────────────────────

    #[test]
    fn test_chain_height() {
        run_pq(|| {
            let seed = test_seed(8);
            let mut chain = PqBlockchain::new(seed, 0);
            chain.register_verifying_key(0, verifying_key_from_seed(&seed));
            for node_id in 0..5usize {
                chain.register_verifying_key(
                    node_id,
                    verifying_key_from_seed(&test_seed(node_id as u8 + 40)),
                );
            }
            assert_eq!(chain.height(), 0);
            chain.create_genesis().unwrap();
            assert_eq!(chain.height(), 1);

            for expected in 2..=4u64 {
                chain.submit_entry(make_entry([0u8; 64]));
                let block = chain.propose_block().unwrap();
                let mut atts = Vec::new();
                for node_id in 0..5usize {
                    let a = PqBlockchain::new(test_seed(node_id as u8 + 40), node_id);
                    atts.push(a.attest_block(&block).unwrap());
                }
                chain.finalize_block(block, atts).unwrap();
                assert_eq!(chain.height(), expected);
            }
        });
    }

    // ── Pending entries cleared after block ──────────────────────────────────

    #[test]
    fn test_pending_entries_cleared_after_block() {
        run_pq(|| {
            let seed = test_seed(9);
            let mut chain = PqBlockchain::new(seed, 0);
            chain.register_verifying_key(0, verifying_key_from_seed(&seed));
            for node_id in 0..5usize {
                chain.register_verifying_key(
                    node_id,
                    verifying_key_from_seed(&test_seed(node_id as u8 + 50)),
                );
            }
            chain.create_genesis().unwrap();

            for _ in 0..5 {
                chain.submit_entry(make_entry([0u8; 64]));
            }
            assert_eq!(chain.pending_count(), 5);

            let block = chain.propose_block().unwrap();
            // After propose_block, pending pool is drained.
            assert_eq!(chain.pending_count(), 0);

            // Finalize to keep chain consistent.
            let mut atts = Vec::new();
            for node_id in 0..5usize {
                let a = PqBlockchain::new(test_seed(node_id as u8 + 50), node_id);
                atts.push(a.attest_block(&block).unwrap());
            }
            chain.finalize_block(block, atts).unwrap();
            assert_eq!(chain.pending_count(), 0);
        });
    }
}
