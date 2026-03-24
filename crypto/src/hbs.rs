//! Hash-Based Signatures (SP 800-208) — LMS/XMSS interface.
//!
//! Implements stateful hash-based signature schemes for firmware and code
//! signing where the number of signatures is bounded. These schemes offer
//! the strongest possible post-quantum security guarantees since their
//! security relies solely on the properties of hash functions.
//!
//! # Why stateful HBS for code/firmware signing?
//!
//! Unlike stateless schemes (ML-DSA, SLH-DSA), LMS/XMSS signatures are
//! stateful: each private key can produce a bounded number of signatures,
//! and the signer must track which one-time keys have been used. Reusing
//! a one-time key completely breaks security.
//!
//! This is acceptable for firmware signing where:
//! - Signatures are infrequent (firmware releases)
//! - State can be reliably persisted (HSM-backed)
//! - The bounded signature count is a feature (limits exposure)
//!
//! # Implementation
//!
//! Uses SHA2-256 as the hash function per SP 800-208 and NIST SP 800-208
//! recommendations. The Winternitz parameter w=16 balances signature size
//! and computation.
//!
//! # State Management
//!
//! The `LmsStatePersistence` trait allows plugging in HSM-backed or
//! database-backed state persistence to prevent one-time key reuse
//! across restarts.

use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Security parameter: hash output size in bytes.
const N: usize = 32;

/// LMS tree height (H=20 allows 2^20 = ~1M signatures).
const LMS_H: usize = 20;

/// Winternitz parameter.
const WOTS_W: usize = 16;

/// WOTS+ chain length parameters for w=16, n=32.
/// len1 = ceil(8*n / log2(w)) = ceil(256/4) = 64
/// len2 = floor(log2(len1*(w-1)) / log2(w)) + 1 = 3
const WOTS_LEN1: usize = 64;
const WOTS_LEN2: usize = 3;
const WOTS_LEN: usize = WOTS_LEN1 + WOTS_LEN2;

/// Maximum number of signatures: 2^H.
pub const MAX_SIGNATURES: u64 = 1u64 << LMS_H;

/// LMS algorithm identifier for LMS_SHA256_M32_H20.
const LMS_TYPE: u32 = 0x00000006;

/// LMOTS algorithm identifier for LMOTS_SHA256_N32_W16.
const LMOTS_TYPE: u32 = 0x00000004;

// ── State Persistence Trait ─────────────────────────────────────────

/// Trait for persisting LMS signing state.
///
/// Implementations MUST ensure atomicity: if `save_index` succeeds,
/// the index is durably recorded. If it fails, the previous index
/// is still valid.
///
/// For HSM-backed implementations, the index should be stored in
/// the HSM's secure storage to survive restarts.
pub trait LmsStatePersistence {
    /// Load the current one-time signature index.
    /// Returns `None` if no state has been saved yet (fresh key).
    fn load_index(&self) -> Result<Option<u64>, String>;

    /// Save the next one-time signature index.
    /// This MUST be called BEFORE the signature is produced to prevent
    /// index reuse on crash recovery.
    fn save_index(&self, index: u64) -> Result<(), String>;
}

/// In-memory state persistence (for testing only).
///
/// WARNING: Not suitable for production use — state is lost on restart,
/// which could lead to one-time key reuse.
pub struct InMemoryPersistence {
    index: std::cell::Cell<Option<u64>>,
}

impl InMemoryPersistence {
    pub fn new() -> Self {
        Self {
            index: std::cell::Cell::new(None),
        }
    }
}

impl Default for InMemoryPersistence {
    fn default() -> Self {
        Self::new()
    }
}

impl LmsStatePersistence for InMemoryPersistence {
    fn load_index(&self) -> Result<Option<u64>, String> {
        Ok(self.index.get())
    }

    fn save_index(&self, index: u64) -> Result<(), String> {
        self.index.set(Some(index));
        Ok(())
    }
}

/// File-backed state persistence.
///
/// Stores the signature index in a file, using fsync for durability.
/// Suitable for non-HSM deployments where the filesystem is reliable.
pub struct FilePersistence {
    path: std::path::PathBuf,
}

impl FilePersistence {
    pub fn new(path: std::path::PathBuf) -> Self {
        Self { path }
    }
}

impl LmsStatePersistence for FilePersistence {
    fn load_index(&self) -> Result<Option<u64>, String> {
        match std::fs::read(&self.path) {
            Ok(data) => {
                if data.len() < 8 {
                    return Err("corrupt state file: too short".into());
                }
                let mut bytes = [0u8; 8];
                bytes.copy_from_slice(&data[..8]);
                Ok(Some(u64::from_le_bytes(bytes)))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(format!("failed to read state file: {}", e)),
        }
    }

    fn save_index(&self, index: u64) -> Result<(), String> {
        use std::io::Write;
        let tmp_path = self.path.with_extension("tmp");
        let mut f = std::fs::File::create(&tmp_path)
            .map_err(|e| format!("failed to create temp state file: {}", e))?;
        f.write_all(&index.to_le_bytes())
            .map_err(|e| format!("failed to write state: {}", e))?;
        f.sync_all()
            .map_err(|e| format!("failed to sync state file: {}", e))?;
        drop(f);
        std::fs::rename(&tmp_path, &self.path)
            .map_err(|e| format!("failed to rename state file: {}", e))?;
        Ok(())
    }
}

// ── LMS Key Types ───────────────────────────────────────────────────

/// LMS private (signing) key.
///
/// Contains the secret seed and the identifier, plus the current
/// one-time signature index. The index MUST be persisted before
/// each signing operation.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct LmsPrivateKey {
    /// Secret seed for deriving WOTS+ private keys.
    seed: [u8; N],
    /// Key identifier (random, binds the key to its tree).
    #[zeroize(skip)]
    identifier: [u8; 16],
    /// Current one-time signature index.
    #[zeroize(skip)]
    current_index: u64,
}

/// LMS public key.
///
/// Contains the LMS tree root, algorithm identifiers, and the key
/// identifier for binding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LmsPublicKey {
    /// LMS algorithm type.
    pub lms_type: u32,
    /// LMOTS algorithm type.
    pub lmots_type: u32,
    /// Key identifier.
    pub identifier: [u8; 16],
    /// Root of the Merkle tree.
    pub root: [u8; N],
}

impl LmsPublicKey {
    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 4 + 16 + N);
        out.extend_from_slice(&self.lms_type.to_be_bytes());
        out.extend_from_slice(&self.lmots_type.to_be_bytes());
        out.extend_from_slice(&self.identifier);
        out.extend_from_slice(&self.root);
        out
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 4 + 4 + 16 + N {
            return None;
        }
        let lms_type = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let lmots_type = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let mut identifier = [0u8; 16];
        identifier.copy_from_slice(&bytes[8..24]);
        let mut root = [0u8; N];
        root.copy_from_slice(&bytes[24..24 + N]);
        Some(Self {
            lms_type,
            lmots_type,
            identifier,
            root,
        })
    }
}

/// LMS signature.
#[derive(Debug)]
pub struct LmsSignature {
    /// The one-time signature index q.
    pub q: u32,
    /// LMOTS signature (randomizer C + y values).
    pub lmots_sig: Vec<u8>,
    /// Authentication path (H * N bytes).
    pub auth_path: Vec<u8>,
}

impl LmsSignature {
    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.q.to_be_bytes());
        // LMOTS signature: type(4) + C(N) + y(LEN*N)
        out.extend_from_slice(&self.lmots_sig);
        // LMS type
        out.extend_from_slice(&LMS_TYPE.to_be_bytes());
        // Auth path
        out.extend_from_slice(&self.auth_path);
        out
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let min_len = 4 + 4 + N + WOTS_LEN * N + 4 + LMS_H * N;
        if bytes.len() < min_len {
            return None;
        }
        let q = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let lmots_end = 4 + 4 + N + WOTS_LEN * N;
        let lmots_sig = bytes[4..lmots_end].to_vec();
        let auth_start = lmots_end + 4; // skip LMS type
        let auth_end = auth_start + LMS_H * N;
        if bytes.len() < auth_end {
            return None;
        }
        let auth_path = bytes[auth_start..auth_end].to_vec();
        Some(Self {
            q,
            lmots_sig,
            auth_path,
        })
    }
}

// ── Internal Hash Functions ─────────────────────────────────────────

/// Derive WOTS+ secret value for chain `chain` at index `q`.
fn wots_secret(
    seed: &[u8; N],
    identifier: &[u8; 16],
    q: u32,
    chain: u16,
) -> [u8; N] {
    let mut hasher = Sha256::new();
    hasher.update(identifier);
    hasher.update(q.to_be_bytes());
    hasher.update(chain.to_be_bytes());
    hasher.update([0xFF]); // domain separator for secret derivation
    hasher.update(seed);
    let result = hasher.finalize();
    let mut out = [0u8; N];
    out.copy_from_slice(&result);
    out
}

/// WOTS+ chain computation: iterate hash `steps` times.
fn wots_chain(
    identifier: &[u8; 16],
    q: u32,
    chain: u16,
    input: &[u8; N],
    start: u32,
    steps: u32,
) -> [u8; N] {
    let mut tmp = *input;
    for j in start..start + steps {
        let mut hasher = Sha256::new();
        hasher.update(identifier);
        hasher.update(q.to_be_bytes());
        hasher.update(chain.to_be_bytes());
        hasher.update((j as u16).to_be_bytes());
        hasher.update(&tmp);
        let result = hasher.finalize();
        tmp.copy_from_slice(&result);
    }
    tmp
}

/// Convert message hash to base-w coefficients.
fn to_base_w(hash: &[u8], out_len: usize) -> Vec<u32> {
    let mut result = Vec::with_capacity(out_len);
    for &byte in hash.iter() {
        if result.len() >= out_len {
            break;
        }
        result.push((byte >> 4) as u32);
        if result.len() < out_len {
            result.push((byte & 0x0F) as u32);
        }
    }
    while result.len() < out_len {
        result.push(0);
    }
    result
}

/// Compute LMOTS public key from private key at index q.
fn lmots_compute_pk(
    seed: &[u8; N],
    identifier: &[u8; 16],
    q: u32,
) -> [u8; N] {
    let mut chain_outputs = Vec::with_capacity(WOTS_LEN * N);
    for i in 0..WOTS_LEN {
        let sk = wots_secret(seed, identifier, q, i as u16);
        let pk_i = wots_chain(identifier, q, i as u16, &sk, 0, (WOTS_W - 1) as u32);
        chain_outputs.extend_from_slice(&pk_i);
    }

    // Hash all chain outputs together to get the LMOTS public key
    let mut hasher = Sha256::new();
    hasher.update(identifier);
    hasher.update(q.to_be_bytes());
    hasher.update([0xD8]); // D_PBLC domain separator
    hasher.update(&chain_outputs);
    let result = hasher.finalize();
    let mut out = [0u8; N];
    out.copy_from_slice(&result);
    out
}

/// Compute leaf node of the LMS tree at index q.
fn lms_leaf(
    seed: &[u8; N],
    identifier: &[u8; 16],
    q: u32,
) -> [u8; N] {
    let ots_pk = lmots_compute_pk(seed, identifier, q);
    let mut hasher = Sha256::new();
    hasher.update(identifier);
    hasher.update(q.to_be_bytes());
    hasher.update([0x82]); // D_LEAF domain separator
    hasher.update(&ots_pk);
    let result = hasher.finalize();
    let mut out = [0u8; N];
    out.copy_from_slice(&result);
    out
}

/// Compute internal node of the LMS tree.
fn lms_internal_node(
    identifier: &[u8; 16],
    node_num: u32,
    left: &[u8; N],
    right: &[u8; N],
) -> [u8; N] {
    let mut hasher = Sha256::new();
    hasher.update(identifier);
    hasher.update(node_num.to_be_bytes());
    hasher.update([0x83]); // D_INTR domain separator
    hasher.update(left);
    hasher.update(right);
    let result = hasher.finalize();
    let mut out = [0u8; N];
    out.copy_from_slice(&result);
    out
}

// ── Key Generation ──────────────────────────────────────────────────

/// Generate an LMS key pair.
///
/// This is computationally expensive (builds the full Merkle tree of
/// 2^H leaves). For H=20, this requires computing ~2M hash operations.
///
/// For production use with large H values, consider using a smaller H
/// (e.g., H=10 for 1024 signatures) or use hierarchical key management
/// with HSS (Hierarchical Signature System).
///
/// `tree_height_override` allows using a smaller tree for testing.
/// Pass `None` to use the default LMS_H=20.
pub fn lms_keygen_with_height(tree_height: usize) -> (LmsPrivateKey, LmsPublicKey) {
    let mut seed = [0u8; N];
    getrandom::getrandom(&mut seed).expect("getrandom failed");

    let mut identifier = [0u8; 16];
    getrandom::getrandom(&mut identifier).expect("getrandom failed");

    lms_keygen_from_seed(&seed, &identifier, tree_height)
}

/// Generate an LMS key pair from a seed (deterministic, for testing).
pub fn lms_keygen_from_seed(
    seed: &[u8; N],
    identifier: &[u8; 16],
    tree_height: usize,
) -> (LmsPrivateKey, LmsPublicKey) {
    let leaves = 1usize << tree_height;

    // Build all leaf nodes
    let mut nodes: Vec<[u8; N]> = Vec::with_capacity(2 * leaves);
    // Index 0 unused; nodes[1] will be the root
    nodes.resize(2 * leaves, [0u8; N]);

    // Compute leaves at positions [leaves..2*leaves)
    for i in 0..leaves {
        nodes[leaves + i] = lms_leaf(seed, identifier, i as u32);
    }

    // Build tree bottom-up
    for i in (1..leaves).rev() {
        nodes[i] = lms_internal_node(
            identifier,
            i as u32,
            &nodes[2 * i],
            &nodes[2 * i + 1],
        );
    }

    let root = nodes[1];

    let sk = LmsPrivateKey {
        seed: *seed,
        identifier: *identifier,
        current_index: 0,
    };

    let pk = LmsPublicKey {
        lms_type: LMS_TYPE,
        lmots_type: LMOTS_TYPE,
        identifier: *identifier,
        root,
    };

    (sk, pk)
}

/// Generate an LMS key pair with default height (H=20).
pub fn lms_keygen() -> (LmsPrivateKey, LmsPublicKey) {
    lms_keygen_with_height(LMS_H)
}

// ── Signing ─────────────────────────────────────────────────────────

/// Sign a message with LMS.
///
/// This function:
/// 1. Advances the one-time signature index (persisted via `state`)
/// 2. Computes the LMOTS one-time signature
/// 3. Computes the authentication path
///
/// `tree_height` must match the height used during key generation.
///
/// # Errors
///
/// Returns an error if:
/// - All one-time keys have been exhausted
/// - State persistence fails
pub fn lms_sign(
    sk: &mut LmsPrivateKey,
    message: &[u8],
    state: &dyn LmsStatePersistence,
    tree_height: usize,
) -> Result<LmsSignature, String> {
    let max_sigs = 1u64 << tree_height;

    // Load persisted index (may be ahead of in-memory index after restart)
    if let Some(persisted_idx) = state.load_index()? {
        if persisted_idx > sk.current_index {
            sk.current_index = persisted_idx;
        }
    }

    if sk.current_index >= max_sigs {
        return Err(format!(
            "LMS key exhausted: all {} one-time signatures have been used",
            max_sigs
        ));
    }

    let q = sk.current_index as u32;

    // Advance and persist index BEFORE signing (crash-safe)
    let next_index = sk.current_index + 1;
    state.save_index(next_index)?;
    sk.current_index = next_index;

    // Hash the message
    let mut hasher = Sha256::new();
    hasher.update(&sk.identifier);
    hasher.update(q.to_be_bytes());
    hasher.update([0x80]); // D_MESG domain separator
    hasher.update(message);
    let msg_hash_full = hasher.finalize();
    let mut msg_hash = [0u8; N];
    msg_hash.copy_from_slice(&msg_hash_full);

    // Generate randomizer C
    let mut c = [0u8; N];
    getrandom::getrandom(&mut c).expect("getrandom failed");

    // Compute LMOTS signature: hash message with C to get the checksum input
    let mut q_hash = Sha256::new();
    q_hash.update(&sk.identifier);
    q_hash.update(q.to_be_bytes());
    q_hash.update([0x81]); // D_ITER for LMOTS
    q_hash.update(&c);
    q_hash.update(&msg_hash);
    let q_digest = q_hash.finalize();
    let mut hash_input = [0u8; N];
    hash_input.copy_from_slice(&q_digest);

    let coeffs = to_base_w(&hash_input, WOTS_LEN1);

    // Compute checksum
    let mut csum: u32 = 0;
    for &v in &coeffs {
        csum += (WOTS_W as u32 - 1) - v;
    }
    csum <<= 4;
    let csum_bytes = csum.to_be_bytes();
    let csum_coeffs = to_base_w(&csum_bytes, WOTS_LEN2);

    // Build LMOTS signature
    let mut lmots_sig = Vec::with_capacity(4 + N + WOTS_LEN * N);
    lmots_sig.extend_from_slice(&LMOTS_TYPE.to_be_bytes());
    lmots_sig.extend_from_slice(&c);

    for i in 0..WOTS_LEN {
        let sk_i = wots_secret(&sk.seed, &sk.identifier, q, i as u16);
        let steps = if i < WOTS_LEN1 {
            coeffs[i]
        } else {
            csum_coeffs[i - WOTS_LEN1]
        };
        let y = wots_chain(&sk.identifier, q, i as u16, &sk_i, 0, steps);
        lmots_sig.extend_from_slice(&y);
    }

    // Compute authentication path
    let leaves = 1usize << tree_height;
    let mut tree_nodes: Vec<[u8; N]> = vec![[0u8; N]; 2 * leaves];

    for i in 0..leaves {
        tree_nodes[leaves + i] = lms_leaf(&sk.seed, &sk.identifier, i as u32);
    }
    for i in (1..leaves).rev() {
        tree_nodes[i] = lms_internal_node(
            &sk.identifier,
            i as u32,
            &tree_nodes[2 * i],
            &tree_nodes[2 * i + 1],
        );
    }

    let mut auth_path = Vec::with_capacity(tree_height * N);
    let mut node_idx = leaves + q as usize;
    for _ in 0..tree_height {
        let sibling = node_idx ^ 1;
        auth_path.extend_from_slice(&tree_nodes[sibling]);
        node_idx /= 2;
    }

    Ok(LmsSignature {
        q,
        lmots_sig,
        auth_path,
    })
}

// ── Verification ────────────────────────────────────────────────────

/// Verify an LMS signature.
///
/// This is a stateless operation that only requires the public key.
pub fn lms_verify(
    pk: &LmsPublicKey,
    message: &[u8],
    signature: &LmsSignature,
    tree_height: usize,
) -> bool {
    let q = signature.q;
    let max_q = 1u32 << tree_height;
    if q >= max_q {
        return false;
    }

    // Validate LMOTS signature length
    let expected_lmots_len = 4 + N + WOTS_LEN * N;
    if signature.lmots_sig.len() < expected_lmots_len {
        return false;
    }

    // Extract C from LMOTS signature
    let mut c = [0u8; N];
    c.copy_from_slice(&signature.lmots_sig[4..4 + N]);

    // Hash the message
    let mut hasher = Sha256::new();
    hasher.update(&pk.identifier);
    hasher.update(q.to_be_bytes());
    hasher.update([0x80]); // D_MESG
    hasher.update(message);
    let msg_hash_full = hasher.finalize();
    let mut msg_hash = [0u8; N];
    msg_hash.copy_from_slice(&msg_hash_full);

    // Re-hash with C
    let mut q_hash = Sha256::new();
    q_hash.update(&pk.identifier);
    q_hash.update(q.to_be_bytes());
    q_hash.update([0x81]); // D_ITER
    q_hash.update(&c);
    q_hash.update(&msg_hash);
    let q_digest = q_hash.finalize();
    let mut hash_input = [0u8; N];
    hash_input.copy_from_slice(&q_digest);

    let coeffs = to_base_w(&hash_input, WOTS_LEN1);

    let mut csum: u32 = 0;
    for &v in &coeffs {
        csum += (WOTS_W as u32 - 1) - v;
    }
    csum <<= 4;
    let csum_bytes = csum.to_be_bytes();
    let csum_coeffs = to_base_w(&csum_bytes, WOTS_LEN2);

    // Compute LMOTS public key candidate
    let y_start = 4 + N;
    let mut chain_outputs = Vec::with_capacity(WOTS_LEN * N);
    for i in 0..WOTS_LEN {
        let offset = y_start + i * N;
        let mut y = [0u8; N];
        y.copy_from_slice(&signature.lmots_sig[offset..offset + N]);
        let steps = if i < WOTS_LEN1 {
            coeffs[i]
        } else {
            csum_coeffs[i - WOTS_LEN1]
        };
        let remaining = (WOTS_W as u32 - 1) - steps;
        let pk_i = wots_chain(&pk.identifier, q, i as u16, &y, steps, remaining);
        chain_outputs.extend_from_slice(&pk_i);
    }

    let mut pk_hasher = Sha256::new();
    pk_hasher.update(&pk.identifier);
    pk_hasher.update(q.to_be_bytes());
    pk_hasher.update([0xD8]); // D_PBLC
    pk_hasher.update(&chain_outputs);
    let ots_pk_hash = pk_hasher.finalize();
    let mut ots_pk = [0u8; N];
    ots_pk.copy_from_slice(&ots_pk_hash);

    // Compute leaf from LMOTS public key
    let mut leaf_hasher = Sha256::new();
    leaf_hasher.update(&pk.identifier);
    leaf_hasher.update(q.to_be_bytes());
    leaf_hasher.update([0x82]); // D_LEAF
    leaf_hasher.update(&ots_pk);
    let leaf_hash = leaf_hasher.finalize();
    let mut node = [0u8; N];
    node.copy_from_slice(&leaf_hash);

    // Walk up the authentication path
    let leaves = 1usize << tree_height;
    let mut node_idx = leaves + q as usize;

    if signature.auth_path.len() < tree_height * N {
        return false;
    }

    for height in 0..tree_height {
        let auth_offset = height * N;
        let mut sibling = [0u8; N];
        sibling.copy_from_slice(&signature.auth_path[auth_offset..auth_offset + N]);

        let parent_idx = node_idx / 2;
        if node_idx % 2 == 0 {
            node = lms_internal_node(&pk.identifier, parent_idx as u32, &node, &sibling);
        } else {
            node = lms_internal_node(&pk.identifier, parent_idx as u32, &sibling, &node);
        }
        node_idx = parent_idx;
    }

    // The computed root should match PK.root
    node == pk.root
}

// ── Convenience: remaining signatures ───────────────────────────────

/// Returns the number of remaining one-time signatures for this key.
pub fn remaining_signatures(sk: &LmsPrivateKey, tree_height: usize) -> u64 {
    let max = 1u64 << tree_height;
    max.saturating_sub(sk.current_index)
}

/// Returns the current signature index.
pub fn current_index(sk: &LmsPrivateKey) -> u64 {
    sk.current_index
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Use a small tree height for fast tests.
    const TEST_H: usize = 4; // 16 signatures

    #[test]
    fn test_keygen_deterministic() {
        let seed = [0x42u8; N];
        let id = [0x01u8; 16];
        let (sk1, pk1) = lms_keygen_from_seed(&seed, &id, TEST_H);
        let (sk2, pk2) = lms_keygen_from_seed(&seed, &id, TEST_H);
        assert_eq!(pk1, pk2);
        assert_eq!(sk1.seed, sk2.seed);
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let seed = [0x55u8; N];
        let id = [0x02u8; 16];
        let (mut sk, pk) = lms_keygen_from_seed(&seed, &id, TEST_H);
        let state = InMemoryPersistence::new();

        let message = b"test firmware image v1.0.0";
        let sig = lms_sign(&mut sk, message, &state, TEST_H).expect("sign should succeed");

        assert!(
            lms_verify(&pk, message, &sig, TEST_H),
            "LMS signature should verify"
        );
    }

    #[test]
    fn test_wrong_message_rejected() {
        let seed = [0x66u8; N];
        let id = [0x03u8; 16];
        let (mut sk, pk) = lms_keygen_from_seed(&seed, &id, TEST_H);
        let state = InMemoryPersistence::new();

        let sig = lms_sign(&mut sk, b"original", &state, TEST_H).expect("sign");
        assert!(!lms_verify(&pk, b"tampered", &sig, TEST_H));
    }

    #[test]
    fn test_wrong_key_rejected() {
        let seed1 = [0x77u8; N];
        let seed2 = [0x88u8; N];
        let id1 = [0x04u8; 16];
        let id2 = [0x05u8; 16];
        let (mut sk1, _pk1) = lms_keygen_from_seed(&seed1, &id1, TEST_H);
        let (_sk2, pk2) = lms_keygen_from_seed(&seed2, &id2, TEST_H);
        let state = InMemoryPersistence::new();

        let sig = lms_sign(&mut sk1, b"test", &state, TEST_H).expect("sign");
        assert!(!lms_verify(&pk2, b"test", &sig, TEST_H));
    }

    #[test]
    fn test_index_advances() {
        let seed = [0x99u8; N];
        let id = [0x06u8; 16];
        let (mut sk, pk) = lms_keygen_from_seed(&seed, &id, TEST_H);
        let state = InMemoryPersistence::new();

        for i in 0..4 {
            let msg = format!("message {}", i);
            let sig =
                lms_sign(&mut sk, msg.as_bytes(), &state, TEST_H).expect("sign should succeed");
            assert!(lms_verify(&pk, msg.as_bytes(), &sig, TEST_H));
            assert_eq!(current_index(&sk), (i + 1) as u64);
        }

        assert_eq!(remaining_signatures(&sk, TEST_H), (1 << TEST_H) - 4);
    }

    #[test]
    fn test_key_exhaustion() {
        let seed = [0xAAu8; N];
        let id = [0x07u8; 16];
        // Use height=2 for only 4 signatures
        let h = 2;
        let (mut sk, _pk) = lms_keygen_from_seed(&seed, &id, h);
        let state = InMemoryPersistence::new();

        for i in 0..4 {
            let msg = format!("msg {}", i);
            lms_sign(&mut sk, msg.as_bytes(), &state, h).expect("should succeed");
        }

        let result = lms_sign(&mut sk, b"one too many", &state, h);
        assert!(result.is_err(), "should fail when key exhausted");
        assert!(result.unwrap_err().contains("exhausted"));
    }

    #[test]
    fn test_public_key_serialization() {
        let seed = [0xBBu8; N];
        let id = [0x08u8; 16];
        let (_sk, pk) = lms_keygen_from_seed(&seed, &id, TEST_H);

        let bytes = pk.to_bytes();
        let pk2 = LmsPublicKey::from_bytes(&bytes).expect("deserialize");
        assert_eq!(pk, pk2);
    }

    #[test]
    fn test_multiple_signatures_all_verify() {
        let seed = [0xCCu8; N];
        let id = [0x09u8; 16];
        let (mut sk, pk) = lms_keygen_from_seed(&seed, &id, TEST_H);
        let state = InMemoryPersistence::new();

        let mut sigs = Vec::new();
        let mut msgs = Vec::new();

        for i in 0..8 {
            let msg = format!("firmware release v{}.0", i);
            let sig =
                lms_sign(&mut sk, msg.as_bytes(), &state, TEST_H).expect("sign");
            sigs.push(sig);
            msgs.push(msg);
        }

        // All signatures should verify
        for (sig, msg) in sigs.iter().zip(msgs.iter()) {
            assert!(
                lms_verify(&pk, msg.as_bytes(), sig, TEST_H),
                "signature for '{}' should verify",
                msg
            );
        }
    }

    #[test]
    fn test_remaining_signatures() {
        let seed = [0xDDu8; N];
        let id = [0x0Au8; 16];
        let (sk, _pk) = lms_keygen_from_seed(&seed, &id, TEST_H);
        assert_eq!(remaining_signatures(&sk, TEST_H), 1 << TEST_H);
    }
}
