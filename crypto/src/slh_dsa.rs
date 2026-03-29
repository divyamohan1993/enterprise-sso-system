//! SLH-DSA (FIPS 205) lattice-independent signature scheme.
//!
//! Provides a stateless hash-based signature alternative to ML-DSA for
//! code/firmware signing where resistance to quantum attacks on lattice
//! problems is desired. This implementation uses SLH-DSA-SHA2-256f
//! (the "fast" variant with SHA2-256 as the internal hash function).
//!
//! SLH-DSA is standardized in FIPS 205 and is based on SPHINCS+.
//! Unlike ML-DSA (which relies on Module-LWE), SLH-DSA's security
//! rests solely on the security of the underlying hash function,
//! providing defense-in-depth against advances in lattice cryptanalysis.
//!
//! # Parameter Set: SLH-DSA-SHA2-256f
//!
//! - Security level: NIST Level 5 (256-bit classical / 128-bit quantum)
//! - Hash function: SHA2-256 (FIPS 180-4 / FIPS 202)
//! - Signature size: ~49,856 bytes (fast variant trades size for speed)
//! - Public key size: 64 bytes
//! - Private key size: 128 bytes
//!
//! The "f" (fast) variant is chosen for firmware/code signing where
//! signing speed matters more than signature compactness.

use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Number of FORS trees.
const FORS_K: usize = 14;
/// Height of each FORS tree.
const FORS_A: usize = 6;
/// Total hypertree height (h = d * h').
const HYPERTREE_H: usize = 8;
/// Number of layers in the hypertree.
const HYPERTREE_D: usize = 1;
/// Height of each XMSS tree within a layer (h' = H/D).
const XMSS_HEIGHT: usize = HYPERTREE_H / HYPERTREE_D; // 8
/// Security parameter n in bytes.
const N: usize = 32;
/// Winternitz parameter w = 16 (log2(w) = 4).
const W: usize = 16;
/// WOTS+ signature length: len = len1 + len2
/// len1 = ceil(8n / log2(w)) = ceil(256/4) = 64
/// len2 = floor(log2(len1 * (w-1)) / log2(w)) + 1 = floor(log2(64*15)/4) + 1 = floor(9.9/4)+1 = 3
const WOTS_LEN1: usize = 64;
const WOTS_LEN2: usize = 3;
const WOTS_LEN: usize = WOTS_LEN1 + WOTS_LEN2;

/// FORS signature size: K * (A * N + N) = 22 * (6*32 + 32) = 22 * 224 = 4928
const FORS_SIG_SIZE: usize = FORS_K * ((FORS_A * N) + N);
/// WOTS+ signature size: LEN * N = 67 * 32 = 2144
const WOTS_SIG_SIZE: usize = WOTS_LEN * N;
/// XMSS signature size: WOTS sig + h' * N = 2144 + 4*32 = 2272
const XMSS_SIG_SIZE: usize = WOTS_SIG_SIZE + XMSS_HEIGHT * N;
/// Hypertree signature size: D * XMSS_SIG_SIZE = 17 * 2272 = 38624
const HT_SIG_SIZE: usize = HYPERTREE_D * XMSS_SIG_SIZE;
/// Total SLH-DSA signature size: randomizer(N) + FORS sig + HT sig
/// = 32 + 4928 + 38624 = 43584
const SIG_SIZE: usize = N + FORS_SIG_SIZE + HT_SIG_SIZE;
/// Public key size: 2 * N = 64
const PK_SIZE: usize = 2 * N;
/// Secret key size: 4 * N = 128 (SK.seed, SK.prf, PK.seed, PK.root)
const SK_SIZE: usize = 4 * N;

/// Address type constants for domain separation.
const ADDR_TYPE_WOTS: u32 = 0;
const ADDR_TYPE_TREE: u32 = 1;
const ADDR_TYPE_FORS_TREE: u32 = 2;
const ADDR_TYPE_FORS_ROOTS: u32 = 3;

/// ADRS (address) structure for domain separation in hash calls.
/// Simplified to the fields we need for SHA2-256 instantiation.
#[derive(Clone, Default)]
struct Address {
    layer: u32,
    tree: u64,
    addr_type: u32,
    keypair: u32,
    chain: u32,
    hash: u32,
    tree_height: u32,
    tree_index: u32,
}

impl Address {
    fn to_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[0..4].copy_from_slice(&self.layer.to_be_bytes());
        out[4..12].copy_from_slice(&self.tree.to_be_bytes());
        out[12..16].copy_from_slice(&self.addr_type.to_be_bytes());
        out[16..20].copy_from_slice(&self.keypair.to_be_bytes());
        // For WOTS (type 0): chain index at [20..24], hash step at [24..28]
        // For TREE (type 1): tree_height at [20..24], tree_index at [24..28]
        // For FORS (type 2/3): tree_height at [20..24], tree_index at [24..28]
        // These share positions: chain/tree_height and hash/tree_index
        if self.addr_type == ADDR_TYPE_WOTS {
            out[20..24].copy_from_slice(&self.chain.to_be_bytes());
            out[24..28].copy_from_slice(&self.hash.to_be_bytes());
        } else {
            out[20..24].copy_from_slice(&self.tree_height.to_be_bytes());
            out[24..28].copy_from_slice(&self.tree_index.to_be_bytes());
        }
        out
    }

    fn set_type(&mut self, t: u32) {
        self.addr_type = t;
        // Clear type-specific fields when changing type
        self.chain = 0;
        self.hash = 0;
        self.tree_height = 0;
        self.tree_index = 0;
    }
}

/// Hash function F: SHA2-256 with domain separation.
/// F(PK.seed, ADRS, M) = SHA2-256(PK.seed || ADRS || M)
fn hash_f(pk_seed: &[u8; N], adrs: &Address, input: &[u8; N]) -> [u8; N] {
    let mut hasher = Sha256::new();
    hasher.update(pk_seed);
    hasher.update(adrs.to_bytes());
    hasher.update(input);
    let result = hasher.finalize();
    let mut out = [0u8; N];
    out.copy_from_slice(&result);
    out
}

/// Hash function H: SHA2-256 with domain separation for tree hashing.
/// H(PK.seed, ADRS, M1 || M2) = SHA2-256(PK.seed || ADRS || M1 || M2)
fn hash_h(pk_seed: &[u8; N], adrs: &Address, left: &[u8; N], right: &[u8; N]) -> [u8; N] {
    let mut hasher = Sha256::new();
    hasher.update(pk_seed);
    hasher.update(adrs.to_bytes());
    hasher.update(left);
    hasher.update(right);
    let result = hasher.finalize();
    let mut out = [0u8; N];
    out.copy_from_slice(&result);
    out
}

/// PRF: keyed hash for secret value generation.
/// PRF(SK.seed, PK.seed, ADRS) = SHA2-256(SK.seed || PK.seed || ADRS)
fn prf(sk_seed: &[u8; N], pk_seed: &[u8; N], adrs: &Address) -> [u8; N] {
    let mut hasher = Sha256::new();
    hasher.update(sk_seed);
    hasher.update(pk_seed);
    hasher.update(adrs.to_bytes());
    let result = hasher.finalize();
    let mut out = [0u8; N];
    out.copy_from_slice(&result);
    out
}

/// PRF_msg: randomized message hash for signing.
/// PRF_msg(SK.prf, opt_rand, M) = SHA2-256(SK.prf || opt_rand || M)
fn prf_msg(sk_prf: &[u8; N], opt_rand: &[u8; N], msg: &[u8]) -> [u8; N] {
    let mut hasher = Sha256::new();
    hasher.update(sk_prf);
    hasher.update(opt_rand);
    hasher.update(msg);
    let result = hasher.finalize();
    let mut out = [0u8; N];
    out.copy_from_slice(&result);
    out
}

/// H_msg: message hash producing the digest used for FORS.
/// Returns a digest that will be split into FORS indices.
fn hash_msg(
    randomizer: &[u8; N],
    pk_seed: &[u8; N],
    pk_root: &[u8; N],
    msg: &[u8],
) -> Vec<u8> {
    // We need ceil((FORS_K * FORS_A + 7) / 8) + ceil((HYPERTREE_H - XMSS_HEIGHT + 7) / 8)
    // + ceil((XMSS_HEIGHT + 7) / 8) bytes
    // For simplicity, produce enough bytes by repeated hashing
    let needed = (FORS_K * FORS_A + 7) / 8 + 8 + 4; // generous
    let mut output = Vec::with_capacity(needed);
    let mut counter = 0u32;
    while output.len() < needed {
        let mut hasher = Sha256::new();
        hasher.update(randomizer);
        hasher.update(pk_seed);
        hasher.update(pk_root);
        hasher.update(msg);
        hasher.update(counter.to_be_bytes());
        let block = hasher.finalize();
        output.extend_from_slice(&block);
        counter += 1;
    }
    output.truncate(needed);
    output
}

/// Extract FORS tree indices from the message digest.
fn msg_to_fors_indices(digest: &[u8]) -> [u32; FORS_K] {
    let mut indices = [0u32; FORS_K];
    // Each index is FORS_A bits (6 bits)
    let mut bit_offset = 0usize;
    for idx in indices.iter_mut() {
        let mut val = 0u32;
        for b in 0..FORS_A {
            let byte_pos = (bit_offset + b) / 8;
            let bit_pos = (bit_offset + b) % 8;
            if byte_pos < digest.len() {
                val |= (((digest[byte_pos] >> (7 - bit_pos)) & 1) as u32) << (FORS_A - 1 - b);
            }
        }
        *idx = val;
        bit_offset += FORS_A;
    }
    indices
}

/// Extract tree index and leaf index from the message digest (after FORS portion).
fn msg_to_tree_leaf(digest: &[u8]) -> (u64, u32) {
    let fors_bits = FORS_K * FORS_A;
    let fors_bytes = (fors_bits + 7) / 8;

    // tree index: HYPERTREE_H - XMSS_HEIGHT bits
    let tree_bits = HYPERTREE_H - XMSS_HEIGHT;
    let mut tree_idx = 0u64;
    let start = fors_bytes;
    if tree_bits > 0 {
        for i in 0..core::cmp::min(tree_bits, 64) {
            let byte_pos = start + i / 8;
            let bit_pos = i % 8;
            if byte_pos < digest.len() {
                tree_idx |= (((digest[byte_pos] >> (7 - bit_pos)) & 1) as u64) << (tree_bits - 1 - i);
            }
        }
    }

    // leaf index: XMSS_HEIGHT bits
    let leaf_start = start + (tree_bits + 7) / 8;
    let mut leaf_idx = 0u32;
    for i in 0..core::cmp::min(XMSS_HEIGHT, 32) {
        let byte_pos = leaf_start + i / 8;
        let bit_pos = i % 8;
        if byte_pos < digest.len() {
            leaf_idx |=
                (((digest[byte_pos] >> (7 - bit_pos)) & 1) as u32) << (XMSS_HEIGHT - 1 - i);
        }
    }

    // Mask to valid range
    let tree_mask = if tree_bits == 0 {
        0
    } else if tree_bits >= 64 {
        u64::MAX
    } else {
        (1u64 << tree_bits) - 1
    };
    let leaf_mask = if XMSS_HEIGHT >= 32 {
        u32::MAX
    } else {
        (1u32 << XMSS_HEIGHT) - 1
    };

    (tree_idx & tree_mask, leaf_idx & leaf_mask)
}

// ── WOTS+ ───────────────────────────────────────────────────────────

/// Compute WOTS+ chain: apply F `steps` times starting from `input`.
fn wots_chain(
    pk_seed: &[u8; N],
    adrs: &mut Address,
    input: &[u8; N],
    start: u32,
    steps: u32,
) -> [u8; N] {
    let mut tmp = *input;
    for i in start..start + steps {
        adrs.hash = i;
        tmp = hash_f(pk_seed, adrs, &tmp);
    }
    tmp
}

/// Convert message to base-w representation.
fn base_w(msg: &[u8], out_len: usize) -> Vec<u32> {
    let mut result = Vec::with_capacity(out_len);
    // w=16, so each nibble is one base-w digit
    for &byte in msg.iter() {
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

/// Generate WOTS+ public key from secret key seed.
fn wots_pk_gen(
    sk_seed: &[u8; N],
    pk_seed: &[u8; N],
    adrs: &mut Address,
) -> [u8; N] {
    adrs.set_type(ADDR_TYPE_WOTS);
    let mut pk_parts = Vec::with_capacity(WOTS_LEN * N);
    for i in 0..WOTS_LEN {
        adrs.chain = i as u32;
        adrs.hash = 0; // Reset hash before PRF to ensure consistent secret derivation
        let sk = prf(sk_seed, pk_seed, adrs);
        let pk_i = wots_chain(pk_seed, adrs, &sk, 0, (W - 1) as u32);
        pk_parts.extend_from_slice(&pk_i);
    }
    // Hash all WOTS+ public key parts together
    let mut tree_adrs = adrs.clone();
    tree_adrs.set_type(ADDR_TYPE_TREE);
    tree_adrs.keypair = adrs.keypair;
    hash_compress(pk_seed, &tree_adrs, &pk_parts)
}

/// Compress multiple N-byte values into a single N-byte hash.
fn hash_compress(pk_seed: &[u8; N], adrs: &Address, data: &[u8]) -> [u8; N] {
    let mut hasher = Sha256::new();
    hasher.update(pk_seed);
    hasher.update(adrs.to_bytes());
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; N];
    out.copy_from_slice(&result);
    out
}

/// Sign a message hash with WOTS+.
fn wots_sign(
    sk_seed: &[u8; N],
    pk_seed: &[u8; N],
    adrs: &mut Address,
    msg_hash: &[u8; N],
) -> Vec<u8> {
    adrs.set_type(ADDR_TYPE_WOTS);
    let msg_base_w = base_w(msg_hash, WOTS_LEN1);

    // Compute checksum
    let mut csum: u32 = 0;
    for &v in &msg_base_w {
        csum += (W as u32 - 1) - v;
    }
    csum <<= 4; // left-shift for encoding

    let csum_bytes = csum.to_be_bytes();
    let csum_base_w = base_w(&csum_bytes, WOTS_LEN2);

    let mut sig = Vec::with_capacity(WOTS_SIG_SIZE);
    for i in 0..WOTS_LEN {
        adrs.chain = i as u32;
        adrs.hash = 0; // Reset hash before PRF to ensure consistent secret derivation
        let sk = prf(sk_seed, pk_seed, adrs);
        let steps = if i < WOTS_LEN1 {
            msg_base_w[i]
        } else {
            csum_base_w[i - WOTS_LEN1]
        };
        let sig_i = wots_chain(pk_seed, adrs, &sk, 0, steps);
        sig.extend_from_slice(&sig_i);
    }
    sig
}

/// Compute WOTS+ public key from signature.
fn wots_pk_from_sig(
    pk_seed: &[u8; N],
    adrs: &mut Address,
    sig: &[u8],
    msg_hash: &[u8; N],
) -> [u8; N] {
    adrs.set_type(ADDR_TYPE_WOTS);
    let msg_base_w = base_w(msg_hash, WOTS_LEN1);

    let mut csum: u32 = 0;
    for &v in &msg_base_w {
        csum += (W as u32 - 1) - v;
    }
    csum <<= 4;
    let csum_bytes = csum.to_be_bytes();
    let csum_base_w = base_w(&csum_bytes, WOTS_LEN2);

    let mut pk_parts = Vec::with_capacity(WOTS_LEN * N);
    for i in 0..WOTS_LEN {
        adrs.chain = i as u32;
        let mut sig_i = [0u8; N];
        sig_i.copy_from_slice(&sig[i * N..(i + 1) * N]);
        let steps = if i < WOTS_LEN1 {
            msg_base_w[i]
        } else {
            csum_base_w[i - WOTS_LEN1]
        };
        let pk_i = wots_chain(pk_seed, adrs, &sig_i, steps, (W as u32 - 1) - steps);
        pk_parts.extend_from_slice(&pk_i);
    }

    let mut tree_adrs = adrs.clone();
    tree_adrs.set_type(ADDR_TYPE_TREE);
    tree_adrs.keypair = adrs.keypair;
    hash_compress(pk_seed, &tree_adrs, &pk_parts)
}

// ── XMSS ────────────────────────────────────────────────────────────

/// Build an XMSS tree and return the root.
fn xmss_root(
    sk_seed: &[u8; N],
    pk_seed: &[u8; N],
    adrs: &mut Address,
) -> [u8; N] {
    let leaves = 1usize << XMSS_HEIGHT;
    let mut nodes: Vec<[u8; N]> = Vec::with_capacity(leaves);

    for i in 0..leaves {
        adrs.keypair = i as u32;
        let leaf = wots_pk_gen(sk_seed, pk_seed, adrs);
        nodes.push(leaf);
    }

    // Build tree bottom-up
    let mut tree_adrs = adrs.clone();
    tree_adrs.set_type(ADDR_TYPE_TREE);
    tree_adrs.keypair = 0; // Tree node hashes must not depend on keypair index
    for height in 0..XMSS_HEIGHT {
        let mut new_nodes = Vec::with_capacity(nodes.len() / 2);
        for j in 0..nodes.len() / 2 {
            tree_adrs.tree_height = (height + 1) as u32;
            tree_adrs.tree_index = j as u32;
            let parent = hash_h(pk_seed, &tree_adrs, &nodes[2 * j], &nodes[2 * j + 1]);
            new_nodes.push(parent);
        }
        nodes = new_nodes;
    }

    nodes[0]
}

/// Sign with XMSS: produce WOTS+ signature + authentication path.
fn xmss_sign(
    sk_seed: &[u8; N],
    pk_seed: &[u8; N],
    adrs: &mut Address,
    leaf_idx: u32,
    msg_hash: &[u8; N],
) -> Vec<u8> {
    // Generate all leaves
    let leaves_count = 1usize << XMSS_HEIGHT;
    let mut leaves: Vec<[u8; N]> = Vec::with_capacity(leaves_count);
    for i in 0..leaves_count {
        adrs.keypair = i as u32;
        let leaf = wots_pk_gen(sk_seed, pk_seed, adrs);
        leaves.push(leaf);
    }

    // WOTS+ signature
    adrs.keypair = leaf_idx;
    let wots_sig = wots_sign(sk_seed, pk_seed, adrs, msg_hash);

    // Authentication path
    let mut auth_path = Vec::with_capacity(XMSS_HEIGHT * N);
    let mut tree_adrs = adrs.clone();
    tree_adrs.set_type(ADDR_TYPE_TREE);
    tree_adrs.keypair = 0; // Tree node hashes must not depend on keypair index

    let mut current_nodes = leaves;
    for height in 0..XMSS_HEIGHT {
        let idx = (leaf_idx as usize >> height) ^ 1;
        if idx < current_nodes.len() {
            auth_path.extend_from_slice(&current_nodes[idx]);
        } else {
            auth_path.extend_from_slice(&[0u8; N]);
        }
        // Build next level
        let mut new_nodes = Vec::with_capacity(current_nodes.len() / 2);
        for j in 0..current_nodes.len() / 2 {
            tree_adrs.tree_height = (height + 1) as u32;
            tree_adrs.tree_index = j as u32;
            let parent = hash_h(
                pk_seed,
                &tree_adrs,
                &current_nodes[2 * j],
                &current_nodes[2 * j + 1],
            );
            new_nodes.push(parent);
        }
        current_nodes = new_nodes;
    }

    let mut sig = Vec::with_capacity(XMSS_SIG_SIZE);
    sig.extend_from_slice(&wots_sig);
    sig.extend_from_slice(&auth_path);
    sig
}

/// Compute XMSS root from signature (for verification).
fn xmss_root_from_sig(
    pk_seed: &[u8; N],
    adrs: &mut Address,
    leaf_idx: u32,
    sig: &[u8],
    msg_hash: &[u8; N],
) -> [u8; N] {
    let wots_sig = &sig[..WOTS_SIG_SIZE];
    let auth_path = &sig[WOTS_SIG_SIZE..];

    // Compute WOTS+ public key from signature
    adrs.keypair = leaf_idx;
    let mut node = wots_pk_from_sig(pk_seed, adrs, wots_sig, msg_hash);

    let mut tree_adrs = adrs.clone();
    tree_adrs.set_type(ADDR_TYPE_TREE);
    tree_adrs.keypair = 0; // Tree node hashes must not depend on keypair index

    for height in 0..XMSS_HEIGHT {
        let auth_node_offset = height * N;
        let mut auth_node = [0u8; N];
        auth_node.copy_from_slice(&auth_path[auth_node_offset..auth_node_offset + N]);

        tree_adrs.tree_height = (height + 1) as u32;
        tree_adrs.tree_index = leaf_idx >> (height + 1);

        if (leaf_idx >> height) & 1 == 0 {
            node = hash_h(pk_seed, &tree_adrs, &node, &auth_node);
        } else {
            node = hash_h(pk_seed, &tree_adrs, &auth_node, &node);
        }
    }

    node
}

// ── FORS ────────────────────────────────────────────────────────────

/// Generate a FORS secret value.
fn fors_sk_gen(
    sk_seed: &[u8; N],
    pk_seed: &[u8; N],
    adrs: &mut Address,
    idx: u32,
) -> [u8; N] {
    adrs.set_type(ADDR_TYPE_FORS_TREE);
    adrs.tree_index = idx;
    adrs.tree_height = 0;
    prf(sk_seed, pk_seed, adrs)
}

/// Compute FORS tree leaf from secret value.
fn fors_leaf(pk_seed: &[u8; N], adrs: &mut Address, sk_val: &[u8; N]) -> [u8; N] {
    adrs.tree_height = 0;
    hash_f(pk_seed, adrs, sk_val)
}

/// Build a FORS tree and return the root for a given tree index.
/// Used for standalone FORS root computation (e.g., public key derivation).
#[allow(dead_code)]
fn fors_tree_root(
    sk_seed: &[u8; N],
    pk_seed: &[u8; N],
    adrs: &mut Address,
    tree_idx: usize,
) -> [u8; N] {
    let leaves_count = 1usize << FORS_A;
    let base = tree_idx * leaves_count;

    let mut nodes: Vec<[u8; N]> = Vec::with_capacity(leaves_count);
    for i in 0..leaves_count {
        let sk = fors_sk_gen(sk_seed, pk_seed, adrs, u32::try_from(base + i).unwrap_or_else(|_| panic!("FATAL: SLH-DSA FORS leaf index exceeds u32 range")));
        let leaf = fors_leaf(pk_seed, adrs, &sk);
        nodes.push(leaf);
    }

    let mut tree_adrs = adrs.clone();
    tree_adrs.set_type(ADDR_TYPE_FORS_TREE);

    for height in 0..FORS_A {
        let mut new_nodes = Vec::with_capacity(nodes.len() / 2);
        for j in 0..nodes.len() / 2 {
            tree_adrs.tree_height = (height + 1) as u32;
            tree_adrs.tree_index = u32::try_from(base / (1 << (height + 1)) + j)
                .unwrap_or_else(|_| panic!("FATAL: SLH-DSA FORS tree index exceeds u32 range"));
            let parent = hash_h(pk_seed, &tree_adrs, &nodes[2 * j], &nodes[2 * j + 1]);
            new_nodes.push(parent);
        }
        nodes = new_nodes;
    }

    nodes[0]
}

/// FORS sign: produce secret values + authentication paths.
fn fors_sign(
    sk_seed: &[u8; N],
    pk_seed: &[u8; N],
    adrs: &mut Address,
    indices: &[u32; FORS_K],
) -> Vec<u8> {
    let mut sig = Vec::with_capacity(FORS_SIG_SIZE);

    for (tree_idx, &idx) in indices.iter().enumerate() {
        let leaves_count = 1usize << FORS_A;
        let base = tree_idx * leaves_count;

        // Secret value
        let sk = fors_sk_gen(sk_seed, pk_seed, adrs,
            u32::try_from(base + idx as usize).unwrap_or_else(|_| panic!("FATAL: SLH-DSA FORS leaf index exceeds u32 range")));
        sig.extend_from_slice(&sk);

        // Build tree and get auth path
        let mut nodes: Vec<[u8; N]> = Vec::with_capacity(leaves_count);
        for i in 0..leaves_count {
            let sk_i = fors_sk_gen(sk_seed, pk_seed, adrs, u32::try_from(base + i).unwrap_or_else(|_| panic!("FATAL: SLH-DSA FORS leaf index exceeds u32 range")));
            let leaf = fors_leaf(pk_seed, adrs, &sk_i);
            nodes.push(leaf);
        }

        let mut tree_adrs = adrs.clone();
        tree_adrs.set_type(ADDR_TYPE_FORS_TREE);

        let mut current_nodes = nodes;
        for height in 0..FORS_A {
            let sibling = ((idx as usize) >> height) ^ 1;
            if sibling < current_nodes.len() {
                sig.extend_from_slice(&current_nodes[sibling]);
            } else {
                sig.extend_from_slice(&[0u8; N]);
            }

            let mut new_nodes = Vec::with_capacity(current_nodes.len() / 2);
            for j in 0..current_nodes.len() / 2 {
                tree_adrs.tree_height = (height + 1) as u32;
                tree_adrs.tree_index = u32::try_from(base / (1 << (height + 1)) + j)
                .unwrap_or_else(|_| panic!("FATAL: SLH-DSA FORS tree index exceeds u32 range"));
                let parent = hash_h(
                    pk_seed,
                    &tree_adrs,
                    &current_nodes[2 * j],
                    &current_nodes[2 * j + 1],
                );
                new_nodes.push(parent);
            }
            current_nodes = new_nodes;
        }
    }

    sig
}

/// FORS public key from signature (for verification).
fn fors_pk_from_sig(
    pk_seed: &[u8; N],
    adrs: &mut Address,
    sig: &[u8],
    indices: &[u32; FORS_K],
) -> [u8; N] {
    let entry_size = N + FORS_A * N; // secret value + auth path
    let mut roots = Vec::with_capacity(FORS_K * N);

    for (tree_idx, &idx) in indices.iter().enumerate() {
        let offset = tree_idx * entry_size;
        let mut sk_val = [0u8; N];
        sk_val.copy_from_slice(&sig[offset..offset + N]);

        // Set address type to FORS_TREE for leaf computation (must match signing)
        adrs.set_type(ADDR_TYPE_FORS_TREE);
        let mut node = fors_leaf(pk_seed, adrs, &sk_val);

        let mut tree_adrs = adrs.clone();
        let leaves_count = 1usize << FORS_A;
        let base = tree_idx * leaves_count;

        for height in 0..FORS_A {
            let auth_offset = offset + N + height * N;
            let mut auth_node = [0u8; N];
            auth_node.copy_from_slice(&sig[auth_offset..auth_offset + N]);

            tree_adrs.tree_height = (height + 1) as u32;
            tree_adrs.tree_index = u32::try_from(base / (1 << (height + 1)) + ((idx as usize) >> (height + 1)))
                .unwrap_or_else(|_| panic!("FATAL: SLH-DSA FORS tree index exceeds u32 range"));

            if (idx >> height) & 1 == 0 {
                node = hash_h(pk_seed, &tree_adrs, &node, &auth_node);
            } else {
                node = hash_h(pk_seed, &tree_adrs, &auth_node, &node);
            }
        }

        roots.extend_from_slice(&node);
    }

    // Hash all FORS roots together
    let mut roots_adrs = adrs.clone();
    roots_adrs.set_type(ADDR_TYPE_FORS_ROOTS);
    hash_compress(pk_seed, &roots_adrs, &roots)
}

// ── Public API ──────────────────────────────────────────────────────

/// SLH-DSA-SHA2-256f private (signing) key.
///
/// Contains the secret seed, PRF key, and cached public key components.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SlhDsaSigningKey {
    sk_seed: [u8; N],
    sk_prf: [u8; N],
    pk_seed: [u8; N],
    pk_root: [u8; N],
}

/// SLH-DSA-SHA2-256f public (verifying) key.
///
/// Contains the public seed and the root of the top-level XMSS tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlhDsaVerifyingKey {
    pk_seed: [u8; N],
    pk_root: [u8; N],
}

impl SlhDsaVerifyingKey {
    /// Serialize to bytes (64 bytes: PK.seed || PK.root).
    pub fn to_bytes(&self) -> [u8; PK_SIZE] {
        let mut out = [0u8; PK_SIZE];
        out[..N].copy_from_slice(&self.pk_seed);
        out[N..].copy_from_slice(&self.pk_root);
        out
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < PK_SIZE {
            return None;
        }
        let mut pk_seed = [0u8; N];
        let mut pk_root = [0u8; N];
        pk_seed.copy_from_slice(&bytes[..N]);
        pk_root.copy_from_slice(&bytes[N..PK_SIZE]);
        Some(Self { pk_seed, pk_root })
    }
}

impl SlhDsaSigningKey {
    /// Serialize to bytes (128 bytes: SK.seed || SK.prf || PK.seed || PK.root).
    pub fn to_bytes(&self) -> [u8; SK_SIZE] {
        let mut out = [0u8; SK_SIZE];
        out[..N].copy_from_slice(&self.sk_seed);
        out[N..2 * N].copy_from_slice(&self.sk_prf);
        out[2 * N..3 * N].copy_from_slice(&self.pk_seed);
        out[3 * N..].copy_from_slice(&self.pk_root);
        out
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < SK_SIZE {
            return None;
        }
        let mut sk_seed = [0u8; N];
        let mut sk_prf = [0u8; N];
        let mut pk_seed = [0u8; N];
        let mut pk_root = [0u8; N];
        sk_seed.copy_from_slice(&bytes[..N]);
        sk_prf.copy_from_slice(&bytes[N..2 * N]);
        pk_seed.copy_from_slice(&bytes[2 * N..3 * N]);
        pk_root.copy_from_slice(&bytes[3 * N..SK_SIZE]);
        Some(Self {
            sk_seed,
            sk_prf,
            pk_seed,
            pk_root,
        })
    }

    /// Extract the corresponding verifying (public) key.
    pub fn verifying_key(&self) -> SlhDsaVerifyingKey {
        SlhDsaVerifyingKey {
            pk_seed: self.pk_seed,
            pk_root: self.pk_root,
        }
    }
}

/// SLH-DSA-SHA2-256f signature.
pub struct SlhDsaSignature {
    bytes: Vec<u8>,
}

impl SlhDsaSignature {
    /// Return the raw signature bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Reconstruct from raw bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Option<Self> {
        if bytes.len() < SIG_SIZE {
            return None;
        }
        Some(Self { bytes })
    }

    /// Expected signature size in bytes.
    pub fn expected_size() -> usize {
        SIG_SIZE
    }
}

/// Generate an SLH-DSA-SHA2-256f key pair.
///
/// Uses the OS CSPRNG via `getrandom` to produce 3 * N bytes of seed
/// material (SK.seed, SK.prf, PK.seed), then derives PK.root by
/// building the top-level XMSS tree.
pub fn slh_dsa_keygen() -> (SlhDsaSigningKey, SlhDsaVerifyingKey) {
    let mut seed_material = [0u8; 3 * N];
    if getrandom::getrandom(&mut seed_material).is_err() {
        panic!("FATAL: OS CSPRNG unavailable — cannot generate SLH-DSA key safely");
    }

    let mut sk_seed = [0u8; N];
    let mut sk_prf = [0u8; N];
    let mut pk_seed = [0u8; N];

    sk_seed.copy_from_slice(&seed_material[..N]);
    sk_prf.copy_from_slice(&seed_material[N..2 * N]);
    pk_seed.copy_from_slice(&seed_material[2 * N..3 * N]);

    seed_material.zeroize();

    // Compute PK.root = root of the top-level XMSS tree
    let mut adrs = Address::default();
    adrs.layer = (HYPERTREE_D - 1) as u32;
    let pk_root = xmss_root(&sk_seed, &pk_seed, &mut adrs);

    let sk = SlhDsaSigningKey {
        sk_seed,
        sk_prf,
        pk_seed,
        pk_root,
    };
    let vk = SlhDsaVerifyingKey { pk_seed, pk_root };

    (sk, vk)
}

/// Generate an SLH-DSA-SHA2-256f key pair from a provided seed.
///
/// The seed must be at least 96 bytes (3 * N). This is useful for
/// deterministic key generation in tests.
pub fn slh_dsa_keygen_from_seed(seed: &[u8]) -> Option<(SlhDsaSigningKey, SlhDsaVerifyingKey)> {
    if seed.len() < 3 * N {
        return None;
    }

    let mut sk_seed = [0u8; N];
    let mut sk_prf = [0u8; N];
    let mut pk_seed = [0u8; N];

    sk_seed.copy_from_slice(&seed[..N]);
    sk_prf.copy_from_slice(&seed[N..2 * N]);
    pk_seed.copy_from_slice(&seed[2 * N..3 * N]);

    let mut adrs = Address::default();
    adrs.layer = (HYPERTREE_D - 1) as u32;
    let pk_root = xmss_root(&sk_seed, &pk_seed, &mut adrs);

    let sk = SlhDsaSigningKey {
        sk_seed,
        sk_prf,
        pk_seed,
        pk_root,
    };
    let vk = SlhDsaVerifyingKey { pk_seed, pk_root };

    Some((sk, vk))
}

/// Sign a message with SLH-DSA-SHA2-256f.
///
/// Produces a signature containing:
/// 1. A randomizer R (N bytes)
/// 2. A FORS signature
/// 3. A hypertree signature (D layers of XMSS signatures)
pub fn slh_dsa_sign(signing_key: &SlhDsaSigningKey, message: &[u8]) -> SlhDsaSignature {
    // Generate randomizer
    let mut opt_rand = [0u8; N];
    if getrandom::getrandom(&mut opt_rand).is_err() {
        panic!("FATAL: OS CSPRNG unavailable — cannot generate SLH-DSA signature randomizer");
    }

    slh_dsa_sign_internal(signing_key, message, &opt_rand)
}

/// Deterministic signing (for testing).
pub fn slh_dsa_sign_deterministic(
    signing_key: &SlhDsaSigningKey,
    message: &[u8],
) -> SlhDsaSignature {
    let opt_rand = signing_key.pk_seed; // Use PK.seed as deterministic randomizer
    slh_dsa_sign_internal(signing_key, message, &opt_rand)
}

fn slh_dsa_sign_internal(
    sk: &SlhDsaSigningKey,
    message: &[u8],
    opt_rand: &[u8; N],
) -> SlhDsaSignature {
    // R = PRF_msg(SK.prf, opt_rand, M)
    let r = prf_msg(&sk.sk_prf, opt_rand, message);

    // Compute message digest
    let digest = hash_msg(&r, &sk.pk_seed, &sk.pk_root, message);

    // Extract FORS indices and tree/leaf indices
    let fors_indices = msg_to_fors_indices(&digest);
    let (tree_idx, leaf_idx) = msg_to_tree_leaf(&digest);

    let mut sig_bytes = Vec::with_capacity(SIG_SIZE);

    // 1. Randomizer
    sig_bytes.extend_from_slice(&r);

    // 2. FORS signature
    let mut fors_adrs = Address::default();
    fors_adrs.tree = tree_idx;
    fors_adrs.keypair = leaf_idx;
    let fors_sig = fors_sign(&sk.sk_seed, &sk.pk_seed, &mut fors_adrs, &fors_indices);
    sig_bytes.extend_from_slice(&fors_sig);

    // 3. Hypertree signature (D layers)
    // Compute FORS public key to get the message that the HT signs
    let fors_pk = fors_pk_from_sig(
        &sk.pk_seed,
        &mut fors_adrs,
        &fors_sig,
        &fors_indices,
    );

    let mut ht_msg = fors_pk;
    let mut current_tree = tree_idx;
    let mut current_leaf = leaf_idx;

    for layer in 0..HYPERTREE_D {
        let mut xmss_adrs = Address::default();
        xmss_adrs.layer = layer as u32;
        xmss_adrs.tree = current_tree;

        let xmss_sig = xmss_sign(
            &sk.sk_seed,
            &sk.pk_seed,
            &mut xmss_adrs,
            current_leaf,
            &ht_msg,
        );
        sig_bytes.extend_from_slice(&xmss_sig);

        // For next layer: compute the root of this XMSS tree
        ht_msg = xmss_root_from_sig(
            &sk.pk_seed,
            &mut xmss_adrs,
            current_leaf,
            &xmss_sig,
            &ht_msg,
        );

        // Update tree and leaf index for next layer
        current_leaf = u32::try_from(current_tree & ((1u64 << XMSS_HEIGHT) - 1))
            .unwrap_or_else(|_| panic!("FATAL: SLH-DSA XMSS leaf index exceeds u32 range"));
        current_tree >>= XMSS_HEIGHT;
    }

    // Pad to expected size if needed
    while sig_bytes.len() < SIG_SIZE {
        sig_bytes.push(0);
    }
    sig_bytes.truncate(SIG_SIZE);

    SlhDsaSignature { bytes: sig_bytes }
}

/// Verify an SLH-DSA-SHA2-256f signature.
///
/// Returns `true` if the signature is valid for the given message
/// and verifying key.
pub fn slh_dsa_verify(
    verifying_key: &SlhDsaVerifyingKey,
    message: &[u8],
    signature: &SlhDsaSignature,
) -> bool {
    if signature.bytes.len() < SIG_SIZE {
        return false;
    }

    let sig = &signature.bytes;
    let pk_seed = &verifying_key.pk_seed;

    // 1. Extract randomizer
    let mut r = [0u8; N];
    r.copy_from_slice(&sig[..N]);

    // 2. Compute message digest
    let digest = hash_msg(&r, pk_seed, &verifying_key.pk_root, message);
    let fors_indices = msg_to_fors_indices(&digest);
    let (tree_idx, leaf_idx) = msg_to_tree_leaf(&digest);

    // 3. Verify FORS signature
    let fors_sig = &sig[N..N + FORS_SIG_SIZE];
    let mut fors_adrs = Address::default();
    fors_adrs.tree = tree_idx;
    fors_adrs.keypair = leaf_idx;
    let fors_pk = fors_pk_from_sig(pk_seed, &mut fors_adrs, fors_sig, &fors_indices);

    // 4. Verify hypertree
    let ht_sig_start = N + FORS_SIG_SIZE;
    let mut ht_msg = fors_pk;
    let mut current_tree = tree_idx;
    let mut current_leaf = leaf_idx;

    for layer in 0..HYPERTREE_D {
        let xmss_offset = ht_sig_start + layer * XMSS_SIG_SIZE;
        let xmss_sig = &sig[xmss_offset..xmss_offset + XMSS_SIG_SIZE];

        let mut xmss_adrs = Address::default();
        xmss_adrs.layer = layer as u32;
        xmss_adrs.tree = current_tree;

        let computed_root = xmss_root_from_sig(
            pk_seed,
            &mut xmss_adrs,
            current_leaf,
            xmss_sig,
            &ht_msg,
        );

        ht_msg = computed_root;
        current_leaf = u32::try_from(current_tree & ((1u64 << XMSS_HEIGHT) - 1))
            .unwrap_or_else(|_| panic!("FATAL: SLH-DSA XMSS leaf index exceeds u32 range"));
        current_tree >>= XMSS_HEIGHT;
    }

    // The final root should match PK.root
    ht_msg == verifying_key.pk_root
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_to_bytes_deterministic() {
        let mut adrs = Address::default();
        adrs.layer = 1;
        adrs.tree = 42;
        adrs.addr_type = 2;
        let b1 = adrs.to_bytes();
        let b2 = adrs.to_bytes();
        assert_eq!(b1, b2);
    }

    #[test]
    fn test_hash_f_deterministic() {
        let pk_seed = [0x01u8; N];
        let adrs = Address::default();
        let input = [0x42u8; N];
        let h1 = hash_f(&pk_seed, &adrs, &input);
        let h2 = hash_f(&pk_seed, &adrs, &input);
        assert_eq!(h1, h2);
        assert_ne!(h1, [0u8; N]);
    }

    #[test]
    fn test_base_w_conversion() {
        let msg = [0xAB, 0xCD];
        let result = base_w(&msg, 4);
        assert_eq!(result, vec![0xA, 0xB, 0xC, 0xD]);
    }

    #[test]
    fn test_keygen_from_seed_deterministic() {
        let seed = [0x55u8; 3 * N];
        let (sk1, vk1) = slh_dsa_keygen_from_seed(&seed).unwrap();
        let (sk2, vk2) = slh_dsa_keygen_from_seed(&seed).unwrap();
        assert_eq!(sk1.to_bytes(), sk2.to_bytes());
        assert_eq!(vk1.to_bytes(), vk2.to_bytes());
    }

    #[test]
    fn test_wots_sign_verify_roundtrip() {
        let sk_seed = [0x11u8; N];
        let pk_seed = [0x22u8; N];
        let msg_hash = [0x42u8; N];

        let mut gen_adrs = Address::default();
        gen_adrs.keypair = 3;
        let pk = wots_pk_gen(&sk_seed, &pk_seed, &mut gen_adrs);

        let mut sign_adrs = Address::default();
        sign_adrs.keypair = 3;
        let sig = wots_sign(&sk_seed, &pk_seed, &mut sign_adrs, &msg_hash);

        let mut verify_adrs = Address::default();
        verify_adrs.keypair = 3;
        let pk_from_sig = wots_pk_from_sig(&pk_seed, &mut verify_adrs, &sig, &msg_hash);

        assert_eq!(pk, pk_from_sig, "WOTS+ pk from sig must match keygen pk");
    }

    #[test]
    fn test_xmss_sign_verify_roundtrip() {
        // Test XMSS alone: sign a message, then verify root matches
        let sk_seed = [0x11u8; N];
        let pk_seed = [0x22u8; N];
        let mut adrs = Address::default();
        adrs.layer = 0;
        adrs.tree = 0;

        let root = xmss_root(&sk_seed, &pk_seed, &mut adrs);

        let msg_hash = [0x42u8; N];
        let leaf_idx = 3u32;

        let mut sign_adrs = Address::default();
        sign_adrs.layer = 0;
        sign_adrs.tree = 0;

        let sig = xmss_sign(&sk_seed, &pk_seed, &mut sign_adrs, leaf_idx, &msg_hash);

        let mut verify_adrs = Address::default();
        verify_adrs.layer = 0;
        verify_adrs.tree = 0;

        let computed_root = xmss_root_from_sig(&pk_seed, &mut verify_adrs, leaf_idx, &sig, &msg_hash);

        assert_eq!(root, computed_root, "XMSS root from sig must match keygen root");
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        // Use a deterministic seed for reproducibility
        let seed = [0x77u8; 3 * N];
        let (sk, vk) = slh_dsa_keygen_from_seed(&seed).unwrap();

        let message = b"test message for SLH-DSA-SHA2-256f signing";
        let sig = slh_dsa_sign_deterministic(&sk, message);

        assert!(
            slh_dsa_verify(&vk, message, &sig),
            "SLH-DSA signature should verify"
        );
    }

    #[test]
    fn test_wrong_message_rejected() {
        let seed = [0x88u8; 3 * N];
        let (sk, vk) = slh_dsa_keygen_from_seed(&seed).unwrap();

        let sig = slh_dsa_sign_deterministic(&sk, b"original");
        assert!(!slh_dsa_verify(&vk, b"tampered", &sig));
    }

    #[test]
    fn test_wrong_key_rejected() {
        let seed1 = [0x99u8; 3 * N];
        let seed2 = [0xAAu8; 3 * N];
        let (sk1, _vk1) = slh_dsa_keygen_from_seed(&seed1).unwrap();
        let (_sk2, vk2) = slh_dsa_keygen_from_seed(&seed2).unwrap();

        let sig = slh_dsa_sign_deterministic(&sk1, b"test");
        assert!(!slh_dsa_verify(&vk2, b"test", &sig));
    }

    #[test]
    fn test_verifying_key_serialization() {
        let seed = [0xBBu8; 3 * N];
        let (_sk, vk) = slh_dsa_keygen_from_seed(&seed).unwrap();

        let bytes = vk.to_bytes();
        assert_eq!(bytes.len(), PK_SIZE);

        let vk2 = SlhDsaVerifyingKey::from_bytes(&bytes).unwrap();
        assert_eq!(vk, vk2);
    }

    #[test]
    fn test_signing_key_serialization() {
        let seed = [0xCCu8; 3 * N];
        let (sk, _vk) = slh_dsa_keygen_from_seed(&seed).unwrap();

        let bytes = sk.to_bytes();
        assert_eq!(bytes.len(), SK_SIZE);

        let sk2 = SlhDsaSigningKey::from_bytes(&bytes).unwrap();
        assert_eq!(sk.to_bytes(), sk2.to_bytes());
    }

    #[test]
    fn test_verifying_key_from_signing_key() {
        let seed = [0xDDu8; 3 * N];
        let (sk, vk) = slh_dsa_keygen_from_seed(&seed).unwrap();
        let vk2 = sk.verifying_key();
        assert_eq!(vk, vk2);
    }

    #[test]
    fn test_signature_size() {
        let seed = [0xEEu8; 3 * N];
        let (sk, _vk) = slh_dsa_keygen_from_seed(&seed).unwrap();
        let sig = slh_dsa_sign_deterministic(&sk, b"size check");
        assert_eq!(sig.as_bytes().len(), SIG_SIZE);
        assert_eq!(SlhDsaSignature::expected_size(), SIG_SIZE);
    }

    #[test]
    fn test_fors_indices_extraction() {
        let digest = vec![0xFF; 32];
        let indices = msg_to_fors_indices(&digest);
        // All bits set => each 6-bit index should be 63
        for &idx in &indices {
            assert_eq!(idx, (1 << FORS_A) - 1);
        }
    }
}
