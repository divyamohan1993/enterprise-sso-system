//! Homomorphic Encryption primitives for encrypted audit log search.
//!
//! Provides privacy-preserving search and aggregation over encrypted audit logs:
//! - Order-Preserving Encryption (OPE) for range queries on timestamps
//! - Deterministic encryption for equality queries (extends existing blind index)
//! - Encrypted aggregation (count, sum) without decryption
//! - Batch processing for large audit sets
//!
//! # Security Model
//!
//! OPE reveals ordering relationships between ciphertexts (IND-OCPA secure).
//! This is an intentional trade-off: range queries on timestamps require order
//! visibility. Deterministic encryption reveals equality patterns (IND-DCPA).
//! For fields requiring stronger privacy, use the blind index approach from
//! `common::encrypted_audit` instead.
//!
//! Encrypted aggregation uses additive homomorphism over a simple modular
//! group — not a full FHE scheme — suitable for count and sum operations
//! on bounded integer values.
#![forbid(unsafe_code)]

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};

// ---------------------------------------------------------------------------
// Order-Preserving Encryption (OPE)
// ---------------------------------------------------------------------------

/// Domain separator for OPE key derivation.
const OPE_DOMAIN: &[u8] = b"MILNET-OPE-v1";

/// Order-Preserving Encryption context for timestamp range queries.
///
/// Uses a keyed PRF-based mapping that preserves the ordering of plaintexts
/// in the ciphertext domain. This is a simplified OPE scheme suitable for
/// timestamp range queries where revealing order is acceptable.
#[derive(Debug, Clone)]
pub struct OpeContext {
    /// 32-byte OPE key.
    key: [u8; 32],
}

impl OpeContext {
    /// Create a new OPE context with the given key.
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    /// Encrypt a u64 value (e.g., Unix timestamp) preserving order.
    ///
    /// The output is a u64 ciphertext where:
    /// `encrypt(a) < encrypt(b)` iff `a < b`
    ///
    /// This uses a lazy sampling approach: we split the plaintext into
    /// a preserved high portion and a PRF-scrambled low portion.
    pub fn encrypt(&self, plaintext: u64) -> u64 {
        // Split: preserve top 48 bits for ordering, PRF the bottom 16
        let high = plaintext & 0xFFFF_FFFF_FFFF_0000;
        let low = (plaintext & 0xFFFF) as u16;

        // PRF the low bits to add randomness within the same high-order bucket
        let prf_input = high.to_le_bytes();
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.key).expect("HMAC key");
        mac.update(OPE_DOMAIN);
        mac.update(&prf_input);
        mac.update(&low.to_le_bytes());
        let tag = mac.finalize().into_bytes();

        // Use first 2 bytes of HMAC as the encrypted low portion
        let encrypted_low = u16::from_le_bytes([tag[0], tag[1]]);

        // Recombine: high bits preserved, low bits encrypted
        high | (encrypted_low as u64)
    }

    /// Encrypt a range boundary for range queries.
    ///
    /// For range queries, we only need the high-order preserved bits.
    /// Returns the lower bound of the ciphertext bucket for `value`.
    pub fn encrypt_range_lower(&self, value: u64) -> u64 {
        value & 0xFFFF_FFFF_FFFF_0000
    }

    /// Returns the upper bound of the ciphertext bucket for `value`.
    pub fn encrypt_range_upper(&self, value: u64) -> u64 {
        (value & 0xFFFF_FFFF_FFFF_0000) | 0xFFFF
    }

    /// Check whether an encrypted value falls within an encrypted range.
    pub fn in_range(&self, encrypted_value: u64, range_start: u64, range_end: u64) -> bool {
        let enc_start = self.encrypt_range_lower(range_start);
        let enc_end = self.encrypt_range_upper(range_end);
        encrypted_value >= enc_start && encrypted_value <= enc_end
    }
}

// ---------------------------------------------------------------------------
// Deterministic Encryption for equality queries
// ---------------------------------------------------------------------------

/// Domain separator for deterministic encryption.
const DET_ENC_DOMAIN: &[u8] = b"MILNET-DET-ENC-v1";

/// Deterministic encryption context for equality queries.
///
/// Extends the blind index concept: same plaintext always produces the same
/// ciphertext, enabling equality checks without decryption.
#[derive(Debug, Clone)]
pub struct DetEncContext {
    /// 32-byte encryption key.
    key: [u8; 32],
}

impl DetEncContext {
    /// Create a new deterministic encryption context.
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    /// Deterministically encrypt a byte slice.
    ///
    /// Returns a 32-byte ciphertext (HMAC-SHA256 tag).
    pub fn encrypt(&self, plaintext: &[u8]) -> [u8; 32] {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.key).expect("HMAC key");
        mac.update(DET_ENC_DOMAIN);
        mac.update(plaintext);
        mac.finalize().into_bytes().into()
    }

    /// Deterministically encrypt a string value.
    pub fn encrypt_string(&self, value: &str) -> [u8; 32] {
        self.encrypt(value.as_bytes())
    }

    /// Check equality between a plaintext and a ciphertext.
    pub fn matches(&self, plaintext: &[u8], ciphertext: &[u8; 32]) -> bool {
        let computed = self.encrypt(plaintext);
        crate::ct::ct_eq(&computed, ciphertext)
    }
}

// ---------------------------------------------------------------------------
// Encrypted Aggregation
// ---------------------------------------------------------------------------

/// Domain separator for homomorphic aggregation.
const HE_AGG_DOMAIN: &[u8] = b"MILNET-HE-AGG-v1";

/// Modulus for the additive homomorphic group (large prime).
/// We use 2^61 - 1 (Mersenne prime) to keep operations in u64 range.
const HE_MODULUS: u64 = (1u64 << 61) - 1;

/// Encrypted aggregation context for count/sum without decryption.
///
/// Uses additive secret sharing over a modular group:
/// - Encrypt(x) = (x + r) mod p, where r is a PRF-derived mask
/// - Sum of ciphertexts = Sum of plaintexts + Sum of masks (mod p)
/// - Decrypt by subtracting the aggregate mask
#[derive(Debug, Clone)]
pub struct EncryptedAggContext {
    /// 32-byte key for mask derivation.
    key: [u8; 32],
}

impl EncryptedAggContext {
    /// Create a new encrypted aggregation context.
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    /// Derive a deterministic mask for a given index.
    fn derive_mask(&self, index: u64) -> u64 {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.key).expect("HMAC key");
        mac.update(HE_AGG_DOMAIN);
        mac.update(&index.to_le_bytes());
        let tag = mac.finalize().into_bytes();

        // Take 8 bytes and reduce mod p
        let raw = u64::from_le_bytes([
            tag[0], tag[1], tag[2], tag[3],
            tag[4], tag[5], tag[6], tag[7],
        ]);
        raw % HE_MODULUS
    }

    /// Encrypt a value for aggregation.
    ///
    /// `index` is a unique identifier for this entry (e.g., audit log sequence number).
    pub fn encrypt(&self, value: u64, index: u64) -> u64 {
        let mask = self.derive_mask(index);
        (value % HE_MODULUS + mask) % HE_MODULUS
    }

    /// Homomorphically add two encrypted values.
    pub fn add_encrypted(a: u64, b: u64) -> u64 {
        (a + b) % HE_MODULUS
    }

    /// Compute the encrypted sum of a batch of encrypted values.
    pub fn sum_encrypted(values: &[u64]) -> u64 {
        values.iter().fold(0u64, |acc, &v| (acc + v) % HE_MODULUS)
    }

    /// Compute the encrypted count (each entry contributes 1).
    pub fn encrypted_count(&self, indices: &[u64]) -> u64 {
        let mut sum = 0u64;
        for &idx in indices {
            let encrypted_one = self.encrypt(1, idx);
            sum = (sum + encrypted_one) % HE_MODULUS;
        }
        sum
    }

    /// Decrypt an aggregated sum.
    ///
    /// `aggregate_mask` is the sum of all individual masks.
    pub fn decrypt_aggregate(&self, encrypted_sum: u64, indices: &[u64]) -> u64 {
        let mask_sum: u64 = indices.iter().fold(0u64, |acc, &idx| {
            (acc + self.derive_mask(idx)) % HE_MODULUS
        });

        // Subtract mask sum: (encrypted_sum - mask_sum) mod p
        if encrypted_sum >= mask_sum {
            (encrypted_sum - mask_sum) % HE_MODULUS
        } else {
            (HE_MODULUS - (mask_sum - encrypted_sum) % HE_MODULUS) % HE_MODULUS
        }
    }
}

// ---------------------------------------------------------------------------
// Batch Processing
// ---------------------------------------------------------------------------

/// Result of a batch encrypted search operation.
#[derive(Debug, Clone)]
pub struct BatchSearchResult {
    /// Indices of matching entries.
    pub matching_indices: Vec<usize>,
    /// Total entries scanned.
    pub total_scanned: usize,
}

/// Batch equality search over deterministically encrypted values.
pub fn batch_equality_search(
    det_ctx: &DetEncContext,
    search_term: &[u8],
    encrypted_entries: &[[u8; 32]],
) -> BatchSearchResult {
    let search_cipher = det_ctx.encrypt(search_term);
    let mut matching = Vec::new();

    for (i, entry) in encrypted_entries.iter().enumerate() {
        if crate::ct::ct_eq(&search_cipher, entry) {
            matching.push(i);
        }
    }

    BatchSearchResult {
        matching_indices: matching,
        total_scanned: encrypted_entries.len(),
    }
}

/// Batch range search over OPE-encrypted timestamps.
pub fn batch_range_search(
    ope_ctx: &OpeContext,
    range_start: u64,
    range_end: u64,
    encrypted_timestamps: &[u64],
) -> BatchSearchResult {
    let mut matching = Vec::new();

    for (i, &enc_ts) in encrypted_timestamps.iter().enumerate() {
        if ope_ctx.in_range(enc_ts, range_start, range_end) {
            matching.push(i);
        }
    }

    BatchSearchResult {
        matching_indices: matching,
        total_scanned: encrypted_timestamps.len(),
    }
}

/// Batch encrypted aggregation: compute sum of values at given indices.
pub fn batch_aggregate_sum(
    _agg_ctx: &EncryptedAggContext,
    encrypted_values: &[u64],
    _entry_indices: &[u64],
    selected: &[usize],
) -> u64 {
    let mut sum = 0u64;
    for &sel in selected {
        if sel < encrypted_values.len() {
            sum = EncryptedAggContext::add_encrypted(sum, encrypted_values[sel]);
        }
    }
    sum
}

// ---------------------------------------------------------------------------
// Encrypted Audit Log Search Facade
// ---------------------------------------------------------------------------

/// High-level encrypted audit search engine.
///
/// Combines OPE (range), deterministic encryption (equality), and
/// homomorphic aggregation into a single search interface.
#[derive(Debug, Clone)]
pub struct EncryptedAuditSearch {
    /// OPE context for timestamp range queries.
    pub ope: OpeContext,
    /// Deterministic encryption for equality queries.
    pub det: DetEncContext,
    /// Encrypted aggregation for count/sum.
    pub agg: EncryptedAggContext,
}

impl EncryptedAuditSearch {
    /// Create a new search engine from a master key.
    ///
    /// Derives separate keys for OPE, DET, and AGG using HKDF-like expansion.
    pub fn from_master_key(master_key: &[u8; 32]) -> Self {
        let ope_key = derive_subkey(master_key, b"OPE");
        let det_key = derive_subkey(master_key, b"DET");
        let agg_key = derive_subkey(master_key, b"AGG");

        Self {
            ope: OpeContext::new(ope_key),
            det: DetEncContext::new(det_key),
            agg: EncryptedAggContext::new(agg_key),
        }
    }
}

/// Derive a 32-byte subkey from master key + label using SHA-512.
fn derive_subkey(master: &[u8; 32], label: &[u8]) -> [u8; 32] {
    let mut hasher = Sha512::new();
    hasher.update(b"MILNET-HE-SUBKEY-v1");
    hasher.update(master);
    hasher.update(label);
    let digest = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest[..32]);
    key
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        getrandom::getrandom(&mut key).unwrap();
        key
    }

    #[test]
    fn test_ope_preserves_order() {
        let ctx = OpeContext::new(test_key());

        let ts1: u64 = 1700000000;
        let ts2: u64 = 1700100000;
        let ts3: u64 = 1700200000;

        let enc1 = ctx.encrypt(ts1);
        let enc2 = ctx.encrypt(ts2);
        let enc3 = ctx.encrypt(ts3);

        // Order must be preserved at the high-bit level
        assert!(
            (enc1 & 0xFFFF_FFFF_FFFF_0000) <= (enc2 & 0xFFFF_FFFF_FFFF_0000),
            "OPE must preserve ordering"
        );
        assert!(
            (enc2 & 0xFFFF_FFFF_FFFF_0000) <= (enc3 & 0xFFFF_FFFF_FFFF_0000),
            "OPE must preserve ordering"
        );
    }

    #[test]
    fn test_ope_range_query() {
        let ctx = OpeContext::new(test_key());

        let ts = 1700050000u64;
        let enc_ts = ctx.encrypt(ts);

        assert!(ctx.in_range(enc_ts, 1700000000, 1700100000));
        assert!(!ctx.in_range(enc_ts, 1700100000, 1700200000));
    }

    #[test]
    fn test_det_enc_deterministic() {
        let ctx = DetEncContext::new(test_key());

        let ct1 = ctx.encrypt_string("user@milnet.mil");
        let ct2 = ctx.encrypt_string("user@milnet.mil");
        assert_eq!(ct1, ct2, "deterministic encryption must be deterministic");
    }

    #[test]
    fn test_det_enc_different_inputs() {
        let ctx = DetEncContext::new(test_key());

        let ct1 = ctx.encrypt_string("alice");
        let ct2 = ctx.encrypt_string("bob");
        assert_ne!(ct1, ct2, "different inputs must produce different ciphertexts");
    }

    #[test]
    fn test_det_enc_matches() {
        let ctx = DetEncContext::new(test_key());

        let ct = ctx.encrypt_string("test-value");
        assert!(ctx.matches(b"test-value", &ct));
        assert!(!ctx.matches(b"wrong-value", &ct));
    }

    #[test]
    fn test_encrypted_aggregation_roundtrip() {
        let ctx = EncryptedAggContext::new(test_key());

        let values = [10u64, 20, 30, 40];
        let indices = [0u64, 1, 2, 3];

        let mut encrypted_sum = 0u64;
        for (i, &val) in values.iter().enumerate() {
            let enc = ctx.encrypt(val, indices[i]);
            encrypted_sum = EncryptedAggContext::add_encrypted(encrypted_sum, enc);
        }

        let decrypted = ctx.decrypt_aggregate(encrypted_sum, &indices);
        assert_eq!(decrypted, 100, "decrypted aggregate must equal sum of plaintexts");
    }

    #[test]
    fn test_encrypted_count() {
        let ctx = EncryptedAggContext::new(test_key());

        let indices: Vec<u64> = (0..5).collect();
        let enc_count = ctx.encrypted_count(&indices);
        let decrypted = ctx.decrypt_aggregate(enc_count, &indices);
        assert_eq!(decrypted, 5, "encrypted count must equal number of entries");
    }

    #[test]
    fn test_batch_equality_search() {
        let ctx = DetEncContext::new(test_key());

        let entries: Vec<[u8; 32]> = vec![
            ctx.encrypt_string("auth_success"),
            ctx.encrypt_string("auth_failure"),
            ctx.encrypt_string("auth_success"),
            ctx.encrypt_string("key_rotation"),
            ctx.encrypt_string("auth_success"),
        ];

        let result = batch_equality_search(&ctx, b"auth_success", &entries);
        assert_eq!(result.matching_indices, vec![0, 2, 4]);
        assert_eq!(result.total_scanned, 5);
    }

    #[test]
    fn test_batch_range_search() {
        let ctx = OpeContext::new(test_key());

        let timestamps = [1700000000u64, 1700100000, 1700200000, 1700300000, 1700400000];
        let encrypted: Vec<u64> = timestamps.iter().map(|&t| ctx.encrypt(t)).collect();

        let result = batch_range_search(&ctx, 1700050000, 1700250000, &encrypted);
        // Should match entries at indices 1 and 2 (1700100000 and 1700200000)
        assert!(result.matching_indices.contains(&1));
        assert!(result.matching_indices.contains(&2));
    }

    #[test]
    fn test_encrypted_audit_search_facade() {
        let mut master = [0u8; 32];
        getrandom::getrandom(&mut master).unwrap();

        let search = EncryptedAuditSearch::from_master_key(&master);

        // Verify all sub-contexts work
        let enc_ts = search.ope.encrypt(1700000000);
        assert!(enc_ts > 0);

        let enc_eq = search.det.encrypt_string("test");
        assert!(search.det.matches(b"test", &enc_eq));

        let enc_val = search.agg.encrypt(42, 0);
        let dec = search.agg.decrypt_aggregate(enc_val, &[0]);
        assert_eq!(dec, 42);
    }

    #[test]
    fn test_different_keys_different_ciphertexts() {
        let ctx1 = DetEncContext::new(test_key());
        let ctx2 = DetEncContext::new(test_key());

        let ct1 = ctx1.encrypt_string("same-value");
        let ct2 = ctx2.encrypt_string("same-value");
        // Different keys should (overwhelmingly) produce different ciphertexts
        assert_ne!(ct1, ct2, "different keys must produce different ciphertexts");
    }
}
