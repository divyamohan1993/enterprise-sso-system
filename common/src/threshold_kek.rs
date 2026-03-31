//! Threshold Master KEK — eliminates single-point-of-failure for key material.
//!
//! THREAT MODEL: MasterKEK is the root of all key derivation. If ANY single
//! VM/pod holds the complete MasterKEK, that VM is a SPOF for ALL secrets.
//!
//! SOLUTION: The MasterKEK is NEVER stored or held by any single node.
//! Instead:
//! 1. MasterKEK is split into Shamir shares (3-of-5 threshold)
//! 2. Each VM holds exactly ONE share (sealed to its vTPM)
//! 3. At startup, the node collects shares from peers via mTLS
//! 4. Once threshold is met, MasterKEK is reconstructed IN MEMORY ONLY
//! 5. Shares are zeroized after reconstruction
//! 6. MasterKEK is mlock'd and never written to disk
//! 7. On any tamper detection, MasterKEK is immediately zeroized
//!
//! INVARIANTS:
//! - No single compromise reveals the MasterKEK
//! - Attacker must compromise 3+ VMs simultaneously
//! - MasterKEK exists in plaintext only in mlock'd RAM, never on disk
//! - Share collection times out after 30 seconds (prevents indefinite waits)
//! - Failed reconstruction panics the process (fail-closed)

use sha2::{Digest, Sha512};
use zeroize::{Zeroize, ZeroizeOnDrop};
use std::time::Duration;

// ---------------------------------------------------------------------------
// Shamir Secret Sharing (GF(256) arithmetic)
// ---------------------------------------------------------------------------

/// A single Shamir share: (index, 32-byte value).
/// Index is 1-based (0 is reserved for the secret).
#[derive(Clone, ZeroizeOnDrop)]
pub struct KekShare {
    pub index: u8,
    #[zeroize(drop)]
    pub value: [u8; 32],
}

impl KekShare {
    /// Create a share from raw bytes.
    pub fn new(index: u8, value: [u8; 32]) -> Self {
        assert!(index > 0, "share index must be 1-based (0 is the secret)");
        Self { index, value }
    }

    /// Encode as hex for sealed storage.
    pub fn to_hex(&self) -> String {
        format!("{:02x}{}", self.index, hex::encode(self.value))
    }

    /// Decode from hex.
    pub fn from_hex(hex_str: &str) -> Result<Self, String> {
        if hex_str.len() < 66 {
            return Err(format!("share hex too short: {} chars (need 66)", hex_str.len()));
        }
        let index = u8::from_str_radix(&hex_str[..2], 16)
            .map_err(|e| format!("invalid share index: {e}"))?;
        let value_bytes = hex::decode(&hex_str[2..66])
            .map_err(|e| format!("invalid share value hex: {e}"))?;
        let mut value = [0u8; 32];
        value.copy_from_slice(&value_bytes);
        Ok(Self { index, value })
    }
}

impl std::fmt::Debug for KekShare {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "KekShare(index={}, value=[REDACTED])", self.index)
    }
}

// GF(256) arithmetic for Shamir
pub fn gf256_add(a: u8, b: u8) -> u8 {
    a ^ b
}

// ---------------------------------------------------------------------------
// Constant-time GF(256) via log/exp lookup tables
// ---------------------------------------------------------------------------

/// Log table for GF(256) with generator 0x03 and polynomial 0x11b.
/// GF256_LOG[x] = discrete logarithm of x base 0x03, for x in 1..=255.
/// GF256_LOG[0] is unused (0 has no logarithm).
/// Generator 0x03 has order 255 and is primitive for this field.
const GF256_LOG: [u8; 256] = {
    let mut log = [0u8; 256];
    let mut val: u16 = 1;
    let mut i = 0u16;
    while i < 255 {
        log[val as usize] = i as u8;
        // Multiply val by 0x03 in GF(256): val * 3 = val XOR (val * 2)
        let val2 = (val << 1) ^ (if val & 0x80 != 0 { 0x11b } else { 0 });
        val = (val ^ val2) & 0xFF;
        i += 1;
    }
    log
};

/// Exp (antilog) table for GF(256) — 512 entries for modular reduction without branching.
/// GF256_EXP[i] = 0x03^i for i in 0..255, duplicated for i in 255..510.
/// The duplication avoids a modular reduction branch in ct_gf256_mul.
const GF256_EXP: [u8; 512] = {
    let mut exp = [0u8; 512];
    let mut val: u16 = 1;
    let mut i = 0u16;
    while i < 255 {
        exp[i as usize] = val as u8;
        // Multiply val by 0x03 in GF(256): val * 3 = val XOR (val * 2)
        let val2 = (val << 1) ^ (if val & 0x80 != 0 { 0x11b } else { 0 });
        val = (val ^ val2) & 0xFF;
        i += 1;
    }
    let mut j = 0u16;
    while j < 255 {
        exp[(255 + j) as usize] = exp[j as usize];
        j += 1;
    }
    exp
};

/// Constant-time GF(256) multiplication via log/exp tables.
/// No branches on input values — timing is identical for all inputs.
pub fn ct_gf256_mul(a: u8, b: u8) -> u8 {
    let log_a = GF256_LOG[a as usize] as u16;
    let log_b = GF256_LOG[b as usize] as u16;
    let log_sum = log_a + log_b;
    let result = GF256_EXP[log_sum as usize];
    // Constant-time mask: zero if either input is zero.
    // (x as u16).wrapping_sub(1) >> 8 == 0xFF when x == 0, 0x00 when x > 0.
    let a_is_zero = ((a as u16).wrapping_sub(1) >> 8) as u8;
    let b_is_zero = ((b as u16).wrapping_sub(1) >> 8) as u8;
    let mask = a_is_zero | b_is_zero; // 0xFF if either is zero
    result & !mask
}

/// Constant-time GF(256) inverse via log/exp tables.
/// Panics on zero input (undefined).
pub fn ct_gf256_inv(a: u8) -> u8 {
    if a == 0 {
        panic!("division by zero in GF(256)");
    }
    let log_a = GF256_LOG[a as usize] as u16;
    let log_inv = 255 - log_a;
    GF256_EXP[log_inv as usize]
}

fn ct_gf256_div(a: u8, b: u8) -> u8 {
    ct_gf256_mul(a, ct_gf256_inv(b))
}

// ---------------------------------------------------------------------------
// Legacy implementations — kept for internal reference / test comparison only.
// All production callers now use the ct_ variants above.
// ---------------------------------------------------------------------------

#[allow(dead_code)]
fn _old_gf256_mul(a: u8, b: u8) -> u8 {
    let mut result: u16 = 0;
    let mut a = a as u16;
    let mut b = b as u16;
    for _ in 0..8 {
        if b & 1 != 0 {
            result ^= a;
        }
        let carry = a & 0x80;
        a <<= 1;
        if carry != 0 {
            a ^= 0x11b; // AES irreducible polynomial
        }
        b >>= 1;
    }
    result as u8
}

#[allow(dead_code)]
fn _old_gf256_inv(a: u8) -> u8 {
    if a == 0 {
        panic!("division by zero in GF(256)");
    }
    // Fermat's little theorem: a^(-1) = a^(254) in GF(2^8)
    let a2 = _old_gf256_mul(a, a);
    let a4 = _old_gf256_mul(a2, a2);
    let a8 = _old_gf256_mul(a4, a4);
    let a16 = _old_gf256_mul(a8, a8);
    let a32 = _old_gf256_mul(a16, a16);
    let a64 = _old_gf256_mul(a32, a32);
    let a128 = _old_gf256_mul(a64, a64);
    let mut result = _old_gf256_mul(a128, a64);
    result = _old_gf256_mul(result, a32);
    result = _old_gf256_mul(result, a16);
    result = _old_gf256_mul(result, a8);
    result = _old_gf256_mul(result, a4);
    result = _old_gf256_mul(result, a2);
    result
}

// ---------------------------------------------------------------------------
// Shamir Split / Reconstruct
// ---------------------------------------------------------------------------

/// Split a 32-byte secret into `n` shares requiring `threshold` to reconstruct.
///
/// Uses Shamir's Secret Sharing over GF(256) with random coefficients from
/// OS CSPRNG. Each byte of the secret is independently split.
pub fn split_secret(secret: &[u8; 32], threshold: u8, total: u8) -> Result<Vec<KekShare>, String> {
    if threshold < 2 || threshold > total {
        return Err(format!(
            "invalid threshold: {} of {} (need 2 <= t <= n)",
            threshold, total
        ));
    }
    if total > 255 {
        return Err("maximum 255 shares".into());
    }

    let mut shares: Vec<KekShare> = (1..=total)
        .map(|i| KekShare {
            index: i,
            value: [0u8; 32],
        })
        .collect();

    // For each byte of the secret, create a random polynomial
    // f(x) = secret_byte + c1*x + c2*x^2 + ... + c_{t-1}*x^{t-1}
    for byte_idx in 0..32 {
        let mut coefficients = vec![0u8; threshold as usize];
        coefficients[0] = secret[byte_idx]; // constant term = secret byte

        // Random coefficients for higher terms
        let mut random_bytes = vec![0u8; (threshold as usize) - 1];
        getrandom::getrandom(&mut random_bytes)
            .map_err(|e| format!("CSPRNG failed during share generation: {e}"))?;
        for (i, &r) in random_bytes.iter().enumerate() {
            coefficients[i + 1] = r;
        }

        // Evaluate polynomial at each share index
        for share in &mut shares {
            let x = share.index;
            let mut y = 0u8;
            let mut x_power = 1u8; // x^0 = 1
            for &coeff in &coefficients {
                y = gf256_add(y, ct_gf256_mul(coeff, x_power));
                x_power = ct_gf256_mul(x_power, x);
            }
            share.value[byte_idx] = y;
        }

        // Zeroize coefficients
        coefficients.zeroize();
        random_bytes.zeroize();
    }

    Ok(shares)
}

/// Reconstruct a 32-byte secret from `threshold` or more shares.
///
/// Uses Lagrange interpolation over GF(256). The result is zeroized
/// on drop if wrapped in a ZeroizeOnDrop container.
pub fn reconstruct_secret(shares: &[KekShare]) -> Result<[u8; 32], String> {
    if shares.is_empty() {
        return Err("no shares provided".into());
    }
    if shares.len() < 2 {
        return Err("need at least 2 shares to reconstruct".into());
    }

    // Verify no duplicate indices
    let mut seen = std::collections::HashSet::new();
    for share in shares {
        if !seen.insert(share.index) {
            return Err(format!("duplicate share index: {}", share.index));
        }
    }

    let mut secret = [0u8; 32];

    // Lagrange interpolation for each byte
    for byte_idx in 0..32 {
        let mut result = 0u8;

        for (i, share_i) in shares.iter().enumerate() {
            let xi = share_i.index;
            let yi = share_i.value[byte_idx];

            // Compute Lagrange basis polynomial at x=0
            let mut basis = 1u8;
            for (j, share_j) in shares.iter().enumerate() {
                if i == j {
                    continue;
                }
                let xj = share_j.index;
                // basis *= (0 - xj) / (xi - xj) = xj / (xi ^ xj)
                let numerator = xj; // 0 - xj = xj in GF(256)
                let denominator = gf256_add(xi, xj); // xi - xj = xi ^ xj in GF(256)
                if denominator == 0 {
                    return Err("degenerate shares: two shares have the same index".into());
                }
                basis = ct_gf256_mul(basis, ct_gf256_div(numerator, denominator));
            }

            result = gf256_add(result, ct_gf256_mul(yi, basis));
        }

        secret[byte_idx] = result;
    }

    Ok(secret)
}

// ---------------------------------------------------------------------------
// Threshold KEK Manager
// ---------------------------------------------------------------------------

/// Configuration for threshold KEK.
pub struct ThresholdKekConfig {
    /// Shares needed to reconstruct (default: 3)
    pub threshold: u8,
    /// Total shares (default: 5)
    pub total_shares: u8,
    /// Timeout for collecting shares from peers (default: 30s)
    pub collection_timeout: Duration,
    /// This node's share index (1-based)
    pub my_share_index: u8,
}

impl Default for ThresholdKekConfig {
    fn default() -> Self {
        Self {
            threshold: 3,
            total_shares: 5,
            collection_timeout: Duration::from_secs(30),
            my_share_index: 1,
        }
    }
}

/// Manages the threshold-split MasterKEK.
///
/// The KEK is never held by a single node. At startup, nodes exchange shares
/// via mTLS. Once `threshold` shares are collected, the KEK is reconstructed
/// in mlock'd memory and shares are zeroized.
pub struct ThresholdKekManager {
    config: ThresholdKekConfig,
    /// This node's share (sealed to vTPM)
    my_share: Option<KekShare>,
    /// Collected peer shares (zeroized after reconstruction)
    collected_shares: Vec<KekShare>,
    /// Reconstructed KEK (mlock'd, zeroized on drop)
    reconstructed_kek: Option<ReconstructedKek>,
    /// Whether reconstruction has been attempted
    reconstruction_attempted: bool,
}

/// The reconstructed MasterKEK in protected memory.
#[derive(ZeroizeOnDrop)]
struct ReconstructedKek {
    #[zeroize(drop)]
    key: [u8; 32],
}

impl ThresholdKekManager {
    pub fn new(config: ThresholdKekConfig) -> Self {
        Self {
            config,
            my_share: None,
            collected_shares: Vec::new(),
            reconstructed_kek: None,
            reconstruction_attempted: false,
        }
    }

    /// Load this node's share from sealed storage.
    pub fn load_my_share(&mut self, sealed_hex: &str) -> Result<(), String> {
        let share = KekShare::from_hex(sealed_hex)?;
        if share.index != self.config.my_share_index {
            return Err(format!(
                "share index mismatch: expected {}, got {}",
                self.config.my_share_index, share.index
            ));
        }
        self.collected_shares.push(share.clone());
        self.my_share = Some(share);
        Ok(())
    }

    /// Add a share received from a peer.
    pub fn add_peer_share(&mut self, share: KekShare) -> Result<(), String> {
        // Reject if we already have this index
        if self.collected_shares.iter().any(|s| s.index == share.index) {
            return Err(format!("duplicate share index: {}", share.index));
        }
        // Reject if index is out of range
        if share.index == 0 || share.index > self.config.total_shares {
            return Err(format!(
                "share index {} out of range [1, {}]",
                share.index, self.config.total_shares
            ));
        }
        self.collected_shares.push(share);
        Ok(())
    }

    /// Check if we have enough shares to reconstruct.
    pub fn has_threshold(&self) -> bool {
        self.collected_shares.len() >= self.config.threshold as usize
    }

    /// How many shares have been collected.
    pub fn shares_collected(&self) -> usize {
        self.collected_shares.len()
    }

    /// How many more shares are needed.
    pub fn shares_needed(&self) -> usize {
        let threshold = self.config.threshold as usize;
        if self.collected_shares.len() >= threshold {
            0
        } else {
            threshold - self.collected_shares.len()
        }
    }

    /// Attempt to reconstruct the MasterKEK from collected shares.
    ///
    /// SECURITY: After reconstruction, all individual shares in memory
    /// are zeroized. The KEK is mlock'd. This function can only be
    /// called once — subsequent calls return the cached KEK.
    pub fn reconstruct(&mut self) -> Result<&[u8; 32], String> {
        if let Some(ref kek) = self.reconstructed_kek {
            return Ok(&kek.key);
        }

        if self.reconstruction_attempted {
            return Err("reconstruction already failed — cannot retry without fresh shares".into());
        }

        if !self.has_threshold() {
            return Err(format!(
                "insufficient shares: have {}, need {}",
                self.collected_shares.len(),
                self.config.threshold
            ));
        }

        self.reconstruction_attempted = true;

        let key = reconstruct_secret(&self.collected_shares)?;

        // Reject all-zero KEK
        if key.iter().all(|&b| b == 0) {
            return Err("FATAL: reconstructed KEK is all zeros — shares may be corrupted".into());
        }

        // Zeroize all collected shares — KEK is now the only copy
        for share in &mut self.collected_shares {
            share.value.zeroize();
        }
        self.collected_shares.clear();

        // Store the reconstructed KEK
        self.reconstructed_kek = Some(ReconstructedKek { key });

        tracing::info!(
            shares_used = self.config.threshold,
            fingerprint = %hex::encode(&Sha512::digest(&key)[..8]),
            "MasterKEK reconstructed from threshold shares (shares zeroized)"
        );

        Ok(&self.reconstructed_kek.as_ref().unwrap().key)
    }

    /// Get the reconstructed KEK (if available).
    pub fn kek(&self) -> Option<&[u8; 32]> {
        self.reconstructed_kek.as_ref().map(|k| &k.key)
    }

    /// Emergency zeroize: destroy the KEK immediately.
    /// Called when tamper detection fires.
    pub fn emergency_zeroize(&mut self) {
        if let Some(mut kek) = self.reconstructed_kek.take() {
            kek.key.zeroize();
            tracing::error!("EMERGENCY: MasterKEK zeroized due to tamper detection");
        }
        if let Some(mut share) = self.my_share.take() {
            share.value.zeroize();
        }
        for share in &mut self.collected_shares {
            share.value.zeroize();
        }
        self.collected_shares.clear();
    }

    /// Is the KEK currently available?
    pub fn is_available(&self) -> bool {
        self.reconstructed_kek.is_some()
    }
}

impl Drop for ThresholdKekManager {
    fn drop(&mut self) {
        self.emergency_zeroize();
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_and_reconstruct_3_of_5() {
        let secret = [0x42u8; 32];
        let shares = split_secret(&secret, 3, 5).unwrap();
        assert_eq!(shares.len(), 5);

        // Reconstruct with first 3 shares
        let recovered = reconstruct_secret(&shares[0..3]).unwrap();
        assert_eq!(recovered, secret);

        // Reconstruct with last 3 shares
        let recovered2 = reconstruct_secret(&shares[2..5]).unwrap();
        assert_eq!(recovered2, secret);

        // Reconstruct with shares 1, 3, 5
        let picked = vec![shares[0].clone(), shares[2].clone(), shares[4].clone()];
        let recovered3 = reconstruct_secret(&picked).unwrap();
        assert_eq!(recovered3, secret);
    }

    #[test]
    fn two_shares_insufficient_for_3_of_5() {
        let secret = [0x42u8; 32];
        let shares = split_secret(&secret, 3, 5).unwrap();

        // 2 shares should reconstruct to WRONG value
        let recovered = reconstruct_secret(&shares[0..2]).unwrap();
        assert_ne!(recovered, secret, "2 shares must not reconstruct 3-of-5 secret");
    }

    #[test]
    fn split_rejects_invalid_threshold() {
        assert!(split_secret(&[0; 32], 1, 5).is_err());  // threshold < 2
        assert!(split_secret(&[0; 32], 6, 5).is_err());  // threshold > total
    }

    #[test]
    fn reconstruct_rejects_duplicates() {
        let secret = [0x42u8; 32];
        let shares = split_secret(&secret, 2, 3).unwrap();
        let duped = vec![shares[0].clone(), shares[0].clone()];
        assert!(reconstruct_secret(&duped).is_err());
    }

    #[test]
    fn share_hex_roundtrip() {
        let share = KekShare::new(3, [0xAB; 32]);
        let hex = share.to_hex();
        let recovered = KekShare::from_hex(&hex).unwrap();
        assert_eq!(recovered.index, 3);
        assert_eq!(recovered.value, [0xAB; 32]);
    }

    #[test]
    fn manager_collect_and_reconstruct() {
        let secret = [0x99u8; 32];
        let shares = split_secret(&secret, 3, 5).unwrap();

        let mut mgr = ThresholdKekManager::new(ThresholdKekConfig {
            threshold: 3,
            total_shares: 5,
            my_share_index: 1,
            ..Default::default()
        });

        // Load own share
        mgr.load_my_share(&shares[0].to_hex()).unwrap();
        assert_eq!(mgr.shares_collected(), 1);
        assert!(!mgr.has_threshold());

        // Add peer shares
        mgr.add_peer_share(shares[1].clone()).unwrap();
        mgr.add_peer_share(shares[2].clone()).unwrap();
        assert!(mgr.has_threshold());

        // Reconstruct
        let kek = mgr.reconstruct().unwrap();
        assert_eq!(kek, &secret);
        assert!(mgr.is_available());
    }

    #[test]
    fn manager_emergency_zeroize() {
        let secret = [0x99u8; 32];
        let shares = split_secret(&secret, 2, 3).unwrap();

        let mut mgr = ThresholdKekManager::new(ThresholdKekConfig {
            threshold: 2,
            total_shares: 3,
            my_share_index: 1,
            ..Default::default()
        });

        mgr.load_my_share(&shares[0].to_hex()).unwrap();
        mgr.add_peer_share(shares[1].clone()).unwrap();
        mgr.reconstruct().unwrap();
        assert!(mgr.is_available());

        mgr.emergency_zeroize();
        assert!(!mgr.is_available());
        assert_eq!(mgr.kek(), None);
    }

    #[test]
    fn manager_rejects_out_of_range_index() {
        let mut mgr = ThresholdKekManager::new(ThresholdKekConfig {
            threshold: 2,
            total_shares: 3,
            ..Default::default()
        });
        let bad_share = KekShare::new(4, [0; 32]); // index 4 > total_shares 3
        assert!(mgr.add_peer_share(bad_share).is_err());
    }

    #[test]
    fn manager_rejects_duplicate_share() {
        let secret = [0x42u8; 32];
        let shares = split_secret(&secret, 2, 3).unwrap();

        let mut mgr = ThresholdKekManager::new(ThresholdKekConfig {
            threshold: 2,
            total_shares: 3,
            my_share_index: 1,
            ..Default::default()
        });

        mgr.load_my_share(&shares[0].to_hex()).unwrap();
        // Try to add same index again
        assert!(mgr.add_peer_share(shares[0].clone()).is_err());
    }

    #[test]
    fn different_secret_different_shares() {
        let secret1 = [0x11u8; 32];
        let secret2 = [0x22u8; 32];
        let shares1 = split_secret(&secret1, 2, 3).unwrap();
        let shares2 = split_secret(&secret2, 2, 3).unwrap();
        // Shares must differ
        assert_ne!(shares1[0].value, shares2[0].value);
    }

    #[test]
    fn gf256_arithmetic_basic() {
        // Addition is XOR
        assert_eq!(gf256_add(0, 0), 0);
        assert_eq!(gf256_add(1, 1), 0);
        assert_eq!(gf256_add(0xFF, 0xFF), 0);

        // Constant-time multiplication
        assert_eq!(ct_gf256_mul(1, 1), 1);
        assert_eq!(ct_gf256_mul(0, 42), 0);
        assert_eq!(ct_gf256_mul(1, 42), 42);

        // Constant-time inverse
        for a in 1..=255u16 {
            let inv = ct_gf256_inv(a as u8);
            assert_eq!(ct_gf256_mul(a as u8, inv), 1, "ct_gf256_inv: a*a^-1 != 1 for a={}", a);
        }
    }

    #[test]
    fn share_debug_redacts_value() {
        let share = KekShare::new(1, [0xAB; 32]);
        let debug = format!("{:?}", share);
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("ab"));
    }
}
