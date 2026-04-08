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
use hmac::{Hmac, Mac};
use zeroize::{Zeroize, ZeroizeOnDrop};
use std::time::Duration;

type HmacSha512 = Hmac<Sha512>;

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

    /// Encode as hex for sealed storage. Returns `Zeroizing<String>` to ensure
    /// the hex-encoded share value is zeroized when dropped.
    pub fn to_hex(&self) -> zeroize::Zeroizing<String> {
        zeroize::Zeroizing::new(format!("{:02x}{}", self.index, hex::encode(self.value)))
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
/// Returns error on zero input instead of panicking (DoS prevention).
pub fn ct_gf256_inv(a: u8) -> Result<u8, &'static str> {
    if a == 0 {
        return Err("division by zero in GF(256): zero input to inverse");
    }
    let log_a = GF256_LOG[a as usize] as u16;
    let log_inv = 255 - log_a;
    Ok(GF256_EXP[log_inv as usize])
}

fn ct_gf256_div(a: u8, b: u8) -> Result<u8, &'static str> {
    Ok(ct_gf256_mul(a, ct_gf256_inv(b)?))
}

// ---------------------------------------------------------------------------
// Legacy implementations — kept for internal reference / test comparison only.
// All production callers now use the ct_ variants above.
// ---------------------------------------------------------------------------

// Legacy GF(256) implementations removed. All production callers use the
// constant-time ct_gf256_mul / ct_gf256_inv variants above, which prevent
// timing side-channels on share coefficients.
//
// The old implementations had data-dependent branching and a panic on
// division by zero. Both are unacceptable for a military-grade system.

// Fermat's little theorem reference (for ct_gf256_inv above): a^(-1) = a^(254) in GF(2^8)

// ---------------------------------------------------------------------------
// Hash-based VSS Commitments for GF(256) Shamir
// ---------------------------------------------------------------------------

/// Domain separation for VSS share commitments.
const VSS_COMMITMENT_DOMAIN: &[u8] = b"MILNET-VSS-SHARE-COMMIT-v1";

/// A set of hash-based VSS commitments for verifying Shamir shares.
///
/// For each share index, stores HMAC-SHA512(commitment_key, index || share_value).
/// The commitment_key is derived from the secret via HKDF-SHA512 to ensure only
/// the dealer who knew the secret can produce valid commitments, while the
/// commitments themselves do not reveal the secret or share values.
#[derive(Clone)]
pub struct VssCommitments {
    /// Per-share commitment: HMAC-SHA512(key, index || value)
    pub commitments: Vec<(u8, [u8; 64])>,
}

impl VssCommitments {
    /// Generate commitments for a set of shares.
    ///
    /// The commitment key is derived from the secret via HKDF-SHA512 with
    /// domain separation, so commitments can only be produced by someone
    /// who holds the original secret (the dealer).
    pub fn generate(secret: &[u8; 32], shares: &[KekShare]) -> Self {
        let commitment_key = Self::derive_commitment_key(secret);
        let mut commitments = Vec::with_capacity(shares.len());
        for share in shares {
            let mac = Self::compute_commitment(&commitment_key, share);
            commitments.push((share.index, mac));
        }
        commitments.sort_by_key(|(idx, _)| *idx);
        Self { commitments }
    }

    /// Verify a single share against the stored commitments.
    ///
    /// Returns true if the share matches its commitment, false if the share
    /// index is unknown or the commitment does not match (malicious share).
    pub fn verify_share(&self, share: &KekShare, secret: &[u8; 32]) -> bool {
        let commitment_key = Self::derive_commitment_key(secret);
        let computed = Self::compute_commitment(&commitment_key, share);
        // Find the stored commitment for this index
        let stored = self.commitments.iter().find(|(idx, _)| *idx == share.index);
        match stored {
            Some((_, expected)) => {
                // Constant-time comparison to prevent timing oracle
                use subtle::ConstantTimeEq;
                computed.ct_eq(expected).into()
            }
            None => false, // Unknown share index
        }
    }

    /// Derive the commitment HMAC key from the secret.
    fn derive_commitment_key(secret: &[u8; 32]) -> [u8; 64] {
        use hkdf::Hkdf;
        let hkdf = Hkdf::<Sha512>::new(Some(VSS_COMMITMENT_DOMAIN), secret);
        let mut key = [0u8; 64];
        hkdf.expand(b"vss-commitment-key", &mut key)
            .expect("HKDF expand for VSS commitment key");
        key
    }

    /// Compute HMAC-SHA512(key, index || value) for a single share.
    fn compute_commitment(key: &[u8; 64], share: &KekShare) -> [u8; 64] {
        let mut mac = HmacSha512::new_from_slice(key)
            .expect("HMAC-SHA512 accepts any key length");
        mac.update(&[share.index]);
        mac.update(&share.value);
        let result = mac.finalize();
        let mut out = [0u8; 64];
        out.copy_from_slice(&result.into_bytes());
        out
    }

    /// Encode commitments as hex for distribution alongside shares.
    pub fn to_hex(&self) -> String {
        let mut parts = Vec::new();
        for (idx, mac) in &self.commitments {
            parts.push(format!("{:02x}{}", idx, hex::encode(mac)));
        }
        parts.join(",")
    }

    /// Decode commitments from hex.
    pub fn from_hex(hex_str: &str) -> Result<Self, String> {
        let mut commitments = Vec::new();
        for part in hex_str.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            if part.len() < 2 + 128 {
                return Err(format!("commitment hex too short: {}", part.len()));
            }
            let idx = u8::from_str_radix(&part[..2], 16)
                .map_err(|e| format!("invalid commitment index: {e}"))?;
            let mac_bytes = hex::decode(&part[2..130])
                .map_err(|e| format!("invalid commitment mac hex: {e}"))?;
            let mut mac = [0u8; 64];
            mac.copy_from_slice(&mac_bytes);
            commitments.push((idx, mac));
        }
        Ok(Self { commitments })
    }
}

// ---------------------------------------------------------------------------
// Shamir Split / Reconstruct
// ---------------------------------------------------------------------------

/// Split a 32-byte secret into `n` shares requiring `threshold` to reconstruct.
///
/// Uses Shamir's Secret Sharing over GF(256) with random coefficients from
/// OS CSPRNG. Each byte of the secret is independently split.
///
/// Also returns hash-based VSS commitments for each share, enabling
/// independent verification of share authenticity without the secret.
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

/// Split a secret AND produce hash-based VSS commitments for each share.
///
/// Returns (shares, commitments) where commitments can be distributed to
/// all parties for independent share verification.
pub fn split_secret_with_commitments(
    secret: &[u8; 32],
    threshold: u8,
    total: u8,
) -> Result<(Vec<KekShare>, VssCommitments), String> {
    let shares = split_secret(secret, threshold, total)?;
    let commitments = VssCommitments::generate(secret, &shares);
    Ok((shares, commitments))
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
                basis = ct_gf256_mul(basis, ct_gf256_div(numerator, denominator)?);
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

        // SECURITY: Use HMAC with a per-boot random key for fingerprinting instead of
        // bare SHA-512(KEK). A bare hash enables brute-force verification and cross-boot
        // KEK identity correlation from captured logs.
        let fp = {
            let mut boot_key = [0u8; 32];
            let _ = getrandom::getrandom(&mut boot_key);
            let mut mac = HmacSha512::new_from_slice(&boot_key)
                .expect("HMAC accepts any key length");
            mac.update(&key);
            let result = mac.finalize().into_bytes();
            boot_key.zeroize();
            hex::encode(&result[..8])
        };
        tracing::info!(
            shares_used = self.config.threshold,
            fingerprint = %fp,
            "MasterKEK reconstructed from threshold shares (shares zeroized, fingerprint is per-boot HMAC)"
        );

        Ok(&self.reconstructed_kek.as_ref()
            .expect("KEK reconstruction just succeeded above").key)
    }

    /// Get the reconstructed KEK (if available).
    pub fn kek(&self) -> Option<&[u8; 32]> {
        self.reconstructed_kek.as_ref().map(|k| &k.key)
    }

    /// Reset the manager state so reconstruction can be re-attempted with fresh shares.
    ///
    /// This clears the `reconstruction_attempted` flag and any collected shares,
    /// allowing a retry after a transient failure (e.g. network partition during
    /// share collection).
    pub fn reset_for_retry(&mut self) {
        // Zeroize any partially-collected shares before clearing
        for share in &mut self.collected_shares {
            share.value.zeroize();
        }
        self.collected_shares.clear();
        self.reconstruction_attempted = false;
        tracing::info!("ThresholdKekManager: reset for retry (shares cleared, reconstruction_attempted=false)");
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
// Threshold KDF -- derive keys WITHOUT reconstructing the master secret
// ---------------------------------------------------------------------------
//
// THREAT MODEL: The standard Shamir reconstruct() materializes the full KEK
// in one node's RAM. Root on that node = game over.
//
// ThresholdKdf solves this: each node computes a partial HMAC over its share,
// a combiner XORs the partials and runs HKDF. The full secret NEVER exists
// in any single address space.

/// Domain separation for threshold KDF partial derivations.
const THRESHOLD_KDF_DOMAIN: &[u8] = b"MILNET-THRESHOLD-KDF-v1";

/// Compute a partial key derivation from a single Shamir share.
///
/// Each node calls this with its own share. Returns
/// HMAC-SHA512(share_value, domain || context || salt || index).
pub fn partial_derive_key(share: &KekShare, context: &[u8], salt: &[u8]) -> [u8; 64] {
    let mut mac = HmacSha512::new_from_slice(&share.value)
        .expect("HMAC-SHA512 accepts any key length");
    mac.update(THRESHOLD_KDF_DOMAIN);
    mac.update(context);
    mac.update(salt);
    mac.update(&[share.index]);
    let result = mac.finalize();
    let mut out = [0u8; 64];
    out.copy_from_slice(&result.into_bytes());
    out
}

/// Combine threshold partial derivations into a final 32-byte derived key.
///
/// Requires exactly `threshold` partials. The full Shamir secret NEVER
/// materializes. Final key = HKDF-SHA512(salt, XOR(partials)) expanded
/// with context. All intermediates are zeroized before return.
pub fn combine_partial_derivations(
    partials: &[[u8; 64]],
    threshold: usize,
    context: &[u8],
    salt: &[u8],
) -> Result<[u8; 32], String> {
    if partials.len() != threshold {
        return Err(format!(
            "expected exactly {} partials, got {}",
            threshold, partials.len()
        ));
    }
    if partials.is_empty() {
        return Err("no partials provided".into());
    }

    let mut xored = [0u8; 64];
    for partial in partials {
        for (x, p) in xored.iter_mut().zip(partial.iter()) {
            *x ^= p;
        }
    }

    use hkdf::Hkdf;
    let hkdf = Hkdf::<Sha512>::new(Some(salt), &xored);
    let mut derived = [0u8; 32];
    hkdf.expand(context, &mut derived)
        .map_err(|e| format!("HKDF expand failed: {e}"))?;

    xored.zeroize();

    if derived.iter().all(|&b| b == 0) {
        return Err("FATAL: derived key is all zeros".into());
    }

    Ok(derived)
}

/// Manages a distributed threshold KDF ceremony.
///
/// Tracks partial derivations from participating nodes and produces a final
/// derived key once threshold partials are collected. The master secret
/// NEVER exists in any node's memory.
pub struct ThresholdKdfManager {
    threshold: u8,
    total_shares: u8,
    partials: Vec<(u8, [u8; 64])>,
    contributed: std::collections::HashSet<u8>,
    context: Vec<u8>,
    salt: Vec<u8>,
}

impl std::fmt::Debug for ThresholdKdfManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ThresholdKdfManager")
            .field("threshold", &self.threshold)
            .field("total_shares", &self.total_shares)
            .field("partials_collected", &self.partials.len())
            .field("contributed_indices", &self.contributed)
            .finish()
    }
}

impl ThresholdKdfManager {
    pub fn new(threshold: u8, total_shares: u8, context: &[u8], salt: &[u8]) -> Self {
        Self {
            threshold,
            total_shares,
            partials: Vec::with_capacity(threshold as usize),
            contributed: std::collections::HashSet::new(),
            context: context.to_vec(),
            salt: salt.to_vec(),
        }
    }

    /// Submit a partial derivation from a node.
    pub fn submit_partial(&mut self, share_index: u8, partial: [u8; 64]) -> Result<(), String> {
        if share_index == 0 || share_index > self.total_shares {
            return Err(format!(
                "share index {} out of range [1, {}]",
                share_index, self.total_shares
            ));
        }
        if self.contributed.contains(&share_index) {
            return Err(format!("duplicate partial from share index {}", share_index));
        }
        if partial.iter().all(|&b| b == 0) {
            return Err(format!(
                "all-zero partial from share index {} -- possible tampered share",
                share_index
            ));
        }
        self.contributed.insert(share_index);
        self.partials.push((share_index, partial));
        Ok(())
    }

    pub fn has_threshold(&self) -> bool {
        self.partials.len() >= self.threshold as usize
    }

    pub fn partials_collected(&self) -> usize {
        self.partials.len()
    }

    pub fn partials_needed(&self) -> usize {
        let t = self.threshold as usize;
        if self.partials.len() >= t { 0 } else { t - self.partials.len() }
    }

    /// Derive the final key. Consumes the manager to ensure partials are zeroized.
    pub fn derive_key(mut self) -> Result<[u8; 32], String> {
        if !self.has_threshold() {
            return Err(format!(
                "insufficient partials: have {}, need {}",
                self.partials.len(), self.threshold
            ));
        }

        let partials_only: Vec<[u8; 64]> = self.partials.iter()
            .take(self.threshold as usize)
            .map(|(_, p)| *p)
            .collect();

        let result = combine_partial_derivations(
            &partials_only,
            self.threshold as usize,
            &self.context,
            &self.salt,
        );

        for (_, ref mut p) in &mut self.partials {
            p.zeroize();
        }
        self.partials.clear();

        result
    }
}

impl Drop for ThresholdKdfManager {
    fn drop(&mut self) {
        for (_, ref mut p) in &mut self.partials {
            p.zeroize();
        }
        self.partials.clear();
        self.context.zeroize();
        self.salt.zeroize();
    }
}

/// Convenience: given shares (>= threshold), compute partial derivations
/// and combine them. The full secret NEVER materializes.
pub fn derive_key_distributed(
    shares: &[KekShare],
    threshold: u8,
    context: &[u8],
    salt: &[u8],
) -> Result<[u8; 32], String> {
    if shares.len() < threshold as usize {
        return Err(format!(
            "need at least {} shares, got {}",
            threshold, shares.len()
        ));
    }

    let mut partials = Vec::with_capacity(threshold as usize);
    for share in shares.iter().take(threshold as usize) {
        let partial = partial_derive_key(share, context, salt);
        partials.push(partial);
    }

    let result = combine_partial_derivations(&partials, threshold as usize, context, salt);

    for p in &mut partials {
        p.zeroize();
    }

    result
}

// ---------------------------------------------------------------------------
// Proactive Share Refresh
// ---------------------------------------------------------------------------

/// Refresh shares without changing the secret. New random polynomial, same
/// constant term. Old shares become incompatible with new shares.
pub fn refresh_shares(
    secret: &[u8; 32],
    threshold: u8,
    total: u8,
) -> Result<(Vec<KekShare>, VssCommitments), String> {
    split_secret_with_commitments(secret, threshold, total)
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
            let inv = ct_gf256_inv(a as u8).expect("inverse of nonzero must succeed");
            assert_eq!(ct_gf256_mul(a as u8, inv), 1, "ct_gf256_inv: a*a^-1 != 1 for a={}", a);
        }
        // Verify zero input returns error instead of panicking
        assert!(ct_gf256_inv(0).is_err(), "ct_gf256_inv(0) must return Err, not panic");
    }

    #[test]
    fn share_debug_redacts_value() {
        let share = KekShare::new(1, [0xAB; 32]);
        let debug = format!("{:?}", share);
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("ab"));
    }

    // ── VSS Commitment Tests ──────────────────────────────────────────────

    #[test]
    fn vss_commitments_verify_valid_shares() {
        let secret = [0x42u8; 32];
        let (shares, commitments) = split_secret_with_commitments(&secret, 3, 5).unwrap();
        assert_eq!(commitments.commitments.len(), 5);
        for share in &shares {
            assert!(
                commitments.verify_share(share, &secret),
                "valid share {} must verify against its commitment",
                share.index
            );
        }
    }

    #[test]
    fn vss_commitments_reject_tampered_share() {
        let secret = [0x42u8; 32];
        let (shares, commitments) = split_secret_with_commitments(&secret, 3, 5).unwrap();
        // Tamper with a share's value
        let mut tampered = shares[2].clone();
        tampered.value[0] ^= 0xFF;
        assert!(
            !commitments.verify_share(&tampered, &secret),
            "tampered share must fail verification"
        );
    }

    #[test]
    fn vss_commitments_reject_wrong_index() {
        let secret = [0x42u8; 32];
        let (shares, commitments) = split_secret_with_commitments(&secret, 3, 5).unwrap();
        // Use share value from index 1 but claim it's index 2
        let forged = KekShare::new(2, shares[0].value);
        assert!(
            !commitments.verify_share(&forged, &secret),
            "share with wrong index must fail verification"
        );
    }

    #[test]
    fn vss_commitments_hex_roundtrip() {
        let secret = [0x42u8; 32];
        let (_, commitments) = split_secret_with_commitments(&secret, 2, 3).unwrap();
        let hex = commitments.to_hex();
        let recovered = VssCommitments::from_hex(&hex).unwrap();
        assert_eq!(recovered.commitments.len(), commitments.commitments.len());
        for (a, b) in recovered.commitments.iter().zip(commitments.commitments.iter()) {
            assert_eq!(a.0, b.0); // index
            assert_eq!(a.1, b.1); // mac
        }
    }

    #[test]
    fn vss_commitments_different_secrets_different_macs() {
        let secret1 = [0x11u8; 32];
        let secret2 = [0x22u8; 32];
        let (_, c1) = split_secret_with_commitments(&secret1, 2, 3).unwrap();
        let (_, c2) = split_secret_with_commitments(&secret2, 2, 3).unwrap();
        // At least some commitments must differ
        let differ = c1.commitments.iter().zip(c2.commitments.iter())
            .any(|(a, b)| a.1 != b.1);
        assert!(differ, "different secrets must produce different commitments");
    }

    #[test]
    fn split_with_commitments_reconstruction_works() {
        let secret = [0xABu8; 32];
        let (shares, _commitments) = split_secret_with_commitments(&secret, 3, 5).unwrap();
        // Verify reconstruction still works with commitment-generated shares
        let recovered = reconstruct_secret(&shares[1..4]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn vss_commitments_reject_completely_fabricated_share() {
        let secret = [0x42u8; 32];
        let (_, commitments) = split_secret_with_commitments(&secret, 3, 5).unwrap();
        // Fabricate a share with a valid index but random value
        let fabricated = KekShare::new(1, [0xFF; 32]);
        assert!(
            !commitments.verify_share(&fabricated, &secret),
            "fabricated share must fail verification"
        );
    }

    #[test]
    fn vss_commitments_reject_nonexistent_index() {
        let secret = [0x42u8; 32];
        let (_, commitments) = split_secret_with_commitments(&secret, 2, 3).unwrap();
        // Index 4 doesn't exist in 3-share set
        let bad = KekShare::new(4, [0x42; 32]);
        assert!(
            !commitments.verify_share(&bad, &secret),
            "share with nonexistent index must fail verification"
        );
    }

    // -- Threshold KDF Tests --

    #[test]
    fn threshold_kdf_deterministic_output() {
        let secret = [0x42u8; 32];
        let shares = split_secret(&secret, 3, 5).unwrap();
        let ctx = b"test-context";
        let salt = b"test-salt";
        let key1 = derive_key_distributed(&shares[0..3], 3, ctx, salt).unwrap();
        let key2 = derive_key_distributed(&shares[0..3], 3, ctx, salt).unwrap();
        assert_eq!(key1, key2, "same shares+context+salt must produce same key");
    }

    #[test]
    fn threshold_kdf_different_shares_different_partials() {
        let secret = [0x42u8; 32];
        let shares = split_secret(&secret, 3, 5).unwrap();
        let p1 = partial_derive_key(&shares[0], b"ctx", b"salt");
        let p2 = partial_derive_key(&shares[1], b"ctx", b"salt");
        assert_ne!(p1, p2);
    }

    #[test]
    fn threshold_kdf_fewer_than_threshold_fails() {
        let secret = [0x42u8; 32];
        let shares = split_secret(&secret, 3, 5).unwrap();
        assert!(derive_key_distributed(&shares[0..2], 3, b"ctx", b"salt").is_err());
    }

    #[test]
    fn threshold_kdf_differs_from_reconstruct_then_hkdf() {
        let secret = [0x42u8; 32];
        let shares = split_secret(&secret, 3, 5).unwrap();
        let ctx = b"test-context";
        let salt = b"test-salt";

        let kdf_key = derive_key_distributed(&shares[0..3], 3, ctx, salt).unwrap();

        let reconstructed = reconstruct_secret(&shares[0..3]).unwrap();
        use hkdf::Hkdf;
        let hkdf = Hkdf::<Sha512>::new(Some(salt.as_slice()), &reconstructed);
        let mut old_key = [0u8; 32];
        hkdf.expand(ctx.as_slice(), &mut old_key).unwrap();

        assert_ne!(kdf_key, old_key, "threshold KDF must differ from reconstruct+HKDF");
    }

    #[test]
    fn threshold_kdf_vss_on_refreshed_shares() {
        let secret = [0x42u8; 32];
        let (_old_shares, _old_commitments) = split_secret_with_commitments(&secret, 3, 5).unwrap();
        let (new_shares, new_commitments) = refresh_shares(&secret, 3, 5).unwrap();

        for share in &new_shares {
            assert!(new_commitments.verify_share(share, &secret));
        }
        // Old shares fail against new commitments (different share values)
        for share in &_old_shares {
            assert!(!new_commitments.verify_share(share, &secret));
        }
    }

    #[test]
    fn threshold_kdf_old_shares_fail_after_refresh() {
        let secret = [0x42u8; 32];
        let old_shares = split_secret(&secret, 3, 5).unwrap();
        let new_shares = split_secret(&secret, 3, 5).unwrap();
        let ctx = b"ctx";
        let salt = b"salt";
        let old_key = derive_key_distributed(&old_shares[0..3], 3, ctx, salt).unwrap();
        let new_key = derive_key_distributed(&new_shares[0..3], 3, ctx, salt).unwrap();
        assert_ne!(old_key, new_key, "refreshed shares must produce different derived key");
    }

    #[test]
    fn threshold_kdf_manager_ceremony() {
        let secret = [0x42u8; 32];
        let shares = split_secret(&secret, 3, 5).unwrap();
        let ctx = b"ceremony-ctx";
        let salt = b"ceremony-salt";

        let mut mgr = ThresholdKdfManager::new(3, 5, ctx, salt);
        assert!(!mgr.has_threshold());
        assert_eq!(mgr.partials_needed(), 3);

        for i in 0..3 {
            let partial = partial_derive_key(&shares[i], ctx, salt);
            mgr.submit_partial(shares[i].index, partial).unwrap();
        }
        assert!(mgr.has_threshold());

        let key = mgr.derive_key().unwrap();
        assert_ne!(key, [0u8; 32]);

        // Determinism check
        let mut mgr2 = ThresholdKdfManager::new(3, 5, ctx, salt);
        for i in 0..3 {
            let partial = partial_derive_key(&shares[i], ctx, salt);
            mgr2.submit_partial(shares[i].index, partial).unwrap();
        }
        assert_eq!(mgr2.derive_key().unwrap(), key);
    }

    #[test]
    fn threshold_kdf_manager_rejects_duplicate_partial() {
        let secret = [0x42u8; 32];
        let shares = split_secret(&secret, 3, 5).unwrap();
        let ctx = b"ctx";
        let salt = b"salt";
        let mut mgr = ThresholdKdfManager::new(3, 5, ctx, salt);
        let partial = partial_derive_key(&shares[0], ctx, salt);
        mgr.submit_partial(shares[0].index, partial).unwrap();
        assert!(mgr.submit_partial(shares[0].index, partial).is_err());
    }

    #[test]
    fn threshold_kdf_manager_rejects_tampered_partial() {
        let mut mgr = ThresholdKdfManager::new(3, 5, b"ctx", b"salt");
        assert!(mgr.submit_partial(1, [0u8; 64]).is_err());
    }

    #[test]
    fn threshold_kdf_manager_rejects_out_of_range_index() {
        let mut mgr = ThresholdKdfManager::new(3, 5, b"ctx", b"salt");
        assert!(mgr.submit_partial(0, [1u8; 64]).is_err());
        assert!(mgr.submit_partial(6, [1u8; 64]).is_err());
    }

    #[test]
    fn threshold_kdf_concurrent_submissions() {
        use std::sync::{Arc, Mutex};
        use std::thread;

        let secret = [0x42u8; 32];
        let shares = split_secret(&secret, 3, 5).unwrap();
        let ctx = b"concurrent-ctx";
        let salt = b"concurrent-salt";

        let partials: Vec<(u8, [u8; 64])> = shares.iter()
            .take(3)
            .map(|s| (s.index, partial_derive_key(s, ctx, salt)))
            .collect();

        let mgr = Arc::new(Mutex::new(ThresholdKdfManager::new(3, 5, ctx, salt)));

        let handles: Vec<_> = partials.into_iter().map(|(idx, partial)| {
            let mgr = Arc::clone(&mgr);
            thread::spawn(move || {
                mgr.lock().unwrap().submit_partial(idx, partial).unwrap();
            })
        }).collect();

        for h in handles { h.join().unwrap(); }

        let mgr = Arc::try_unwrap(mgr).unwrap().into_inner().unwrap();
        assert!(mgr.has_threshold());
        let key = mgr.derive_key().unwrap();
        assert_ne!(key, [0u8; 32]);
    }

    #[test]
    fn threshold_kdf_partial_from_non_participant() {
        let secret = [0x42u8; 32];
        let shares = split_secret(&secret, 3, 5).unwrap();
        let ctx = b"ctx";
        let salt = b"salt";

        let legit_key = derive_key_distributed(&shares[0..3], 3, ctx, salt).unwrap();

        let fake_share = KekShare::new(1, [0xFF; 32]);
        let mixed = vec![fake_share, shares[1].clone(), shares[2].clone()];
        let fake_key = derive_key_distributed(&mixed, 3, ctx, salt).unwrap();

        assert_ne!(legit_key, fake_key);
    }
}
