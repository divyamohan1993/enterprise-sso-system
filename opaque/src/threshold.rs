//! Threshold OPAQUE: 2-of-3 distributed password authentication.
//!
//! # Status: NOT production-ready — combiner disabled (fail-closed)
//!
//! The intended design splits the OPRF key into 3 Shamir shares, one per
//! OPAQUE server, so registration and login require 2-of-3 cooperation and no
//! single server can reconstruct the key. The Shamir split/reconstruct and
//! GF(256) arithmetic below are correct and tested.
//!
//! However, the *combiner* ([`ThresholdOpaqueCoordinator::combine_evaluations_for_input`])
//! was found unsound by the 2026-04-30 security audit: it XORed independent
//! `HMAC(share_i, input)` values, which is **not** a threshold OPRF (HMAC is
//! not homomorphic, so different server subsets produce different outputs and
//! 2-of-3 login cannot complete). It now fails closed. A correct construction
//! is a DH-OPRF combining `share_i · H(input)` group elements with Lagrange
//! coefficients in the exponent; that, plus a real key ceremony and an
//! orchestrator, is out of scope for the current hardening pass.
//!
//! Threshold OPAQUE mode is therefore disabled at the service entry point —
//! the service runs single-server OPAQUE. This module is retained for the
//! sound Shamir primitives and so the correct combiner has a home when it
//! lands; the proof-of-concept combiner / register / authenticate paths
//! return an explicit error rather than a wrong result.

use hmac::{Hmac, Mac};
use sha2::Sha512;
use zeroize::{Zeroize, ZeroizeOnDrop};
use serde::{Serialize, Deserialize};

/// Zeroize-on-drop wrapper for Shamir polynomial coefficients.
///
/// SECURITY: B4 — coefficients carry the secret share polynomial; if a panic
/// unwinds shamir_split they must be wiped before stack memory is released.
/// `ZeroizeOnDrop` ensures the inner Vec is wiped on every exit path including
/// panic unwind.
#[derive(Zeroize, ZeroizeOnDrop)]
struct PolyCoeffs(Vec<u8>);

impl PolyCoeffs {
    fn new(len: usize) -> Self {
        Self(vec![0u8; len])
    }
    fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl core::ops::Deref for PolyCoeffs {
    type Target = [u8];
    fn deref(&self) -> &[u8] { &self.0 }
}

impl core::ops::DerefMut for PolyCoeffs {
    fn deref_mut(&mut self) -> &mut [u8] { &mut self.0 }
}

// ---------------------------------------------------------------------------
// GF(256) arithmetic — irreducible polynomial x^8 + x^4 + x^3 + x + 1 (0x11B)
// ---------------------------------------------------------------------------

/// Addition in GF(256) is XOR.
#[inline]
fn gf256_add(a: u8, b: u8) -> u8 {
    a ^ b
}

/// Subtraction in GF(256) is also XOR (additive inverse = identity in char 2).
#[inline]
fn gf256_sub(a: u8, b: u8) -> u8 {
    a ^ b
}

/// Constant-time multiplication in GF(256).
/// Irreducible polynomial: x^8 + x^4 + x^3 + x + 1 = 0x11B.
///
/// SECURITY: Always iterates exactly 8 times and uses bitwise masking
/// instead of data-dependent branches. Prevents timing side-channels
/// that could leak Shamir share coefficients to an attacker with
/// precise timing measurement (e.g., co-located VM, cache timing).
fn gf256_mul(mut a: u8, b: u8) -> u8 {
    let mut result: u8 = 0;
    for i in 0..8u8 {
        // Constant-time conditional XOR: mask is 0xFF if bit i of b is set, else 0x00
        let mask = 0u8.wrapping_sub((b >> i) & 1);
        result ^= a & mask;
        // Constant-time conditional reduction: mask is 0xFF if high bit of a is set
        let reduce_mask = 0u8.wrapping_sub((a >> 7) & 1);
        a = (a << 1) ^ (0x1B & reduce_mask);
    }
    result
}

/// Multiplicative inverse in GF(256) via Fermat's little theorem: a^(-1) = a^254.
fn gf256_inv(a: u8) -> u8 {
    assert_ne!(a, 0, "cannot invert zero in GF(256)");
    // a^254 = a^(2^8 - 2) = a^(-1) in GF(256)
    let mut result = a;
    // Square-and-multiply for a^254
    // 254 = 11111110 in binary
    for _ in 0..6 {
        result = gf256_mul(result, result);
        result = gf256_mul(result, a);
    }
    result = gf256_mul(result, result); // final square without multiply (bit 0 is 0)
    result
}

// ---------------------------------------------------------------------------
// Shamir Secret Sharing over GF(256)
// ---------------------------------------------------------------------------

/// Split a 32-byte secret into `total` shares with threshold `threshold`.
///
/// Each byte of the secret is independently split using a random polynomial
/// of degree `threshold - 1` over GF(256). Shares are evaluated at points
/// 1, 2, ..., total (never at 0, since f(0) = secret).
fn shamir_split(secret: &[u8; 32], threshold: u8, total: u8) -> Vec<OprfShare> {
    assert!(threshold >= 2, "threshold must be at least 2");
    assert!(total >= threshold, "total must be >= threshold");
    assert!((total as u16) <= 255, "total must fit in GF(256) non-zero elements");

    let mut shares: Vec<OprfShare> = (1..=total)
        .map(|id| OprfShare {
            server_id: id,
            share_value: [0u8; 32],
        })
        .collect();

    // For each byte position, create a random polynomial and evaluate.
    // SECURITY (B4): PolyCoeffs is `ZeroizeOnDrop` — the secret-bearing
    // coefficients are wiped on every exit path, including panic unwind.
    let mut coefficients = PolyCoeffs::new(threshold as usize);
    for byte_idx in 0..32 {
        // coefficient[0] = secret byte (the constant term)
        coefficients[0] = secret[byte_idx];

        // Random coefficients for degrees 1..threshold-1
        getrandom::getrandom(&mut coefficients.as_mut_slice()[1..]).unwrap_or_else(|e| {
            tracing::error!("FATAL: CSPRNG failure in OPAQUE threshold sharing: {e}");
            std::process::exit(1);
        });

        // Evaluate polynomial at each server's x-coordinate
        for share in shares.iter_mut() {
            let x = share.server_id;
            let mut y = coefficients[0];
            let mut x_pow = x; // x^1
            for coeff in &coefficients[1..] {
                y = gf256_add(y, gf256_mul(*coeff, x_pow));
                x_pow = gf256_mul(x_pow, x);
            }
            share.share_value[byte_idx] = y;
        }
    }

    // PolyCoeffs Drop runs here — explicit drop documents the wipe.
    drop(coefficients);

    shares
}

/// Reconstruct a 32-byte secret from at least `threshold` shares using
/// Lagrange interpolation over GF(256).
fn shamir_reconstruct(shares: &[&OprfShare], _threshold: u8) -> [u8; 32] {
    assert!(shares.len() >= 2, "need at least 2 shares for reconstruction");

    let mut secret = [0u8; 32];
    let n = shares.len();

    for byte_idx in 0..32 {
        let mut value: u8 = 0;

        for i in 0..n {
            let xi = shares[i].server_id;
            let yi = shares[i].share_value[byte_idx];

            // Compute Lagrange basis polynomial L_i(0)
            // L_i(0) = product_{j != i} (0 - x_j) / (x_i - x_j)
            //         = product_{j != i} x_j / (x_i - x_j)
            // In GF(256), subtraction = XOR, negation = identity
            let mut numerator: u8 = 1;
            let mut denominator: u8 = 1;
            for j in 0..n {
                if i == j {
                    continue;
                }
                let xj = shares[j].server_id;
                numerator = gf256_mul(numerator, xj);           // 0 - xj = xj in GF(256)
                denominator = gf256_mul(denominator, gf256_sub(xi, xj)); // xi - xj
            }

            let lagrange_coeff = gf256_mul(numerator, gf256_inv(denominator));
            value = gf256_add(value, gf256_mul(yi, lagrange_coeff));
        }

        secret[byte_idx] = value;
    }

    secret
}

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

/// Shamir share of the OPRF key.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct OprfShare {
    /// Server identifier (1-indexed).
    server_id: u8,
    /// The Shamir share value (32 bytes).
    share_value: [u8; 32],
}

impl OprfShare {
    /// Returns the server identifier for this share.
    pub fn server_id(&self) -> u8 {
        self.server_id
    }
}

/// Configuration for a threshold OPAQUE deployment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdOpaqueConfig {
    /// Number of shares required to reconstruct (threshold).
    pub threshold: u8,
    /// Total number of servers holding shares.
    pub total_servers: u8,
    /// Server identifier for this node (0 for coordinator).
    pub server_id: u8,
}

/// A single threshold OPAQUE server node.
pub struct ThresholdOpaqueServer {
    config: ThresholdOpaqueConfig,
    /// This server's share of the OPRF key.
    oprf_share: OprfShare,
}

/// Coordinator that combines partial OPRF evaluations from threshold servers.
/// The coordinator does NOT hold any key material.
pub struct ThresholdOpaqueCoordinator {
    config: ThresholdOpaqueConfig,
}

/// Partial OPRF evaluation from a single server.
#[derive(Clone, Serialize, Deserialize)]
pub struct PartialOprfEvaluation {
    pub server_id: u8,
    pub evaluation: Vec<u8>,
    /// HMAC proof that this evaluation is authentic.
    pub proof: [u8; 32],
}

/// Result of threshold OPRF key generation.
pub struct ThresholdOprfKeygenResult {
    /// The shares to distribute to servers (one per server).
    pub shares: Vec<OprfShare>,
    /// Public verification key (can be shared publicly).
    pub verification_key: [u8; 32],
}

// ---------------------------------------------------------------------------
// Key generation
// ---------------------------------------------------------------------------

/// Generate a random OPRF master key, split it via Shamir, and return shares.
///
/// The master key is zeroized after splitting — it is NEVER persisted.
/// The verification key is HMAC-SHA512(master_key, "threshold-opaque-verification") truncated to 32 bytes (CNSA 2.0).
pub fn generate_threshold_oprf_key(threshold: u8, total: u8) -> ThresholdOprfKeygenResult {
    // Generate random master key
    let mut master_key = [0u8; 32];
    getrandom::getrandom(&mut master_key).unwrap_or_else(|e| {
        tracing::error!("FATAL: CSPRNG failure in threshold OPRF keygen: {e}");
        std::process::exit(1);
    });

    // Derive a public verification key before splitting (CNSA 2.0: HMAC-SHA512)
    let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(&master_key)
        .unwrap_or_else(|e| {
            tracing::error!("FATAL: HMAC-SHA512 key init failed in threshold OPRF: {e}");
            std::process::exit(1);
        });
    mac.update(b"threshold-opaque-verification-v2");
    let full = mac.finalize().into_bytes();
    let mut verification_key = [0u8; 32];
    verification_key.copy_from_slice(&full[..32]);

    // Split the master key into Shamir shares
    let shares = shamir_split(&master_key, threshold, total);

    // Zeroize master key — it must never be persisted
    master_key.zeroize();

    ThresholdOprfKeygenResult {
        shares,
        verification_key,
    }
}

// ---------------------------------------------------------------------------
// Server (partial evaluator)
// ---------------------------------------------------------------------------

impl ThresholdOpaqueServer {
    /// Create a new threshold OPAQUE server node.
    pub fn new(config: ThresholdOpaqueConfig, oprf_share: OprfShare) -> Self {
        Self { config, oprf_share }
    }

    /// Compute a partial OPRF evaluation using this server's share.
    ///
    /// The "evaluation" carries this server's Shamir share value so that the
    /// coordinator can reconstruct the OPRF key transiently. The proof is
    /// HMAC-SHA512(share_value, blinded_element || server_id) — it binds the
    /// share to the specific request, proving the server actually holds the
    /// share and processed this exact input (CNSA 2.0).
    ///
    /// In production, the share would be encrypted in transit via mTLS/SHARD.
    pub fn partial_evaluate(&self, blinded_element: &[u8]) -> PartialOprfEvaluation {
        // Compute HMAC-SHA512(share_value, blinded_element) as the partial evaluation.
        // This ensures the raw share is NEVER transmitted — only the evaluation
        // output leaves this node. The coordinator combines evaluations, not shares.
        let mut eval_mac = <Hmac<Sha512> as Mac>::new_from_slice(&self.oprf_share.share_value)
            .unwrap_or_else(|e| {
                tracing::error!("FATAL: HMAC-SHA512 key init failed in partial_evaluate: {e}");
                std::process::exit(1);
            });
        eval_mac.update(blinded_element);
        let evaluation: Vec<u8> = eval_mac.finalize().into_bytes().to_vec();

        // Authentication proof: HMAC-SHA512(share, blinded_element || server_id)
        let mut proof_mac = <Hmac<Sha512> as Mac>::new_from_slice(&self.oprf_share.share_value)
            .unwrap_or_else(|e| {
                tracing::error!("FATAL: HMAC-SHA512 key init failed in partial_evaluate proof: {e}");
                std::process::exit(1);
            });
        proof_mac.update(blinded_element);
        proof_mac.update(&[self.oprf_share.server_id]);
        let full_proof = proof_mac.finalize().into_bytes();
        let mut proof = [0u8; 32];
        proof.copy_from_slice(&full_proof[..32]);

        PartialOprfEvaluation {
            server_id: self.oprf_share.server_id,
            evaluation,
            proof,
        }
    }

    /// Return the server's configuration.
    pub fn config(&self) -> &ThresholdOpaqueConfig {
        &self.config
    }
}

// ---------------------------------------------------------------------------
// Coordinator (combiner — holds NO key material)
// ---------------------------------------------------------------------------

impl ThresholdOpaqueCoordinator {
    /// Create a new coordinator (no key material needed).
    pub fn new(config: ThresholdOpaqueConfig) -> Self {
        Self { config }
    }

    /// **DISABLED.** Always returns an error — see
    /// [`combine_evaluations_for_input`](Self::combine_evaluations_for_input).
    pub fn combine_evaluations(
        &self,
        partials: &[PartialOprfEvaluation],
    ) -> Result<Vec<u8>, String> {
        self.combine_evaluations_for_input(partials, b"threshold-opaque-combine")
    }

    /// **DISABLED (fail-closed).** Always returns an error.
    ///
    /// # Why
    ///
    /// The previous implementation XORed independent `HMAC(share_i, input)`
    /// values and HKDF'd the result. That is **not** a threshold OPRF: HMAC is
    /// not homomorphic, so there is no algebraic relationship between the XOR
    /// of per-share HMACs and `HMAC(master_key, input)`. Different server
    /// subsets ({1,2} vs {2,3}) yield **different** outputs, so a user who
    /// registered against one subset cannot authenticate against another —
    /// the construction silently breaks 2-of-3 login.
    ///
    /// A correct threshold OPRF must produce the **same** output for any
    /// qualified subset. The standard construction is a DH-OPRF: each server
    /// returns `share_i · H(input)` (a group element), and the coordinator
    /// combines with Lagrange coefficients *in the exponent*
    /// (`Σ λ_i · (share_i · H) = (Σ λ_i·share_i)·H = k·H`). Implementing that
    /// correctly requires ristretto255 group operations, a real key ceremony,
    /// and an orchestrator — out of scope for the current hardening pass and
    /// not something to home-grow unreviewed.
    ///
    /// Per the project security posture, this combiner now fails closed rather
    /// than returning a wrong "OPRF output". Threshold OPAQUE mode is disabled
    /// at the service entry point (`run_threshold_mode`); use single mode.
    pub fn combine_evaluations_for_input(
        &self,
        _partials: &[PartialOprfEvaluation],
        _input: &[u8],
    ) -> Result<Vec<u8>, String> {
        Err(
            "threshold OPRF combine is disabled: the XOR-of-HMACs construction \
             is not a valid Shamir-based threshold PRF (inconsistent output \
             across server subsets). A correct DH-OPRF is required — see \
             opaque::threshold docs."
                .to_string(),
        )
    }

    /// Distributed user registration.
    ///
    /// **DISABLED (fail-closed):** delegates to the disabled combiner and
    /// therefore always returns an error. See
    /// [`combine_evaluations_for_input`](Self::combine_evaluations_for_input).
    pub fn register_user(
        &self,
        blinded_element: &[u8],
        servers: &[&ThresholdOpaqueServer],
    ) -> Result<Vec<u8>, String> {
        if (servers.len() as u8) < self.config.threshold {
            return Err(format!(
                "need at least {} servers for registration, got {}",
                self.config.threshold,
                servers.len()
            ));
        }

        let partials: Vec<PartialOprfEvaluation> = servers
            .iter()
            .map(|s| s.partial_evaluate(blinded_element))
            .collect();

        self.combine_evaluations_for_input(&partials, blinded_element)
    }

    /// Distributed user authentication.
    ///
    /// **DISABLED (fail-closed):** delegates to the disabled combiner and
    /// therefore always returns an error. See
    /// [`combine_evaluations_for_input`](Self::combine_evaluations_for_input).
    pub fn authenticate_user(
        &self,
        blinded_element: &[u8],
        servers: &[&ThresholdOpaqueServer],
    ) -> Result<Vec<u8>, String> {
        if (servers.len() as u8) < self.config.threshold {
            return Err(format!(
                "need at least {} servers for authentication, got {}",
                self.config.threshold,
                servers.len()
            ));
        }

        let partials: Vec<PartialOprfEvaluation> = servers
            .iter()
            .map(|s| s.partial_evaluate(blinded_element))
            .collect();

        self.combine_evaluations_for_input(&partials, blinded_element)
    }

    /// Return the coordinator's configuration.
    pub fn config(&self) -> &ThresholdOpaqueConfig {
        &self.config
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- GF(256) arithmetic tests --

    #[test]
    fn test_gf256_add_identity() {
        assert_eq!(gf256_add(0, 0), 0);
        assert_eq!(gf256_add(42, 0), 42);
        assert_eq!(gf256_add(0, 42), 42);
    }

    #[test]
    fn test_gf256_add_self_inverse() {
        // a + a = 0 in GF(256)
        for a in 0..=255u8 {
            assert_eq!(gf256_add(a, a), 0);
        }
    }

    #[test]
    fn test_gf256_mul_identity() {
        assert_eq!(gf256_mul(1, 1), 1);
        assert_eq!(gf256_mul(42, 1), 42);
        assert_eq!(gf256_mul(1, 42), 42);
    }

    #[test]
    fn test_gf256_mul_zero() {
        assert_eq!(gf256_mul(0, 42), 0);
        assert_eq!(gf256_mul(42, 0), 0);
    }

    #[test]
    fn test_gf256_mul_commutative() {
        for a in 1..=255u8 {
            for b in 1..=255u8 {
                assert_eq!(gf256_mul(a, b), gf256_mul(b, a), "commutativity failed for ({a}, {b})");
            }
        }
    }

    #[test]
    fn test_gf256_inv_roundtrip() {
        // a * a^(-1) = 1 for all non-zero a
        for a in 1..=255u8 {
            let inv = gf256_inv(a);
            assert_eq!(gf256_mul(a, inv), 1, "inverse failed for {a}");
        }
    }

    #[test]
    fn test_gf256_known_values() {
        // 2 * 2 = 4 (no reduction needed)
        assert_eq!(gf256_mul(2, 2), 4);
        // 0x80 * 2 should trigger reduction: 0x100 ^ 0x1B = 0x1B
        assert_eq!(gf256_mul(0x80, 2), 0x1B);
    }

    // -- Shamir Secret Sharing tests --

    #[test]
    fn test_shamir_split_reconstruct_roundtrip() {
        let secret = [42u8; 32];
        let shares = shamir_split(&secret, 2, 3);
        assert_eq!(shares.len(), 3);

        // Any 2 of 3 shares should reconstruct the secret
        let reconstructed = shamir_reconstruct(&[&shares[0], &shares[1]], 2);
        assert_eq!(reconstructed, secret);

        let reconstructed2 = shamir_reconstruct(&[&shares[0], &shares[2]], 2);
        assert_eq!(reconstructed2, secret);

        let reconstructed3 = shamir_reconstruct(&[&shares[1], &shares[2]], 2);
        assert_eq!(reconstructed3, secret);
    }

    #[test]
    fn test_shamir_split_reconstruct_random_secret() {
        let mut secret = [0u8; 32];
        getrandom::getrandom(&mut secret).unwrap();

        let shares = shamir_split(&secret, 2, 3);

        // All 3 pairwise combinations
        let r01 = shamir_reconstruct(&[&shares[0], &shares[1]], 2);
        let r02 = shamir_reconstruct(&[&shares[0], &shares[2]], 2);
        let r12 = shamir_reconstruct(&[&shares[1], &shares[2]], 2);

        assert_eq!(r01, secret);
        assert_eq!(r02, secret);
        assert_eq!(r12, secret);
    }

    #[test]
    fn test_shamir_3_of_5() {
        let secret = [0xAB; 32];
        let shares = shamir_split(&secret, 3, 5);
        assert_eq!(shares.len(), 5);

        // Any 3 of 5 should reconstruct
        let r = shamir_reconstruct(&[&shares[0], &shares[2], &shares[4]], 3);
        assert_eq!(r, secret);

        let r2 = shamir_reconstruct(&[&shares[1], &shares[3], &shares[4]], 3);
        assert_eq!(r2, secret);
    }

    #[test]
    fn test_shamir_single_share_insufficient() {
        // 1 share should NOT be enough for threshold=2
        // We verify that a single share's value differs from the secret
        let secret = [42u8; 32];
        let shares = shamir_split(&secret, 2, 3);

        // Each individual share should not equal the secret
        // (with overwhelming probability for random coefficients)
        let all_match = shares.iter().all(|s| s.share_value == secret);
        assert!(!all_match, "shares should not trivially equal the secret");
    }

    #[test]
    fn test_shamir_shares_are_distinct() {
        let secret = [42u8; 32];
        let shares = shamir_split(&secret, 2, 3);

        // All shares should be pairwise distinct
        assert_ne!(shares[0].share_value, shares[1].share_value);
        assert_ne!(shares[0].share_value, shares[2].share_value);
        assert_ne!(shares[1].share_value, shares[2].share_value);
    }

    // -- Threshold keygen tests --

    #[test]
    fn test_threshold_keygen() {
        let result = generate_threshold_oprf_key(2, 3);
        assert_eq!(result.shares.len(), 3);
        assert_ne!(result.verification_key, [0u8; 32]);
    }

    #[test]
    fn test_threshold_keygen_shares_reconstruct() {
        // The shares should reconstruct the original master key (verified
        // indirectly through the verification key).
        let result = generate_threshold_oprf_key(2, 3);

        // Reconstruct the master key from any 2 shares
        let mk1 = shamir_reconstruct(&[&result.shares[0], &result.shares[1]], 2);
        let mk2 = shamir_reconstruct(&[&result.shares[0], &result.shares[2]], 2);
        let mk3 = shamir_reconstruct(&[&result.shares[1], &result.shares[2]], 2);

        // All reconstructions should be the same
        assert_eq!(mk1, mk2);
        assert_eq!(mk2, mk3);

        // Verify the reconstructed key produces the same verification key (HMAC-SHA512)
        let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(&mk1).unwrap();
        mac.update(b"threshold-opaque-verification-v2");
        let full = mac.finalize().into_bytes();
        let mut vk = [0u8; 32];
        vk.copy_from_slice(&full[..32]);
        assert_eq!(vk, result.verification_key);
    }

    // -- Partial evaluation tests --

    #[test]
    fn test_partial_evaluation() {
        let result = generate_threshold_oprf_key(2, 3);
        let server = ThresholdOpaqueServer::new(
            ThresholdOpaqueConfig { threshold: 2, total_servers: 3, server_id: 1 },
            result.shares[0].clone(),
        );
        let eval = server.partial_evaluate(b"test-blinded-element");
        assert_eq!(eval.server_id, 1);
        assert!(!eval.evaluation.is_empty());
        assert_eq!(eval.evaluation.len(), 64); // HMAC-SHA512 output (CNSA 2.0)
    }

    #[test]
    fn test_partial_evaluation_deterministic() {
        let result = generate_threshold_oprf_key(2, 3);
        let server = ThresholdOpaqueServer::new(
            ThresholdOpaqueConfig { threshold: 2, total_servers: 3, server_id: 1 },
            result.shares[0].clone(),
        );
        let eval1 = server.partial_evaluate(b"test-input");
        let eval2 = server.partial_evaluate(b"test-input");
        assert_eq!(eval1.evaluation, eval2.evaluation);
        assert_eq!(eval1.proof, eval2.proof);
    }

    #[test]
    fn test_partial_evaluation_different_inputs_different_evaluations() {
        // Each partial evaluation is HMAC(share, input), so different inputs
        // produce different evaluations from the same server.
        let result = generate_threshold_oprf_key(2, 3);
        let server = ThresholdOpaqueServer::new(
            ThresholdOpaqueConfig { threshold: 2, total_servers: 3, server_id: 1 },
            result.shares[0].clone(),
        );
        let eval1 = server.partial_evaluate(b"input-a");
        let eval2 = server.partial_evaluate(b"input-b");
        // Evaluations differ because they are HMAC(share, different_input)
        assert_ne!(eval1.evaluation, eval2.evaluation);
        // Proofs also differ because they bind to the input
        assert_ne!(eval1.proof, eval2.proof);
    }

    // -- Combine evaluations tests (combiner is disabled fail-closed) --

    #[test]
    fn test_combine_evaluations_disabled_fail_closed() {
        // SECURITY: the XOR-of-HMACs combiner was unsound; combine must now
        // refuse rather than return a wrong "OPRF output".
        let result = generate_threshold_oprf_key(2, 3);
        let servers: Vec<ThresholdOpaqueServer> = result.shares.iter().enumerate().map(|(i, share)| {
            ThresholdOpaqueServer::new(
                ThresholdOpaqueConfig { threshold: 2, total_servers: 3, server_id: (i + 1) as u8 },
                share.clone(),
            )
        }).collect();
        let coordinator = ThresholdOpaqueCoordinator::new(
            ThresholdOpaqueConfig { threshold: 2, total_servers: 3, server_id: 0 },
        );
        let evals = vec![
            servers[0].partial_evaluate(b"test-input"),
            servers[1].partial_evaluate(b"test-input"),
        ];
        assert!(
            coordinator.combine_evaluations(&evals).is_err(),
            "disabled combiner must return an error, never a forged output"
        );
    }

    // -- Distributed registration / authentication (disabled fail-closed) --

    #[test]
    fn test_register_and_authenticate_disabled_fail_closed() {
        let result = generate_threshold_oprf_key(2, 3);
        let servers: Vec<ThresholdOpaqueServer> = result.shares.iter().enumerate().map(|(i, share)| {
            ThresholdOpaqueServer::new(
                ThresholdOpaqueConfig { threshold: 2, total_servers: 3, server_id: (i + 1) as u8 },
                share.clone(),
            )
        }).collect();
        let coordinator = ThresholdOpaqueCoordinator::new(
            ThresholdOpaqueConfig { threshold: 2, total_servers: 3, server_id: 0 },
        );
        let server_refs: Vec<&ThresholdOpaqueServer> = servers.iter().take(2).collect();
        assert!(
            coordinator.register_user(b"blinded-pw", &server_refs).is_err(),
            "register_user must fail closed while threshold OPRF is disabled"
        );
        assert!(
            coordinator.authenticate_user(b"blinded-pw", &server_refs).is_err(),
            "authenticate_user must fail closed while threshold OPRF is disabled"
        );
    }

    #[test]
    fn test_master_key_never_persisted() {
        // After keygen, the master key should be gone — only shares exist.
        // We verify that shares reconstruct to a consistent value (proving
        // correctness) but no ThresholdOprfKeygenResult field exposes the
        // master key directly.
        let result = generate_threshold_oprf_key(2, 3);

        // The struct has no master_key field — only shares and verification_key.
        // This is a compile-time guarantee. We just verify the shares are valid.
        let mk = shamir_reconstruct(&[&result.shares[0], &result.shares[1]], 2);
        let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(&mk).unwrap();
        mac.update(b"threshold-opaque-verification-v2");
        let full = mac.finalize().into_bytes();
        let mut vk = [0u8; 32];
        vk.copy_from_slice(&full[..32]);
        assert_eq!(vk, result.verification_key, "shares must be consistent with verification key");
    }

    #[test]
    fn test_partial_evaluation_distinct_per_input() {
        // The per-server partial evaluation (HMAC over the input) is still a
        // sound deterministic function of (share, input) even though the
        // cross-server combiner is disabled. Different inputs differ.
        let result = generate_threshold_oprf_key(2, 3);
        let server = ThresholdOpaqueServer::new(
            ThresholdOpaqueConfig { threshold: 2, total_servers: 3, server_id: 1 },
            result.shares[0].clone(),
        );
        let eval_a = server.partial_evaluate(b"password-a");
        let eval_b = server.partial_evaluate(b"password-b");
        assert_ne!(eval_a.evaluation, eval_b.evaluation);
    }
}
