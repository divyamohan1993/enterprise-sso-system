//! Zero-Knowledge Proofs for MILNET SSO — **DISABLED (fail-closed)**.
//!
//! # Status: UNAVAILABLE
//!
//! This module previously shipped a home-grown "Schnorr-style" sigma protocol
//! built entirely on SHA-512 commitments. A security audit (2026-04-30) found
//! the construction to be **cryptographically unsound**:
//!
//! * `verify_range_gte` checked `commit(s_value, s_blinding) == V`, where the
//!   "verification commitment" `V` was itself supplied by the prover as
//!   `commit(s_value, s_blinding)`. The equality was therefore *true by
//!   construction* and tied to nothing — a forger could fabricate a valid
//!   proof with no knowledge of any value.
//! * `verify_audit_integrity` recomputed the Fiat-Shamir challenge into a
//!   discarded local and only checked a self-referential `proof_hash`,
//!   so any `(R, s_response)` pair passed verification.
//!
//! The root cause is structural, not a bug: SHA-512 commitments are **not
//! homomorphic**. A Schnorr/sigma protocol requires a group in which the
//! verifier can compute `commit(s) == R · commit(x)^c`. There is no `·` or
//! `^` on hash digests, so a sound proof of knowledge of a committed value
//! cannot be built from `commit() = SHA-512(...)` alone. A correct range
//! proof needs either a Pedersen commitment over an elliptic-curve group with
//! a real Bulletproof, or a bit-decomposition commitment with a genuine
//! interactive (then Fiat-Shamir transformed) sigma protocol.
//!
//! Building a correct construction is out of scope for the current hardening
//! pass, and the project standard forbids shipping home-grown crypto that has
//! not been independently reviewed. Per the security posture "fail closed,
//! security wins", every verification entry point in this module now
//! **rejects unconditionally** and every prover entry point returns
//! [`ZkpUnavailable`]. No caller can obtain or rely on an unsound proof.
//!
//! These functions are intentionally retained (rather than deleted) so that
//! the API surface and any downstream `use` sites fail loudly and visibly,
//! instead of silently disappearing. When a reviewed ZK construction is
//! adopted (e.g. `bulletproofs` over `curve25519-dalek`, or `arkworks`), this
//! module is the single place to re-enable it.

use sha2::{Digest, Sha512};

/// Error returned by every prover entry point while the ZKP module is disabled.
///
/// The audit-blocked construction is unsound; callers must treat the absence
/// of a proof as a hard failure (fail-closed), never substitute a weaker check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZkpUnavailable;

impl core::fmt::Display for ZkpUnavailable {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(
            "zero-knowledge proofs are unavailable: the hash-based construction \
             was found unsound and is disabled fail-closed (see crypto::zkp docs)",
        )
    }
}

impl std::error::Error for ZkpUnavailable {}

impl From<ZkpUnavailable> for String {
    fn from(e: ZkpUnavailable) -> String {
        e.to_string()
    }
}

// ---------------------------------------------------------------------------
// Commitment primitive
// ---------------------------------------------------------------------------

/// Create a binding commitment to `value` using a 32-byte blinding factor.
///
/// `C = SHA-512("MILNET-ZKP-COMMIT-v1" || value_le64 || blinding)[..32]`
///
/// This is a sound *commitment* primitive (binding + hiding under the
/// random-oracle model) and remains available — it is used as a building
/// block elsewhere. It is **not**, on its own, a zero-knowledge proof: it
/// reveals nothing only because the opening is withheld. Knowledge of the
/// committed value cannot be proven from this primitive without a homomorphic
/// group structure, which is why the proof protocols below are disabled.
pub fn commit(value: u64, blinding: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha512::new();
    h.update(b"MILNET-ZKP-COMMIT-v1");
    h.update(value.to_le_bytes());
    h.update(blinding);
    let digest = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..32]);
    out
}

// ---------------------------------------------------------------------------
// Proof types (retained for API stability; never produced while disabled)
// ---------------------------------------------------------------------------

/// Proof that a committed value satisfies a range condition.
#[derive(Debug, Clone)]
pub struct RangeProof {
    /// Commitment to the value.
    pub commitment: [u8; 32],
    /// Sigma-protocol transcript bytes.
    pub proof_data: Vec<u8>,
    /// Public lower bound.
    pub min_value: u64,
    /// Public upper bound (`u64::MAX` means unbounded above).
    pub max_value: u64,
}

/// Classification clearance ZK proof: proves `level >= min_required`.
#[derive(Debug, Clone)]
pub struct ClassificationProof {
    pub commitment: [u8; 32],
    pub proof: Vec<u8>,
    pub min_required: u8,
}

/// Compliance attestation: proves `passed_count >= threshold`.
#[derive(Debug, Clone)]
pub struct ComplianceAttestation {
    pub commitment: [u8; 32],
    pub proof: Vec<u8>,
    pub total_checks: u32,
    pub threshold: u32,
}

/// Audit integrity proof: proves knowledge of chain root without revealing it.
#[derive(Debug, Clone)]
pub struct AuditIntegrityProof {
    pub commitment: [u8; 32],
    pub proof: Vec<u8>,
    pub chain_length: u64,
}

// ---------------------------------------------------------------------------
// Range proof: prove value >= min_value — DISABLED
// ---------------------------------------------------------------------------

/// **DISABLED.** Always returns [`ZkpUnavailable`].
///
/// The previous SHA-512 "Schnorr-like" range proof was unsound (a forger could
/// fabricate a valid proof with no knowledge of `value`). No proof is produced
/// until a reviewed construction replaces it. Callers must fail closed.
pub fn prove_range_gte(
    _value: u64,
    _min_value: u64,
    _blinding: &[u8; 32],
) -> Result<RangeProof, ZkpUnavailable> {
    Err(ZkpUnavailable)
}

/// **DISABLED.** Always returns `false` (fail-closed).
///
/// The hash-based verification was trivially satisfiable; rejecting every
/// proof is the only safe behaviour until a sound construction is adopted.
pub fn verify_range_gte(_proof: &RangeProof) -> bool {
    false
}

// ---------------------------------------------------------------------------
// Classification proof — DISABLED
// ---------------------------------------------------------------------------

/// **DISABLED.** Always returns [`ZkpUnavailable`]. See [`prove_range_gte`].
pub fn prove_classification_range(
    _level: u8,
    _min_required: u8,
    _blinding: &[u8; 32],
) -> Result<ClassificationProof, ZkpUnavailable> {
    Err(ZkpUnavailable)
}

/// **DISABLED.** Always returns `false` (fail-closed). See [`verify_range_gte`].
pub fn verify_classification_range(_proof: &ClassificationProof) -> bool {
    false
}

// ---------------------------------------------------------------------------
// Compliance attestation — DISABLED
// ---------------------------------------------------------------------------

/// **DISABLED.** Always returns [`ZkpUnavailable`]. See [`prove_range_gte`].
pub fn prove_compliance_threshold(
    _passed: u32,
    _total: u32,
    _threshold: u32,
    _blinding: &[u8; 32],
) -> Result<ComplianceAttestation, ZkpUnavailable> {
    Err(ZkpUnavailable)
}

/// **DISABLED.** Always returns `false` (fail-closed). See [`verify_range_gte`].
pub fn verify_compliance_threshold(_att: &ComplianceAttestation) -> bool {
    false
}

// ---------------------------------------------------------------------------
// Audit integrity proof — DISABLED
// ---------------------------------------------------------------------------

/// **DISABLED.** Always returns [`ZkpUnavailable`].
///
/// The previous "Schnorr-style" audit proof verified only a self-referential
/// `proof_hash`; any `(R, s_response)` pair passed. No proof is produced until
/// a reviewed construction replaces it.
pub fn prove_audit_integrity(
    _chain_root: &[u8; 64],
    _chain_length: u64,
    _blinding: &[u8; 32],
) -> Result<AuditIntegrityProof, ZkpUnavailable> {
    Err(ZkpUnavailable)
}

/// **DISABLED.** Always returns `false` (fail-closed). See [`prove_audit_integrity`].
pub fn verify_audit_integrity(_proof: &AuditIntegrityProof, _expected_length: u64) -> bool {
    false
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn random_blinding() -> [u8; 32] {
        let mut b = [0u8; 32];
        getrandom::getrandom(&mut b).expect("getrandom failed");
        b
    }

    #[test]
    fn commitment_is_deterministic() {
        let blinding = random_blinding();
        let c1 = commit(1234, &blinding);
        let c2 = commit(1234, &blinding);
        assert_eq!(c1, c2, "same value + blinding must produce identical commitment");
    }

    #[test]
    fn commitment_differs_with_blinding() {
        let b1 = random_blinding();
        let b2 = random_blinding();
        assert_ne!(
            commit(999, &b1),
            commit(999, &b2),
            "different blindings must produce different commitments"
        );
    }

    /// The disabled prover entry points must never hand back a proof.
    #[test]
    fn provers_are_disabled_fail_closed() {
        let blinding = random_blinding();
        assert!(prove_range_gte(100, 50, &blinding).is_err());
        assert!(prove_classification_range(4, 2, &blinding).is_err());
        assert!(prove_compliance_threshold(18, 24, 15, &blinding).is_err());
        assert!(prove_audit_integrity(&[0u8; 64], 42, &blinding).is_err());
    }

    /// Verification must reject every proof, including a hand-crafted one,
    /// so an attacker cannot smuggle an unsound transcript past the verifier.
    #[test]
    fn verifiers_reject_forged_proofs() {
        let forged_range = RangeProof {
            commitment: [0u8; 32],
            proof_data: vec![0u8; 200],
            min_value: 0,
            max_value: u64::MAX,
        };
        assert!(!verify_range_gte(&forged_range), "fail-closed: no range proof verifies");

        let forged_class = ClassificationProof {
            commitment: [0u8; 32],
            proof: vec![0u8; 200],
            min_required: 0,
        };
        assert!(!verify_classification_range(&forged_class));

        let forged_comp = ComplianceAttestation {
            commitment: [0u8; 32],
            proof: vec![0u8; 200],
            total_checks: 0,
            threshold: 0,
        };
        assert!(!verify_compliance_threshold(&forged_comp));

        let forged_audit = AuditIntegrityProof {
            commitment: [0u8; 32],
            proof: vec![0u8; 160],
            chain_length: 42,
        };
        assert!(!verify_audit_integrity(&forged_audit, 42));
    }
}
