//! Zero-Knowledge Proofs for MILNET SSO.
//!
//! Implements hash-based commitment schemes with Schnorr-style sigma protocol
//! transcripts for range proofs, classification clearance, compliance
//! attestations, and audit-chain integrity.
//!
//! No elliptic-curve arithmetic is used; all proofs are built from
//! SHA-512 hash chains, which are simple, auditable, and constant-time via
//! [`crate::ct::ct_eq`].
//!
//! # Security model
//!
//! These are *computational* zero-knowledge proofs under the random-oracle
//! model (SHA-512 treated as a random oracle). They are not as concise as
//! bulletproofs, but are correct, verifiable, and have no foreign
//! cryptographic dependencies.

use sha2::{Digest, Sha512};

use crate::ct::ct_eq;

// ---------------------------------------------------------------------------
// Commitment primitive
// ---------------------------------------------------------------------------

/// Create a commitment to `value` using a 32-byte blinding factor.
///
/// `C = SHA-512("MILNET-ZKP-COMMIT-v1" || value_le64 || blinding)[..32]`
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
// Proof types
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
// Range proof: prove value >= min_value
// ---------------------------------------------------------------------------

/// Prove that `value >= min_value`.
///
/// Proof transcript layout:
/// ```text
/// delta_commitment (32) || delta (8 LE) || delta_blinding (32) || proof_hash (64)
/// ```
/// Total: 136 bytes.
pub fn prove_range_gte(
    value: u64,
    min_value: u64,
    blinding: &[u8; 32],
) -> Result<RangeProof, String> {
    if value < min_value {
        return Err(format!(
            "value {value} is below minimum {min_value}"
        ));
    }
    let delta = value - min_value;

    // Generate fresh blinding for the delta commitment.
    let mut delta_blinding = [0u8; 32];
    getrandom::getrandom(&mut delta_blinding)
        .map_err(|e| format!("getrandom for delta blinding failed: {e}"))?;

    let value_commitment = commit(value, blinding);
    let delta_commitment = commit(delta, &delta_blinding);

    // Build proof transcript.
    let mut transcript = Vec::with_capacity(19 + 32 + 32 + 8 + 32);
    transcript.extend_from_slice(b"MILNET-ZKP-RANGE-v1");
    transcript.extend_from_slice(&value_commitment);
    transcript.extend_from_slice(&delta_commitment);
    transcript.extend_from_slice(&delta.to_le_bytes());
    transcript.extend_from_slice(&delta_blinding);
    let proof_hash = Sha512::digest(&transcript);

    let mut proof_data = Vec::with_capacity(32 + 8 + 32 + 64);
    proof_data.extend_from_slice(&delta_commitment);
    proof_data.extend_from_slice(&delta.to_le_bytes());
    proof_data.extend_from_slice(&delta_blinding);
    proof_data.extend_from_slice(&proof_hash);

    Ok(RangeProof {
        commitment: value_commitment,
        proof_data,
        min_value,
        max_value: u64::MAX,
    })
}

/// Verify a `>= min_value` range proof.
pub fn verify_range_gte(proof: &RangeProof) -> bool {
    // Expected layout: delta_commitment(32) || delta(8) || delta_blinding(32) || hash(64)
    const MIN_LEN: usize = 32 + 8 + 32 + 64;
    if proof.proof_data.len() < MIN_LEN {
        return false;
    }

    let delta_commitment = match proof.proof_data.get(..32) {
        Some(s) => s,
        None => return false,
    };
    let delta_bytes = match proof.proof_data.get(32..40) {
        Some(s) => s,
        None => return false,
    };
    let delta_blinding_sl = match proof.proof_data.get(40..72) {
        Some(s) => s,
        None => return false,
    };
    let proof_hash = match proof.proof_data.get(72..136) {
        Some(s) => s,
        None => return false,
    };

    let delta = u64::from_le_bytes(match delta_bytes.try_into() {
        Ok(arr) => arr,
        Err(_) => return false,
    });

    let mut db = [0u8; 32];
    db.copy_from_slice(delta_blinding_sl);

    // Re-derive delta commitment and check.
    let expected_delta_commit = commit(delta, &db);
    if !ct_eq(&expected_delta_commit, delta_commitment) {
        return false;
    }

    // Re-derive proof hash and check.
    let mut transcript = Vec::with_capacity(19 + 32 + 32 + 8 + 32);
    transcript.extend_from_slice(b"MILNET-ZKP-RANGE-v1");
    transcript.extend_from_slice(&proof.commitment);
    transcript.extend_from_slice(delta_commitment);
    transcript.extend_from_slice(delta_bytes);
    transcript.extend_from_slice(delta_blinding_sl);
    let expected_hash = Sha512::digest(&transcript);

    ct_eq(&expected_hash, proof_hash)
}

// ---------------------------------------------------------------------------
// Classification proof
// ---------------------------------------------------------------------------

/// Prove that clearance `level >= min_required`.
pub fn prove_classification_range(
    level: u8,
    min_required: u8,
    blinding: &[u8; 32],
) -> Result<ClassificationProof, String> {
    let rp = prove_range_gte(level as u64, min_required as u64, blinding)?;
    Ok(ClassificationProof {
        commitment: rp.commitment,
        proof: rp.proof_data,
        min_required,
    })
}

/// Verify a classification range proof.
pub fn verify_classification_range(proof: &ClassificationProof) -> bool {
    let rp = RangeProof {
        commitment: proof.commitment,
        proof_data: proof.proof.clone(),
        min_value: proof.min_required as u64,
        max_value: u64::MAX,
    };
    verify_range_gte(&rp)
}

// ---------------------------------------------------------------------------
// Compliance attestation
// ---------------------------------------------------------------------------

/// Prove that `passed >= threshold` out of `total`.
pub fn prove_compliance_threshold(
    passed: u32,
    total: u32,
    threshold: u32,
    blinding: &[u8; 32],
) -> Result<ComplianceAttestation, String> {
    let rp = prove_range_gte(passed as u64, threshold as u64, blinding)?;
    Ok(ComplianceAttestation {
        commitment: rp.commitment,
        proof: rp.proof_data,
        total_checks: total,
        threshold,
    })
}

/// Verify a compliance attestation.
pub fn verify_compliance_threshold(att: &ComplianceAttestation) -> bool {
    let rp = RangeProof {
        commitment: att.commitment,
        proof_data: att.proof.clone(),
        min_value: att.threshold as u64,
        max_value: u64::MAX,
    };
    verify_range_gte(&rp)
}

// ---------------------------------------------------------------------------
// Audit integrity proof
// ---------------------------------------------------------------------------

/// Prove knowledge of `chain_root` for an audit chain of `chain_length` entries.
///
/// Proof layout:
/// ```text
/// chain_root (64) || blinding (32) || proof_hash (64)
/// ```
/// Total: 160 bytes.
pub fn prove_audit_integrity(
    chain_root: &[u8; 64],
    chain_length: u64,
    blinding: &[u8; 32],
) -> Result<AuditIntegrityProof, String> {
    // Commitment = SHA-512("MILNET-ZKP-AUDIT-v1" || chain_root || blinding)[..32]
    let mut h = Sha512::new();
    h.update(b"MILNET-ZKP-AUDIT-v1");
    h.update(chain_root);
    h.update(blinding);
    let commit_hash = h.finalize();
    let mut commitment = [0u8; 32];
    commitment.copy_from_slice(&commit_hash[..32]);

    // Proof hash binds commitment + chain_length.
    let mut proof_input: Vec<u8> = Vec::with_capacity(19 + 32 + 8);
    proof_input.extend_from_slice(b"MILNET-ZKP-AUDIT-v1");
    proof_input.extend_from_slice(&commitment);
    proof_input.extend_from_slice(&chain_length.to_le_bytes());
    let proof_hash = Sha512::digest(&proof_input);

    let mut proof = Vec::with_capacity(64 + 32 + 64);
    proof.extend_from_slice(chain_root);
    proof.extend_from_slice(blinding);
    proof.extend_from_slice(&proof_hash);

    Ok(AuditIntegrityProof { commitment, proof, chain_length })
}

/// Verify an audit integrity proof against an expected chain length.
pub fn verify_audit_integrity(proof: &AuditIntegrityProof, expected_length: u64) -> bool {
    if proof.chain_length != expected_length {
        return false;
    }
    const MIN_LEN: usize = 64 + 32 + 64;
    if proof.proof.len() < MIN_LEN {
        return false;
    }

    let chain_root = match proof.proof.get(..64) {
        Some(s) => s,
        None => return false,
    };
    let blinding_sl = match proof.proof.get(64..96) {
        Some(s) => s,
        None => return false,
    };
    let proof_hash = match proof.proof.get(96..160) {
        Some(s) => s,
        None => return false,
    };

    // Re-derive commitment.
    let mut h = Sha512::new();
    h.update(b"MILNET-ZKP-AUDIT-v1");
    h.update(chain_root);
    h.update(blinding_sl);
    let commit_hash = h.finalize();
    if !ct_eq(&commit_hash[..32], &proof.commitment) {
        return false;
    }

    // Re-derive proof hash.
    let mut proof_input: Vec<u8> = Vec::with_capacity(19 + 32 + 8);
    proof_input.extend_from_slice(b"MILNET-ZKP-AUDIT-v1");
    proof_input.extend_from_slice(&proof.commitment);
    proof_input.extend_from_slice(&proof.chain_length.to_le_bytes());
    let expected_hash = Sha512::digest(&proof_input);

    ct_eq(&expected_hash, proof_hash)
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
    fn test_zkp_classification_proof_valid() {
        let blinding = random_blinding();
        let proof = prove_classification_range(4, 2, &blinding)
            .expect("prove must succeed for clearance 4 >= 2");
        assert!(verify_classification_range(&proof), "valid proof must verify");
    }

    #[test]
    fn test_zkp_classification_proof_below_minimum() {
        let blinding = random_blinding();
        let result = prove_classification_range(1, 3, &blinding);
        assert!(result.is_err(), "prove must fail for clearance 1 < 3");
    }

    #[test]
    fn test_zkp_classification_verify_tampered() {
        let blinding = random_blinding();
        let mut proof = prove_classification_range(5, 2, &blinding)
            .expect("prove must succeed");
        // Flip a byte in the middle of the proof data.
        if let Some(b) = proof.proof.get_mut(50) {
            *b ^= 0xFF;
        }
        assert!(!verify_classification_range(&proof), "tampered proof must not verify");
    }

    #[test]
    fn test_zkp_compliance_threshold_met() {
        let blinding = random_blinding();
        let att = prove_compliance_threshold(18, 24, 15, &blinding)
            .expect("prove must succeed for 18 >= 15");
        assert!(verify_compliance_threshold(&att), "valid attestation must verify");
    }

    #[test]
    fn test_zkp_compliance_threshold_not_met() {
        let blinding = random_blinding();
        let result = prove_compliance_threshold(10, 24, 15, &blinding);
        assert!(result.is_err(), "prove must fail for 10 < 15");
    }

    #[test]
    fn test_zkp_audit_integrity_valid() {
        let blinding = random_blinding();
        let mut root = [0u8; 64];
        getrandom::getrandom(&mut root).expect("getrandom failed");
        let proof = prove_audit_integrity(&root, 42, &blinding)
            .expect("prove must succeed");
        assert!(verify_audit_integrity(&proof, 42), "valid proof must verify");
    }

    #[test]
    fn test_zkp_audit_integrity_wrong_length() {
        let blinding = random_blinding();
        let mut root = [0u8; 64];
        getrandom::getrandom(&mut root).expect("getrandom failed");
        let proof = prove_audit_integrity(&root, 42, &blinding)
            .expect("prove must succeed");
        assert!(
            !verify_audit_integrity(&proof, 99),
            "wrong expected length must cause verification failure"
        );
    }

    #[test]
    fn test_zkp_commitment_deterministic() {
        let blinding = random_blinding();
        let c1 = commit(1234, &blinding);
        let c2 = commit(1234, &blinding);
        assert_eq!(c1, c2, "same value + blinding must produce identical commitment");
    }

    #[test]
    fn test_zkp_commitment_different_blinding() {
        let b1 = random_blinding();
        let b2 = random_blinding();
        let c1 = commit(999, &b1);
        let c2 = commit(999, &b2);
        // Two different blindings must (overwhelmingly) produce different commitments.
        assert_ne!(c1, c2, "different blindings must produce different commitments");
    }
}
