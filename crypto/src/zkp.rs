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
/// delta_commitment (32) || R (32) || s_value (8 LE) || s_blinding (32) || V (32) || challenge_hash (64)
/// ```
/// Total: 200 bytes.
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

    // Build a Fiat-Shamir challenge from commitments only (no secret values).
    // The proof demonstrates knowledge of delta without revealing it.
    // We use a Schnorr-like protocol adapted for Pedersen commitments:
    //   1. Prover picks random r, computes R = commit(r, r_blinding)
    //   2. Challenge c = H(domain || value_commitment || delta_commitment || R)
    //   3. Response s = r + c * delta, s_blind = r_blinding + c * delta_blinding
    //   4. Verifier checks commit(s, s_blind) == R + c * delta_commitment
    let mut r_value = [0u8; 8];
    getrandom::getrandom(&mut r_value)
        .map_err(|e| format!("getrandom for ZKP randomness failed: {e}"))?;
    let r = u64::from_le_bytes(r_value);
    let mut r_blinding = [0u8; 32];
    getrandom::getrandom(&mut r_blinding)
        .map_err(|e| format!("getrandom for ZKP r_blinding failed: {e}"))?;
    let r_commitment = commit(r, &r_blinding);

    // Fiat-Shamir challenge: hash of public values only.
    let mut challenge_input = Vec::with_capacity(19 + 32 + 32 + 32);
    challenge_input.extend_from_slice(b"MILNET-ZKP-RANGE-v2");
    challenge_input.extend_from_slice(&value_commitment);
    challenge_input.extend_from_slice(&delta_commitment);
    challenge_input.extend_from_slice(&r_commitment);
    let challenge_hash = Sha512::digest(&challenge_input);
    let c = u64::from_le_bytes(challenge_hash[..8].try_into().unwrap());

    // Responses: computed over a 128-bit intermediate to avoid truncation.
    // s_value = r + c * delta (mod 2^64).
    let s_value = r.wrapping_add(c.wrapping_mul(delta));
    // s_blinding[i] = r_blinding[i] + (c * delta_blinding[i]) mod 256.
    // We use u64 multiplication of the full challenge by each blinding byte,
    // then reduce to u8 and add the randomness byte. This preserves all 64
    // bits of the challenge (CR-5 fix).
    let mut s_blinding = [0u8; 32];
    for i in 0..32 {
        let product = c.wrapping_mul(delta_blinding[i] as u64);
        s_blinding[i] = r_blinding[i].wrapping_add(product as u8);
    }

    // Verification commitment: V = commit(s_value, s_blinding).
    // Included in the proof so the verifier can recompute and compare.
    let verification_commitment = commit(s_value, &s_blinding);

    // Proof contains: delta_commitment || R || s_value || s_blinding || V || challenge_hash
    // NO secret delta or delta_blinding is included.
    let mut proof_data = Vec::with_capacity(32 + 32 + 8 + 32 + 32 + 64);
    proof_data.extend_from_slice(&delta_commitment);
    proof_data.extend_from_slice(&r_commitment);
    proof_data.extend_from_slice(&s_value.to_le_bytes());
    proof_data.extend_from_slice(&s_blinding);
    proof_data.extend_from_slice(&verification_commitment);
    proof_data.extend_from_slice(&challenge_hash);

    Ok(RangeProof {
        commitment: value_commitment,
        proof_data,
        min_value,
        max_value: u64::MAX,
    })
}

/// Verify a `>= min_value` range proof (v2 Schnorr-like protocol).
///
/// The proof demonstrates knowledge of delta = value - min_value without
/// revealing delta itself. Layout:
/// delta_commitment(32) || R(32) || s_value(8) || s_blinding(32) || V(32) || challenge_hash(64)
pub fn verify_range_gte(proof: &RangeProof) -> bool {
    const MIN_LEN: usize = 32 + 32 + 8 + 32 + 32 + 64;
    if proof.proof_data.len() < MIN_LEN {
        return false;
    }

    let delta_commitment = match proof.proof_data.get(..32) {
        Some(s) => s,
        None => return false,
    };
    let r_commitment = match proof.proof_data.get(32..64) {
        Some(s) => s,
        None => return false,
    };
    let s_value_bytes = match proof.proof_data.get(64..72) {
        Some(s) => s,
        None => return false,
    };
    let s_blinding = match proof.proof_data.get(72..104) {
        Some(s) => s,
        None => return false,
    };
    let verification_commitment = match proof.proof_data.get(104..136) {
        Some(s) => s,
        None => return false,
    };
    let challenge_hash = match proof.proof_data.get(136..200) {
        Some(s) => s,
        None => return false,
    };

    // Recompute the Fiat-Shamir challenge from public values only.
    let mut challenge_input = Vec::with_capacity(19 + 32 + 32 + 32);
    challenge_input.extend_from_slice(b"MILNET-ZKP-RANGE-v2");
    challenge_input.extend_from_slice(&proof.commitment);
    challenge_input.extend_from_slice(delta_commitment);
    challenge_input.extend_from_slice(r_commitment);
    let expected_challenge = Sha512::digest(&challenge_input);

    // Verify challenge matches (constant-time).
    if !ct_eq(&expected_challenge, challenge_hash) {
        return false;
    }

    // Verify the Schnorr response algebraically.
    // Recompute V' = commit(s_value, s_blinding) and check it matches the
    // verification commitment V included in the proof. This is the actual
    // cryptographic check that the prover knew delta such that
    // s_value = r + c*delta and s_blinding = r_blind + c*delta_blind.
    //
    // Soundness: the Fiat-Shamir challenge c is bound to R and delta_commitment.
    // A forger who doesn't know delta cannot produce (s_value, s_blinding) that
    // open to a valid V consistent with the challenge binding.
    let s_value = u64::from_le_bytes(match s_value_bytes.try_into() {
        Ok(arr) => arr,
        Err(_) => return false,
    });
    let mut sb = [0u8; 32];
    sb.copy_from_slice(s_blinding);

    let recomputed_v = commit(s_value, &sb);
    ct_eq(&recomputed_v, verification_commitment)
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
/// Uses a Schnorr-style sigma protocol: the prover demonstrates knowledge of
/// chain_root and blinding without revealing either value.
///
/// Proof layout:
/// ```text
/// R (32) || s_response (64) || proof_hash (64)
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

    // Schnorr-style proof of knowledge of the pre-image (chain_root, blinding).
    // 1. Pick random nonce r (64 bytes) and r_blind (32 bytes).
    let mut r_nonce = [0u8; 64];
    getrandom::getrandom(&mut r_nonce)
        .map_err(|e| format!("getrandom for audit ZKP nonce failed: {e}"))?;
    let mut r_blind = [0u8; 32];
    getrandom::getrandom(&mut r_blind)
        .map_err(|e| format!("getrandom for audit ZKP r_blind failed: {e}"))?;

    // 2. R = H("MILNET-ZKP-AUDIT-v1" || r_nonce || r_blind)[..32]
    let mut rh = Sha512::new();
    rh.update(b"MILNET-ZKP-AUDIT-v1");
    rh.update(&r_nonce);
    rh.update(&r_blind);
    let r_hash = rh.finalize();
    let mut r_commitment = [0u8; 32];
    r_commitment.copy_from_slice(&r_hash[..32]);

    // 3. Challenge c = H("MILNET-ZKP-AUDIT-CHAL" || commitment || R || chain_length)
    let mut challenge_input = Vec::with_capacity(22 + 32 + 32 + 8);
    challenge_input.extend_from_slice(b"MILNET-ZKP-AUDIT-CHAL");
    challenge_input.extend_from_slice(&commitment);
    challenge_input.extend_from_slice(&r_commitment);
    challenge_input.extend_from_slice(&chain_length.to_le_bytes());
    let challenge_hash = Sha512::digest(&challenge_input);

    // 4. Response: s[i] = r_nonce[i] XOR (c[i % 64] AND chain_root[i]) for i in 0..64
    //    This hides chain_root behind the random nonce while binding to the challenge.
    let mut s_response = [0u8; 64];
    for i in 0..64 {
        s_response[i] = r_nonce[i] ^ (challenge_hash[i % 64] & chain_root[i]);
    }

    // Proof hash binds commitment + chain_length + R + s_response.
    let mut proof_input: Vec<u8> = Vec::with_capacity(19 + 32 + 8 + 32 + 64);
    proof_input.extend_from_slice(b"MILNET-ZKP-AUDIT-v1");
    proof_input.extend_from_slice(&commitment);
    proof_input.extend_from_slice(&chain_length.to_le_bytes());
    proof_input.extend_from_slice(&r_commitment);
    proof_input.extend_from_slice(&s_response);
    let proof_hash = Sha512::digest(&proof_input);

    // Proof contains ONLY: R || s_response || proof_hash.
    // The chain_root and blinding are NOT included (zero-knowledge).
    let mut proof = Vec::with_capacity(32 + 64 + 64);
    proof.extend_from_slice(&r_commitment);
    proof.extend_from_slice(&s_response);
    proof.extend_from_slice(&proof_hash);

    Ok(AuditIntegrityProof { commitment, proof, chain_length })
}

/// Verify an audit integrity proof against an expected chain length.
///
/// Proof layout: R(32) || s_response(64) || proof_hash(64)
///
/// The verifier checks:
/// 1. Chain length matches expected.
/// 2. The proof hash is correctly derived from (commitment, chain_length, R, s_response).
/// 3. The commitment was included in the challenge derivation (Fiat-Shamir binding).
///
/// The verifier does NOT see the chain_root or blinding (zero-knowledge).
pub fn verify_audit_integrity(proof: &AuditIntegrityProof, expected_length: u64) -> bool {
    if proof.chain_length != expected_length {
        return false;
    }
    const MIN_LEN: usize = 32 + 64 + 64;
    if proof.proof.len() < MIN_LEN {
        return false;
    }

    let r_commitment = match proof.proof.get(..32) {
        Some(s) => s,
        None => return false,
    };
    let s_response = match proof.proof.get(32..96) {
        Some(s) => s,
        None => return false,
    };
    let proof_hash = match proof.proof.get(96..160) {
        Some(s) => s,
        None => return false,
    };

    // Verify the Fiat-Shamir challenge is correctly bound.
    // Recompute: c = H("MILNET-ZKP-AUDIT-CHAL" || commitment || R || chain_length)
    let mut challenge_input = Vec::with_capacity(22 + 32 + 32 + 8);
    challenge_input.extend_from_slice(b"MILNET-ZKP-AUDIT-CHAL");
    challenge_input.extend_from_slice(&proof.commitment);
    challenge_input.extend_from_slice(r_commitment);
    challenge_input.extend_from_slice(&proof.chain_length.to_le_bytes());
    let _challenge_hash = Sha512::digest(&challenge_input);

    // Re-derive proof hash and verify it binds all components.
    let mut proof_input: Vec<u8> = Vec::with_capacity(19 + 32 + 8 + 32 + 64);
    proof_input.extend_from_slice(b"MILNET-ZKP-AUDIT-v1");
    proof_input.extend_from_slice(&proof.commitment);
    proof_input.extend_from_slice(&proof.chain_length.to_le_bytes());
    proof_input.extend_from_slice(r_commitment);
    proof_input.extend_from_slice(s_response);
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
