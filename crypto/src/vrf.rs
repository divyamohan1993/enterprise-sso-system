//! Post-Quantum Verifiable Random Function (VRF) using ML-DSA-87.
//!
//! Provides unpredictable but verifiable random output for fair leader election
//! where no node can predict or bias the outcome.
//!
//! Properties:
//! - Given input x and secret key sk: output = VRF(sk, x)
//! - Anyone with public key pk can verify the output
//! - Output is uniformly distributed and unpredictable without sk
//!
//! Construction (PQ-safe):
//! - Proof = ML-DSA-87_Sign(sk, input)
//! - Output = HKDF-SHA512(proof, "MILNET-PQ-VRF-v1")[0..32]
//! - Verify: check ML-DSA-87_Verify(pk, input, proof) then recompute output
use sha2::Sha512;
use hkdf;

// ---------------------------------------------------------------------------
// Post-Quantum VRF using ML-DSA-87
// ---------------------------------------------------------------------------

/// VRF output: a 32-byte pseudo-random value.
pub type VrfOutput = [u8; 32];

/// Prove a VRF output using ML-DSA-87 (post-quantum safe).
///
/// The VRF output is derived as HKDF-SHA512(ML-DSA-87_signature(input), "MILNET-PQ-VRF-v1").
/// The proof is the ML-DSA-87 signature itself.
pub fn pq_vrf_prove(
    signing_key: &crate::pq_sign::PqSigningKey,
    input: &[u8],
) -> (VrfOutput, Vec<u8>) {
    // Sign the input with ML-DSA-87
    let proof = crate::pq_sign::pq_sign_raw(signing_key, input);

    // Derive VRF output from the signature via HKDF-SHA512
    let hk = hkdf::Hkdf::<Sha512>::new(Some(b"MILNET-PQ-VRF-v1"), &proof);
    let mut output = [0u8; 32];
    hk.expand(b"pq-vrf-output", &mut output)
        .expect("HKDF-SHA512 expand for 32 bytes cannot fail");

    (output, proof)
}

/// Verify a PQ-VRF proof and recover the output.
///
/// Returns `Some(output)` if the ML-DSA-87 signature is valid for the given
/// input and verifying key, or `None` if verification fails.
pub fn pq_vrf_verify(
    verifying_key: &crate::pq_sign::PqVerifyingKey,
    input: &[u8],
    output: &VrfOutput,
    proof: &[u8],
) -> bool {
    // Verify the ML-DSA-87 signature
    if !crate::pq_sign::pq_verify_raw(verifying_key, input, proof) {
        return false;
    }

    // Recompute the VRF output from the proof
    let hk = hkdf::Hkdf::<Sha512>::new(Some(b"MILNET-PQ-VRF-v1"), proof);
    let mut expected_output = [0u8; 32];
    hk.expand(b"pq-vrf-output", &mut expected_output)
        .expect("HKDF-SHA512 expand for 32 bytes cannot fail");

    // Constant-time comparison to prevent timing oracle attacks
    crate::ct::ct_eq(&expected_output, output)
}

/// Post-quantum leader election using PQ-VRF (ML-DSA-87).
///
/// Derives a leader index deterministically from the VRF output for the given
/// round. The proof can be verified by any participant holding the verifying key.
///
/// Returns `(leader_index, vrf_output, proof)`.
pub fn pq_leader_election(
    signing_key: &crate::pq_sign::PqSigningKey,
    verifying_key: &crate::pq_sign::PqVerifyingKey,
    round: u64,
    participants: usize,
) -> (usize, Vec<u8>, Vec<u8>) {
    let input = format!("leader-election-round-{}", round);
    let (output, proof) = pq_vrf_prove(signing_key, input.as_bytes());

    // Verify our own proof to ensure correctness before publishing
    debug_assert!(pq_vrf_verify(verifying_key, input.as_bytes(), &output, &proof));

    // Derive leader index from VRF output (first 8 bytes as little-endian u64)
    let leader_idx = u64::from_le_bytes(
        output[..8].try_into().unwrap_or([0u8; 8]),
    ) as usize % participants;

    (leader_idx, output.to_vec(), proof)
}

// ── Post-Quantum VRF (ML-DSA-87) — struct-based API ───────────────────────

/// A PQ-VRF keypair using ML-DSA-87 (FIPS 204, NIST Level 5).
/// This is the recommended VRF for all new deployments.
pub struct PqVrfKeypair {
    signing_key: crate::pq_sign::PqSigningKey,
    verifying_key: crate::pq_sign::PqVerifyingKey,
}

/// The output of a PQ-VRF evaluation.
#[derive(Debug, Clone)]
pub struct PqVrfProof {
    /// The pseudo-random output, uniformly distributed.
    pub output: [u8; 32],
    /// The ML-DSA-87 signature serving as the proof.
    pub proof: Vec<u8>,
}

impl PqVrfKeypair {
    /// Generate a new PQ-VRF keypair from OS entropy.
    pub fn generate() -> Self {
        let (sk, pk) = crate::pq_sign::generate_pq_keypair();
        Self {
            signing_key: sk,
            verifying_key: pk,
        }
    }

    /// Return the public verifying key.
    pub fn verifying_key(&self) -> &crate::pq_sign::PqVerifyingKey {
        &self.verifying_key
    }

    /// Evaluate the PQ-VRF on the given input.
    pub fn evaluate(&self, input: &[u8]) -> PqVrfProof {
        let proof = crate::pq_sign::pq_sign_raw(&self.signing_key, input);
        let output = pq_hash_proof_to_output(&proof);
        PqVrfProof { output, proof }
    }
}

/// Verify a PQ-VRF proof and recover the output.
pub fn pq_vrf_verify_proof(
    verifying_key: &crate::pq_sign::PqVerifyingKey,
    input: &[u8],
    proof: &PqVrfProof,
) -> Option<[u8; 32]> {
    if !crate::pq_sign::pq_verify_raw(verifying_key, input, &proof.proof) {
        return None;
    }
    let output = pq_hash_proof_to_output(&proof.proof);
    if !crate::ct::ct_eq(&output, &proof.output) {
        return None;
    }
    Some(output)
}

/// Hash a PQ-VRF proof to derive the uniform output using HKDF-SHA512.
fn pq_hash_proof_to_output(proof: &[u8]) -> [u8; 32] {
    let hkdf = hkdf::Hkdf::<Sha512>::new(
        Some(b"MILNET-PQ-VRF-OUTPUT-v1"),
        proof,
    );
    let mut output = [0u8; 32];
    hkdf.expand(b"vrf-output", &mut output)
        .expect("HKDF expand for 32 bytes always succeeds");
    output
}

/// PQ leader election using ML-DSA-87 VRF.
pub fn pq_leader_election_struct(
    epoch: u64,
    candidates: &[(PqVrfKeypair, String)],
) -> Option<(usize, String, PqVrfProof)> {
    if candidates.is_empty() {
        return None;
    }
    let epoch_bytes = epoch.to_le_bytes();
    let mut best_idx = 0;
    let mut best_output = [0xFFu8; 32];
    let mut best_proof = None;

    for (i, (keypair, _node_id)) in candidates.iter().enumerate() {
        let proof = keypair.evaluate(&epoch_bytes);
        if proof.output < best_output {
            best_output = proof.output;
            best_idx = i;
            best_proof = Some(proof);
        }
    }
    best_proof.map(|p| (best_idx, candidates[best_idx].1.clone(), p))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pq_vrf_evaluate_verify_roundtrip() {
        let keypair = PqVrfKeypair::generate();
        let input = b"epoch-42";

        let proof = keypair.evaluate(input);
        let result = pq_vrf_verify_proof(keypair.verifying_key(), input, &proof);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), proof.output);
    }

    #[test]
    fn test_pq_vrf_wrong_key_rejects() {
        let keypair1 = PqVrfKeypair::generate();
        let keypair2 = PqVrfKeypair::generate();
        let input = b"epoch-42";

        let proof = keypair1.evaluate(input);
        let result = pq_vrf_verify_proof(keypair2.verifying_key(), input, &proof);
        assert!(result.is_none());
    }

    #[test]
    fn test_pq_vrf_wrong_input_rejects() {
        let keypair = PqVrfKeypair::generate();

        let proof = keypair.evaluate(b"epoch-42");
        let result = pq_vrf_verify_proof(keypair.verifying_key(), b"epoch-99", &proof);
        assert!(result.is_none());
    }

    #[test]
    fn test_pq_vrf_different_inputs_different_outputs() {
        let keypair = PqVrfKeypair::generate();

        let proof1 = keypair.evaluate(b"input-1");
        let proof2 = keypair.evaluate(b"input-2");
        assert_ne!(proof1.output, proof2.output);
    }

    #[test]
    fn test_pq_vrf_prove_verify_roundtrip() {
        let (sk, pk) = crate::pq_sign::generate_pq_keypair();
        let input = b"pq-vrf-test-input";
        let (output, proof) = pq_vrf_prove(&sk, input);
        assert!(pq_vrf_verify(&pk, input, &output, &proof));
    }

    #[test]
    fn test_pq_vrf_prove_wrong_key_rejects() {
        let (sk, _pk) = crate::pq_sign::generate_pq_keypair();
        let (_sk2, pk2) = crate::pq_sign::generate_pq_keypair();
        let input = b"pq-vrf-test-input";
        let (output, proof) = pq_vrf_prove(&sk, input);
        assert!(!pq_vrf_verify(&pk2, input, &output, &proof));
    }

    #[test]
    fn test_pq_leader_election_struct_roundtrip() {
        let candidates: Vec<(PqVrfKeypair, String)> = (0..3)
            .map(|i| (PqVrfKeypair::generate(), format!("node-{}", i)))
            .collect();

        let result = pq_leader_election_struct(42, &candidates);
        assert!(result.is_some());

        let (winner_idx, _name, proof) = result.unwrap();
        let winner_vk = candidates[winner_idx].0.verifying_key();
        let verified = pq_vrf_verify_proof(winner_vk, &42u64.to_le_bytes(), &proof);
        assert!(verified.is_some());
    }

    #[test]
    fn test_pq_leader_election_struct_empty() {
        let result = pq_leader_election_struct(1, &[]);
        assert!(result.is_none());
    }

    #[test]
    fn test_pq_vrf_tampered_output_rejected() {
        let keypair = PqVrfKeypair::generate();
        let input = b"test-input";

        let mut proof = keypair.evaluate(input);
        proof.output[0] ^= 0xFF;

        let result = pq_vrf_verify_proof(keypair.verifying_key(), input, &proof);
        assert!(result.is_none());
    }

    #[test]
    fn test_pq_vrf_tampered_proof_bytes_rejected() {
        let keypair = PqVrfKeypair::generate();
        let input = b"test-input";

        let mut proof = keypair.evaluate(input);
        proof.proof[0] ^= 0xFF;

        let result = pq_vrf_verify_proof(keypair.verifying_key(), input, &proof);
        assert!(result.is_none());
    }

    #[test]
    fn test_pq_leader_election_functional() {
        let (sk, pk) = crate::pq_sign::generate_pq_keypair();
        let (idx, output, proof) = pq_leader_election(&sk, &pk, 99, 10);
        assert!(idx < 10);
        assert!(!output.is_empty());
        assert!(!proof.is_empty());
        // Verify the proof
        let input = format!("leader-election-round-{}", 99);
        let mut out = [0u8; 32];
        out.copy_from_slice(&output);
        assert!(pq_vrf_verify(&pk, input.as_bytes(), &out, &proof));
    }
}
