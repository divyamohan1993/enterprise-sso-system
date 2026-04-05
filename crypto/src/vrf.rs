//! Verifiable Random Function (VRF) using Ed25519.
//!
//! Provides unpredictable but verifiable random output for fair leader election
//! where no node can predict or bias the outcome.
//!
//! Properties:
//! - Given input x and secret key sk: output = VRF(sk, x)
//! - Anyone with public key pk can verify the output
//! - Output is uniformly distributed and unpredictable without sk
//!
//! Construction:
//! - Proof = Ed25519_Sign(sk, input)
//! - Output = SHA-512(proof)[0..32]  (hash the signature to get uniform output)
//! - Verify: check Ed25519_Verify(pk, input, proof) then recompute output
use ed25519_dalek::{Signer, Verifier};
use sha2::{Digest, Sha512};
use hkdf;

/// A VRF keypair wrapping Ed25519 keys.
pub struct VrfKeypair {
    signing_key: ed25519_dalek::SigningKey,
    verifying_key: ed25519_dalek::VerifyingKey,
}

/// The output of a VRF evaluation: a 32-byte random value plus a proof.
#[derive(Debug, Clone)]
pub struct VrfProof {
    /// The pseudo-random output, uniformly distributed.
    pub output: [u8; 32],
    /// The proof that `output` was correctly derived (an Ed25519 signature).
    pub proof: Vec<u8>,
}

impl VrfKeypair {
    /// Generate a new VRF keypair from OS entropy.
    pub fn generate() -> Self {
        let mut rng = rand::rngs::OsRng;
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();
        Self { signing_key, verifying_key }
    }

    /// Construct from an existing Ed25519 signing key.
    pub fn from_signing_key(signing_key: ed25519_dalek::SigningKey) -> Self {
        let verifying_key = signing_key.verifying_key();
        Self { signing_key, verifying_key }
    }

    /// Return the public verifying key.
    pub fn verifying_key(&self) -> &ed25519_dalek::VerifyingKey {
        &self.verifying_key
    }

    /// Evaluate the VRF on the given input.
    ///
    /// Returns a `VrfProof` containing the pseudo-random output and its proof.
    pub fn evaluate(&self, input: &[u8]) -> VrfProof {
        // Sign the input to produce the proof
        let signature = self.signing_key.sign(input);
        let proof_bytes = signature.to_bytes().to_vec();

        // Hash the proof to derive the uniform output
        let output = hash_proof_to_output(&proof_bytes);

        VrfProof {
            output,
            proof: proof_bytes,
        }
    }
}

/// Verify a VRF proof and recover the output.
///
/// Returns `Some(output)` if the proof is valid for the given input and
/// verifying key, or `None` if verification fails.
pub fn verify(
    verifying_key: &ed25519_dalek::VerifyingKey,
    input: &[u8],
    proof: &VrfProof,
) -> Option<[u8; 32]> {
    // Reconstruct the Ed25519 signature from the proof bytes
    if proof.proof.len() != 64 {
        return None;
    }
    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(&proof.proof);
    let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);

    // Verify the signature
    if verifying_key.verify(input, &signature).is_err() {
        return None;
    }

    // Recompute the output from the proof
    let output = hash_proof_to_output(&proof.proof);

    // The recomputed output must match what was claimed
    if output != proof.output {
        return None;
    }

    Some(output)
}

/// Run a leader election for the given epoch.
///
/// Each candidate evaluates VRF(sk, epoch_bytes) and the candidate with the
/// lowest output wins.  Returns `(winner_index, winner_proof)`.
///
/// The `candidates` slice contains `(keypair, node_id)` pairs.
pub fn leader_election(epoch: u64, candidates: &[(VrfKeypair, String)]) -> Option<(usize, String, VrfProof)> {
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

    best_proof.map(|proof| (best_idx, candidates[best_idx].1.clone(), proof))
}

/// Hash proof bytes to a 32-byte uniform output using SHA-512 (truncated).
fn hash_proof_to_output(proof: &[u8]) -> [u8; 32] {
    let hash = Sha512::digest(proof);
    let mut output = [0u8; 32];
    output.copy_from_slice(&hash[..32]);
    output
}

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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evaluate_verify_roundtrip() {
        let keypair = VrfKeypair::generate();
        let input = b"epoch-42";

        let proof = keypair.evaluate(input);
        let result = verify(keypair.verifying_key(), input, &proof);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), proof.output);
    }

    #[test]
    fn test_wrong_key_rejects() {
        let keypair1 = VrfKeypair::generate();
        let keypair2 = VrfKeypair::generate();
        let input = b"epoch-42";

        let proof = keypair1.evaluate(input);
        // Verify with wrong key should fail
        let result = verify(keypair2.verifying_key(), input, &proof);
        assert!(result.is_none());
    }

    #[test]
    fn test_wrong_input_rejects() {
        let keypair = VrfKeypair::generate();

        let proof = keypair.evaluate(b"epoch-42");
        // Verify with wrong input should fail
        let result = verify(keypair.verifying_key(), b"epoch-99", &proof);
        assert!(result.is_none());
    }

    #[test]
    fn test_different_inputs_different_outputs() {
        let keypair = VrfKeypair::generate();

        let proof1 = keypair.evaluate(b"input-1");
        let proof2 = keypair.evaluate(b"input-2");
        assert_ne!(proof1.output, proof2.output);
    }

    #[test]
    fn test_same_input_same_output() {
        let keypair = VrfKeypair::generate();
        let input = b"deterministic-input";

        let proof1 = keypair.evaluate(input);
        let proof2 = keypair.evaluate(input);
        // Ed25519 signing is deterministic (RFC 8032), so same input -> same output
        assert_eq!(proof1.output, proof2.output);
    }

    #[test]
    fn test_leader_election_deterministic_for_same_epoch() {
        // Build candidates with fixed keys
        let candidates: Vec<(VrfKeypair, String)> = (0..5)
            .map(|i| {
                let keypair = VrfKeypair::generate();
                (keypair, format!("node-{}", i))
            })
            .collect();

        let epoch = 100u64;
        let result1 = leader_election(epoch, &candidates);
        let result2 = leader_election(epoch, &candidates);

        assert!(result1.is_some());
        assert!(result2.is_some());

        let (idx1, name1, proof1) = result1.unwrap();
        let (idx2, name2, proof2) = result2.unwrap();

        // Same candidates + same epoch = same winner (deterministic)
        assert_eq!(idx1, idx2);
        assert_eq!(name1, name2);
        assert_eq!(proof1.output, proof2.output);
    }

    #[test]
    fn test_leader_election_empty_candidates() {
        let result = leader_election(1, &[]);
        assert!(result.is_none());
    }

    #[test]
    fn test_leader_election_winner_is_verifiable() {
        let candidates: Vec<(VrfKeypair, String)> = (0..3)
            .map(|i| (VrfKeypair::generate(), format!("node-{}", i)))
            .collect();

        let epoch = 42u64;
        let (winner_idx, _name, proof) = leader_election(epoch, &candidates).unwrap();

        // Anyone can verify the winner's proof
        let winner_vk = candidates[winner_idx].0.verifying_key();
        let verified = verify(winner_vk, &epoch.to_le_bytes(), &proof);
        assert!(verified.is_some());
    }

    #[test]
    fn test_tampered_proof_rejected() {
        let keypair = VrfKeypair::generate();
        let input = b"test-input";

        let mut proof = keypair.evaluate(input);
        // Tamper with the output
        proof.output[0] ^= 0xFF;

        let result = verify(keypair.verifying_key(), input, &proof);
        assert!(result.is_none());
    }

    #[test]
    fn test_tampered_proof_bytes_rejected() {
        let keypair = VrfKeypair::generate();
        let input = b"test-input";

        let mut proof = keypair.evaluate(input);
        // Tamper with the proof signature bytes
        proof.proof[0] ^= 0xFF;

        let result = verify(keypair.verifying_key(), input, &proof);
        assert!(result.is_none());
    }
}
