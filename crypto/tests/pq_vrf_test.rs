//! Post-quantum VRF tests using ML-DSA-87.
//!
//! Verifies correctness, uniqueness, and security properties of the
//! PQ-VRF construction: HKDF-SHA512(ML-DSA-87_signature(input)).

use crypto::pq_sign::generate_pq_keypair;
use crypto::vrf::{pq_vrf_prove, pq_vrf_verify};

/// Spawn test on large stack for ML-DSA-87 key sizes.
fn large_stack<F: FnOnce() + Send + 'static>(f: F) {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(f)
        .expect("thread spawn failed")
        .join()
        .expect("thread panicked");
}

#[test]
fn pq_vrf_prove_verify_roundtrip() {
    large_stack(|| {
        let (sk, vk) = generate_pq_keypair();
        let input = b"epoch-42-leader-election";

        let (output, proof) = pq_vrf_prove(&sk, input);

        assert!(
            pq_vrf_verify(&vk, input, &output, &proof),
            "PQ-VRF prove/verify roundtrip must succeed"
        );
    });
}

#[test]
fn pq_vrf_different_inputs_produce_different_outputs() {
    large_stack(|| {
        let (sk, _vk) = generate_pq_keypair();

        let (output1, _proof1) = pq_vrf_prove(&sk, b"input-alpha");
        let (output2, _proof2) = pq_vrf_prove(&sk, b"input-beta");

        assert_ne!(
            output1, output2,
            "PQ-VRF must produce different outputs for different inputs"
        );
    });
}

#[test]
fn pq_vrf_wrong_key_fails_verification() {
    large_stack(|| {
        let (sk1, _vk1) = generate_pq_keypair();
        let (_sk2, vk2) = generate_pq_keypair();
        let input = b"wrong-key-test";

        let (output, proof) = pq_vrf_prove(&sk1, input);

        assert!(
            !pq_vrf_verify(&vk2, input, &output, &proof),
            "PQ-VRF must reject proof verified with wrong key"
        );
    });
}

#[test]
fn pq_vrf_tampered_proof_fails_verification() {
    large_stack(|| {
        let (sk, vk) = generate_pq_keypair();
        let input = b"tamper-test";

        let (output, mut proof) = pq_vrf_prove(&sk, input);

        // Flip a bit in the proof
        if !proof.is_empty() {
            let mid = proof.len() / 2;
            proof[mid] ^= 0x01;
        }

        assert!(
            !pq_vrf_verify(&vk, input, &output, &proof),
            "PQ-VRF must reject tampered proof"
        );
    });
}

#[test]
fn pq_vrf_tampered_output_fails_verification() {
    large_stack(|| {
        let (sk, vk) = generate_pq_keypair();
        let input = b"output-tamper-test";

        let (mut output, proof) = pq_vrf_prove(&sk, input);

        // Flip a bit in the output
        output[0] ^= 0xFF;

        assert!(
            !pq_vrf_verify(&vk, input, &output, &proof),
            "PQ-VRF must reject tampered output"
        );
    });
}

#[test]
fn pq_vrf_wrong_input_fails_verification() {
    large_stack(|| {
        let (sk, vk) = generate_pq_keypair();

        let (output, proof) = pq_vrf_prove(&sk, b"original-input");

        assert!(
            !pq_vrf_verify(&vk, b"wrong-input", &output, &proof),
            "PQ-VRF must reject proof for wrong input"
        );
    });
}

#[test]
fn pq_vrf_empty_proof_fails() {
    large_stack(|| {
        let (_sk, vk) = generate_pq_keypair();
        let output = [0u8; 32];

        assert!(
            !pq_vrf_verify(&vk, b"input", &output, &[]),
            "PQ-VRF must reject empty proof"
        );
    });
}
