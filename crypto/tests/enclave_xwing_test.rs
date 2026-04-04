//! Enclave-to-enclave X-Wing secure channel tests.
//!
//! Verifies that the X-Wing hybrid KEM (ML-KEM-1024 + X25519) correctly
//! establishes enclave channels, both parties derive the same session key,
//! and tampered ciphertexts produce different keys.

use crypto::enclave::{
    complete_channel_xwing, establish_channel_xwing, EnclaveBackend, EnclaveIdentity,
};
use crypto::xwing::XWingKeyPair;

/// Create a test enclave identity with the given measurement byte.
fn test_identity(measurement_byte: u8) -> EnclaveIdentity {
    EnclaveIdentity {
        measurement: [measurement_byte; 32],
        signer: [measurement_byte.wrapping_add(1); 32],
        product_id: 1,
        security_version: 1,
        backend: EnclaveBackend::SoftwareFallback,
        attributes: vec![],
    }
}

#[test]
fn xwing_enclave_channel_roundtrip() {
    let initiator_kp = XWingKeyPair::generate();
    let responder_kp = XWingKeyPair::generate();
    let responder_pk = responder_kp.public_key();

    let initiator_id = test_identity(0xAA);
    let responder_id = test_identity(0xBB);
    let session_id = [0x01; 16];

    // Initiator: encapsulate
    let (initiator_channel, ciphertext) = establish_channel_xwing(
        &initiator_kp,
        &responder_pk,
        &initiator_id,
        &responder_id,
        &session_id,
    )
    .expect("initiator channel establishment failed");

    // Responder: decapsulate
    let responder_channel = complete_channel_xwing(
        &responder_kp,
        &ciphertext,
        &responder_id,
        &initiator_id,
        &session_id,
    )
    .expect("responder channel completion failed");

    // Both must derive the same session key
    assert_eq!(
        initiator_channel.session_key, responder_channel.session_key,
        "both parties must derive the same session key"
    );

    // Session IDs must match
    assert_eq!(initiator_channel.session_id, session_id);
    assert_eq!(responder_channel.session_id, session_id);
}

#[test]
fn xwing_enclave_channel_different_sessions_different_keys() {
    let initiator_kp = XWingKeyPair::generate();
    let responder_kp = XWingKeyPair::generate();
    let responder_pk = responder_kp.public_key();

    let initiator_id = test_identity(0xAA);
    let responder_id = test_identity(0xBB);

    let (channel1, _ct1) = establish_channel_xwing(
        &initiator_kp,
        &responder_pk,
        &initiator_id,
        &responder_id,
        &[0x01; 16],
    )
    .expect("channel 1 failed");

    let (channel2, _ct2) = establish_channel_xwing(
        &initiator_kp,
        &responder_pk,
        &initiator_id,
        &responder_id,
        &[0x02; 16],
    )
    .expect("channel 2 failed");

    assert_ne!(
        channel1.session_key, channel2.session_key,
        "different session IDs must produce different session keys"
    );
}

#[test]
fn xwing_enclave_tampered_ciphertext_produces_different_key() {
    let initiator_kp = XWingKeyPair::generate();
    let responder_kp = XWingKeyPair::generate();
    let responder_pk = responder_kp.public_key();

    let initiator_id = test_identity(0xAA);
    let responder_id = test_identity(0xBB);
    let session_id = [0x01; 16];

    let (initiator_channel, ciphertext) = establish_channel_xwing(
        &initiator_kp,
        &responder_pk,
        &initiator_id,
        &responder_id,
        &session_id,
    )
    .expect("channel establishment failed");

    // Tamper with the ciphertext
    let mut ct_bytes = ciphertext.to_bytes();
    let mid = ct_bytes.len() / 2;
    ct_bytes[mid] ^= 0xFF;
    let tampered_ct = crypto::xwing::Ciphertext::from_bytes(&ct_bytes)
        .expect("ciphertext reconstruction");

    // Responder decapsulates the tampered ciphertext
    // ML-KEM uses implicit rejection, so it returns a pseudorandom value
    match complete_channel_xwing(
        &responder_kp,
        &tampered_ct,
        &responder_id,
        &initiator_id,
        &session_id,
    ) {
        Ok(tampered_channel) => {
            assert_ne!(
                initiator_channel.session_key, tampered_channel.session_key,
                "tampered ciphertext must produce a different session key"
            );
        }
        Err(_) => { /* explicit rejection is also acceptable */ }
    }
}

#[test]
fn xwing_enclave_wrong_responder_key_produces_different_key() {
    let initiator_kp = XWingKeyPair::generate();
    let responder_kp = XWingKeyPair::generate();
    let wrong_kp = XWingKeyPair::generate();
    let responder_pk = responder_kp.public_key();

    let initiator_id = test_identity(0xAA);
    let responder_id = test_identity(0xBB);
    let session_id = [0x01; 16];

    let (initiator_channel, ciphertext) = establish_channel_xwing(
        &initiator_kp,
        &responder_pk,
        &initiator_id,
        &responder_id,
        &session_id,
    )
    .expect("channel establishment failed");

    // Decapsulate with wrong key
    match complete_channel_xwing(
        &wrong_kp,
        &ciphertext,
        &responder_id,
        &initiator_id,
        &session_id,
    ) {
        Ok(wrong_channel) => {
            assert_ne!(
                initiator_channel.session_key, wrong_channel.session_key,
                "wrong responder key must produce a different session key"
            );
        }
        Err(_) => { /* explicit rejection is also acceptable */ }
    }
}
