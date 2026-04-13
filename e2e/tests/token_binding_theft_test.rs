//! I2 [CRIT] DPoP token-binding theft.
//!
//! An attacker who steals a DPoP signing key from one client must be unable
//! to reuse it under a different client fingerprint: the verifier checks
//! the SHA-512 thumbprint of the signer's verifying key against the
//! expected `expected_key_hash` bound to the resource server's session.
//! Cross-thumbprint reuse must fail.

use crypto::dpop::{
    dpop_key_hash, generate_dpop_keypair_raw, generate_dpop_proof, verify_dpop_proof,
};

const HTM: &[u8] = b"POST";
const HTU: &[u8] = b"https://sso.milnet.example/token";

fn now() -> i64 {
    common::secure_time::secure_now_secs_i64()
}

#[test]
fn stolen_dpop_key_rejected_under_different_thumbprint() {
    let (victim_sk, victim_vk) = generate_dpop_keypair_raw();
    let (attacker_sk, attacker_vk) = generate_dpop_keypair_raw();

    let victim_vk_bytes = victim_vk.encode();
    let attacker_vk_bytes = attacker_vk.encode();
    let victim_jkt = dpop_key_hash(victim_vk_bytes.as_ref());
    let attacker_jkt = dpop_key_hash(attacker_vk_bytes.as_ref());
    assert_ne!(victim_jkt, attacker_jkt);

    let claims = b"resource-request";
    let ts = now();

    // Attacker signs with their own key but tries to pose as the victim by
    // claiming the victim's thumbprint binding.
    let attacker_proof = generate_dpop_proof(&attacker_sk, claims, ts, HTM, HTU, None);
    let cross_check = verify_dpop_proof(
        &attacker_vk,
        &attacker_proof,
        claims,
        ts,
        &victim_jkt, // resource server expects victim's thumbprint
        HTM,
        HTU,
        None,
    );
    assert!(!cross_check, "attacker's vk thumbprint must not match victim's expected jkt");

    // Sanity: the attacker's own thumbprint binding does verify with the
    // attacker's own proof — confirms the binding gate is the rejecting layer.
    let self_check = verify_dpop_proof(
        &attacker_vk,
        &attacker_proof,
        claims,
        ts,
        &attacker_jkt,
        HTM,
        HTU,
        None,
    );
    assert!(self_check, "attacker can use their OWN binding");

    // Cross-key proof verification: even if the attacker had the victim's vk
    // bytes, supplying the wrong vk to verify_dpop_proof must fail because
    // the signature was made with attacker_sk.
    let wrong_vk_check = verify_dpop_proof(
        &victim_vk,
        &attacker_proof,
        claims,
        ts,
        &victim_jkt,
        HTM,
        HTU,
        None,
    );
    assert!(!wrong_vk_check, "victim_vk cannot validate signature made by attacker_sk");

    // Drop secrets to silence unused warnings.
    let _ = victim_sk;
}

#[test]
fn replayed_proof_with_wrong_htu_rejected() {
    let (sk, vk) = generate_dpop_keypair_raw();
    let vk_bytes = vk.encode();
    let jkt = dpop_key_hash(vk_bytes.as_ref());

    let claims = b"req";
    let ts = now();
    let proof = generate_dpop_proof(&sk, claims, ts, HTM, HTU, None);

    let evil_htu = b"https://evil.example/steal";
    let ok = verify_dpop_proof(&vk, &proof, claims, ts, &jkt, HTM, evil_htu, None);
    assert!(!ok, "replay against attacker URL must fail htu binding");
}
