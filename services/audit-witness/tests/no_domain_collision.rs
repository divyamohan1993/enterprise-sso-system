// X-K: an audit-witness signature MUST NOT validate as a different
// ML-DSA-87 use of the same key (e.g. credential signing, threshold
// signing, undomained pq_sign_raw, or a different domain tag). The FIPS 204
// `ctx` parameter binds the signature to the witness role; cross-protocol
// presentation must fail.

use audit_witness::{
    build_witness_signing_payload, verify_witness_signature, AUDIT_WITNESS_DOMAIN,
};
use ml_dsa::{KeyGen, MlDsa87};

fn make_keys() -> (
    crypto::pq_sign::PqSigningKey,
    crypto::pq_sign::PqVerifyingKey,
) {
    let kp = MlDsa87::from_seed(&[0x33u8; 32].into());
    (kp.signing_key().clone(), kp.verifying_key().clone())
}

#[test]
fn witness_sig_rejected_by_undomained_verify() {
    let (sk, vk) = make_keys();
    let seq = 12u64;
    let hash = [0x44u8; 32];
    let payload = build_witness_signing_payload(seq, &hash);

    // Sign with the audit-witness domain tag.
    let sig =
        crypto::pq_sign::pq_sign_raw_domain(&sk, &payload, AUDIT_WITNESS_DOMAIN).unwrap();

    // The companion domain-bound verify accepts it.
    assert!(verify_witness_signature(&vk, seq, &hash, &sig));

    // The undomained verifier (used for credentials, signed tree heads,
    // etc.) MUST NOT accept this signature even with the SAME key and SAME
    // payload bytes. If it ever does, the witness role separator is broken.
    assert!(
        !crypto::pq_sign::pq_verify_raw(&vk, &payload, &sig),
        "audit-witness signature must NOT verify under undomained context"
    );
}

#[test]
fn witness_sig_rejected_under_different_domain() {
    let (sk, vk) = make_keys();
    let seq = 12u64;
    let hash = [0x44u8; 32];
    let payload = build_witness_signing_payload(seq, &hash);
    let sig =
        crypto::pq_sign::pq_sign_raw_domain(&sk, &payload, AUDIT_WITNESS_DOMAIN).unwrap();

    let other_domain: [u8; 32] = *b"OTHER-PROTOCOL-VERY-DIFFERENT--\0";
    assert!(
        !crypto::pq_sign::pq_verify_raw_domain(&vk, &payload, &other_domain, &sig),
        "signature must not validate under a different domain tag"
    );
}

#[test]
fn undomained_signature_rejected_by_witness_verify() {
    // Reverse direction: a legitimate undomained pq_sign_raw signature on
    // the SAME payload must NOT pass the witness-domain verifier.
    let (sk, vk) = make_keys();
    let seq = 12u64;
    let hash = [0x44u8; 32];
    let payload = build_witness_signing_payload(seq, &hash);

    let undomained_sig = crypto::pq_sign::pq_sign_raw(&sk, &payload);
    assert!(
        !verify_witness_signature(&vk, seq, &hash, &undomained_sig),
        "undomained signature must not satisfy the audit-witness verifier"
    );
}

#[test]
fn distinct_seq_changes_signature_payload() {
    // Sanity: payload composition binds seq AND hash; flipping either
    // breaks verification.
    let (sk, vk) = make_keys();
    let hash = [0x55u8; 32];
    let payload_a = build_witness_signing_payload(1, &hash);
    let sig =
        crypto::pq_sign::pq_sign_raw_domain(&sk, &payload_a, AUDIT_WITNESS_DOMAIN).unwrap();
    assert!(verify_witness_signature(&vk, 1, &hash, &sig));
    // Same hash but different seq → must fail.
    assert!(!verify_witness_signature(&vk, 2, &hash, &sig));
    // Same seq but different hash → must fail.
    let other_hash = [0x66u8; 32];
    assert!(!verify_witness_signature(&vk, 1, &other_hash, &sig));
}
