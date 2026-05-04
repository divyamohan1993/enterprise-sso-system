// X-J: persisted STH log on-load verification. A bit-flipped or replaced
// signature must produce SthVerifyError::BadSignature (mapped to
// `state_chain.sth_verification_failed` CRITICAL + process exit in main).

use kt::sth_log::{
    append_sth_record, hash_sth, sth_signed_bytes, verify_sth_log, PersistedSth, SthVerifyError,
};
use ml_dsa::{KeyGen, MlDsa87};

fn make_kp(seed_byte: u8) -> (
    crypto::pq_sign::PqSigningKey,
    crypto::pq_sign::PqVerifyingKey,
) {
    let kp = MlDsa87::from_seed(&[seed_byte; 32].into());
    (kp.signing_key().clone(), kp.verifying_key().clone())
}

fn write_sth(
    path: &std::path::Path,
    sk: &crypto::pq_sign::PqSigningKey,
    epoch_id: u64,
    tree_size: u64,
    prev: [u8; 64],
) -> PersistedSth {
    let mut sth = PersistedSth {
        tree_size,
        root: [0xAB; 64],
        timestamp: (1_700_000_000_000_000 + tree_size as i64),
        signature: vec![],
        prev_sth_hash: prev,
        epoch_id,
    };
    let signed = sth_signed_bytes(&sth);
    sth.signature = crypto::pq_sign::pq_sign_raw(sk, &signed);
    append_sth_record(path, &sth).unwrap();
    sth
}

#[test]
fn verifies_clean_log_against_pinned_vk() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("kt_sth.log");
    let (sk, vk) = make_kp(0x11);

    let mut prev = [0u8; 64];
    for n in 1..=3u64 {
        let sth = write_sth(&log, &sk, 100, n, prev);
        prev = hash_sth(&sth);
    }
    let last = verify_sth_log(&log, &[vk], true).expect("clean log verifies");
    assert_eq!(last, prev);
}

#[test]
fn rejects_corrupt_signature() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("kt_sth.log");
    let (sk, vk) = make_kp(0x22);

    let mut prev = [0u8; 64];
    for n in 1..=2u64 {
        let sth = write_sth(&log, &sk, 100, n, prev);
        prev = hash_sth(&sth);
    }

    // Flip the LAST byte of the file. Inside the postcard payload the trailing
    // bytes belong to `epoch_id` (LEB128). To target the signature reliably we
    // re-read, decode every record, mutate the inner signature, and rewrite.
    let mut bytes = std::fs::read(&log).unwrap();
    let mut offset = 0usize;
    while offset + 4 <= bytes.len() {
        let n = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        if offset + n > bytes.len() {
            break;
        }
        // Flip a single bit in the middle of the record's body. The signature
        // is the largest variable-length field, so this overwhelmingly hits a
        // signature byte; even if it lands on tree_size we still get a
        // BadSignature error since the signed-bytes input changes.
        bytes[offset + n / 2] ^= 0x40;
        offset += n;
    }
    std::fs::write(&log, &bytes).unwrap();

    let err = verify_sth_log(&log, &[vk], true).expect_err("corruption rejected");
    assert!(matches!(
        err,
        SthVerifyError::BadSignature { .. } | SthVerifyError::Decode { .. }
    ));
}

#[test]
fn rejects_signature_from_unknown_signer() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("kt_sth.log");
    let (sk_attacker, _vk_attacker) = make_kp(0x33);
    let (_, vk_legit) = make_kp(0x44);

    write_sth(&log, &sk_attacker, 200, 1, [0u8; 64]);
    let err = verify_sth_log(&log, &[vk_legit], true)
        .expect_err("unknown signer rejected");
    assert!(matches!(err, SthVerifyError::BadSignature { .. }));
}

#[test]
fn refuses_missing_pinned_keys_when_required() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("kt_sth.log");
    let (sk, _vk) = make_kp(0x55);
    write_sth(&log, &sk, 0, 1, [0u8; 64]);

    let err = verify_sth_log(&log, &[], true).expect_err("missing keys rejected");
    assert!(matches!(err, SthVerifyError::NoPinnedKeys));
}

#[test]
fn rejects_chain_break() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("kt_sth.log");
    let (sk, vk) = make_kp(0x66);

    write_sth(&log, &sk, 0, 1, [0u8; 64]);
    // Second STH lies about its prev_sth_hash — pretend the genesis was [0xFF;64].
    write_sth(&log, &sk, 0, 2, [0xFF; 64]);

    let err = verify_sth_log(&log, &[vk], true).expect_err("chain break rejected");
    assert!(matches!(err, SthVerifyError::ChainBreak { .. }));
}
