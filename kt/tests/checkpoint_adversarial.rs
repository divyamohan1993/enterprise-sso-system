//! Adversarial tests for the KT checkpoint publish / hash-chain path.

use kt::consensus::{
    append_checkpoint, canonical_checkpoint_bytes, hash_checkpoint, last_hash_in_log,
    sign_checkpoint, synthesize_signing_keys, verify_checkpoint, Checkpoint,
    CheckpointSignature, KT_THRESHOLD,
};
use tempfile::NamedTempFile;

fn mk_unsigned(tree_size: u64, prev_hash: [u8; 64], root_fill: u8) -> Checkpoint {
    Checkpoint {
        tree_size,
        range_start: 0,
        range_end: tree_size,
        root: [root_fill; 64],
        epoch_id: 1,
        timestamp_us: 1_700_000_000_000_000,
        prev_hash,
        signatures: Vec::new(),
    }
}

#[test]
fn checkpoint_chain_link_and_quorum_verify() {
    std::env::set_var("MILNET_MASTER_KEK", "ab".repeat(32));
    let keys = synthesize_signing_keys();
    let vks: Vec<crypto::pq_sign::PqVerifyingKey> = keys
        .iter()
        .map(|k| k.as_ref().unwrap().verifying_key().clone())
        .collect();

    let tmp = NamedTempFile::new().unwrap();
    let path = tmp.path();

    // Row 0
    let mut cp0 = mk_unsigned(1, [0u8; 64], 0xAA);
    cp0.signatures = sign_checkpoint(&cp0, &keys);
    assert!(verify_checkpoint(&cp0, &vks));
    append_checkpoint(path, &cp0).unwrap();

    // Row 1 — prev_hash must match row 0's hash.
    let mut cp1 = mk_unsigned(2, hash_checkpoint(&cp0), 0xBB);
    cp1.signatures = sign_checkpoint(&cp1, &keys);
    assert!(verify_checkpoint(&cp1, &vks));
    append_checkpoint(path, &cp1).unwrap();

    // Row 2 with a wrong prev_hash must be rejected.
    let mut bad = mk_unsigned(3, [0u8; 64], 0xCC);
    bad.signatures = sign_checkpoint(&bad, &keys);
    let err = append_checkpoint(path, &bad).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);

    // Auditor replay from file.
    let count = kt::auditor::verify_log_file(path, &vks).unwrap();
    assert_eq!(count, 2);

    // Tamper detection: overwrite the log with a row whose signatures
    // have been flipped — auditor must reject.
    let mut tampered = cp0.clone();
    if let Some(first) = tampered.signatures.get_mut(0) {
        first.signature[0] ^= 0xFF;
    }
    let mut bytes = serde_json::to_string(&tampered).unwrap();
    bytes.push('\n');
    std::fs::write(path, bytes).unwrap();
    let res = kt::auditor::verify_log_file(path, &vks);
    assert!(res.is_err(), "tampered log must fail auditor");

    std::env::remove_var("MILNET_MASTER_KEK");
}

#[test]
fn checkpoint_below_threshold_signatures_rejected() {
    std::env::set_var("MILNET_MASTER_KEK", "cd".repeat(32));
    let keys = synthesize_signing_keys();
    let vks: Vec<crypto::pq_sign::PqVerifyingKey> = keys
        .iter()
        .map(|k| k.as_ref().unwrap().verifying_key().clone())
        .collect();

    let mut cp = mk_unsigned(1, [0u8; 64], 0xAA);
    // Only one signature; below the 2-of-5 threshold.
    let mut sigs = sign_checkpoint(&cp, &keys);
    sigs.truncate(1);
    assert!(sigs.len() < KT_THRESHOLD);
    cp.signatures = sigs;
    assert!(
        !verify_checkpoint(&cp, &vks),
        "below-threshold checkpoint must not verify"
    );

    std::env::remove_var("MILNET_MASTER_KEK");
}

#[test]
fn last_hash_in_empty_log_is_zero() {
    let tmp = NamedTempFile::new().unwrap();
    std::fs::remove_file(tmp.path()).ok();
    let h = last_hash_in_log(tmp.path()).unwrap();
    assert_eq!(h, [0u8; 64]);
}
