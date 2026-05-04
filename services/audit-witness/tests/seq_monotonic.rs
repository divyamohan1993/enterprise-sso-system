// X-K: per-witness sequence chain rejects replay and equivocation, and the
// chain is verifiable on reload. Equivocation = signing two different
// histories at the same seq for two different observers.

use audit_witness::{WitnessSeqError, WitnessSeqState, SEQ_RECORD_LEN};

#[test]
fn record_rejects_replayed_seq() {
    let dir = tempfile::tempdir().unwrap();
    let mut st = WitnessSeqState::open(dir.path()).expect("open");
    assert_eq!(st.last_seq(), None);

    let h1 = [0x11u8; 32];
    st.record(1, &h1).expect("seq=1 accepted");

    // Replay of the same seq with the SAME hash must be rejected.
    let err = st.record(1, &h1).expect_err("replay rejected");
    assert!(matches!(
        err,
        WitnessSeqError::SeqReplay { requested: 1, persisted: 1 }
    ));

    // Replay of the same seq with a DIFFERENT hash must also be rejected
    // (this is the equivocation case — same seq, two different histories).
    let h_alt = [0x22u8; 32];
    let err2 = st.record(1, &h_alt).expect_err("equivocation rejected");
    assert!(matches!(
        err2,
        WitnessSeqError::SeqReplay { requested: 1, persisted: 1 }
    ));

    // Older seq must also be rejected.
    let err3 = st.record(0, &h1).expect_err("backdated rejected");
    assert!(matches!(err3, WitnessSeqError::SeqReplay { .. }));

    // A strictly higher seq must be accepted.
    st.record(2, &[0x22u8; 32]).expect("seq=2 accepted");
    assert_eq!(st.last_seq(), Some(2));
}

#[test]
fn chain_persists_and_reverifies_on_reopen() {
    let dir = tempfile::tempdir().unwrap();
    {
        let mut st = WitnessSeqState::open(dir.path()).unwrap();
        st.record(7, &[0xAAu8; 32]).unwrap();
        st.record(8, &[0xBBu8; 32]).unwrap();
        st.record(42, &[0xCCu8; 32]).unwrap();
    }
    // Reopen — chain must verify and report the last seq.
    let st2 = WitnessSeqState::open(dir.path()).unwrap();
    assert_eq!(st2.last_seq(), Some(42));
}

#[test]
fn truncated_seq_log_fails_to_open() {
    use std::io::Write;
    let dir = tempfile::tempdir().unwrap();
    {
        let mut st = WitnessSeqState::open(dir.path()).unwrap();
        st.record(1, &[0xAAu8; 32]).unwrap();
    }
    // Truncate the last byte — file is no longer a multiple of SEQ_RECORD_LEN.
    let log_path = dir.path().join("witness_seq.log");
    let bytes = std::fs::read(&log_path).unwrap();
    assert_eq!(bytes.len(), SEQ_RECORD_LEN);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&log_path)
        .unwrap();
    f.write_all(&bytes[..bytes.len() - 1]).unwrap();
    drop(f);

    let err = WitnessSeqState::open(dir.path()).expect_err("truncated log rejected");
    assert!(matches!(err, WitnessSeqError::Corrupt(_)));
}

#[test]
fn flipped_chain_byte_fails_to_open() {
    use std::io::Write;
    let dir = tempfile::tempdir().unwrap();
    {
        let mut st = WitnessSeqState::open(dir.path()).unwrap();
        st.record(1, &[0xAAu8; 32]).unwrap();
        st.record(2, &[0xBBu8; 32]).unwrap();
    }
    let log_path = dir.path().join("witness_seq.log");
    let mut bytes = std::fs::read(&log_path).unwrap();
    // Flip a byte inside the second record's chain_after field.
    bytes[SEQ_RECORD_LEN + 60] ^= 0x01;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&log_path)
        .unwrap();
    f.write_all(&bytes).unwrap();
    drop(f);

    let err = WitnessSeqState::open(dir.path()).expect_err("tampered chain rejected");
    assert!(matches!(err, WitnessSeqError::Corrupt(_)));
}

#[test]
fn end_to_end_sign_via_process_request_rejects_replay() {
    use audit_witness::process_request;
    use ml_dsa::{KeyGen, MlDsa87};
    use std::sync::Mutex;

    let dir = tempfile::tempdir().unwrap();
    let st = Mutex::new(WitnessSeqState::open(dir.path()).unwrap());

    let kp = MlDsa87::from_seed(&[0x55u8; 32].into());
    let sk = kp.signing_key().clone();
    let vk_bytes = kp.verifying_key().encode();
    let vk_hex = hex::encode(AsRef::<[u8]>::as_ref(&vk_bytes));

    let h = [0x77u8; 32];
    let req = format!("SIGN 5 {}", hex::encode(h));
    let r = process_request(&req, &st, &sk, &vk_hex);
    assert!(r.starts_with("SIG "), "first sign should succeed: {r}");

    // Replay same seq → ERR seq replayed.
    let r2 = process_request(&req, &st, &sk, &vk_hex);
    assert!(
        r2.starts_with("ERR seq replayed"),
        "replay must be rejected: {r2}"
    );

    // Lower seq → also rejected.
    let req_low = format!("SIGN 4 {}", hex::encode(h));
    let r3 = process_request(&req_low, &st, &sk, &vk_hex);
    assert!(r3.starts_with("ERR seq replayed"), "backdated rejected: {r3}");

    // Higher seq → accepted.
    let req_hi = format!("SIGN 6 {}", hex::encode(h));
    let r4 = process_request(&req_hi, &st, &sk, &vk_hex);
    assert!(r4.starts_with("SIG "), "higher seq accepted: {r4}");
}
