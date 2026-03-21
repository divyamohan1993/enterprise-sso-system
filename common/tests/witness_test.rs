use common::witness::WitnessLog;

#[test]
fn test_witness_checkpoint() {
    let mut log = WitnessLog::new();
    assert!(log.is_empty());
    assert_eq!(log.len(), 0);
    assert!(log.latest().is_none());

    let audit_root = [0xAA; 32];
    let kt_root = [0xBB; 32];
    let signature = vec![0xCC; 128];

    log.add_checkpoint(audit_root, kt_root, signature.clone());
    assert_eq!(log.len(), 1);
    assert!(!log.is_empty());

    let cp = log.latest().unwrap();
    assert_eq!(cp.audit_root, audit_root);
    assert_eq!(cp.kt_root, kt_root);
    assert_eq!(cp.sequence, 0);
    assert_eq!(cp.signature, signature);
    let first_timestamp = cp.timestamp;

    // Add a second checkpoint
    log.add_checkpoint([0xDD; 32], [0xEE; 32], vec![0xFF; 64]);
    assert_eq!(log.len(), 2);
    let cp2 = log.latest().unwrap();
    assert_eq!(cp2.sequence, 1);
    assert!(cp2.timestamp >= first_timestamp);
}
