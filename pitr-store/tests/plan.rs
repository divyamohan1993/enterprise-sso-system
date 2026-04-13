use pitr_store::*;

#[test]
fn picks_latest_base_before_target() {
    let bases = vec![
        BaseBackup { backup_id: "a".into(), taken_at: 100, object_url: "s3://a".into() },
        BaseBackup { backup_id: "b".into(), taken_at: 200, object_url: "s3://b".into() },
    ];
    let wals = vec![WalSegment { lsn: "1/0".into(), start_ts: 50, end_ts: 500, object_url: "s3://w".into() }];
    let p = plan_recovery(&bases, &wals, 300).unwrap();
    assert_eq!(p.base.backup_id, "b");
    assert_eq!(p.target_ts, 300);
}

#[test]
fn rejects_target_too_old() {
    let bases = vec![BaseBackup { backup_id: "a".into(), taken_at: 1, object_url: "x".into() }];
    let wals = vec![WalSegment { lsn: "1".into(), start_ts: 100, end_ts: 200, object_url: "x".into() }];
    let err = plan_recovery(&bases, &wals, 50).unwrap_err();
    matches!(err, PitrError::TargetTooOld(_, _));
}
