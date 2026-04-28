use jit_access::*;
use std::time::Duration;

#[test]
fn full_lifecycle() {
    let s = JitStore::new();
    let r = s.request("alice", "admin", "fix outage", Duration::from_secs(900)).unwrap();
    assert_eq!(r.status, ElevationStatus::Pending);
    s.approve(r.id, "bob", true).unwrap();
    let r2 = s.get(r.id).unwrap();
    assert_eq!(r2.status, ElevationStatus::Approved);
    assert_eq!(r2.approver_id.as_deref(), Some("bob"));
}

#[test]
fn deny_blocks_approve() {
    let s = JitStore::new();
    let r = s.request("alice", "admin", "x", Duration::from_secs(60)).unwrap();
    s.deny(r.id, "bob").unwrap();
    assert!(s.approve(r.id, "bob", true).is_err());
}

#[test]
fn self_approval_forbidden() {
    let s = JitStore::new();
    let r = s.request("alice", "admin", "x", Duration::from_secs(60)).unwrap();
    assert!(matches!(
        s.approve(r.id, "alice", true),
        Err(JitError::SelfApprovalForbidden)
    ));
    assert_eq!(s.get(r.id).unwrap().status, ElevationStatus::Pending);
}

#[test]
fn unauthorised_approver_rejected() {
    let s = JitStore::new();
    let r = s.request("alice", "admin", "x", Duration::from_secs(60)).unwrap();
    assert!(matches!(
        s.approve(r.id, "bob", false),
        Err(JitError::ApproverNotAuthorised(_))
    ));
    assert_eq!(s.get(r.id).unwrap().status, ElevationStatus::Pending);
}

#[test]
fn expire_pass_marks_expired() {
    let s = JitStore::new();
    let r = s.request("a", "r", "j", Duration::from_secs(0)).unwrap();
    std::thread::sleep(Duration::from_millis(1100));
    let n = s.expire_pass().unwrap();
    assert!(n >= 1);
    assert_eq!(s.get(r.id).unwrap().status, ElevationStatus::Expired);
}
