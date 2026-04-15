use account_linking::*;
use std::sync::Mutex;

struct CapturingDispatch {
    sent: Mutex<Vec<(String, Provider, String, String)>>,
}
impl CapturingDispatch {
    fn new() -> Self { Self { sent: Mutex::new(Vec::new()) } }
    fn last(&self) -> Option<(String, Provider, String, String)> {
        self.sent.lock().unwrap().last().cloned()
    }
    fn count(&self) -> usize { self.sent.lock().unwrap().len() }
}
impl ChallengeDispatch for CapturingDispatch {
    fn dispatch(&self, user: &str, provider: Provider, claimed_email: &str, token: &str) -> Result<(), String> {
        self.sent.lock().unwrap().push((user.into(), provider, claimed_email.into(), token.into()));
        Ok(())
    }
}

fn fresh_proof(user: &str) -> StepUpProof {
    StepUpProof {
        user: user.into(),
        user_verified: true,
        asserted_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64,
    }
}

#[test]
fn initiate_then_confirm_links() {
    let s = LinkStore::new(b"secret".to_vec());
    let d = CapturingDispatch::new();
    let out = s.initiate_link(
        &fresh_proof("alice@milnet"),
        Provider::Google,
        "google-sub-1",
        "alice@gmail.example",
        &d,
    ).unwrap();
    assert_eq!(d.count(), 1);
    let (u, p, claimed, token) = d.last().unwrap();
    assert_eq!(u, "alice@milnet");
    assert_eq!(p, Provider::Google);
    assert_eq!(claimed, "alice@gmail.example");
    assert_eq!(token, out.confirm_token);

    let link = s.confirm_link("alice@milnet", &out.confirm_token).unwrap();
    assert!(s.verify(&link).is_ok());
    let r = s.resolve(Provider::Google, "google-sub-1").unwrap();
    assert_eq!(r.milnet_user, "alice@milnet");
}

#[test]
fn initiate_without_uv_step_up_rejected() {
    let s = LinkStore::new(b"k".to_vec());
    let d = CapturingDispatch::new();
    let proof = StepUpProof {
        user: "alice".into(),
        user_verified: false,
        asserted_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64,
    };
    let err = s.initiate_link(&proof, Provider::Cac, "edipi-9", "alice@mil", &d).unwrap_err();
    assert!(matches!(err, LinkError::StepUpRequired));
    assert_eq!(d.count(), 0);
}

#[test]
fn stale_step_up_rejected() {
    let s = LinkStore::new(b"k".to_vec());
    let d = CapturingDispatch::new();
    let stale = StepUpProof {
        user: "alice".into(),
        user_verified: true,
        asserted_at: 0, // ancient
    };
    let err = s.initiate_link(&stale, Provider::Cac, "edipi-9", "alice@mil", &d).unwrap_err();
    assert!(matches!(err, LinkError::StepUpRequired));
}

#[test]
fn confirm_with_wrong_challenge_fails_ct() {
    let s = LinkStore::new(b"k".to_vec());
    let d = CapturingDispatch::new();
    let _ = s.initiate_link(&fresh_proof("alice"), Provider::EntraId, "oid-1", "a@e.x", &d).unwrap();
    let bad = "00".repeat(32);
    let err = s.confirm_link("alice", &bad).unwrap_err();
    assert!(matches!(err, LinkError::PendingExpired));
}

#[test]
fn confirm_for_other_user_fails() {
    let s = LinkStore::new(b"k".to_vec());
    let d = CapturingDispatch::new();
    let out = s.initiate_link(&fresh_proof("alice"), Provider::EntraId, "oid-1", "a@e.x", &d).unwrap();
    let err = s.confirm_link("mallory", &out.confirm_token).unwrap_err();
    assert!(matches!(err, LinkError::PendingExpired));
}

#[test]
fn pending_expires_after_ttl_simulated() {
    let s = LinkStore::new(b"k".to_vec());
    let d = CapturingDispatch::new();
    let out = s.initiate_link(&fresh_proof("alice"), Provider::Okta, "okta-1", "a@e.x", &d).unwrap();
    s._expire_all_pending();
    let err = s.confirm_link("alice", &out.confirm_token).unwrap_err();
    assert!(matches!(err, LinkError::PendingExpired));
}

#[test]
fn rate_limit_blocks_after_three_initiations() {
    let s = LinkStore::new(b"k".to_vec());
    let d = CapturingDispatch::new();
    for i in 0..3 {
        let sub = format!("sub-{i}");
        s.initiate_link(&fresh_proof("alice"), Provider::Saml, &sub, "a@e.x", &d).unwrap();
    }
    let err = s.initiate_link(&fresh_proof("alice"), Provider::Saml, "sub-4", "a@e.x", &d).unwrap_err();
    assert!(matches!(err, LinkError::RateLimited));
}

#[test]
fn double_link_other_user_rejected() {
    let s = LinkStore::new(b"k".to_vec());
    let d = CapturingDispatch::new();
    let out = s.initiate_link(&fresh_proof("alice"), Provider::EntraId, "oid-1", "a@e.x", &d).unwrap();
    s.confirm_link("alice", &out.confirm_token).unwrap();
    // bob attempts to link the same upstream subject
    let err = s.initiate_link(&fresh_proof("bob"), Provider::EntraId, "oid-1", "b@e.x", &d).unwrap_err();
    assert!(matches!(err, LinkError::AlreadyLinked(_)));
}

#[test]
fn tampered_attestation_rejected() {
    let s = LinkStore::new(b"k".to_vec());
    let d = CapturingDispatch::new();
    let out = s.initiate_link(&fresh_proof("alice"), Provider::Cac, "edipi-9", "a@e.x", &d).unwrap();
    let mut l = s.confirm_link("alice", &out.confirm_token).unwrap();
    l.milnet_user = "mallory".into();
    assert!(s.verify(&l).is_err());
}

#[test]
fn dispatch_targets_user_account_not_claimed_email() {
    // Critical ATO defense: confirmation must go to user's existing verified
    // address (passed via dispatch sink which the gateway wires to the user
    // record), NOT to the claimed upstream email.
    let s = LinkStore::new(b"k".to_vec());
    let d = CapturingDispatch::new();
    let _ = s.initiate_link(
        &fresh_proof("alice@milnet"),
        Provider::Google,
        "google-sub-1",
        "attacker-controlled@evil.example",
        &d,
    ).unwrap();
    let (user, _, _claimed, _) = d.last().unwrap();
    // Dispatch sink receives the milnet user identity — gateway resolves it
    // to the user's own verified address before sending. Test asserts the
    // user identity is propagated correctly.
    assert_eq!(user, "alice@milnet");
}
