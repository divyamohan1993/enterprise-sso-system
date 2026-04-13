use logout_bch::*;

#[test]
fn encodes_three_segment_jws() {
    let c = LogoutTokenClaims::new("https://idp", "client123", "user-1", "sid-abc");
    let jws = encode_logout_token(&c, |_| Ok(vec![1, 2, 3, 4])).unwrap();
    assert_eq!(jws.split('.').count(), 3);
}

#[test]
fn events_claim_present() {
    let c = LogoutTokenClaims::new("i", "a", "s", "sid");
    let v = serde_json::to_value(&c).unwrap();
    assert!(v["events"]["http://schemas.openid.net/event/backchannel-logout"].is_object());
}
