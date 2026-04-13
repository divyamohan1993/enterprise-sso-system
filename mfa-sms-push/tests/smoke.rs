use mfa_sms_push::*;

#[tokio::test]
async fn push_rejects_until_wired() {
    let p = PushProvider { vendor: "apns".into() };
    let r = p.send(&MfaMessage { destination: "tok".into(), body: "x".into() }).await;
    assert!(r.is_err());
}

#[test]
fn twilio_constructs() {
    let _ = TwilioSmsProvider::new("AC".into(), "tok".into(), "+10000000000".into());
}
