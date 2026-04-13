use mdm_compliance::*;

#[tokio::test]
async fn intune_empty_until_wired() {
    let a = IntuneAdapter {
        tenant_id: "t".into(),
        client_id: "c".into(),
        client_secret: "s".into(),
        http: reqwest::Client::new(),
    };
    assert_eq!(a.name(), "intune");
    assert!(a.fetch().await.unwrap().is_empty());
}

#[test]
fn posture_serializes() {
    let p = DevicePosture {
        device_id: "d".into(),
        user_principal: None,
        state: ComplianceState::Compliant,
        os: "iOS 17".into(),
        last_check_in: 0,
        source: "intune".into(),
    };
    serde_json::to_string(&p).unwrap();
}
