use mdm_compliance::*;

#[tokio::test]
async fn intune_not_wired_fails_loud() {
    let a = IntuneAdapter {
        tenant_id: "t".into(),
        client_id: "c".into(),
        client_secret: "s".into(),
        http: reqwest::Client::new(),
    };
    assert_eq!(a.name(), "intune");
    // The Intune adapter is not yet wired to Microsoft Graph. Until it is,
    // `fetch()` MUST fail loud with `NotImplemented` rather than return an
    // empty device set: a compliance gate would read an empty set as a false
    // "all devices compliant" all-clear. Fail-closed, never fail-open.
    let err = a
        .fetch()
        .await
        .expect_err("unwired intune adapter must fail loud, not return empty");
    assert!(matches!(err, MdmError::NotImplemented { adapter: "intune" }));
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
