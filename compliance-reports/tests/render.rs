use compliance_reports::*;

#[test]
fn html_contains_findings() {
    let r = Report {
        framework: Framework::FedRamp,
        generated_at: 1, period_start: 0, period_end: 1,
        findings: vec![
            Finding { control_id: "AC-2".into(), title: "Account Mgmt".into(), status: "PASS".into(), severity: "high".into(), evidence: "ok".into() },
            Finding { control_id: "AU-3".into(), title: "Audit Records".into(), status: "FAIL".into(), severity: "med".into(), evidence: "miss".into() },
        ],
    };
    let h = r.render_html();
    assert!(h.contains("AC-2"));
    assert!(h.contains("AU-3"));
    assert_eq!(r.pass_count(), 1);
    assert_eq!(r.fail_count(), 1);
}

#[test]
fn envelope_has_mime() {
    let cfg = SmtpConfig { host: "h".into(), port: 587, username: "u".into(), password: "p".into(), from: "a@b".into() };
    let env = build_envelope(&cfg, "c@d", "subj", "<p>x</p>");
    assert!(env.contains("MIME-Version: 1.0"));
}
