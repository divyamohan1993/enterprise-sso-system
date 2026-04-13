use siem_cef_leef::*;
use std::collections::BTreeMap;

fn sample() -> SecurityEvent {
    let mut ext = BTreeMap::new();
    ext.insert("src".into(), "10.0.0.1".into());
    ext.insert("suser".into(), "alice".into());
    SecurityEvent {
        vendor: "MILNET".into(),
        product: "SSO".into(),
        version: "0.1.0".into(),
        event_id: "AUTH_FAIL".into(),
        name: "Authentication failed".into(),
        severity: 7,
        extensions: ext,
    }
}

#[test]
fn cef_header_shape() {
    let s = format_cef(&sample());
    assert!(s.starts_with("CEF:0|MILNET|SSO|0.1.0|AUTH_FAIL|Authentication failed|7|"));
    assert!(s.contains("src=10.0.0.1"));
}

#[test]
fn cef_escapes_pipe_in_header() {
    let mut ev = sample();
    ev.product = "S|SO".into();
    let s = format_cef(&ev);
    assert!(s.contains(r"S\|SO"));
}

#[test]
fn leef_v2_shape() {
    let s = format_leef(&sample());
    assert!(s.starts_with("LEEF:2.0|MILNET|SSO|0.1.0|AUTH_FAIL|^|"));
    assert!(s.contains("sev=7"));
}
