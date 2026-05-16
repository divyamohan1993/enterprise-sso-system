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
    let s = format_cef(&sample()).unwrap();
    assert!(s.starts_with("CEF:0|MILNET|SSO|0.1.0|AUTH_FAIL|Authentication failed|7|"));
    assert!(s.contains("src=10.0.0.1"));
}

#[test]
fn cef_escapes_pipe_in_header() {
    let mut ev = sample();
    ev.product = "S|SO".into();
    let s = format_cef(&ev).unwrap();
    assert!(s.contains(r"S\|SO"));
}

#[test]
fn leef_v2_shape() {
    let s = format_leef(&sample());
    assert!(s.starts_with("LEEF:2.0|MILNET|SSO|0.1.0|AUTH_FAIL|^|"));
    assert!(s.contains("sev=7"));
}

#[test]
fn cef_header_escapes_newlines_no_record_injection() {
    let mut ev = sample();
    ev.name = "Auth failed\nCEF:0|x|x|x|FORGED|root login|10|".into();
    let s = format_cef(&ev).unwrap();
    assert!(!s.contains('\n'), "raw newline must not survive into CEF output");
    assert!(s.contains(r"\n"));
}

#[test]
fn cef_ext_value_escapes_crlf() {
    let mut ev = sample();
    ev.extensions
        .insert("suser".into(), "alice\r\nCEF:0|forged".into());
    let s = format_cef(&ev).unwrap();
    assert!(!s.contains('\n') && !s.contains('\r'));
}

#[test]
fn cef_ext_key_sanitized_no_pair_smuggling() {
    let mut ev = sample();
    ev.extensions
        .insert("evil key=smuggled val suser".into(), "x".into());
    let s = format_cef(&ev).unwrap();
    assert!(s.contains("evil_key_smuggled_val_suser="));
}

#[test]
fn cef_rejects_out_of_range_severity() {
    let mut ev = sample();
    ev.severity = 200; // e.g. an HTTP status mis-assigned to severity.
    assert_eq!(format_cef(&ev), Err(FormatError::SeverityOutOfRange(200)));
}

#[test]
fn cef_accepts_boundary_severity() {
    let mut ev = sample();
    ev.severity = 10;
    assert!(format_cef(&ev).is_ok());
}

#[test]
fn leef_value_escapes_newlines_no_record_injection() {
    let mut ev = sample();
    ev.extensions
        .insert("msg".into(), "ok\nLEEF:2.0|x|x|x|FORGED|^|".into());
    let s = format_leef(&ev);
    assert!(!s.contains('\n') && !s.contains('\r'));
    assert!(s.contains(r"\n"));
}

#[test]
fn leef_header_escapes_newlines() {
    let mut ev = sample();
    ev.product = "SSO\nLEEF:2.0|forged".into();
    let s = format_leef(&ev);
    assert!(!s.contains('\n'));
    assert!(s.contains(r"\n"));
}

#[test]
fn leef_ext_key_sanitized() {
    let mut ev = sample();
    ev.extensions.insert("a\tb=c".into(), "x".into());
    let s = format_leef(&ev);
    assert!(!s.contains("a\tb=c"));
    assert!(s.contains("a_b_c="));
}

#[test]
fn leef_no_duplicate_sev_when_caller_supplies_it() {
    let mut ev = sample();
    ev.extensions.insert("sev".into(), "3".into());
    let s = format_leef(&ev);
    // Exactly one `sev=` pair: the caller's, not an extra auto-appended one.
    assert_eq!(s.matches("sev=").count(), 1);
    assert!(s.contains("sev=3"));
}
