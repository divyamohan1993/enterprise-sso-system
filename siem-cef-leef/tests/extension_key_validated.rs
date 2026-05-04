// X-L: extension keys must be `[A-Za-z0-9_]+`. Anything else is rejected
// at insertion time so a downstream renamer / refactor cannot move
// attacker-influenced bytes into key position later.

use siem_cef_leef::*;

#[test]
fn empty_key_rejected() {
    let mut ext = ExtensionMap::new();
    let err = ext.insert("", "x").unwrap_err();
    assert!(matches!(err, FormatError::InvalidExtensionKey(_)));
}

#[test]
fn key_with_equals_rejected() {
    let mut ext = ExtensionMap::new();
    let err = ext.insert("evil=key", "x").unwrap_err();
    assert!(matches!(err, FormatError::InvalidExtensionKey(_)));
}

#[test]
fn key_with_pipe_rejected() {
    let mut ext = ExtensionMap::new();
    let err = ext.insert("evil|key", "x").unwrap_err();
    assert!(matches!(err, FormatError::InvalidExtensionKey(_)));
}

#[test]
fn key_with_space_rejected() {
    let mut ext = ExtensionMap::new();
    let err = ext.insert("space key", "x").unwrap_err();
    assert!(matches!(err, FormatError::InvalidExtensionKey(_)));
}

#[test]
fn key_with_tab_rejected() {
    let mut ext = ExtensionMap::new();
    let err = ext.insert("tab\tkey", "x").unwrap_err();
    assert!(matches!(err, FormatError::InvalidExtensionKey(_)));
}

#[test]
fn key_with_newline_rejected() {
    let mut ext = ExtensionMap::new();
    let err = ext.insert("nl\nkey", "x").unwrap_err();
    assert!(matches!(err, FormatError::InvalidExtensionKey(_)));
}

#[test]
fn key_with_unicode_rejected() {
    let mut ext = ExtensionMap::new();
    let err = ext.insert("user\u{2028}name", "x").unwrap_err();
    assert!(matches!(err, FormatError::InvalidExtensionKey(_)));
}

#[test]
fn valid_keys_accepted() {
    let mut ext = ExtensionMap::new();
    ext.insert("src", "1.2.3.4").unwrap();
    ext.insert("Suser", "alice").unwrap();
    ext.insert("dvc_ip", "10.0.0.1").unwrap();
    ext.insert("cs1", "label").unwrap();
    ext.insert("event_id_99", "x").unwrap();
}

#[test]
fn severity_out_of_range_rejected() {
    let ev = SecurityEvent {
        vendor: "v".into(),
        product: "p".into(),
        version: "1".into(),
        event_id: "e".into(),
        name: "n".into(),
        severity: 11,
        extensions: ExtensionMap::new(),
    };
    let err = format_cef(&ev).unwrap_err();
    assert_eq!(err, FormatError::SeverityOutOfRange(11));
    let err2 = format_leef(&ev).unwrap_err();
    assert_eq!(err2, FormatError::SeverityOutOfRange(11));
}
