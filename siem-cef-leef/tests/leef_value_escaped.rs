// X-L: LEEF value escaping. The reviewer specifically flagged that the
// previous `leef_escape` only escaped `\\` and the configured delim — not
// `\n` or `\r`. These tests pin the new behaviour: every LEEF value is
// escaped against the full SIEM line-terminator set AND the delimiter.

use siem_cef_leef::*;

fn ev(value: &str) -> SecurityEvent {
    let mut ext = ExtensionMap::new();
    ext.insert("v", value).unwrap();
    SecurityEvent {
        vendor: "V".into(),
        product: "P".into(),
        version: "1".into(),
        event_id: "E".into(),
        name: "N".into(),
        severity: 3,
        extensions: ext,
    }
}

#[test]
fn lf_in_leef_value_is_escaped() {
    let s = format_leef(&ev("a\nb")).unwrap();
    assert!(!s.contains('\n'));
    assert!(s.contains(r"a\nb"));
}

#[test]
fn cr_in_leef_value_is_escaped() {
    let s = format_leef(&ev("a\rb")).unwrap();
    assert!(!s.contains('\r'));
    assert!(s.contains(r"a\rb"));
}

#[test]
fn nel_and_unicode_separators_in_leef_value_are_escaped() {
    let payload = format!("a{}b{}c{}d", '\u{0085}', '\u{2028}', '\u{2029}');
    let s = format_leef(&ev(&payload)).unwrap();
    assert!(!s.contains('\u{0085}'));
    assert!(!s.contains('\u{2028}'));
    assert!(!s.contains('\u{2029}'));
    assert!(s.contains("\\u0085"));
    assert!(s.contains("\\u2028"));
    assert!(s.contains("\\u2029"));
}

#[test]
fn pipe_in_leef_value_is_escaped() {
    // Pipe is the LEEF header separator. Even though values appear AFTER
    // the header, escaping is unconditional so a renamer that re-uses an
    // escape function elsewhere can't reintroduce the bug.
    let s = format_leef(&ev("payload|attack")).unwrap();
    let unescaped_pipes = s
        .as_bytes()
        .iter()
        .enumerate()
        .filter(|(i, b)| **b == b'|' && (*i == 0 || s.as_bytes()[*i - 1] != b'\\'))
        .count();
    // LEEF:2.0|V|P|1|E|^|... gives 6 unescaped pipes from the header.
    assert_eq!(unescaped_pipes, 6, "got {unescaped_pipes} unescaped pipes in {s:?}");
}

#[test]
fn caller_supplied_sev_does_not_duplicate() {
    let mut ext = ExtensionMap::new();
    ext.insert("sev", "9").unwrap();
    let event = SecurityEvent {
        vendor: "V".into(),
        product: "P".into(),
        version: "1".into(),
        event_id: "E".into(),
        name: "N".into(),
        severity: 3,
        extensions: ext,
    };
    let s = format_leef(&event).unwrap();
    let count = s.matches("sev=").count();
    assert_eq!(count, 1, "no duplicate sev= in LEEF output: {s:?}");
}
