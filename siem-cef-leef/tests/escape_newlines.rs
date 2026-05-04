// X-L: line-injection hardening. No attacker-controlled value may end the
// current CEF/LEEF record and forge a fully-formed second record. Every
// rendered output must remain a single line: zero CR, zero LF, zero NEL,
// zero U+2028/U+2029.

use siem_cef_leef::*;

fn rendered_is_single_line(s: &str) {
    for (idx, c) in s.char_indices() {
        assert!(
            !matches!(c, '\r' | '\n' | '\u{0085}' | '\u{2028}' | '\u{2029}'),
            "line terminator U+{:04X} at byte offset {idx} in {s:?}",
            c as u32
        );
    }
}

fn ev_with_value(key: &str, value: &str) -> SecurityEvent {
    let mut ext = ExtensionMap::new();
    ext.insert(key, value).unwrap();
    SecurityEvent {
        vendor: "VENDOR".into(),
        product: "PRODUCT".into(),
        version: "1".into(),
        event_id: "EID".into(),
        name: "NAME".into(),
        severity: 5,
        extensions: ext,
    }
}

#[test]
fn cef_newline_in_extension_value_does_not_split() {
    let ev = ev_with_value("suser", "alice\nCEF:0|EVIL|FORGED|x|y|root pwn|10|");
    let s = format_cef(&ev).unwrap();
    rendered_is_single_line(&s);
    // Forged second record must NOT appear as a literal substring.
    assert!(!s.contains("\nCEF:0"));
    assert!(s.contains(r"\n"));
}

#[test]
fn leef_newline_in_extension_value_does_not_split() {
    let ev = ev_with_value("suser", "alice\nLEEF:2.0|EVIL|FORGED|x|y|^|attack=1");
    let s = format_leef(&ev).unwrap();
    rendered_is_single_line(&s);
    assert!(!s.contains("\nLEEF:2.0"));
}

#[test]
fn cef_cr_in_header_field_is_escaped() {
    let mut ev = ev_with_value("src", "10.0.0.1");
    ev.product = "SSO\rCEF:0|EVIL|...".into();
    let s = format_cef(&ev).unwrap();
    rendered_is_single_line(&s);
    assert!(s.contains(r"\r"));
}

#[test]
fn cef_unicode_line_terminators_are_escaped() {
    let payload = format!(
        "alice{}eve{}mallory{}attacker",
        '\u{2028}', '\u{2029}', '\u{0085}'
    );
    let ev = ev_with_value("suser", &payload);
    let s = format_cef(&ev).unwrap();
    rendered_is_single_line(&s);
    assert!(s.contains("\\u2028"));
    assert!(s.contains("\\u2029"));
    assert!(s.contains("\\u0085"));
}

#[test]
fn leef_tab_delimiter_in_value_is_escaped() {
    // The LEEF delimiter is \t; an unescaped \t in a value would smuggle
    // additional key=value pairs into the record.
    let ev = ev_with_value("suser", "alice\tinjected=hostile");
    let s = format_leef(&ev).unwrap();
    // The literal injected key must not appear unescaped after a tab.
    assert!(!s.contains("\tinjected="));
    // The rendered tab inside the value is preceded by a backslash.
    assert!(s.contains("\\\t"));
    rendered_is_single_line(&s);
}

#[test]
fn cef_pipe_in_header_value_is_escaped() {
    // `vendor` is in the pipe-separated CEF header. Unescaped `|` would
    // forge a new field boundary. The CEF v0 header has 7 separators
    // (8 fields). Anything more shifts downstream parsing.
    let mut ev = ev_with_value("src", "1.2.3.4");
    ev.vendor = "EVIL|FAKE".into();
    let s = format_cef(&ev).unwrap();
    let bytes = s.as_bytes();
    let mut unescaped = 0usize;
    for (i, &b) in bytes.iter().enumerate() {
        if b != b'|' {
            continue;
        }
        // Count contiguous backslashes immediately preceding this byte.
        let mut backslashes = 0;
        let mut j = i;
        while j > 0 && bytes[j - 1] == b'\\' {
            backslashes += 1;
            j -= 1;
        }
        if backslashes % 2 == 0 {
            unescaped += 1;
        }
    }
    assert_eq!(
        unescaped, 7,
        "CEF v0 has exactly 7 unescaped | separators; got {unescaped} in {s:?}"
    );
}
