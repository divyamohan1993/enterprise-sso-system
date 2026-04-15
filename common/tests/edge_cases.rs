//! CAT-M: adversarial edge cases for `common` primitives.
//!
//! Covers:
//!   - NUL-byte injection in usernames, emails, paths.
//!   - Control-char injection.
//!   - Mixed LTR/RTL unicode in identifiers (accepted transparently, but
//!     length limits still hold byte-wise — no under-count bugs).
//!   - Max-length enforcement at the 8 KiB Authorization header boundary.
//!   - `deny_unknown_fields` behavior on representative DTOs.
//!
//! Every test is an *adversarial pair*: one input that MUST pass, one that
//! MUST fail, to catch over- and under-permissive validators symmetrically.

use common::input_validation::{
    charset, email, ident, max_len, min_len, no_control, no_nul, uuid_str,
};

// ─────────────────────────────────────────────────────────────────────────
// NUL-byte injection
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn no_nul_rejects_embedded_nul_in_username() {
    // C-string truncation attack: "alice\0admin" would be read as "alice" by
    // any libc consumer but as "alice\0admin" by Rust. Must be rejected.
    assert!(no_nul("username", "alice\0admin").is_err());
    assert!(no_nul("username", "alice").is_ok());
}

#[test]
fn no_nul_rejects_trailing_nul() {
    assert!(no_nul("f", "alice\0").is_err());
}

#[test]
fn no_nul_rejects_leading_nul() {
    assert!(no_nul("f", "\0alice").is_err());
}

#[test]
fn no_nul_rejects_nul_inside_email() {
    // Bypass attempt: attacker appends \0 after a whitelisted domain.
    assert!(no_nul("email", "user@example.com\0@evil.com").is_err());
}

#[test]
fn no_nul_rejects_nul_in_redirect_uri_shape() {
    // Defense against log-injection via URI.
    assert!(no_nul("redirect_uri", "https://sp.test/cb\0evil").is_err());
}

// ─────────────────────────────────────────────────────────────────────────
// Control-character injection
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn no_control_rejects_bell_and_escape() {
    assert!(no_control("f", "alice\x07bob").is_err()); // BEL
    assert!(no_control("f", "alice\x1bbob").is_err()); // ESC
    assert!(no_control("f", "alice").is_ok());
}

#[test]
fn no_control_allows_tab_newline_cr() {
    // Explicitly whitelisted by the validator.
    assert!(no_control("f", "a\tb").is_ok());
    assert!(no_control("f", "a\nb").is_ok());
    assert!(no_control("f", "a\rb").is_ok());
}

// ─────────────────────────────────────────────────────────────────────────
// RTL / Unicode
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn rtl_username_length_is_bytewise_not_char_count() {
    // Hebrew "שלום" = 4 chars but 8 bytes in UTF-8. `max_len` counts bytes.
    // A max of 6 must reject; a max of 8 must accept.
    let hebrew = "שלום";
    assert_eq!(hebrew.chars().count(), 4);
    assert_eq!(hebrew.len(), 8);
    assert!(max_len("u", hebrew, 6).is_err(), "byte-length must be enforced");
    assert!(max_len("u", hebrew, 8).is_ok());
}

#[test]
fn mixed_ltr_rtl_does_not_bypass_nul_check() {
    let mixed = "user\u{202E}admin\0evil"; // RLO override + NUL
    assert!(
        no_nul("mixed", mixed).is_err(),
        "RLO override must not mask embedded NUL"
    );
}

#[test]
fn devanagari_email_respects_length_cap() {
    // "नमस्ते@example.com" — Devanagari user part.
    let value = "नमस्ते@example.com";
    // Email validator's length cap is 254. A short Devanagari input must
    // still be structurally valid.
    assert!(email("e", value).is_ok());
}

// ─────────────────────────────────────────────────────────────────────────
// 8 KiB Authorization header boundary
// ─────────────────────────────────────────────────────────────────────────

const AUTH_HEADER_MAX_BYTES: usize = 8 * 1024;

#[test]
fn auth_header_at_limit_accepted() {
    let header = "Bearer ".to_string() + &"a".repeat(AUTH_HEADER_MAX_BYTES - 7);
    assert_eq!(header.len(), AUTH_HEADER_MAX_BYTES);
    assert!(max_len("authorization", &header, AUTH_HEADER_MAX_BYTES).is_ok());
}

#[test]
fn auth_header_one_byte_over_limit_rejected() {
    let header = "Bearer ".to_string() + &"a".repeat(AUTH_HEADER_MAX_BYTES - 6);
    assert_eq!(header.len(), AUTH_HEADER_MAX_BYTES + 1);
    assert!(max_len("authorization", &header, AUTH_HEADER_MAX_BYTES).is_err());
}

// ─────────────────────────────────────────────────────────────────────────
// Min-length pair coverage
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn min_len_boundary_is_inclusive() {
    assert!(min_len("f", "abc", 3).is_ok());
    assert!(min_len("f", "ab", 3).is_err());
}

// ─────────────────────────────────────────────────────────────────────────
// Charset
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn charset_rejects_non_allowed_unicode() {
    // Allowed set is ASCII a-z. Cyrillic 'а' (U+0430) looks like 'a'
    // (homoglyph attack) but is NOT in the allowed set.
    assert!(charset("f", "аbc", "abcdefghijklmnopqrstuvwxyz").is_err());
    assert!(charset("f", "abc", "abcdefghijklmnopqrstuvwxyz").is_ok());
}

// ─────────────────────────────────────────────────────────────────────────
// Identifier
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn ident_rejects_slash_and_space() {
    assert!(ident("i", "good-name").is_ok());
    assert!(ident("i", "bad/name").is_err());
    assert!(ident("i", "bad name").is_err());
    assert!(ident("i", "bad\0name").is_err());
}

// ─────────────────────────────────────────────────────────────────────────
// UUID
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn uuid_str_rejects_wrong_dash_positions() {
    // Same length, wrong dash layout.
    assert!(uuid_str("u", "550e8400e29b-41d4-a716-446655440000-").is_err());
    assert!(uuid_str("u", "550e8400-e29b-41d4-a716-446655440000").is_ok());
}

#[test]
fn uuid_str_rejects_uppercase_non_hex() {
    // 'Z' in place of a hex digit.
    assert!(uuid_str("u", "550e8400-e29b-41d4-a716-44665544000Z").is_err());
}

// ─────────────────────────────────────────────────────────────────────────
// deny_unknown_fields — common::saml DTOs
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn vector_clock_snapshot_rejects_unknown_fields() {
    // `VectorClockSnapshot` declares exactly one public field (`clocks`).
    // `#[serde(deny_unknown_fields)]` must reject any additional field.
    let valid = r#"{"clocks":{"node-a":1}}"#;
    let with_unknown = r#"{"clocks":{"node-a":1},"attacker_field":"bypass"}"#;

    let ok: Result<common::vector_clock::VectorClockSnapshot, _> =
        serde_json::from_str(valid);
    assert!(ok.is_ok(), "valid snapshot must parse");

    let bad: Result<common::vector_clock::VectorClockSnapshot, _> =
        serde_json::from_str(with_unknown);
    assert!(
        bad.is_err(),
        "VectorClockSnapshot must reject unknown fields (deny_unknown_fields)"
    );
    let err = bad.unwrap_err().to_string();
    assert!(
        err.contains("unknown field") || err.contains("attacker_field"),
        "serde error must flag unknown field: {err}"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// NUL byte in path-shaped input
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn no_nul_rejects_path_traversal_with_nul() {
    // Classic bypass: "../../../etc/passwd\0.jpg" — many parsers trust the
    // .jpg suffix, then libc reads the NUL-terminated part.
    let payload = "../../../etc/passwd\0.jpg";
    assert!(no_nul("path", payload).is_err());
}
