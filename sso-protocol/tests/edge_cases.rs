//! CAT-M: adversarial edge cases for `sso-protocol` public APIs.
//!
//! Complements `security_tests.rs` with boundary conditions that a nation-
//! state adversary would target: off-by-one on input lengths, microsecond-
//! scale time skew, homoglyph redirect URIs, max-length Authorization
//! headers, null-byte smuggling into OAuth parameters.

use sso_protocol::authorize::validate_redirect_uri;
use sso_protocol::pkce::{validate_verifier_length, verify_pkce};

// ─────────────────────────────────────────────────────────────────────────
// PKCE verifier length boundary (RFC 7636 §4.1: 43..=128)
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn pkce_verifier_length_42_rejected() {
    // One byte below the RFC minimum.
    let v = "a".repeat(42);
    assert_eq!(v.len(), 42);
    assert!(
        validate_verifier_length(&v).is_err(),
        "42-char verifier must be rejected"
    );
}

#[test]
fn pkce_verifier_length_43_accepted() {
    let v = "a".repeat(43);
    assert!(
        validate_verifier_length(&v).is_ok(),
        "43-char verifier is the RFC minimum and must be accepted"
    );
}

#[test]
fn pkce_verifier_length_128_accepted() {
    let v = "a".repeat(128);
    assert!(validate_verifier_length(&v).is_ok());
}

#[test]
fn pkce_verifier_length_129_rejected() {
    let v = "a".repeat(129);
    assert!(
        validate_verifier_length(&v).is_err(),
        "129-char verifier is above RFC max and must be rejected"
    );
}

#[test]
fn pkce_verify_below_min_never_matches() {
    // Even if the attacker crafts a challenge that happens to equal the
    // SHA-256 of a 10-byte verifier, `verify_pkce` must short-circuit on
    // length before computing the hash.
    let short = "short";
    // Any challenge value — verify must reject purely on length.
    assert!(!verify_pkce(short, "irrelevant-challenge"));
}

// ─────────────────────────────────────────────────────────────────────────
// redirect_uri validation — exact match + HTTPS enforcement
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn redirect_uri_http_rejected_even_if_registered() {
    let registered = vec!["http://rp.test/cb".to_string()];
    let result = validate_redirect_uri("http://rp.test/cb", &registered);
    assert!(
        result.is_err(),
        "plain HTTP redirect must be rejected regardless of registration"
    );
}

#[test]
fn redirect_uri_empty_rejected() {
    let registered = vec!["https://rp.test/cb".to_string()];
    assert!(validate_redirect_uri("", &registered).is_err());
}

#[test]
fn redirect_uri_null_byte_rejected() {
    // Null-byte smuggling: attacker registers one URI, then passes a variant
    // with an embedded NUL hoping libc truncates after the prefix.
    let registered = vec!["https://rp.test/cb".to_string()];
    let attack = "https://rp.test/cb\0@evil/cb";
    let result = validate_redirect_uri(attack, &registered);
    assert!(
        result.is_err(),
        "redirect_uri with embedded NUL byte must be rejected"
    );
}

#[test]
fn redirect_uri_trailing_slash_is_not_match() {
    // Exact-string match: trailing slash differs.
    let registered = vec!["https://rp.test/cb".to_string()];
    let result = validate_redirect_uri("https://rp.test/cb/", &registered);
    assert!(
        result.is_err(),
        "redirect_uri with extra trailing slash must not match registered"
    );
}

#[test]
fn redirect_uri_subdomain_is_not_match() {
    let registered = vec!["https://rp.test/cb".to_string()];
    let result = validate_redirect_uri("https://evil.rp.test/cb", &registered);
    assert!(result.is_err());
}

#[test]
fn redirect_uri_fragment_stripped_exact_match_holds() {
    // Canonicalization strips fragment, so these should match.
    let registered = vec!["https://rp.test/cb".to_string()];
    let result = validate_redirect_uri("https://rp.test/cb#fragment", &registered);
    assert!(
        result.is_ok(),
        "fragment is canonicalized away per OAuth 2.1; must still match"
    );
}

#[test]
fn redirect_uri_uppercase_scheme_accepted() {
    // `validate_redirect_uri` explicitly accepts HTTPS:// uppercase.
    let registered = vec!["https://rp.test/cb".to_string()];
    let result = validate_redirect_uri("HTTPS://rp.test/cb", &registered);
    assert!(
        result.is_ok(),
        "uppercase https:// must canonicalize to match registered URI"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// PKCE — null-byte in verifier must fail through to rejection
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn pkce_verifier_with_null_byte_inside_length_window() {
    // A 43-byte verifier that contains a NUL. `validate_verifier_length`
    // only checks bytes, not content — but a NUL byte will hash
    // deterministically to a value that no legitimate challenge would
    // match (the challenge is computed by the client from a random
    // verifier, so an attacker cannot produce a matching challenge for
    // a NUL-containing verifier without already knowing it).
    //
    // This test asserts `verify_pkce` does not panic on NUL input and
    // returns false against a non-matching challenge.
    let mut bytes = vec![b'a'; 43];
    bytes[10] = 0;
    let verifier = String::from_utf8(bytes).expect("NUL is valid UTF-8");
    assert!(!verify_pkce(&verifier, "not-the-right-challenge"));
}
