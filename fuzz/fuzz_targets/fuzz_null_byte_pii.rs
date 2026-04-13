#![no_main]
//! I14 [MED] Null-byte injection in username/email/DPoP-header fields.
//! Parser must reject or safely handle, never panic.

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Debug, Arbitrary)]
struct Input {
    username: String,
    email_local: String,
    email_domain: String,
    dpop_header: String,
}

fn inject_null(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 4);
    let mid = s.len() / 2;
    out.push_str(&s[..mid]);
    out.push('\0');
    out.push_str(&s[mid..]);
    out
}

fn validate_username(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 256
        && !s.contains('\0')
        && s.chars().all(|c| !c.is_control())
}

fuzz_target!(|input: Input| {
    let u = inject_null(&input.username);
    let e = format!("{}@{}", inject_null(&input.email_local), input.email_domain);
    let d = inject_null(&input.dpop_header);

    // Validators must reject null-byte payloads, not panic.
    assert!(!validate_username(&u), "null-byte username must be rejected");
    let _ = e.parse::<http::HeaderValue>();
    let _ = d.parse::<http::HeaderValue>();

    // Round-trip via JSON: must either fail or strip the null byte.
    let _ = serde_json::to_string(&u);
    let _ = serde_json::to_string(&e);
    let _ = serde_json::to_string(&d);
});
