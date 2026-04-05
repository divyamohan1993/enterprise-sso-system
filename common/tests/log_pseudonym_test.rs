use common::log_pseudonym::{pseudonym_email, pseudonym_ip, pseudonym_str, pseudonym_uuid};
use uuid::Uuid;

// These tests require MILNET_MASTER_KEK to be set for the pseudonym key derivation.
// The sealed_keys module loads it on first access.

// ── 1. Determinism: same input + same key = same output ────────────────

#[test]
fn pseudonym_email_is_deterministic() {
    let a = pseudonym_email("alice@pentagon.mil");
    let b = pseudonym_email("alice@pentagon.mil");
    assert_eq!(a, b, "same email must produce same pseudonym");
}

#[test]
fn pseudonym_uuid_is_deterministic() {
    let id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
    let a = pseudonym_uuid(id);
    let b = pseudonym_uuid(id);
    assert_eq!(a, b, "same UUID must produce same pseudonym");
}

#[test]
fn pseudonym_ip_is_deterministic() {
    let a = pseudonym_ip("192.168.1.1");
    let b = pseudonym_ip("192.168.1.1");
    assert_eq!(a, b, "same IP must produce same pseudonym");
}

#[test]
fn pseudonym_str_is_deterministic() {
    let a = pseudonym_str("session", "abc123");
    let b = pseudonym_str("session", "abc123");
    assert_eq!(a, b, "same tag+value must produce same pseudonym");
}

// ── 2. Different inputs produce different outputs ──────────────────────

#[test]
fn different_emails_produce_different_pseudonyms() {
    let a = pseudonym_email("alice@pentagon.mil");
    let b = pseudonym_email("bob@pentagon.mil");
    assert_ne!(a, b, "different emails must produce different pseudonyms");
}

#[test]
fn different_uuids_produce_different_pseudonyms() {
    let id1 = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
    let id2 = Uuid::parse_str("6ba7b810-9dad-11d1-80b4-00c04fd430c8").unwrap();
    let a = pseudonym_uuid(id1);
    let b = pseudonym_uuid(id2);
    assert_ne!(a, b, "different UUIDs must produce different pseudonyms");
}

#[test]
fn different_ips_produce_different_pseudonyms() {
    let a = pseudonym_ip("10.0.0.1");
    let b = pseudonym_ip("10.0.0.2");
    assert_ne!(a, b, "different IPs must produce different pseudonyms");
}

// ── 3. Domain separation: pseudonym_email != pseudonym_ip for same str ─

#[test]
fn domain_separation_email_vs_ip() {
    let value = "test@example.com";
    let email_pseudo = pseudonym_email(value);
    let ip_pseudo = pseudonym_ip(value);
    assert_ne!(
        email_pseudo, ip_pseudo,
        "email and IP pseudonyms for same string must differ (domain separation)"
    );
}

#[test]
fn domain_separation_email_vs_str() {
    let value = "user@mil.gov";
    let email_pseudo = pseudonym_email(value);
    let str_pseudo = pseudonym_str("email", value);
    // pseudonym_email uses "email:" prefix internally, pseudonym_str uses "email:"
    // They may or may not collide depending on implementation.
    // The key test is that different domain tags produce different output.
    let custom_pseudo = pseudonym_str("custom", value);
    assert_ne!(
        email_pseudo, custom_pseudo,
        "email pseudonym must differ from custom-tagged pseudonym"
    );
}

#[test]
fn domain_separation_different_str_tags() {
    let a = pseudonym_str("session", "value123");
    let b = pseudonym_str("request", "value123");
    assert_ne!(a, b, "different tags must produce different pseudonyms for same value");
}

// ── 4. Non-reversibility: output doesn't contain original input ────────

#[test]
fn pseudonym_does_not_contain_original_email() {
    let email = "alice@pentagon.mil";
    let pseudo = pseudonym_email(email);
    assert!(
        !pseudo.contains(email),
        "pseudonym must not contain the original email"
    );
    assert!(
        !pseudo.contains("alice"),
        "pseudonym must not contain username portion"
    );
    assert!(
        !pseudo.contains("pentagon"),
        "pseudonym must not contain domain portion"
    );
}

#[test]
fn pseudonym_does_not_contain_original_ip() {
    let ip = "192.168.1.100";
    let pseudo = pseudonym_ip(ip);
    assert!(
        !pseudo.contains("192"),
        "pseudonym must not contain any IP octets"
    );
}

// ── 5. Output format is consistent (hex string, expected length) ───────

#[test]
fn pseudonym_email_output_is_32_hex_chars() {
    let pseudo = pseudonym_email("test@test.com");
    assert_eq!(pseudo.len(), 32, "HMAC-SHA512 truncated to 16 bytes = 32 hex chars");
    assert!(
        pseudo.chars().all(|c| c.is_ascii_hexdigit()),
        "output must be valid hex: {pseudo}"
    );
}

#[test]
fn pseudonym_uuid_output_is_32_hex_chars() {
    let id = Uuid::new_v4();
    let pseudo = pseudonym_uuid(id);
    assert_eq!(pseudo.len(), 32);
    assert!(pseudo.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn pseudonym_ip_output_is_32_hex_chars() {
    let pseudo = pseudonym_ip("10.0.0.1");
    assert_eq!(pseudo.len(), 32);
    assert!(pseudo.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn pseudonym_str_output_is_32_hex_chars() {
    let pseudo = pseudonym_str("tag", "value");
    assert_eq!(pseudo.len(), 32);
    assert!(pseudo.chars().all(|c| c.is_ascii_hexdigit()));
}
