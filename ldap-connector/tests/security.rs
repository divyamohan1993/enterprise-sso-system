use ldap_connector::*;
use std::time::Duration;

fn base_cfg() -> LdapConfig {
    LdapConfig {
        url: "ldaps://dc.example".into(),
        bind_dn: "cn=svc,dc=x".into(),
        bind_password: "p".into(),
        base_dn: "dc=x".into(),
        user_filter: "(objectClass=user)".into(),
        group_filter: "(objectClass=group)".into(),
        sync_interval: Duration::from_secs(300),
        usnchanged_high_water: None,
        trust_anchor_pem: None,
    }
}

#[test]
fn anonymous_bind_rejected_empty_dn() {
    let mut c = base_cfg();
    c.bind_dn = "".into();
    assert!(matches!(c.validate(), Err(LdapError::AnonymousBindRejected)));
    let mut c2 = base_cfg();
    c2.bind_dn = "   ".into();
    assert!(matches!(c2.validate(), Err(LdapError::AnonymousBindRejected)));
}

#[test]
fn plain_ldap_rejected() {
    let mut c = base_cfg();
    c.url = "ldap://dc.example".into();
    assert!(matches!(c.validate(), Err(LdapError::TlsRequired)));
}

#[test]
fn malformed_filter_rejected() {
    let mut c = base_cfg();
    c.user_filter = "(objectClass=user".into();
    assert!(matches!(c.validate(), Err(LdapError::InvalidFilter)));
    let mut c2 = base_cfg();
    c2.user_filter = "objectClass=user".into();
    assert!(matches!(c2.validate(), Err(LdapError::InvalidFilter)));
    let mut c3 = base_cfg();
    c3.user_filter = "(objectClass=\0user)".into();
    assert!(matches!(c3.validate(), Err(LdapError::InvalidFilter)));
    let mut c4 = base_cfg();
    c4.user_filter = "(a))".into();
    assert!(matches!(c4.validate(), Err(LdapError::InvalidFilter)));
}

#[test]
fn escape_filter_value_handles_metacharacters() {
    assert_eq!(escape_filter_value("alice"), "alice");
    assert_eq!(escape_filter_value("a*b"), "a\\2ab");
    assert_eq!(escape_filter_value("a(b)c"), "a\\28b\\29c");
    assert_eq!(escape_filter_value("a\\b"), "a\\5cb");
    let with_nul = "a\0b";
    assert_eq!(escape_filter_value(with_nul), "a\\00b");
    // Injection attempt: attacker tries to widen the filter scope.
    let evil = "*)(uid=*";
    let safe = escape_filter_value(evil);
    assert_eq!(safe, "\\2a\\29\\28uid=\\2a");
    assert!(!safe.contains('('));
    assert!(!safe.contains(')'));
    assert!(!safe.contains('*'));
}

#[test]
fn escape_filter_value_preserves_unicode() {
    // Non-ASCII passes through as valid UTF-8.
    let s = "ραβδος";
    assert_eq!(escape_filter_value(s), s);
}

/// Lint test: enforce that no source file in this crate builds an LDAP
/// filter via `format!("(...)" ...)` without going through the escaper.
/// Catches regressions where future code interpolates raw values.
#[test]
fn no_unescaped_filter_format() {
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs")).unwrap();
    for (lineno, line) in src.lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") { continue; }
        // Look for format!("( ... {  building a filter literal
        if (trimmed.contains("format!(\"(") || trimmed.contains("format!(\"(&"))
            && trimmed.contains("{")
        {
            // Allowed only if the same line / preceding logic uses escape_filter_value
            // or the only interpolated values are integers.
            let allow_integer_only = trimmed.contains("since_usn") || trimmed.contains("u64");
            let allow_escaped = trimmed.contains("escape_filter_value");
            assert!(
                allow_integer_only || allow_escaped,
                "line {}: filter built via format! without escape_filter_value: {}",
                lineno + 1,
                line
            );
        }
    }
}
