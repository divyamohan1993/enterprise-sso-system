use kerberos_pkinit::*;
use std::time::{Duration, SystemTime};

#[test]
fn keytab_missing_is_error() {
    assert!(validate_keytab("/nonexistent/keytab").is_err());
}

#[test]
fn trust_anchor_empty_path_rejected() {
    let err = validate_trust_anchor("").unwrap_err();
    assert!(matches!(err, PkinitError::TrustAnchor(_)));
}

#[test]
fn trust_anchor_missing_file_rejected() {
    let err = validate_trust_anchor("/nonexistent/anchors.pem").unwrap_err();
    assert!(matches!(err, PkinitError::TrustAnchor(_)));
}

#[test]
fn trust_anchor_non_pem_rejected() {
    let dir = std::env::temp_dir();
    let p = dir.join(format!("krb-anchor-{}.pem", std::process::id()));
    std::fs::write(&p, b"not a pem file").unwrap();
    let err = validate_trust_anchor(p.to_str().unwrap()).unwrap_err();
    assert!(matches!(err, PkinitError::TrustAnchor(_)));
    let _ = std::fs::remove_file(&p);
}

#[test]
fn trust_anchor_valid_pem_accepted() {
    let dir = std::env::temp_dir();
    let p = dir.join(format!("krb-anchor-ok-{}.pem", std::process::id()));
    std::fs::write(
        &p,
        b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
    ).unwrap();
    assert!(validate_trust_anchor(p.to_str().unwrap()).is_ok());
    let _ = std::fs::remove_file(&p);
}

#[test]
fn replay_cache_blocks_duplicate() {
    let rc = ReplayCache::new(Duration::from_secs(60));
    let auth = b"authenticator-bytes-001";
    rc.observe(auth).unwrap();
    let err = rc.observe(auth).unwrap_err();
    assert!(matches!(err, PkinitError::AuthenticatorReplay));
}

#[test]
fn replay_cache_distinct_auths_pass() {
    let rc = ReplayCache::new(Duration::from_secs(60));
    rc.observe(b"a1").unwrap();
    rc.observe(b"a2").unwrap();
    rc.observe(b"a3").unwrap();
    assert_eq!(rc.len(), 3);
}

#[test]
fn replay_cache_expires_after_ttl() {
    let rc = ReplayCache::new(Duration::from_millis(20));
    rc.observe(b"x").unwrap();
    std::thread::sleep(Duration::from_millis(40));
    // Expired entries are swept on next observe; the same key should pass.
    rc.observe(b"x").unwrap();
}

#[test]
fn config_round_trips() {
    let cfg = KrbConfig {
        realm: "MILNET.MIL".into(),
        kdc_hosts: vec!["kdc1.milnet.mil".into()],
        keytab_path: "/etc/krb5.keytab".into(),
        trust_anchor_pem: "/etc/krb5/anchors.pem".into(),
    };
    let s = serde_json::to_string(&cfg).unwrap();
    let back: KrbConfig = serde_json::from_str(&s).unwrap();
    assert_eq!(back.realm, "MILNET.MIL");
    assert_eq!(back.trust_anchor_pem, "/etc/krb5/anchors.pem");
}

#[test]
fn krb_time_is_positive() {
    assert!(to_krb_time(SystemTime::now()) > 0);
}
