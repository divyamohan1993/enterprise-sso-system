use kerberos_pkinit::{validate_keytab, KrbConfig, to_krb_time};
use std::time::SystemTime;

#[test]
fn keytab_missing_is_error() {
    assert!(validate_keytab("/nonexistent/keytab").is_err());
}

#[test]
fn config_round_trips() {
    let cfg = KrbConfig {
        realm: "MILNET.MIL".into(),
        kdc_hosts: vec!["kdc1.milnet.mil".into()],
        keytab_path: "/etc/krb5.keytab".into(),
        trust_anchor_pem: String::new(),
    };
    let s = serde_json::to_string(&cfg).unwrap();
    let back: KrbConfig = serde_json::from_str(&s).unwrap();
    assert_eq!(back.realm, "MILNET.MIL");
}

#[test]
fn krb_time_is_positive() {
    assert!(to_krb_time(SystemTime::now()) > 0);
}
