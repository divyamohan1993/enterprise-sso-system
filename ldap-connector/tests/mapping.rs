use ldap_connector::*;
use std::collections::HashMap;
use std::time::Duration;

#[test]
fn ldaps_required() {
    let cfg = LdapConfig {
        url: "ldap://dc.example".into(),
        bind_dn: "cn=svc,dc=x".into(),
        bind_password: "p".into(),
        base_dn: "dc=x".into(),
        user_filter: "(objectClass=user)".into(),
        group_filter: "(objectClass=group)".into(),
        sync_interval: Duration::from_secs(300),
        usnchanged_high_water: None,
        trust_anchor_pem: None,
    };
    assert!(matches!(cfg.validate(), Err(LdapError::TlsRequired)));
}

#[test]
fn maps_ad_user_attrs_to_scim() {
    let mut a: HashMap<String, Vec<String>> = HashMap::new();
    a.insert("sAMAccountName".into(), vec!["alice".into()]);
    a.insert("displayName".into(), vec!["Alice Test".into()]);
    a.insert("mail".into(), vec!["alice@milnet.mil".into()]);
    a.insert("userAccountControl".into(), vec!["512".into()]);
    a.insert("uSNChanged".into(), vec!["12345".into()]);
    let u = map_ldap_attrs_to_scim_user("CN=Alice,DC=milnet,DC=mil", &a);
    assert_eq!(u.user_name, "alice");
    assert_eq!(u.display_name, "Alice Test");
    assert!(u.active);
    assert_eq!(u.usnchanged, Some(12345));
}

#[test]
fn disabled_account_inactive() {
    let mut a: HashMap<String, Vec<String>> = HashMap::new();
    a.insert("userAccountControl".into(), vec!["514".into()]);
    let u = map_ldap_attrs_to_scim_user("CN=B", &a);
    assert!(!u.active);
}
