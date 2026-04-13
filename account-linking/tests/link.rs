use account_linking::*;

#[test]
fn link_and_resolve() {
    let s = LinkStore::new(b"secret".to_vec());
    let l = s.link("alice@milnet", Provider::Google, "google-sub-1").unwrap();
    assert!(s.verify(&l).is_ok());
    let r = s.resolve(Provider::Google, "google-sub-1").unwrap();
    assert_eq!(r.milnet_user, "alice@milnet");
}

#[test]
fn double_link_other_user_rejected() {
    let s = LinkStore::new(b"k".to_vec());
    s.link("alice", Provider::EntraId, "oid-1").unwrap();
    let err = s.link("bob", Provider::EntraId, "oid-1").unwrap_err();
    matches!(err, LinkError::AlreadyLinked(_));
}

#[test]
fn tampered_attestation_rejected() {
    let s = LinkStore::new(b"k".to_vec());
    let mut l = s.link("alice", Provider::Cac, "edipi-9").unwrap();
    l.milnet_user = "mallory".into();
    assert!(s.verify(&l).is_err());
}
