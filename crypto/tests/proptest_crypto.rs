use proptest::prelude::*;
use crypto::ct::{ct_eq, ct_eq_32};
use crypto::envelope::{DataEncryptionKey, KeyEncryptionKey, decrypt, encrypt, wrap_key, unwrap_key};
use crypto::xwing::{XWingKeyPair, xwing_decapsulate, xwing_encapsulate, derive_session_key};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]
    #[test]
    fn aes256gcm_roundtrip(pt in prop::collection::vec(any::<u8>(), 0..4096), aad in prop::collection::vec(any::<u8>(), 0..256)) {
        let dek = DataEncryptionKey::generate();
        let sealed = encrypt(&dek, &pt, &aad).unwrap();
        prop_assert_eq!(decrypt(&dek, &sealed, &aad).unwrap(), pt);
    }
    #[test]
    fn aes256gcm_wrong_key(pt in prop::collection::vec(any::<u8>(), 1..512)) {
        let d1 = DataEncryptionKey::generate();
        let d2 = DataEncryptionKey::generate();
        let s = encrypt(&d1, &pt, b"a").unwrap();
        prop_assert!(decrypt(&d2, &s, b"a").is_err());
    }
    #[test]
    fn hkdf_deterministic(ikm in prop::collection::vec(any::<u8>(), 16..128), salt in prop::collection::vec(any::<u8>(), 0..64), info in prop::collection::vec(any::<u8>(), 0..64)) {
        use sha2::Sha512; use hkdf::Hkdf;
        let sr = if salt.is_empty() { None } else { Some(salt.as_slice()) };
        let (mut o1, mut o2) = ([0u8;64],[0u8;64]);
        Hkdf::<Sha512>::new(sr, &ikm).expand(&info, &mut o1).unwrap();
        Hkdf::<Sha512>::new(sr, &ikm).expand(&info, &mut o2).unwrap();
        prop_assert_eq!(o1, o2);
    }
    #[test]
    fn ct_eq_reflexive(d in prop::collection::vec(any::<u8>(), 0..256)) { prop_assert!(ct_eq(&d, &d)); }
    #[test]
    fn ct_eq_diff_len(a in prop::collection::vec(any::<u8>(), 1..128), e in 1..64usize) {
        let mut b = a.clone(); b.extend(vec![0u8; e]); prop_assert!(!ct_eq(&a, &b));
    }
    #[test]
    fn ct_eq32_ref(d in prop::array::uniform32(any::<u8>())) { prop_assert!(ct_eq_32(&d, &d)); }
    #[test]
    fn wrap_unwrap(kb in prop::array::uniform32(any::<u8>())) {
        let kek = KeyEncryptionKey::generate();
        let dek = DataEncryptionKey::from_bytes(kb);
        let o = *dek.as_bytes();
        prop_assert_eq!(*unwrap_key(&kek, &wrap_key(&kek, &dek).unwrap()).unwrap().as_bytes(), o);
    }
    #[test]
    fn nonce_unique(_ in 0..100u32) {
        let d = DataEncryptionKey::generate();
        let s1 = encrypt(&d, b"x", b"a").unwrap();
        let s2 = encrypt(&d, b"x", b"a").unwrap();
        prop_assert_ne!(s1.nonce(), s2.nonce());
    }
}

#[test]
fn xwing_roundtrip() {
    for _ in 0..3 { let kp = XWingKeyPair::generate(); let pk = kp.public_key(); let (cs,ct) = xwing_encapsulate(&pk); assert_eq!(cs.as_bytes(), xwing_decapsulate(&kp, &ct).as_bytes()); }
}
#[test]
fn xwing_session_key_det() {
    let kp = XWingKeyPair::generate(); let (ss,_) = xwing_encapsulate(&kp.public_key());
    assert_eq!(derive_session_key(&ss, b"c"), derive_session_key(&ss, b"c"));
}
#[test]
fn xwing_diff_ctx() {
    let kp = XWingKeyPair::generate(); let (ss,_) = xwing_encapsulate(&kp.public_key());
    assert_ne!(derive_session_key(&ss, b"a"), derive_session_key(&ss, b"b"));
}
