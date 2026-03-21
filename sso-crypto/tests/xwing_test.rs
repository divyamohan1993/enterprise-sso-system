use sso_crypto::xwing::{xwing_decapsulate, xwing_encapsulate, XWingKeyPair};

#[test]
fn xwing_key_exchange_produces_shared_secret() {
    let server_kp = XWingKeyPair::generate();
    let server_pk = server_kp.public_key();

    let (client_ss, ciphertext) = xwing_encapsulate(&server_pk);
    let server_ss = xwing_decapsulate(&server_kp, &ciphertext);

    assert_eq!(
        client_ss.as_bytes(),
        server_ss.as_bytes(),
        "encapsulate and decapsulate must produce the same shared secret"
    );
}

#[test]
fn xwing_different_sessions_different_secrets() {
    let server_kp = XWingKeyPair::generate();
    let server_pk = server_kp.public_key();

    let (ss1, _ct1) = xwing_encapsulate(&server_pk);
    let (ss2, _ct2) = xwing_encapsulate(&server_pk);

    assert_ne!(
        ss1.as_bytes(),
        ss2.as_bytes(),
        "two independent encapsulations must produce different shared secrets"
    );
}

#[test]
fn xwing_wrong_key_fails() {
    let server_kp = XWingKeyPair::generate();
    let wrong_kp = XWingKeyPair::generate();
    let server_pk = server_kp.public_key();

    let (client_ss, ciphertext) = xwing_encapsulate(&server_pk);
    let wrong_ss = xwing_decapsulate(&wrong_kp, &ciphertext);

    assert_ne!(
        client_ss.as_bytes(),
        wrong_ss.as_bytes(),
        "decapsulating with the wrong key must produce a different shared secret"
    );
}
