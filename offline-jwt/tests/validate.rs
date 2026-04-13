use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use offline_jwt::*;

fn build_token() -> String {
    let h = serde_json::json!({"alg":"ED25519","kid":"k1"});
    let p = serde_json::json!({"jti":"abc","exp": 9999999999_i64});
    let h_enc = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&h).unwrap());
    let p_enc = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&p).unwrap());
    let sig_enc = URL_SAFE_NO_PAD.encode([1u8; 8]);
    format!("{}.{}.{}", h_enc, p_enc, sig_enc)
}

#[test]
fn valid_token_passes() {
    let mut store = PinnedTrustStore::new();
    store.pin(PinnedKey { kid: "k1".into(), algorithm: "ED25519".into(), public_key_der: vec![] });
    let crl = RevocationList::default();
    let cache = ReplayCache::new();
    let c = validate(&build_token(), &store, &crl, &cache, 0, |_, _, _| true).unwrap();
    assert_eq!(c.jti, "abc");
}

#[test]
fn replay_rejected() {
    let mut store = PinnedTrustStore::new();
    store.pin(PinnedKey { kid: "k1".into(), algorithm: "ED25519".into(), public_key_der: vec![] });
    let crl = RevocationList::default();
    let cache = ReplayCache::new();
    let t = build_token();
    validate(&t, &store, &crl, &cache, 0, |_, _, _| true).unwrap();
    let err = validate(&t, &store, &crl, &cache, 0, |_, _, _| true).unwrap_err();
    matches!(err, OfflineError::Replayed);
}
