use proptest::prelude::*;
use sso_protocol::pkce::{generate_challenge, verify_pkce};
use sso_protocol::authorize::AuthorizationStore;
use sso_protocol::tokens::{OidcSigningKey, create_id_token, create_id_token_with_tier, verify_id_token, verify_id_token_with_audience};
fn pkce_verifier_strategy() -> impl Strategy<Value = String> { prop::string::string_regex("[A-Za-z0-9\\-._~]{43,128}").unwrap() }
proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]
    #[test] fn pkce_roundtrip(v in pkce_verifier_strategy()) { let c = generate_challenge(&v); prop_assert!(verify_pkce(&v, &c)); }
    #[test] fn pkce_diff_fail(v1 in pkce_verifier_strategy(), v2 in pkce_verifier_strategy()) { prop_assume!(v1 != v2); let c = generate_challenge(&v1); prop_assert!(!verify_pkce(&v2, &c)); }
}
static KEY: std::sync::LazyLock<OidcSigningKey> = std::sync::LazyLock::new(|| { std::thread::Builder::new().stack_size(16*1024*1024).spawn(OidcSigningKey::generate).unwrap().join().unwrap() });
fn big<F: FnOnce() + Send + 'static>(f: F) { std::thread::Builder::new().stack_size(16*1024*1024).spawn(f).unwrap().join().unwrap(); }
#[test] fn token_roundtrip() { big(|| { let k = &*KEY; let u = uuid::Uuid::new_v4(); let t = create_id_token("https://iss", &u, "c", Some("n".into()), k); let cl = verify_id_token(&t, k.verifying_key()).unwrap(); assert_eq!(cl.sub, u.to_string()); }); }
#[test] fn token_wrong_key() { big(|| { let k1 = OidcSigningKey::generate(); let k2 = OidcSigningKey::generate(); let t = create_id_token("https://iss", &uuid::Uuid::new_v4(), "c", None, &k1); assert!(verify_id_token(&t, k2.verifying_key()).is_err()); }); }
#[test] fn token_tier() { big(|| { let k = &*KEY; for tier in [1u8,2,3] { let t = create_id_token_with_tier("https://i", &uuid::Uuid::new_v4(), "c", None, k, tier); assert_eq!(verify_id_token(&t, k.verifying_key()).unwrap().tier, tier); } }); }
#[test] fn auth_code_once() { let mut s = AuthorizationStore::new(); let c = s.create_code("c","https://r",uuid::Uuid::new_v4(),"o",Some(generate_challenge("abcdefghij_1234567890_abcdefghij_1234567890_abc")),None).unwrap(); assert!(s.consume_code(&c).is_some()); assert!(s.consume_code(&c).is_none()); }
#[test] fn audience_mismatch() { big(|| { let k = &*KEY; let t = create_id_token("https://i", &uuid::Uuid::new_v4(), "A", None, k); assert!(verify_id_token_with_audience(&t, k.verifying_key(), "A", true).is_ok()); let r = verify_id_token_with_audience(&t, k.verifying_key(), "B", true); assert!(r.is_err()); assert!(r.err().unwrap().contains("audience mismatch")); }); }
