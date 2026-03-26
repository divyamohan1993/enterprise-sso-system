use sso_protocol::authorize::AuthorizationStore;
use sso_protocol::pkce::generate_challenge;
use sso_protocol::tokens::{OidcSigningKey, create_id_token, verify_id_token};
static KEY: std::sync::LazyLock<OidcSigningKey> = std::sync::LazyLock::new(|| { std::thread::Builder::new().stack_size(16*1024*1024).spawn(OidcSigningKey::generate).unwrap().join().unwrap() });
fn big<F: FnOnce() + Send + 'static>(f: F) { std::thread::Builder::new().stack_size(16*1024*1024).spawn(f).unwrap().join().unwrap(); }
#[test] fn token_now_ok() { big(|| { let t = create_id_token("https://c", &uuid::Uuid::new_v4(), "c", None, &KEY); assert!(verify_id_token(&t, KEY.verifying_key()).is_ok()); }); }
#[test] fn token_exp_iat() { big(|| { let t = create_id_token("https://c", &uuid::Uuid::new_v4(), "c", None, &KEY); let c = verify_id_token(&t, KEY.verifying_key()).unwrap(); assert!(c.exp > c.iat); assert_eq!(c.exp - c.iat, 600, "default tier 2 = 600s (10 min) per hardened tier-based lifetime"); }); }
#[test] fn code_immediate() { let mut s = AuthorizationStore::new(); let c = s.create_code("c","https://r",uuid::Uuid::new_v4(),"o",Some(generate_challenge("abcdefghij_1234567890_abcdefghij_1234567890_abc")),None).unwrap(); assert!(s.consume_code(&c).is_some()); }
#[test] fn code_double() { let mut s = AuthorizationStore::new(); let c = s.create_code("c","https://r",uuid::Uuid::new_v4(),"o",Some(generate_challenge("abcdefghij_1234567890_abcdefghij_1234567890_abc")),None).unwrap(); assert!(s.consume_code(&c).is_some()); assert!(s.consume_code(&c).is_none()); }
#[test] fn code_nonexist() { let mut s = AuthorizationStore::new(); assert!(s.consume_code("x").is_none()); }
#[test] fn ratchet_epochs() { use ratchet::chain::RatchetChain; let mut c = RatchetChain::new(&[0x11u8;64]).unwrap(); assert_eq!(c.epoch(), 0); for i in 1..=10u64 { let mut ce = [0u8; 32]; let mut se = [0u8; 32]; let mut sn = [0u8; 32]; getrandom::getrandom(&mut ce).unwrap(); getrandom::getrandom(&mut se).unwrap(); getrandom::getrandom(&mut sn).unwrap(); c.advance(&ce, &se, &sn); assert_eq!(c.epoch(), i); } assert!(!c.is_expired()); }
