#![no_main]
use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
#[derive(Arbitrary, Debug)]
struct I { v: String, c: String }
fuzz_target!(|i: I| { let _ = sso_protocol::pkce::verify_pkce(&i.v, &i.c); let _ = sso_protocol::pkce::generate_challenge(&i.v); });
