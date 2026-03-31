#![no_main]
use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use crypto::ct::ct_eq;
#[derive(Arbitrary, Debug)]
struct I { a: Vec<u8>, b: Vec<u8> }
fuzz_target!(|i: I| { let _ = ct_eq(&i.a, &i.b); });
