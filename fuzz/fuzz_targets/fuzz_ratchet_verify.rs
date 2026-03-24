#![no_main]
use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use ratchet::chain::RatchetChain;
#[derive(Arbitrary, Debug)] struct RI { ms: [u8;64], claims: Vec<u8>, tag: [u8;64], epoch: u64, steps: u8, ce: Vec<[u8;32]>, se: Vec<[u8;32]> }
fuzz_target!(|i: RI| { let mut c = RatchetChain::new(&i.ms); for s in 0..i.steps.min(10) as usize { let ce = i.ce.get(s).copied().unwrap_or([0;32]); let se = i.se.get(s).copied().unwrap_or([0;32]); c.advance(&ce, &se); } let _ = c.verify_tag(&i.claims, &i.tag, i.epoch); });
