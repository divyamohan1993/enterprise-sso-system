#![no_main]
use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use common::threshold_kek::{KekShare, reconstruct_secret};
#[derive(Arbitrary, Debug)]
struct I { shares: Vec<(u8, [u8; 32])> }
fuzz_target!(|i: I| { let shares: Vec<KekShare> = i.shares.into_iter().filter(|(index, _)| *index > 0).map(|(index, value)| KekShare::new(index, value)).collect(); let _ = reconstruct_secret(&shares); });
