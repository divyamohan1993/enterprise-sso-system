#![no_main]
use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use ratchet::chain::RatchetChain;
#[derive(Arbitrary, Debug)] struct RI { ms: [u8;64], claims: Vec<u8>, tag: [u8;64], epoch: u64, steps: u8, ce: Vec<[u8;32]>, se: Vec<[u8;32]>, sn: Vec<[u8;32]> }
fuzz_target!(|i: RI| {
    let mut c = RatchetChain::new(&i.ms).unwrap();
    for s in 0..i.steps.min(10) as usize {
        let ce = i.ce.get(s).copied().unwrap_or_else(|| { let mut e = [0u8; 32]; for (j, b) in e.iter_mut().enumerate() { *b = (j + s) as u8; } e });
        let se = i.se.get(s).copied().unwrap_or_else(|| { let mut e = [0u8; 32]; for (j, b) in e.iter_mut().enumerate() { *b = (j + s + 128) as u8; } e });
        let sn = i.sn.get(s).copied().unwrap_or_else(|| { let mut n = [0u8; 32]; for (j, b) in n.iter_mut().enumerate() { *b = (j + s + 64) as u8; } n });
        // Skip if entropy doesn't pass quality checks (all-zero or low distinct count)
        let ce_distinct = { let mut seen = [false; 256]; let mut d = 0usize; for &b in ce.iter() { if !seen[b as usize] { seen[b as usize] = true; d += 1; } } d };
        let se_distinct = { let mut seen = [false; 256]; let mut d = 0usize; for &b in se.iter() { if !seen[b as usize] { seen[b as usize] = true; d += 1; } } d };
        if ce_distinct < 4 || se_distinct < 4 || ce == [0u8; 32] || se == [0u8; 32] { continue; }
        c.advance(&ce, &se, &sn).unwrap();
    }
    let _ = c.verify_tag(&i.claims, &i.tag, i.epoch);
});
