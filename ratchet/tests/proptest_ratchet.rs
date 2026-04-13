use proptest::prelude::*;
use ratchet::chain::RatchetChain;

/// Generate entropy that always passes the quality check (>= 4 distinct byte values).
fn quality_entropy() -> [u8; 32] {
    let mut e = [0u8; 32];
    getrandom::getrandom(&mut e).unwrap();
    e
}

/// Generate a unique nonce.
fn fresh_nonce() -> [u8; 32] {
    let mut n = [0u8; 32];
    getrandom::getrandom(&mut n).unwrap();
    n
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))] // I20
    #[test] fn advance_diff(ms in prop::array::uniform32(any::<u8>()).prop_map(|h| { let mut f=[0u8;64]; f[..32].copy_from_slice(&h); f[32..].copy_from_slice(&h); f })) {
        let ce = quality_entropy();
        let se = quality_entropy();
        let sn = fresh_nonce();
        let mut c = RatchetChain::new(&ms).unwrap(); let t1 = c.generate_tag(b"t").unwrap(); let e1 = c.epoch(); c.advance(&ce, &se, &sn).unwrap(); prop_assert_ne!(t1, c.generate_tag(b"t").unwrap()); prop_assert_eq!(c.epoch(), e1+1);
    }
    #[test] fn verify_ok(claims in prop::collection::vec(any::<u8>(), 1..256)) {
        let c = RatchetChain::new(&[0x42u8;64]).unwrap(); let t = c.generate_tag(&claims).unwrap(); prop_assert!(c.verify_tag(&claims, &t, c.epoch()).unwrap());
    }
    #[test] fn verify_wrong(claims in prop::collection::vec(any::<u8>(), 1..128), off in 4u64..100) {
        let c = RatchetChain::new(&[0x42u8;64]).unwrap(); let t = c.generate_tag(&claims).unwrap(); prop_assert!(!c.verify_tag(&claims, &t, c.epoch()+off).unwrap());
    }
}

#[test]
fn expiry_2880() {
    let mut c = RatchetChain::new(&[0x11u8; 64]).unwrap();
    for _ in 0..2879 {
        assert!(!c.is_expired());
        c.advance(&quality_entropy(), &quality_entropy(), &fresh_nonce()).unwrap();
    }
    assert!(!c.is_expired());
    c.advance(&quality_entropy(), &quality_entropy(), &fresh_nonce()).unwrap();
    assert!(c.is_expired());
}

#[test]
fn lookbehind() {
    let mut c = RatchetChain::new(&[0x33u8; 64]).unwrap();
    let t = c.generate_tag(b"lb").unwrap();
    c.advance(&quality_entropy(), &quality_entropy(), &fresh_nonce()).unwrap();
    c.advance(&quality_entropy(), &quality_entropy(), &fresh_nonce()).unwrap();
    assert!(c.verify_tag(b"lb", &t, 0).unwrap());
}
