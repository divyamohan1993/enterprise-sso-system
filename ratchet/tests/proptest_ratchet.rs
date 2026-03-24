use proptest::prelude::*;
use ratchet::chain::RatchetChain;
proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]
    #[test] fn advance_diff(ms in prop::array::uniform32(any::<u8>()).prop_map(|h| { let mut f=[0u8;64]; f[..32].copy_from_slice(&h); f[32..].copy_from_slice(&h); f }), ce in prop::array::uniform32(any::<u8>()), se in prop::array::uniform32(any::<u8>())) {
        let mut c = RatchetChain::new(&ms); let t1 = c.generate_tag(b"t"); let e1 = c.epoch(); c.advance(&ce, &se); prop_assert_ne!(t1, c.generate_tag(b"t")); prop_assert_eq!(c.epoch(), e1+1);
    }
    #[test] fn verify_ok(claims in prop::collection::vec(any::<u8>(), 1..256)) {
        let c = RatchetChain::new(&[0x42u8;64]); let t = c.generate_tag(&claims); prop_assert!(c.verify_tag(&claims, &t, c.epoch()));
    }
    #[test] fn verify_wrong(claims in prop::collection::vec(any::<u8>(), 1..128), off in 4u64..100) {
        let c = RatchetChain::new(&[0x42u8;64]); let t = c.generate_tag(&claims); prop_assert!(!c.verify_tag(&claims, &t, c.epoch()+off));
    }
}
#[test] fn expiry_2880() { let mut c = RatchetChain::new(&[0x11u8;64]); for _ in 0..2879 { assert!(!c.is_expired()); c.advance(&[0xAA;32],&[0xBB;32]); } assert!(!c.is_expired()); c.advance(&[0xAA;32],&[0xBB;32]); assert!(c.is_expired()); }
#[test] fn lookbehind() { let mut c = RatchetChain::new(&[0x33u8;64]); let t = c.generate_tag(b"lb"); c.advance(&[0xCC;32],&[0xDD;32]); c.advance(&[0xCC;32],&[0xDD;32]); assert!(c.verify_tag(b"lb", &t, 0)); }
