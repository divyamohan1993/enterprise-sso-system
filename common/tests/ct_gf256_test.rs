/// Constant-time GF(256) exhaustive correctness tests.
///
/// Verifies that ct_gf256_mul and ct_gf256_inv produce results identical to
/// a naive reference implementation for every possible input.

/// Reference implementation — non-CT, used only for cross-checking.
fn reference_gf256_mul(a: u8, b: u8) -> u8 {
    let mut result: u16 = 0;
    let mut a = a as u16;
    let mut b = b as u16;
    for _ in 0..8 {
        if b & 1 != 0 {
            result ^= a;
        }
        let carry = a & 0x80;
        a <<= 1;
        if carry != 0 {
            a ^= 0x11b;
        }
        b >>= 1;
    }
    result as u8
}

#[test]
fn test_ct_gf256_mul_exhaustive() {
    // Exhaustive test: verify CT implementation matches for all 256x256 pairs.
    for a in 0..=255u16 {
        for b in 0..=255u16 {
            let result = common::threshold_kek::ct_gf256_mul(a as u8, b as u8);
            let reference = reference_gf256_mul(a as u8, b as u8);
            assert_eq!(
                result, reference,
                "ct_gf256_mul mismatch at ({}, {}): got {}, expected {}",
                a, b, result, reference
            );
        }
    }
}

#[test]
fn test_ct_gf256_inv_all_nonzero() {
    for a in 1..=255u16 {
        let inv = common::threshold_kek::ct_gf256_inv(a as u8);
        let product = common::threshold_kek::ct_gf256_mul(a as u8, inv);
        assert_eq!(
            product, 1,
            "a * a^(-1) must equal 1 for a={}: got inv={}, product={}",
            a, inv, product
        );
    }
}

#[test]
fn test_ct_gf256_mul_zero_identity() {
    for a in 0..=255u16 {
        assert_eq!(
            common::threshold_kek::ct_gf256_mul(a as u8, 0),
            0,
            "anything * 0 must be 0, failed for a={}",
            a
        );
        assert_eq!(
            common::threshold_kek::ct_gf256_mul(0, a as u8),
            0,
            "0 * anything must be 0, failed for a={}",
            a
        );
    }
}

#[test]
fn test_ct_gf256_mul_one_identity() {
    for a in 0..=255u16 {
        assert_eq!(
            common::threshold_kek::ct_gf256_mul(a as u8, 1),
            a as u8,
            "a * 1 must be a, failed for a={}",
            a
        );
    }
}
