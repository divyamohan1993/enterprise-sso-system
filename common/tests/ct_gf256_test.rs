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
        let inv = common::threshold_kek::ct_gf256_inv(a as u8)
            .expect("inverse of nonzero must succeed");
        let product = common::threshold_kek::ct_gf256_mul(a as u8, inv);
        assert_eq!(
            product, 1,
            "a * a^(-1) must equal 1 for a={}: got inv={}, product={}",
            a, inv, product
        );
    }
    // Verify zero returns error instead of panicking (DoS prevention)
    assert!(
        common::threshold_kek::ct_gf256_inv(0).is_err(),
        "ct_gf256_inv(0) must return Err, not panic"
    );
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

/// Verify that GF(256) division by zero returns Err (not panic).
/// This tests the hardened ct_gf256_div path through the public ct_gf256_inv.
/// ct_gf256_div(a, b) = ct_gf256_mul(a, ct_gf256_inv(b)?), so dividing by
/// zero propagates the Err from ct_gf256_inv(0).
#[test]
fn test_ct_gf256_div_by_zero_returns_err() {
    // ct_gf256_inv(0) must return Err (the div-by-zero case)
    let result = common::threshold_kek::ct_gf256_inv(0);
    assert!(
        result.is_err(),
        "ct_gf256_inv(0) must return Err to prevent div-by-zero panic"
    );
    let err_msg = result.unwrap_err();
    assert!(
        err_msg.contains("zero"),
        "error must mention zero, got: {err_msg}"
    );
}

/// Verify GF(256) division: for all nonzero a and b, a/b * b == a.
#[test]
fn test_ct_gf256_div_roundtrip_all_nonzero() {
    for a in 1..=255u16 {
        for b in 1..=255u16 {
            let inv_b = common::threshold_kek::ct_gf256_inv(b as u8)
                .expect("inverse of nonzero must succeed");
            let quotient = common::threshold_kek::ct_gf256_mul(a as u8, inv_b);
            let product = common::threshold_kek::ct_gf256_mul(quotient, b as u8);
            assert_eq!(
                product, a as u8,
                "(a/b)*b must equal a for a={}, b={}",
                a, b
            );
        }
    }
}

/// Verify that ct_gf256_div(0, b) == 0 for all nonzero b.
/// 0 divided by anything is 0 in GF(256).
#[test]
fn test_ct_gf256_div_zero_numerator() {
    for b in 1..=255u16 {
        let inv_b = common::threshold_kek::ct_gf256_inv(b as u8)
            .expect("inverse of nonzero must succeed");
        let result = common::threshold_kek::ct_gf256_mul(0, inv_b);
        assert_eq!(
            result, 0,
            "0/b must be 0 for b={}",
            b
        );
    }
}
