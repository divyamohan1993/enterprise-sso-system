use sso_crypto::ct::{ct_eq, ct_eq_32, ct_eq_64};

#[test]
fn ct_eq_equal_values() {
    let a = [1u8, 2, 3, 4, 5];
    let b = [1u8, 2, 3, 4, 5];
    assert!(ct_eq(&a, &b));
}

#[test]
fn ct_eq_different_values() {
    let a = [1u8, 2, 3, 4, 5];
    let b = [1u8, 2, 3, 4, 6];
    assert!(!ct_eq(&a, &b));
}

#[test]
fn ct_eq_different_lengths() {
    let a = [1u8, 2, 3];
    let b = [1u8, 2, 3, 4];
    assert!(!ct_eq(&a, &b));
}

#[test]
fn ct_eq_empty() {
    let a: [u8; 0] = [];
    let b: [u8; 0] = [];
    assert!(ct_eq(&a, &b));
}

#[test]
fn ct_eq_32_equal() {
    let a = [0xABu8; 32];
    let b = [0xABu8; 32];
    assert!(ct_eq_32(&a, &b));
}

#[test]
fn ct_eq_32_different() {
    let a = [0xABu8; 32];
    let mut b = [0xABu8; 32];
    b[31] = 0xCD;
    assert!(!ct_eq_32(&a, &b));
}

#[test]
fn ct_eq_64_works() {
    let a = [0xFFu8; 64];
    let b = [0xFFu8; 64];
    assert!(ct_eq_64(&a, &b));

    let mut c = [0xFFu8; 64];
    c[0] = 0x00;
    assert!(!ct_eq_64(&a, &c));
}
