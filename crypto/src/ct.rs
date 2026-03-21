//! Constant-time comparison utilities (spec E.6)
//!
//! ALL security-critical byte comparisons MUST use these functions.
//! Using `==` on `[u8]` or `Vec<u8>` in security modules is prohibited.

use subtle::ConstantTimeEq;

/// Constant-time byte slice comparison.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Constant-time fixed-size array comparison.
pub fn ct_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.ct_eq(b.as_slice()).into()
}

/// Constant-time fixed-size array comparison for 64-byte arrays.
pub fn ct_eq_64(a: &[u8; 64], b: &[u8; 64]) -> bool {
    a.as_slice().ct_eq(b.as_slice()).into()
}
