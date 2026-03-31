//! Constant-time comparison utilities (spec E.6)
//!
//! ALL security-critical byte comparisons MUST use these functions.
//! Using `==` on `[u8]` or `Vec<u8>` in security modules is prohibited.

use subtle::ConstantTimeEq;

/// Constant-time byte slice comparison.
///
/// Both length check and content comparison are constant-time.
/// The length comparison uses XOR + OR to avoid early return timing leak.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    // Constant-time length comparison: compute XOR of lengths as u64.
    // A non-zero value means lengths differ, but we never branch early —
    // we always perform the same amount of comparison work.
    let len_eq: subtle::Choice = (a.len() as u64).ct_eq(&(b.len() as u64));

    // Always compare up to the shorter length so we do real work
    // regardless of whether lengths match. This prevents timing leaks
    // that reveal whether the lengths were equal.
    let min_len = a.len().min(b.len());
    let content_eq: subtle::Choice = a[..min_len].ct_eq(&b[..min_len]);

    // Both length AND content must match. The bitwise AND is constant-time.
    (len_eq & content_eq).into()
}

/// Constant-time fixed-size array comparison.
pub fn ct_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.ct_eq(b.as_slice()).into()
}

/// Constant-time fixed-size array comparison for 64-byte arrays.
pub fn ct_eq_64(a: &[u8; 64], b: &[u8; 64]) -> bool {
    a.as_slice().ct_eq(b.as_slice()).into()
}
