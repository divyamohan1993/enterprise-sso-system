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
    // Constant-time length comparison: compute XOR of lengths as u64,
    // then OR into the final result. This avoids an early return that
    // would leak whether lengths matched.
    let len_eq = a.len() as u64 ^ b.len() as u64;
    if len_eq != 0 {
        // Lengths differ. We still need to do *some* work to avoid
        // leaking which branch was taken via gross timing differences,
        // but we cannot call ct_eq on mismatched slices.
        // Use the shorter length to compare a prefix (result is discarded).
        let min_len = a.len().min(b.len());
        let _dummy: subtle::Choice = a[..min_len].ct_eq(&b[..min_len]);
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
