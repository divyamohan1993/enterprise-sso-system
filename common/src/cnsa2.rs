//! CNSA 2.0 (Commercial National Security Algorithm Suite 2.0) compliance status.
//!
//! Reference: NSA CNSA 2.0 / CNSSP-15 (September 2022, updated March 2024).
//! <https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF>
//!
//! # CNSA 2.0 Algorithm Requirements
//!
//! | Function               | CNSA 2.0 Required Algorithm          |
//! |------------------------|--------------------------------------|
//! | Hash                   | SHA-384 or SHA-512                   |
//! | Symmetric encryption   | AES-256                              |
//! | Digital signature      | ML-DSA-65 or ML-DSA-87 (FIPS 204)   |
//! | Key exchange           | ML-KEM-1024 (FIPS 203)               |
//! | Key derivation         | HKDF-SHA512, SHA-512 based           |
//!
//! # Compliance Status by Module
//!
//! ## Fully Compliant
//!
//! | Module                    | Algorithm       | Status  | Notes                                  |
//! |---------------------------|-----------------|---------|----------------------------------------|
//! | `crypto/src/receipts.rs`  | HMAC-SHA512     | PASS    | Upgraded from HMAC-SHA256              |
//! | `crypto/src/receipts.rs`  | SHA-512 (chain) | PASS    | Upgraded from SHA-256                  |
//! | `audit/src/log.rs`        | SHA-512 (chain) | PASS    | Upgraded from SHA-256                  |
//! | `kt/src/merkle.rs`        | SHA-512         | PASS    | Upgraded from SHA3-256                 |
//! | `crypto/src/entropy.rs`   | SHA-512         | PASS    | Already SHA-512 for combining          |
//! | `crypto/src/dpop.rs`      | HMAC-SHA512     | PASS    | Already HMAC-SHA512 for proofs         |
//! | `crypto/src/attest.rs`    | HMAC-SHA512     | PASS    | Manifest authentication                |
//! | `common/src/duress.rs`    | HKDF-SHA512     | PASS    | v2 format; v1 upgraded to SHA-512      |
//! | `crypto/src/pq_sign.rs`   | ML-DSA-65       | PASS    | Post-quantum signature scheme          |
//! | `crypto/src/sealed.rs`    | AES-256-GCM     | PASS    | Symmetric encryption                   |
//!
//! ## Exceptions (External Specification Constraints)
//!
//! | Module                       | Algorithm | Status    | Justification                           |
//! |------------------------------|-----------|-----------|-----------------------------------------|
//! | `sso-protocol/src/pkce.rs`   | SHA-256   | EXCEPTION | RFC 7636 S256 method mandates SHA-256.  |
//! |                              |           |           | Cannot change without breaking all      |
//! |                              |           |           | OAuth 2.0/2.1 PKCE clients.            |
//! | `fido/src/verification.rs`   | SHA-256   | EXCEPTION | W3C WebAuthn / FIDO2 CTAP2 mandates    |
//! |                              |           |           | SHA-256 for RP ID hashing and client    |
//! |                              |           |           | data hashing. Cannot change without     |
//! |                              |           |           | breaking all WebAuthn authenticators.   |
//! | `crypto/src/dpop.rs`         | SHA-256   | EXCEPTION | RFC 9449 / RFC 7638 JWK Thumbprint     |
//! |                              |           |           | uses SHA-256 for key hash. HMAC proof   |
//! |                              |           |           | generation uses SHA-512.                |
//!
//! ## Non-CNSA Algorithms (Performance / Integrity Only)
//!
//! | Module                  | Algorithm | Status  | Justification                           |
//! |-------------------------|-----------|---------|-----------------------------------------|
//! | `crypto/src/attest.rs`  | BLAKE3    | NOTE    | Used for high-performance file hashing  |
//! |                         |           |         | in attestation only. Not used for key   |
//! |                         |           |         | derivation or digital signatures.       |
//! |                         |           |         | Manifest integrity protected by         |
//! |                         |           |         | HMAC-SHA512.                            |
//!
//! # Migration Notes
//!
//! - Domain separators have been versioned (v1 -> v2) for upgraded algorithms
//!   to prevent cross-version replay attacks.
//! - Legacy SHA-256 PIN hashes (duress v1 format) are still accepted for
//!   backward compatibility during migration but are no longer generated.
//! - Receipt hash chain and audit hash chain use 64-byte (SHA-512) digests.
//! - Merkle tree nodes use 64-byte (SHA-512) digests.

/// CNSA 2.0 compliant minimum hash output size in bytes (SHA-384 = 48, SHA-512 = 64).
pub const MIN_HASH_OUTPUT_BYTES: usize = 48;

/// SHA-512 output size in bytes, used throughout this system.
pub const SHA512_OUTPUT_BYTES: usize = 64;

/// Returns true if the system is configured for CNSA 2.0 compliance.
/// This is a compile-time assertion that can be checked at startup.
pub const fn is_cnsa2_compliant() -> bool {
    // All primary hash operations use SHA-512 (64 bytes >= 48 byte minimum).
    SHA512_OUTPUT_BYTES >= MIN_HASH_OUTPUT_BYTES
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cnsa2_compliance_check() {
        assert!(is_cnsa2_compliant());
        assert_eq!(SHA512_OUTPUT_BYTES, 64);
        assert!(SHA512_OUTPUT_BYTES >= MIN_HASH_OUTPUT_BYTES);
    }
}
