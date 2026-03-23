//! Real OPAQUE protocol implementation using opaque-ke 4.0.
//!
//! Defines the cipher suite and provides helper functions for registration
//! and login flows. The server NEVER sees the plaintext password.

use opaque_ke::CipherSuite;

/// OPAQUE cipher suite: Ristretto255 + TripleDH + Argon2id KSF.
///
/// Argon2id is used as the key stretching function to provide memory-hard
/// password hashing within the OPAQUE protocol itself (RFC 9106).
/// This prevents offline brute-force attacks even if the server's OPRF
/// seed is compromised.
pub struct OpaqueCs;

impl CipherSuite for OpaqueCs {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, sha2::Sha512>;
    type Ksf = argon2::Argon2<'static>;
}
