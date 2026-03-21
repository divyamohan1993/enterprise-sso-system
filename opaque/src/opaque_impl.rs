//! Real OPAQUE protocol implementation using opaque-ke 4.0.
//!
//! Defines the cipher suite and provides helper functions for registration
//! and login flows. The server NEVER sees the plaintext password.

use opaque_ke::CipherSuite;

/// OPAQUE cipher suite: Ristretto255 + TripleDH + Identity KSF.
///
/// Identity KSF is used because the key stretching is performed client-side
/// (the orchestrator acting as the OPAQUE client can apply Argon2 if desired
/// before feeding the password to OPAQUE). The OPRF already prevents the
/// server from learning the password.
pub struct OpaqueCs;

impl CipherSuite for OpaqueCs {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, sha2::Sha512>;
    type Ksf = opaque_ke::ksf::Identity;
}
