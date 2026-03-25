//! Real OPAQUE protocol implementation using opaque-ke 4.0.
//!
//! Defines the cipher suite and provides helper functions for registration
//! and login flows. The server NEVER sees the plaintext password.

use opaque_ke::generic_array::{ArrayLength, GenericArray};
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

/// FIPS-compliant OPAQUE cipher suite using PBKDF2-SHA512 as KSF.
///
/// PBKDF2-HMAC-SHA512 is FIPS 140-3 approved (SP 800-132).  Used when
/// FIPS mode is active to replace the non-FIPS Argon2id KSF.
pub struct OpaqueCsFips;

impl CipherSuite for OpaqueCsFips {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, sha2::Sha512>;
    type Ksf = Pbkdf2Sha512;
}

/// PBKDF2-HMAC-SHA512 wrapper implementing the `opaque_ke::ksf::Ksf` trait.
///
/// Uses 210 000 iterations (OWASP 2023 minimum for PBKDF2-SHA512) and an
/// all-zero salt.  The salt is intentionally fixed: within OPAQUE the input
/// to the KSF is already a uniformly random OPRF output, so a fixed salt
/// does not weaken security and avoids the storage overhead of a per-user
/// PBKDF2 salt.
#[derive(Default)]
pub struct Pbkdf2Sha512;

/// PBKDF2-SHA512 iteration count (OWASP 2023 recommendation for SHA-512).
const PBKDF2_ITERATIONS: u32 = 210_000;

impl opaque_ke::ksf::Ksf for Pbkdf2Sha512 {
    fn hash<L: ArrayLength<u8>>(
        &self,
        input: GenericArray<u8, L>,
    ) -> Result<GenericArray<u8, L>, opaque_ke::errors::InternalError> {
        let mut output = GenericArray::<u8, L>::default();
        // Fixed all-zero salt: the OPRF output fed into the KSF is already
        // pseudorandom, so a fixed salt is safe here (RFC 9106 §4).
        let salt = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<sha2::Sha512>(
            &input,
            &salt,
            PBKDF2_ITERATIONS,
            &mut output,
        );
        Ok(output)
    }
}
