//! Dual Key Stretching Function (KSF) abstraction for MILNET SSO.
//!
//! Provides a [`KeyStretchingFunction`] trait with two implementations:
//!
//! - [`Argon2idKsf`]: Argon2id (memory-hard, preferred when FIPS is not required)
//! - [`Pbkdf2Sha512Ksf`]: PBKDF2-HMAC-SHA512 (FIPS 140-3 approved)
//!
//! The convenience functions [`stretch_password`] and [`active_ksf_id`]
//! automatically select the correct algorithm based on the runtime FIPS mode
//! flag ([`common::fips::is_fips_mode`]).

/// Trait representing a key stretching function.
///
/// Implementations must be [`Send`] + [`Sync`] so they can be used behind
/// shared references in async contexts.
pub trait KeyStretchingFunction: Send + Sync {
    /// Stretch `password` using `salt`, returning a derived key.
    fn stretch(&self, password: &[u8], salt: &[u8]) -> Result<Vec<u8>, String>;

    /// Stable algorithm identifier string (e.g. `"argon2id-v19"`).
    fn algorithm_id(&self) -> &'static str;

    /// Whether this KSF is approved under FIPS 140-3.
    fn is_fips_approved(&self) -> bool;
}

// ---------------------------------------------------------------------------
// Argon2id implementation
// ---------------------------------------------------------------------------

/// Argon2id key stretching function.
///
/// Parameters: memory = 64 MiB (65536 KiB), iterations = 4,
/// parallelism = 4, output = 32 bytes.  Not FIPS approved; use
/// [`Pbkdf2Sha512Ksf`] in FIPS mode.
pub struct Argon2idKsf;

impl KeyStretchingFunction for Argon2idKsf {
    fn stretch(&self, password: &[u8], salt: &[u8]) -> Result<Vec<u8>, String> {
        use argon2::{Algorithm, Argon2, Params, Version};

        let params = Params::new(65536, 4, 4, Some(32))
            .map_err(|e| format!("argon2 params error: {e}"))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut output = vec![0u8; 32];
        argon2
            .hash_password_into(password, salt, &mut output)
            .map_err(|e| format!("argon2id stretch error: {e}"))?;

        Ok(output)
    }

    fn algorithm_id(&self) -> &'static str {
        "argon2id-v19"
    }

    fn is_fips_approved(&self) -> bool {
        false
    }
}

// ---------------------------------------------------------------------------
// PBKDF2-SHA512 implementation
// ---------------------------------------------------------------------------

/// PBKDF2-HMAC-SHA512 key stretching function.
///
/// Parameters: iterations = 210 000, hash = HMAC-SHA512, output = 32 bytes.
/// FIPS 140-3 approved; selected automatically when FIPS mode is active.
pub struct Pbkdf2Sha512Ksf;

impl KeyStretchingFunction for Pbkdf2Sha512Ksf {
    fn stretch(&self, password: &[u8], salt: &[u8]) -> Result<Vec<u8>, String> {
        let mut output = vec![0u8; 32];
        pbkdf2::pbkdf2_hmac::<sha2::Sha512>(password, salt, 210_000, &mut output);
        Ok(output)
    }

    fn algorithm_id(&self) -> &'static str {
        "pbkdf2-sha512"
    }

    fn is_fips_approved(&self) -> bool {
        true
    }
}

// ---------------------------------------------------------------------------
// Convenience functions
// ---------------------------------------------------------------------------

/// Returns the algorithm ID for the currently active KSF.
///
/// Returns `"pbkdf2-sha512"` when FIPS mode is active, otherwise
/// `"argon2id-v19"`.
pub fn active_ksf_id() -> &'static str {
    if common::fips::is_fips_mode() {
        "pbkdf2-sha512"
    } else {
        "argon2id-v19"
    }
}

/// Stretch a password using the currently active KSF.
///
/// Automatically selects [`Pbkdf2Sha512Ksf`] in FIPS mode or
/// [`Argon2idKsf`] otherwise.
pub fn stretch_password(password: &[u8], salt: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>, String> {
    let output = if common::fips::is_fips_mode() {
        Pbkdf2Sha512Ksf.stretch(password, salt)?
    } else {
        Argon2idKsf.stretch(password, salt)?
    };
    Ok(zeroize::Zeroizing::new(output))
}

/// Stretch a password using a specific KSF identified by `algorithm_id`.
///
/// Recognised values: `"argon2id-v19"`, `"pbkdf2-sha512"`.
/// Returns `Err` for any unknown identifier.
pub fn stretch_with(algorithm_id: &str, password: &[u8], salt: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>, String> {
    match algorithm_id {
        "argon2id-v19" => Argon2idKsf.stretch(password, salt).map(zeroize::Zeroizing::new),
        "pbkdf2-sha512" => Pbkdf2Sha512Ksf.stretch(password, salt).map(zeroize::Zeroizing::new),
        other => Err(format!("unknown KSF algorithm: {other}")),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn random_salt() -> Vec<u8> {
        use rand::RngCore;
        let mut salt = vec![0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        salt
    }

    #[test]
    fn test_argon2id_stretch_roundtrip() {
        let salt = random_salt();
        let output = Argon2idKsf
            .stretch(b"password", &salt)
            .expect("argon2id stretch must succeed");
        assert_eq!(output.len(), 32, "output must be 32 bytes");
    }

    #[test]
    fn test_pbkdf2_sha512_stretch_roundtrip() {
        let salt = random_salt();
        let output = Pbkdf2Sha512Ksf
            .stretch(b"password", &salt)
            .expect("pbkdf2-sha512 stretch must succeed");
        assert_eq!(output.len(), 32, "output must be 32 bytes");
    }

    #[test]
    fn test_pbkdf2_sha512_deterministic() {
        let password = b"deterministic_test";
        let salt = b"fixed_salt_value!";
        let out1 = Pbkdf2Sha512Ksf
            .stretch(password, salt)
            .expect("first stretch must succeed");
        let out2 = Pbkdf2Sha512Ksf
            .stretch(password, salt)
            .expect("second stretch must succeed");
        assert_eq!(out1, out2, "same password + salt must yield same output");
    }

    #[test]
    fn test_pbkdf2_sha512_different_salt() {
        let password = b"same_password";
        let salt1 = b"salt_one_sixteen";
        let salt2 = b"salt_two_sixteen";
        let out1 = Pbkdf2Sha512Ksf
            .stretch(password, salt1)
            .expect("stretch with salt1 must succeed");
        let out2 = Pbkdf2Sha512Ksf
            .stretch(password, salt2)
            .expect("stretch with salt2 must succeed");
        assert_ne!(out1, out2, "different salts must yield different outputs");
    }

    #[test]
    fn test_active_ksf_follows_fips() {
        common::fips::set_fips_mode_unchecked(true);
        assert_eq!(
            active_ksf_id(),
            "pbkdf2-sha512",
            "FIPS mode must select pbkdf2-sha512"
        );

        common::fips::set_fips_mode_unchecked(false);
        assert_eq!(
            active_ksf_id(),
            "argon2id-v19",
            "non-FIPS mode must select argon2id-v19"
        );
    }

    #[test]
    fn test_stretch_with_argon2id() {
        let salt = random_salt();
        let result = stretch_with("argon2id-v19", b"password", &salt);
        assert!(result.is_ok(), "stretch_with argon2id-v19 must succeed");
        assert_eq!(
            result.unwrap().len(),
            32,
            "output must be 32 bytes"
        );
    }

    #[test]
    fn test_stretch_with_pbkdf2() {
        let salt = random_salt();
        let result = stretch_with("pbkdf2-sha512", b"password", &salt);
        assert!(result.is_ok(), "stretch_with pbkdf2-sha512 must succeed");
        assert_eq!(
            result.unwrap().len(),
            32,
            "output must be 32 bytes"
        );
    }

    #[test]
    fn test_stretch_with_unknown_fails() {
        let salt = random_salt();
        let result = stretch_with("unknown-algo", b"password", &salt);
        assert!(result.is_err(), "stretch_with unknown algorithm must fail");
        let err = result.unwrap_err();
        assert!(
            err.contains("unknown KSF algorithm"),
            "error message must indicate unknown algorithm, got: {err}"
        );
    }
}
