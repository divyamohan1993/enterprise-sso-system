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

#[cfg(test)]
mod tests {
    use super::*;
    use opaque_ke::generic_array::typenum;
    use opaque_ke::ksf::Ksf;
    use opaque_ke::ServerSetup;
    use rand::rngs::OsRng;

    // ── Cipher suite configuration ────────────────────────────────────

    #[test]
    fn opaque_cs_server_setup_creates_successfully() {
        let mut rng = OsRng;
        let setup = ServerSetup::<OpaqueCs>::new(&mut rng);
        let bytes = setup.serialize();
        assert!(!bytes.is_empty(), "OpaqueCs ServerSetup must serialize to non-empty");
    }

    #[test]
    fn opaque_cs_fips_server_setup_creates_successfully() {
        let mut rng = OsRng;
        let setup = ServerSetup::<OpaqueCsFips>::new(&mut rng);
        let bytes = setup.serialize();
        assert!(!bytes.is_empty(), "OpaqueCsFips ServerSetup must serialize to non-empty");
    }

    #[test]
    fn server_setup_serialization_roundtrips() {
        let mut rng = OsRng;
        let setup = ServerSetup::<OpaqueCs>::new(&mut rng);
        let bytes = setup.serialize().to_vec();
        let restored = ServerSetup::<OpaqueCs>::deserialize(&bytes);
        assert!(restored.is_ok(), "ServerSetup must deserialize from its own serialization");
    }

    #[test]
    fn fips_server_setup_serialization_roundtrips() {
        let mut rng = OsRng;
        let setup = ServerSetup::<OpaqueCsFips>::new(&mut rng);
        let bytes = setup.serialize().to_vec();
        let restored = ServerSetup::<OpaqueCsFips>::deserialize(&bytes);
        assert!(restored.is_ok(), "FIPS ServerSetup must deserialize from its own serialization");
    }

    #[test]
    fn two_server_setups_are_distinct() {
        let mut rng = OsRng;
        let s1 = ServerSetup::<OpaqueCs>::new(&mut rng);
        let s2 = ServerSetup::<OpaqueCs>::new(&mut rng);
        assert_ne!(
            s1.serialize().to_vec(),
            s2.serialize().to_vec(),
            "two fresh setups must have different OPRF seeds/keys"
        );
    }

    // ── KSF (key stretching function) ─────────────────────────────────

    #[test]
    fn pbkdf2_sha512_default_creates() {
        let _ksf = Pbkdf2Sha512::default();
    }

    #[test]
    fn pbkdf2_sha512_hash_produces_output() {
        let ksf = Pbkdf2Sha512;
        let input = GenericArray::<u8, typenum::U64>::default();
        let result = ksf.hash(input);
        assert!(result.is_ok(), "PBKDF2 hash must succeed");
        let output = result.unwrap();
        // Output should not be all zeros (the hash of zero input is non-zero)
        assert_ne!(output.as_slice(), &[0u8; 64], "PBKDF2 output must not be all zeros");
    }

    #[test]
    fn pbkdf2_sha512_hash_is_deterministic() {
        let ksf = Pbkdf2Sha512;
        let input1 = GenericArray::<u8, typenum::U64>::clone_from_slice(&[0x42u8; 64]);
        let input2 = GenericArray::<u8, typenum::U64>::clone_from_slice(&[0x42u8; 64]);

        let out1 = ksf.hash(input1).unwrap();
        let out2 = ksf.hash(input2).unwrap();
        assert_eq!(out1, out2, "same input must produce same output");
    }

    #[test]
    fn pbkdf2_sha512_different_inputs_different_outputs() {
        let ksf = Pbkdf2Sha512;
        let input1 = GenericArray::<u8, typenum::U64>::clone_from_slice(&[0x01u8; 64]);
        let input2 = GenericArray::<u8, typenum::U64>::clone_from_slice(&[0x02u8; 64]);

        let out1 = ksf.hash(input1).unwrap();
        let out2 = ksf.hash(input2).unwrap();
        assert_ne!(out1, out2, "different inputs must produce different outputs");
    }

    #[test]
    fn pbkdf2_iterations_is_owasp_minimum() {
        assert_eq!(PBKDF2_ITERATIONS, 210_000, "must meet OWASP 2023 minimum for SHA-512");
    }

    // ── FIPS mode KSF selection ───────────────────────────────────────

    #[test]
    fn argon2_ksf_produces_output() {
        // Verify the Argon2id KSF (used by OpaqueCs) works via the trait
        let ksf = argon2::Argon2::default();
        let input = GenericArray::<u8, typenum::U64>::default();
        let result = Ksf::hash(&ksf, input);
        assert!(result.is_ok(), "Argon2id hash must succeed");
    }

    // ── Registration/login round-trip ─────────────────────────────────

    #[test]
    fn full_opaque_registration_roundtrip() {
        use opaque_ke::{ClientRegistration, ClientRegistrationFinishParameters, ServerRegistration};

        let mut rng = OsRng;
        let setup = ServerSetup::<OpaqueCs>::new(&mut rng);
        let password = b"test-password-roundtrip";
        let username = b"testuser";

        // Client starts
        let client_start = ClientRegistration::<OpaqueCs>::start(&mut rng, password).unwrap();

        // Server processes
        let server_start = ServerRegistration::<OpaqueCs>::start(
            &setup,
            client_start.message,
            username,
        ).unwrap();

        // Client finishes
        let client_finish = client_start.state.finish(
            &mut rng,
            password,
            server_start.message,
            ClientRegistrationFinishParameters::default(),
        ).unwrap();

        // Server finishes -> password file
        let server_reg = ServerRegistration::<OpaqueCs>::finish(client_finish.message);
        let bytes = server_reg.serialize().to_vec();
        assert!(!bytes.is_empty(), "registration must produce non-empty bytes");

        // Bytes must deserialize back
        let restored = ServerRegistration::<OpaqueCs>::deserialize(&bytes);
        assert!(restored.is_ok());
    }

    #[test]
    fn full_opaque_fips_registration_roundtrip() {
        use opaque_ke::{ClientRegistration, ClientRegistrationFinishParameters, ServerRegistration};

        let mut rng = OsRng;
        let setup = ServerSetup::<OpaqueCsFips>::new(&mut rng);
        let password = b"fips-roundtrip-pw";
        let username = b"fipsuser";

        let client_start = ClientRegistration::<OpaqueCsFips>::start(&mut rng, password).unwrap();
        let server_start = ServerRegistration::<OpaqueCsFips>::start(
            &setup,
            client_start.message,
            username,
        ).unwrap();
        let client_finish = client_start.state.finish(
            &mut rng,
            password,
            server_start.message,
            ClientRegistrationFinishParameters::default(),
        ).unwrap();
        let server_reg = ServerRegistration::<OpaqueCsFips>::finish(client_finish.message);
        let bytes = server_reg.serialize().to_vec();
        assert!(!bytes.is_empty());
    }

    #[test]
    fn full_opaque_login_roundtrip() {
        use opaque_ke::{
            ClientRegistration, ClientRegistrationFinishParameters,
            ClientLogin, ClientLoginFinishParameters,
            ServerRegistration, ServerLogin, ServerLoginParameters,
        };

        let mut rng = OsRng;
        let setup = ServerSetup::<OpaqueCs>::new(&mut rng);
        let password = b"login-roundtrip-pw";
        let username = b"loginuser";

        // Register first
        let c_reg_start = ClientRegistration::<OpaqueCs>::start(&mut rng, password).unwrap();
        let s_reg_start = ServerRegistration::<OpaqueCs>::start(
            &setup, c_reg_start.message, username,
        ).unwrap();
        let c_reg_finish = c_reg_start.state.finish(
            &mut rng, password, s_reg_start.message,
            ClientRegistrationFinishParameters::default(),
        ).unwrap();
        let password_file = ServerRegistration::<OpaqueCs>::finish(c_reg_finish.message);

        // Login
        let c_login_start = ClientLogin::<OpaqueCs>::start(&mut rng, password).unwrap();
        let s_login_start = ServerLogin::<OpaqueCs>::start(
            &mut rng, &setup, Some(password_file),
            c_login_start.message, username,
            ServerLoginParameters::default(),
        ).unwrap();
        let c_login_finish = c_login_start.state.finish(
            &mut rng, password, s_login_start.message,
            ClientLoginFinishParameters::default(),
        ).unwrap();

        // Server verifies
        let s_login_finish = s_login_start.state.finish(
            c_login_finish.message,
            ServerLoginParameters::default(),
        );
        assert!(s_login_finish.is_ok(), "login roundtrip must succeed");

        // Session keys must match
        assert_eq!(
            c_login_finish.session_key,
            s_login_finish.unwrap().session_key,
            "client and server session keys must agree"
        );
    }

    #[test]
    fn login_with_wrong_password_fails_at_client() {
        use opaque_ke::{
            ClientRegistration, ClientRegistrationFinishParameters,
            ClientLogin, ClientLoginFinishParameters,
            ServerRegistration, ServerLogin, ServerLoginParameters,
        };

        let mut rng = OsRng;
        let setup = ServerSetup::<OpaqueCs>::new(&mut rng);
        let password = b"correct-pw";
        let username = b"wrongpwuser";

        // Register
        let c_start = ClientRegistration::<OpaqueCs>::start(&mut rng, password).unwrap();
        let s_start = ServerRegistration::<OpaqueCs>::start(
            &setup, c_start.message, username,
        ).unwrap();
        let c_finish = c_start.state.finish(
            &mut rng, password, s_start.message,
            ClientRegistrationFinishParameters::default(),
        ).unwrap();
        let pw_file = ServerRegistration::<OpaqueCs>::finish(c_finish.message);

        // Login with wrong password
        let c_login = ClientLogin::<OpaqueCs>::start(&mut rng, b"wrong-pw").unwrap();
        let s_login = ServerLogin::<OpaqueCs>::start(
            &mut rng, &setup, Some(pw_file),
            c_login.message, username,
            ServerLoginParameters::default(),
        ).unwrap();

        let result = c_login.state.finish(
            &mut rng, b"wrong-pw", s_login.message,
            ClientLoginFinishParameters::default(),
        );
        assert!(result.is_err(), "wrong password must fail at client finish");
    }
}
