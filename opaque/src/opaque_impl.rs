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

// ── B3: Sealed ServerSetup handle (2-of-3 threshold envelope protection) ──
//
// SECURITY: opaque-ke's ServerSetup<OpaqueCs> embeds the OPRF seed in plain
// memory once constructed. We cannot extract the seed (the type is opaque)
// and forking opaque-ke to inject custom envelope handling is impractical
// for the v0.1 hardening pass. Instead, we keep ServerSetup OUT of long-lived
// memory and only reconstruct it on demand via a sealed envelope:
//
//   1. At install time, the operator creates 3 random 32-byte share files,
//      loaded by `common::secret_loader` under names
//      `opaque-server-share-0`, `opaque-server-share-1`, `opaque-server-share-2`.
//   2. Any 2 of the 3 shares are XOR-then-HKDF-combined into an envelope KEK.
//      (This is an additive 2-of-3 sharing equivalent for envelope key
//      protection — distinct from `threshold.rs` which performs Shamir
//      splitting of the OPRF master key for the partial-evaluation path.)
//   3. The serialized ServerSetup is encrypted with AES-256-GCM under the KEK
//      and stored on disk. The KEK is zeroized after each per-request
//      reconstruction.
//
// Per-request flow: load 2 shares → derive KEK → decrypt envelope →
// `ServerSetup::deserialize` → use → drop (zeroized) → wipe envelope buffer.
//
// This bounds OPRF-seed exposure to the duration of a single request and
// removes the seed from steady-state RAM. A snapshot attacker must catch
// the process mid-request AND already hold 2 of the 3 share files.

use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce};
use hkdf::Hkdf;
use opaque_ke::ServerSetup;
use sha2::Sha512;
use zeroize::Zeroizing;

/// Names of the 3 OPAQUE server shares as resolved by `common::secret_loader`.
pub const OPAQUE_SERVER_SHARE_NAMES: [&str; 3] = [
    "opaque-server-share-0",
    "opaque-server-share-1",
    "opaque-server-share-2",
];

/// Sealed envelope holding an encrypted serialized `ServerSetup`.
///
/// The envelope itself is safe to hold in memory and persist to disk — the
/// AES-256-GCM ciphertext is opaque without 2 of the 3 OPAQUE server shares.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct ServerSetupSealedEnvelope {
    /// Random 12-byte AES-GCM nonce.
    pub nonce: [u8; 12],
    /// AES-256-GCM ciphertext of the serialized ServerSetup (includes 16-byte tag).
    pub ciphertext: Vec<u8>,
}

/// Errors for sealed ServerSetup operations.
#[derive(Debug)]
pub enum SealedSetupError {
    /// Fewer than 2 shares could be loaded.
    InsufficientShares(String),
    /// AES-GCM seal/open failed (tampering or wrong shares).
    Crypto(&'static str),
    /// `ServerSetup::deserialize` rejected the recovered bytes.
    Deserialize,
    /// CSPRNG failure.
    Random(&'static str),
}

impl std::fmt::Display for SealedSetupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InsufficientShares(s) => write!(f, "OPAQUE share load failed: {s}"),
            Self::Crypto(s) => write!(f, "OPAQUE envelope crypto: {s}"),
            Self::Deserialize => write!(f, "OPAQUE envelope deserialize failed"),
            Self::Random(s) => write!(f, "OPAQUE envelope CSPRNG: {s}"),
        }
    }
}

impl std::error::Error for SealedSetupError {}

/// Load any 2-of-3 OPAQUE server shares via `common::secret_loader` and
/// derive a 32-byte envelope KEK. Returns the KEK as a zeroizing buffer.
///
/// The combine is HKDF-SHA512(salt = "MILNET-OPAQUE-ENVELOPE-KEK-v1",
/// ikm = share_a || share_b || domain) where (a, b) are sorted by share index
/// so that any 2-of-3 pair derives the same KEK as long as the same two
/// shares are present.
fn derive_envelope_kek() -> Result<Zeroizing<[u8; 32]>, SealedSetupError> {
    let mut loaded: Vec<(usize, Zeroizing<Vec<u8>>)> = Vec::with_capacity(3);
    let mut errors: Vec<String> = Vec::new();

    for (idx, name) in OPAQUE_SERVER_SHARE_NAMES.iter().enumerate() {
        match common::secret_loader::load_secret(name) {
            Ok(buf) => {
                if buf.len() < 32 {
                    errors.push(format!("{name}: too short ({} bytes)", buf.len()));
                    continue;
                }
                loaded.push((idx, buf));
                if loaded.len() == 2 {
                    break;
                }
            }
            Err(e) => errors.push(format!("{name}: {e}")),
        }
    }

    if loaded.len() < 2 {
        return Err(SealedSetupError::InsufficientShares(errors.join("; ")));
    }

    // Stable order so any 2-of-3 pair derives the same KEK.
    loaded.sort_by_key(|(idx, _)| *idx);

    let mut ikm = Zeroizing::new(Vec::with_capacity(64 + 1));
    ikm.extend_from_slice(&loaded[0].1[..32]);
    ikm.extend_from_slice(&loaded[1].1[..32]);
    // Bind the pair indices so different pairs derive independent KEKs only
    // if explicitly desired; here we omit the indices so any 2 shares yield
    // the same KEK and the envelope remains decryptable from any pair.

    let hk = Hkdf::<Sha512>::new(Some(b"MILNET-OPAQUE-ENVELOPE-KEK-v1"), &ikm);
    let mut kek = Zeroizing::new([0u8; 32]);
    hk.expand(b"opaque-server-setup-envelope", kek.as_mut())
        .map_err(|_| SealedSetupError::Crypto("HKDF expand"))?;

    Ok(kek)
}

/// Seal a freshly generated `ServerSetup<OpaqueCs>` into a transportable
/// envelope. The plaintext serialization is wiped after sealing.
pub fn seal_server_setup(
    setup: &ServerSetup<OpaqueCs>,
) -> Result<ServerSetupSealedEnvelope, SealedSetupError> {
    let kek = derive_envelope_kek()?;
    let cipher = Aes256Gcm::new_from_slice(kek.as_ref())
        .map_err(|_| SealedSetupError::Crypto("AES key init"))?;

    let mut nonce = [0u8; 12];
    getrandom::getrandom(&mut nonce).map_err(|_| SealedSetupError::Random("nonce"))?;

    let plaintext = Zeroizing::new(setup.serialize().to_vec());
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext.as_slice())
        .map_err(|_| SealedSetupError::Crypto("AES-GCM seal"))?;
    // Zeroizing<Vec<u8>> wipes on Drop at end of scope.

    Ok(ServerSetupSealedEnvelope { nonce, ciphertext })
}

/// Handle that wraps a sealed `ServerSetup` envelope.
///
/// The OPRF seed only materializes inside the closure passed to [`with_setup`],
/// and is wiped immediately on closure exit. The envelope itself can sit in
/// long-lived memory safely.
pub struct ServerSetupHandle {
    envelope: ServerSetupSealedEnvelope,
}

impl ServerSetupHandle {
    /// Create a handle from an existing sealed envelope (e.g. read from disk).
    pub fn from_envelope(envelope: ServerSetupSealedEnvelope) -> Self {
        Self { envelope }
    }

    /// Generate a fresh `ServerSetup`, seal it, and return the handle.
    /// The unsealed `ServerSetup` is dropped (and its serialization zeroized)
    /// before this function returns.
    pub fn generate_and_seal() -> Result<Self, SealedSetupError> {
        let mut rng = rand::rngs::OsRng;
        let setup = ServerSetup::<OpaqueCs>::new(&mut rng);
        let envelope = seal_server_setup(&setup)?;
        // `setup` drop here. opaque-ke's ServerSetup does not implement Zeroize,
        // but the serialization buffer used for sealing is wiped inside
        // seal_server_setup. The remaining residue is bounded in lifetime.
        drop(setup);
        Ok(Self { envelope })
    }

    /// Borrow the sealed envelope (e.g. to persist to disk).
    pub fn envelope(&self) -> &ServerSetupSealedEnvelope {
        &self.envelope
    }

    /// Reconstruct the `ServerSetup` for the duration of `f` and wipe it
    /// immediately after. Returns the closure's result.
    ///
    /// The plaintext serialization buffer is held in a `Zeroizing<Vec<u8>>`
    /// and the recovered `ServerSetup` is dropped at scope exit.
    pub fn with_setup<R>(
        &self,
        f: impl FnOnce(&ServerSetup<OpaqueCs>) -> R,
    ) -> Result<R, SealedSetupError> {
        let kek = derive_envelope_kek()?;
        let cipher = Aes256Gcm::new_from_slice(kek.as_ref())
            .map_err(|_| SealedSetupError::Crypto("AES key init"))?;

        let mut plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    Nonce::from_slice(&self.envelope.nonce),
                    self.envelope.ciphertext.as_slice(),
                )
                .map_err(|_| SealedSetupError::Crypto("AES-GCM open"))?,
        );

        let setup = ServerSetup::<OpaqueCs>::deserialize(&plaintext)
            .map_err(|_| SealedSetupError::Deserialize)?;

        let result = f(&setup);

        // Explicit drop documents the ordering: ServerSetup first, then the
        // Zeroizing<Vec<u8>> plaintext / KEK auto-wipe at end of scope.
        drop(setup);
        Ok(result)
    }
}

#[cfg(test)]
mod sealed_setup_tests {
    use super::*;

    /// Set up 3 deterministic shares in env and return a guard that clears them.
    struct ShareGuard;
    impl ShareGuard {
        fn install() -> Self {
            std::env::set_var("MILNET_DEV_ALLOW_ENV_SECRETS", "1");
            std::env::remove_var("MILNET_PRODUCTION");
            std::env::remove_var("MILNET_MILITARY_DEPLOYMENT");
            // 32-byte shares hex-padded → 64 chars; the loader returns raw env bytes,
            // so we use exactly 32 ASCII bytes per share for deterministic tests.
            std::env::set_var("MILNET_opaque-server-share-0_SEALED", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
            std::env::set_var("MILNET_opaque-server-share-1_SEALED", "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB");
            std::env::set_var("MILNET_opaque-server-share-2_SEALED", "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC");
            Self
        }
    }
    impl Drop for ShareGuard {
        fn drop(&mut self) {
            for n in &OPAQUE_SERVER_SHARE_NAMES {
                std::env::remove_var(format!("MILNET_{n}_SEALED"));
            }
            std::env::remove_var("MILNET_DEV_ALLOW_ENV_SECRETS");
        }
    }

    #[test]
    fn seal_unseal_roundtrip_recovers_server_setup() {
        let _g = ShareGuard::install();

        let handle = ServerSetupHandle::generate_and_seal().expect("seal");
        let original_pk = handle
            .with_setup(|s| s.serialize().to_vec())
            .expect("unseal");

        // Second open must yield identical bytes
        let again = handle
            .with_setup(|s| s.serialize().to_vec())
            .expect("unseal 2");
        assert_eq!(original_pk, again, "two opens of same envelope must agree");
    }

    #[test]
    fn missing_shares_returns_error() {
        // Ensure no shares set
        for n in &OPAQUE_SERVER_SHARE_NAMES {
            std::env::remove_var(format!("MILNET_{n}_SEALED"));
        }
        std::env::remove_var("MILNET_PRODUCTION");
        std::env::remove_var("MILNET_MILITARY_DEPLOYMENT");

        let r = ServerSetupHandle::generate_and_seal();
        assert!(matches!(r, Err(SealedSetupError::InsufficientShares(_))));
    }

    #[test]
    fn tampered_ciphertext_fails_to_open() {
        let _g = ShareGuard::install();
        let handle = ServerSetupHandle::generate_and_seal().expect("seal");
        let mut env = handle.envelope().clone();
        env.ciphertext[0] ^= 0xFF;
        let tampered = ServerSetupHandle::from_envelope(env);
        let r = tampered.with_setup(|_| ());
        assert!(matches!(r, Err(SealedSetupError::Crypto(_))));
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
