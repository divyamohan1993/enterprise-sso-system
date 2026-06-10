//! Real OPAQUE protocol implementation using opaque-ke 4.0.
//!
//! Defines the cipher suite and provides helper functions for registration
//! and login flows. The server NEVER sees the plaintext password.

use opaque_ke::generic_array::{ArrayLength, GenericArray};
use opaque_ke::CipherSuite;

// ── Military-strength Argon2id KSF parameters (audit F1) ──────────────────
//
// opaque-ke's `Default` for `argon2::Argon2` yields m=19 MiB / t=2 / p=1 —
// the OWASP *floor* (the "second choice" config in OWASP's Password Storage
// Cheat Sheet), which audit finding F1 flagged as too weak for a military
// credential store. RFC 9106 §4 (Argon2 spec) recommends the *first* option
// of m=2 GiB where tolerable and otherwise scaling memory as high as latency
// permits; OWASP's strongest listed Argon2id config is m=46 MiB/t=1/p=1.
//
// We exceed every published baseline deliberately: a server-side OPAQUE KSF is
// run at most a few times per authentication and is the last line of defense
// if the OPRF seed is ever recovered, so a high cost is affordable and
// desirable. References:
//   * OWASP Password Storage Cheat Sheet (Argon2id guidance).
//   * RFC 9106 §4 "Parameter Choice".
//   * draft-irtf-cfrg-opaque (OPAQUE) — the KSF (a.k.a. "MHF"/"stretch")
//     hardens the password-derived key client-side before the AKE.

/// Argon2id memory cost in KiB. 65536 KiB = 64 MiB (≥ task floor of 64 MiB,
/// 3.4× the opaque-ke default and 1.4× the OWASP strongest listed config).
pub const ARGON2_M_COST_KIB: u32 = 65_536;
/// Argon2id time cost (passes). 3 ≥ task floor; exceeds OWASP/RFC 9106 t=1.
pub const ARGON2_T_COST: u32 = 3;
/// Argon2id parallelism (lanes). 4 ≥ task floor; sized for multi-core servers.
pub const ARGON2_P_COST: u32 = 4;

/// Lightweight Argon2id parameters used ONLY for generating throwaway
/// timing-pad registrations (`store::FakeRegistrationPool`). These blobs are
/// never real credentials and are never the target of an authentication; the
/// live per-login timing defense re-runs the FULL-strength KSF on the
/// attacker-supplied password via `ClientLogin::finish`. Using cheap params
/// here avoids paying 64 × 64 MiB at every `CredentialStore::new()` without
/// weakening any real credential or the timing-oracle defense.
pub const ARGON2_PAD_M_COST_KIB: u32 = 8; // 8 KiB — minimum practical
pub const ARGON2_PAD_T_COST: u32 = 1;
pub const ARGON2_PAD_P_COST: u32 = 1;

/// Build an `argon2::Argon2` configured for Argon2id, version 0x13 (v19), with
/// the given cost parameters. Panics only on a programmer error (params that
/// violate Argon2's invariants), which our compile-time constants never do.
fn build_argon2(m_cost_kib: u32, t_cost: u32, p_cost: u32) -> argon2::Argon2<'static> {
    let params = argon2::Params::new(m_cost_kib, t_cost, p_cost, None)
        .expect("Argon2 params are within valid bounds (compile-time constants)");
    argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
}

/// Military-strength Argon2id key-stretching function for OPAQUE.
///
/// Newtype around `argon2::Argon2` whose `Default` impl builds the strong
/// parameters above. Because every OPAQUE finish call site uses
/// `*FinishParameters::default()` (i.e. `ksf == None`), opaque-ke falls back to
/// `CS::Ksf::default()` inside `get_password_derived_key` — so making *this*
/// `Default` strong is what raises the KSF cost for BOTH registration-finish
/// and login-finish, with no call-site changes. (opaque-ke 4.0.1
/// `src/opaque.rs::get_password_derived_key`.)
pub struct MilitaryArgon2(argon2::Argon2<'static>);

impl Default for MilitaryArgon2 {
    fn default() -> Self {
        Self(build_argon2(ARGON2_M_COST_KIB, ARGON2_T_COST, ARGON2_P_COST))
    }
}

impl MilitaryArgon2 {
    /// Construct the lightweight variant for timing-pad generation only.
    /// SECURITY: never use this for a real credential — see the pad-cost
    /// constants' documentation.
    pub fn pad() -> Self {
        Self(build_argon2(
            ARGON2_PAD_M_COST_KIB,
            ARGON2_PAD_T_COST,
            ARGON2_PAD_P_COST,
        ))
    }
}

impl opaque_ke::ksf::Ksf for MilitaryArgon2 {
    fn hash<L: ArrayLength<u8>>(
        &self,
        input: GenericArray<u8, L>,
    ) -> Result<GenericArray<u8, L>, opaque_ke::errors::InternalError> {
        // Delegate to the inner Argon2's Ksf impl (opaque-ke provides
        // `impl Ksf for argon2::Argon2`), which uses a fixed all-zero salt:
        // the OPRF output fed into the KSF is already uniformly random, so a
        // fixed salt is safe here (RFC 9106 §3.1 — salt uniqueness exists to
        // prevent precomputation across distinct passwords; OPAQUE inputs are
        // already unpredictable per-user via the OPRF).
        opaque_ke::ksf::Ksf::hash(&self.0, input)
    }
}

/// OPAQUE cipher suite: Ristretto255 + TripleDH + military-strength Argon2id KSF.
///
/// Argon2id is the key stretching function, hardening the password-derived key
/// client-side before the AKE (RFC 9106 / draft-irtf-cfrg-opaque). With
/// [`MilitaryArgon2`] this runs at 64 MiB / t=3 / p=4 (audit F1), so an
/// attacker who somehow recovers the server's OPRF seed still faces a
/// memory-hard offline cost per password guess.
pub struct OpaqueCs;

impl CipherSuite for OpaqueCs {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, sha2::Sha512>;
    type Ksf = MilitaryArgon2;
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

/// PBKDF2-SHA512 iteration count.
///
/// Set to 600 000, well above OWASP/NIST SP 800-132 contemporary baseline
/// for SHA-512, so the construction remains defensible for at least 5 years
/// against commodity GPU/ASIC speed-ups. Mirrors `crypto::kdf::PBKDF2_SHA512_ITERATIONS`.
const PBKDF2_ITERATIONS: u32 = 600_000;

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

// ── F4/F7: Sealed + persisted ServerSetup (OPRF seed) under the master KEK ──
//
// THREAT (audit F4 — RAM-clone seed recovery): opaque-ke's
// `ServerSetup<OpaqueCs>` embeds the OPRF seed (and server keypair) in plain
// memory once constructed. Holding it as a long-lived plaintext field means a
// RAM snapshot / core dump / cold-boot clone steals the seed, which lets the
// attacker run the OPRF offline against every stored registration.
//
// THREAT (audit F7 — restart-lockout DoS): the seed was never persisted, so a
// restart generated a fresh seed and INVALIDATED every existing user (their
// stored `ServerRegistration` no longer matches the new OPRF key). A crash
// loop therefore becomes a total account-lockout.
//
// FIX: keep the `ServerSetup` OUT of steady-state RAM and persist it sealed:
//
//   1. On first boot, generate a `ServerSetup`, AES-256-GCM seal its
//      serialization under a key derived from the system MASTER KEK
//      (`common::sealed_keys::get_master_kek` — read-only), and persist the
//      sealed envelope to disk under a configured directory.
//   2. On later boots, read the sealed envelope and unseal it. FAIL-CLOSED:
//      if a sealed blob is present but cannot be unsealed (tamper, wrong KEK,
//      truncation), REFUSE to start — never silently regenerate, since that
//      would lock out every user (F7).
//   3. At runtime the seed materializes ONLY transiently inside the closure
//      passed to [`ServerSetupHandle::with_setup`], in a `Zeroizing<Vec<u8>>`
//      that is wiped on every call. No permanent plaintext field exists.
//
// The envelope KEK is HKDF-SHA512(master_kek, info = ENVELOPE_KEK_INFO) and is
// zeroized after every seal/unseal. The AES-GCM AAD binds a versioned domain
// string so the ciphertext cannot be repurposed for another sealed object.
//
// This bounds OPRF-seed exposure in RAM to the duration of a single request
// AND survives restarts. A snapshot attacker must catch the process mid-request
// (the seed is absent from steady-state memory), and a disk-only attacker who
// steals the sealed blob still needs the master KEK (which on a military node
// is itself threshold-derived and never reconstructed in one place).

use aes_gcm::{aead::{Aead, KeyInit, Payload}, Aes256Gcm, Nonce};
use hkdf::Hkdf;
use opaque_ke::ServerSetup;
use sha2::Sha512;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// HKDF-SHA512 `info` string deriving the OPAQUE setup envelope KEK from the
/// master KEK. Versioned for crypto-agility / key rotation.
const ENVELOPE_KEK_INFO: &[u8] = b"MILNET-OPAQUE-SERVER-SETUP-ENVELOPE-KEK-v1";

/// AES-256-GCM additional authenticated data binding the sealed envelope to its
/// purpose and version (domain separation + tamper context). A blob sealed for
/// any other purpose will fail to open here.
const ENVELOPE_AAD: &[u8] = b"MILNET-OPAQUE-SERVER-SETUP-v1";

/// File name of the persisted sealed `ServerSetup` envelope.
pub const SERVER_SETUP_SEALED_FILE: &str = "opaque-server-setup.sealed";

/// Default directory for the persisted sealed `ServerSetup` envelope. Matches
/// the project's sealed-material convention (`/var/lib/milnet/sealed`, see
/// `common::measured_boot`). Overridable via `MILNET_OPAQUE_SETUP_DIR`.
pub const DEFAULT_SERVER_SETUP_DIR: &str = "/var/lib/milnet/sealed";

/// Environment variable overriding the sealed-setup directory.
pub const SERVER_SETUP_DIR_ENV: &str = "MILNET_OPAQUE_SETUP_DIR";

/// Resolve the directory holding the persisted sealed `ServerSetup`.
pub fn server_setup_dir() -> PathBuf {
    std::env::var(SERVER_SETUP_DIR_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_SERVER_SETUP_DIR))
}

/// Full path to the persisted sealed `ServerSetup` envelope file.
pub fn server_setup_path() -> PathBuf {
    server_setup_dir().join(SERVER_SETUP_SEALED_FILE)
}

/// Sealed envelope holding an encrypted serialized `ServerSetup`.
///
/// The envelope itself is safe to hold in memory and persist to disk — the
/// AES-256-GCM ciphertext is opaque without the master KEK.
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
    /// The master KEK could not be obtained / derived into an envelope key.
    KekUnavailable(&'static str),
    /// AES-GCM seal/open failed (tampering, wrong KEK, or truncation).
    Crypto(&'static str),
    /// `ServerSetup::deserialize` rejected the recovered bytes.
    Deserialize,
    /// CSPRNG failure.
    Random(&'static str),
    /// Persistence (filesystem) error.
    Io(String),
}

impl std::fmt::Display for SealedSetupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KekUnavailable(s) => write!(f, "OPAQUE envelope KEK unavailable: {s}"),
            Self::Crypto(s) => write!(f, "OPAQUE envelope crypto: {s}"),
            Self::Deserialize => write!(f, "OPAQUE envelope deserialize failed"),
            Self::Random(s) => write!(f, "OPAQUE envelope CSPRNG: {s}"),
            Self::Io(s) => write!(f, "OPAQUE sealed-setup I/O: {s}"),
        }
    }
}

impl std::error::Error for SealedSetupError {}

/// Derive the 32-byte envelope KEK from the system master KEK via HKDF-SHA512.
///
/// Reads the master KEK through `common::sealed_keys::get_master_kek` (the
/// canonical, already-wired source; READ-ONLY — `opaque` never mutates the
/// master-KEK subsystem). Returns the derived key in a zeroizing buffer so it
/// is wiped when dropped. The master KEK reference itself is owned by `common`
/// (mlock'd `OnceLock`) and is not copied out here beyond the HKDF input.
fn derive_envelope_kek() -> Result<Zeroizing<[u8; 32]>, SealedSetupError> {
    let master_kek: &'static [u8; 32] = common::sealed_keys::get_master_kek();

    let hk = Hkdf::<Sha512>::new(Some(b"MILNET-OPAQUE-ENVELOPE-KEK-v1"), master_kek);
    let mut kek = Zeroizing::new([0u8; 32]);
    hk.expand(ENVELOPE_KEK_INFO, kek.as_mut())
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
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload { msg: plaintext.as_slice(), aad: ENVELOPE_AAD },
        )
        .map_err(|_| SealedSetupError::Crypto("AES-GCM seal"))?;
    // Zeroizing<Vec<u8>> wipes on Drop at end of scope.

    Ok(ServerSetupSealedEnvelope { nonce, ciphertext })
}

/// Handle that wraps a sealed `ServerSetup` envelope.
///
/// The OPRF seed only materializes inside the closure passed to [`with_setup`],
/// and is wiped immediately on closure exit. The envelope itself can sit in
/// long-lived memory safely and is what gets persisted to disk.
pub struct ServerSetupHandle {
    envelope: ServerSetupSealedEnvelope,
}

impl ServerSetupHandle {
    /// Create a handle from an existing sealed envelope (e.g. read from disk).
    pub fn from_envelope(envelope: ServerSetupSealedEnvelope) -> Self {
        Self { envelope }
    }

    /// Generate a fresh `ServerSetup`, seal it under the master KEK, and return
    /// the handle. The unsealed `ServerSetup` is dropped (and its serialization
    /// zeroized inside `seal_server_setup`) before this function returns.
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

    /// Serialize the sealed envelope to its on-disk byte representation.
    fn serialize_envelope(&self) -> Result<Vec<u8>, SealedSetupError> {
        postcard::to_allocvec(&self.envelope)
            .map_err(|e| SealedSetupError::Io(format!("serialize envelope: {e}")))
    }

    /// Parse a sealed envelope from its on-disk byte representation.
    fn deserialize_envelope(bytes: &[u8]) -> Result<ServerSetupSealedEnvelope, SealedSetupError> {
        postcard::from_bytes(bytes)
            .map_err(|e| SealedSetupError::Io(format!("parse envelope: {e}")))
    }

    /// Persist the sealed envelope to `path` atomically (write tmp + rename).
    ///
    /// The parent directory is created with owner-only (0700) permissions on
    /// Unix. The file holds only AES-256-GCM ciphertext, useless without the
    /// master KEK, but we still restrict it defensively.
    pub fn persist_to(&self, path: &Path) -> Result<(), SealedSetupError> {
        let bytes = self.serialize_envelope()?;

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| SealedSetupError::Io(format!("create dir {parent:?}: {e}")))?;
            restrict_dir_permissions(parent)?;
        }

        // Atomic publish: write to a temp file in the same dir, then rename.
        let tmp = path.with_extension("sealed.tmp");
        std::fs::write(&tmp, &bytes)
            .map_err(|e| SealedSetupError::Io(format!("write {tmp:?}: {e}")))?;
        restrict_file_permissions(&tmp)?;
        std::fs::rename(&tmp, path)
            .map_err(|e| SealedSetupError::Io(format!("rename {tmp:?} -> {path:?}: {e}")))?;
        Ok(())
    }

    /// Load a sealed envelope handle from `path` if the file exists.
    ///
    /// Returns `Ok(None)` if the file does not exist (first boot). Returns
    /// `Err` if the file exists but cannot be read or parsed — callers MUST
    /// treat that as fail-closed (do NOT regenerate; see [`load_or_generate`]).
    pub fn load_from(path: &Path) -> Result<Option<Self>, SealedSetupError> {
        match std::fs::read(path) {
            Ok(bytes) => {
                let envelope = Self::deserialize_envelope(&bytes)?;
                Ok(Some(Self { envelope }))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(SealedSetupError::Io(format!("read {path:?}: {e}"))),
        }
    }

    /// Boot-time entry point: load the persisted sealed `ServerSetup`, or
    /// generate+seal+persist one on first boot.
    ///
    /// FAIL-CLOSED semantics (audit F4/F7):
    ///   * No sealed blob at `path` → first boot: generate, seal, persist, use.
    ///   * Sealed blob present AND unseals cleanly → reuse it (user records
    ///     stay verifiable across restarts — fixes F7 restart-lockout).
    ///   * Sealed blob present but FAILS to unseal (tamper, wrong/rotated KEK,
    ///     truncation, parse error) → return `Err`. The caller MUST refuse to
    ///     start. We NEVER silently regenerate, because a new OPRF seed would
    ///     invalidate every stored registration and lock out all users.
    ///
    /// On first boot the freshly generated handle is verified by a probe
    /// unseal before it is persisted, so a write is only published if the blob
    /// is actually recoverable under the current master KEK.
    pub fn load_or_generate(path: &Path) -> Result<Self, SealedSetupError> {
        if let Some(handle) = Self::load_from(path)? {
            // Blob exists: it MUST unseal. Any failure is fatal (fail-closed).
            handle.with_setup(|_| ())?;
            tracing::info!(
                "OPAQUE: loaded sealed ServerSetup from {path:?} (OPRF seed preserved across restart)"
            );
            return Ok(handle);
        }

        // First boot: generate, verify it round-trips under the master KEK,
        // then persist. If sealing/unsealing fails we never write a blob we
        // cannot later open.
        let handle = Self::generate_and_seal()?;
        handle.with_setup(|_| ())?; // probe: confirm recoverable before persisting
        handle.persist_to(path)?;
        tracing::info!(
            "OPAQUE: generated and sealed a fresh ServerSetup at {path:?} (first boot)"
        );
        Ok(handle)
    }

    /// Reconstruct the `ServerSetup` for the duration of `f` and wipe it
    /// immediately after. Returns the closure's result.
    ///
    /// The plaintext serialization buffer is held in a `Zeroizing<Vec<u8>>`
    /// and the recovered `ServerSetup` is dropped at scope exit. This is the
    /// ONLY place the OPRF seed materializes at runtime.
    pub fn with_setup<R>(
        &self,
        f: impl FnOnce(&ServerSetup<OpaqueCs>) -> R,
    ) -> Result<R, SealedSetupError> {
        let kek = derive_envelope_kek()?;
        let cipher = Aes256Gcm::new_from_slice(kek.as_ref())
            .map_err(|_| SealedSetupError::Crypto("AES key init"))?;

        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    Nonce::from_slice(&self.envelope.nonce),
                    Payload { msg: self.envelope.ciphertext.as_slice(), aad: ENVELOPE_AAD },
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

/// Restrict a directory to owner-only (0700) on Unix. No-op elsewhere.
fn restrict_dir_permissions(dir: &Path) -> Result<(), SealedSetupError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o700);
        std::fs::set_permissions(dir, perms)
            .map_err(|e| SealedSetupError::Io(format!("chmod 0700 {dir:?}: {e}")))?;
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
    Ok(())
}

/// Restrict a file to owner read/write (0600) on Unix. No-op elsewhere.
fn restrict_file_permissions(file: &Path) -> Result<(), SealedSetupError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(file, perms)
            .map_err(|e| SealedSetupError::Io(format!("chmod 0600 {file:?}: {e}")))?;
    }
    #[cfg(not(unix))]
    {
        let _ = file;
    }
    Ok(())
}

#[cfg(test)]
mod sealed_setup_tests {
    use super::*;
    use serial_test::serial;

    /// Install a non-production, non-military master-KEK environment so
    /// `common::sealed_keys::get_master_kek()` resolves to the env KEK.
    ///
    /// NOTE: `get_master_kek()` caches the KEK process-wide on first call AND
    /// `load_master_kek_inner` wipes `MILNET_MASTER_KEK` from the environment
    /// after reading it. These tests are therefore `#[serial]` and written to
    /// be KEK-VALUE-AGNOSTIC: they assert round-trip consistency and tamper
    /// rejection, never a specific KEK value, so they pass regardless of which
    /// serial test happened to seed the cache first.
    struct KekGuard;
    impl KekGuard {
        fn install() -> Self {
            std::env::remove_var("MILNET_PRODUCTION");
            std::env::remove_var("MILNET_MILITARY_DEPLOYMENT");
            std::env::remove_var("MILNET_KEK_SHARE");
            // 64 hex chars = 32-byte KEK. Only used if the process cache is not
            // already seeded by an earlier serial test.
            if std::env::var("MILNET_MASTER_KEK").is_err() {
                std::env::set_var("MILNET_MASTER_KEK", "ab".repeat(32));
            }
            std::env::set_var("MILNET_TESTING_SINGLE_KEK_ACK", "1");
            Self
        }
    }
    impl Drop for KekGuard {
        fn drop(&mut self) {
            std::env::remove_var("MILNET_TESTING_SINGLE_KEK_ACK");
        }
    }

    /// Unique scratch directory for a test's sealed file, cleaned up on drop.
    struct ScratchDir(PathBuf);
    impl ScratchDir {
        fn new(tag: &str) -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let dir = std::env::temp_dir()
                .join(format!("milnet-opaque-test-{}-{}-{}", tag, std::process::id(), nanos));
            std::fs::create_dir_all(&dir).expect("create scratch dir");
            Self(dir)
        }
        fn file(&self) -> PathBuf {
            self.0.join(SERVER_SETUP_SEALED_FILE)
        }
    }
    impl Drop for ScratchDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    #[serial]
    fn seal_unseal_roundtrip_recovers_server_setup() {
        let _g = KekGuard::install();

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
    #[serial]
    fn tampered_ciphertext_fails_to_open() {
        let _g = KekGuard::install();
        let handle = ServerSetupHandle::generate_and_seal().expect("seal");
        let mut env = handle.envelope().clone();
        env.ciphertext[0] ^= 0xFF;
        let tampered = ServerSetupHandle::from_envelope(env);
        let r = tampered.with_setup(|_| ());
        assert!(
            matches!(r, Err(SealedSetupError::Crypto(_))),
            "AES-GCM must reject a tampered ciphertext"
        );
    }

    // ── F4/F7: persistence + fail-closed restart ─────────────────────────

    #[test]
    #[serial]
    fn persist_reload_preserves_server_setup() {
        let _g = KekGuard::install();
        let scratch = ScratchDir::new("persist");
        let path = scratch.file();

        // First boot: generate + seal + persist.
        let h1 = ServerSetupHandle::load_or_generate(&path).expect("first boot");
        let pk1 = h1.with_setup(|s| s.serialize().to_vec()).expect("unseal 1");
        assert!(path.exists(), "sealed file must be persisted on first boot");

        // Simulate restart: load_or_generate must find the SAME setup, not a new one.
        let h2 = ServerSetupHandle::load_or_generate(&path).expect("restart load");
        let pk2 = h2.with_setup(|s| s.serialize().to_vec()).expect("unseal 2");

        assert_eq!(
            pk1, pk2,
            "restart must preserve the OPRF seed (audit F7: no restart lockout)"
        );
    }

    #[test]
    #[serial]
    fn restart_preserves_user_verifiability() {
        use crate::store::CredentialStore;
        let _g = KekGuard::install();
        let scratch = ScratchDir::new("verify");
        let path = scratch.file();

        // Boot 1: persist a setup, register a user against THAT setup.
        let h1 = ServerSetupHandle::load_or_generate(&path).expect("boot1");
        let setup1 = h1.with_setup(|s| s.clone()).expect("clone setup1");
        let mut store1 = CredentialStore::with_server_setup(setup1);
        let uid = store1.register_with_password("oprf_user", b"pw-across-restart").unwrap();

        // Boot 2: reload the SAME sealed setup; a store built on it must still
        // verify the user registered in boot 1.
        let h2 = ServerSetupHandle::load_or_generate(&path).expect("boot2");
        let setup2 = h2.with_setup(|s| s.clone()).expect("clone setup2");
        let mut store2 = CredentialStore::with_server_setup(setup2);
        // Re-add the user record (registration bytes survive in the DB layer in
        // production; here we just move the in-memory record to store2).
        let reg_bytes = store1.get_registration_bytes("oprf_user").unwrap();
        store2.restore_user("oprf_user", uid, reg_bytes);

        let verified = store2.verify_password("oprf_user", b"pw-across-restart");
        assert!(
            verified.is_ok(),
            "user must remain verifiable after restart with the persisted OPRF seed"
        );
        assert_eq!(verified.unwrap(), uid);
    }

    #[test]
    #[serial]
    fn tampered_persisted_blob_refuses_start() {
        let _g = KekGuard::install();
        let scratch = ScratchDir::new("tamper");
        let path = scratch.file();

        // First boot writes a good blob.
        ServerSetupHandle::load_or_generate(&path).expect("first boot");

        // Corrupt the persisted ciphertext on disk.
        let mut bytes = std::fs::read(&path).expect("read sealed file");
        // Flip a byte near the end (inside the GCM ciphertext/tag region).
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;
        std::fs::write(&path, &bytes).expect("write tampered file");

        // FAIL-CLOSED: a present-but-corrupt blob must refuse to start, NOT
        // silently regenerate (which would lock out every user — audit F7).
        let r = ServerSetupHandle::load_or_generate(&path);
        assert!(
            r.is_err(),
            "tampered persisted blob must cause start to refuse, never regenerate"
        );
    }

    #[test]
    #[serial]
    fn missing_blob_first_boot_generates_and_persists() {
        let _g = KekGuard::install();
        let scratch = ScratchDir::new("firstboot");
        let path = scratch.file();
        assert!(!path.exists(), "precondition: no sealed file yet");

        let h = ServerSetupHandle::load_or_generate(&path).expect("first boot");
        assert!(path.exists(), "first boot must persist a sealed file");
        // And the freshly persisted blob must be openable.
        h.with_setup(|_| ()).expect("freshly sealed blob must open");
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
        assert!(
            PBKDF2_ITERATIONS >= 600_000,
            "must meet contemporary OWASP/NIST baseline (>=600k) for SHA-512"
        );
    }

    // ── FIPS mode KSF selection ───────────────────────────────────────

    #[test]
    fn argon2_ksf_produces_output() {
        // Verify the military Argon2id KSF (used by OpaqueCs) works via the trait
        let ksf = MilitaryArgon2::default();
        let input = GenericArray::<u8, typenum::U64>::default();
        let result = Ksf::hash(&ksf, input);
        assert!(result.is_ok(), "Argon2id hash must succeed");
    }

    // ── Military-strength Argon2 parameters (audit F1) ────────────────

    #[test]
    fn argon2_params_meet_military_floor() {
        // Task floor: m_cost >= 65536 KiB (64 MiB), t_cost >= 3, p_cost >= 4.
        assert!(
            ARGON2_M_COST_KIB >= 65_536,
            "Argon2 memory cost must be >= 64 MiB, got {ARGON2_M_COST_KIB} KiB"
        );
        assert!(
            ARGON2_T_COST >= 3,
            "Argon2 time cost must be >= 3, got {ARGON2_T_COST}"
        );
        assert!(
            ARGON2_P_COST >= 4,
            "Argon2 parallelism must be >= 4, got {ARGON2_P_COST}"
        );
    }

    #[test]
    fn argon2_params_exceed_opaque_ke_default_floor() {
        // opaque-ke's default Argon2 is the OWASP floor (19 MiB / t2 / p1).
        // Our production KSF must be strictly stronger on every axis.
        assert!(ARGON2_M_COST_KIB > 19 * 1024, "must exceed 19 MiB default");
        assert!(ARGON2_T_COST > 2, "must exceed t=2 default");
        assert!(ARGON2_P_COST > 1, "must exceed p=1 default");
    }

    #[test]
    fn military_argon2_default_builds_strong_params() {
        // Build the strong KSF and confirm it actually hashes (i.e. the
        // params passed Argon2's internal validation for the chosen costs).
        let ksf = MilitaryArgon2::default();
        let input = GenericArray::<u8, typenum::U64>::clone_from_slice(&[0x5Au8; 64]);
        let out = Ksf::hash(&ksf, input).expect("strong Argon2id must hash");
        assert_ne!(out.as_slice(), &[0u8; 64], "Argon2id output must be non-zero");
    }

    #[test]
    fn military_argon2_pad_is_lighter_but_valid() {
        // The pad variant must still produce a valid Argon2id hash (it is a
        // real, parseable OPAQUE blob) — only its cost is lower.
        assert!(ARGON2_PAD_M_COST_KIB < ARGON2_M_COST_KIB);
        assert!(ARGON2_PAD_T_COST <= ARGON2_T_COST);
        let ksf = MilitaryArgon2::pad();
        let input = GenericArray::<u8, typenum::U64>::clone_from_slice(&[0x11u8; 64]);
        let out = Ksf::hash(&ksf, input).expect("pad Argon2id must hash");
        assert_ne!(out.as_slice(), &[0u8; 64]);
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
