//! CNSA 2.0 adapted hybrid KEM using ML-KEM-1024 + X25519.
//!
//! This module implements a hybrid Key Encapsulation Mechanism (KEM) that
//! combines X25519 (classical ECDH) with ML-KEM-1024 (post-quantum lattice
//! KEM, FIPS 203) to produce a shared secret resistant to both classical
//! and quantum attacks.
//!
//! # KEM Agility (CNSA 2.0 / FIPS 140-3)
//!
//! This module supports runtime-selectable KEM algorithms:
//!
//! - **X-Wing** (ML-KEM-1024 + X25519): Default hybrid mode. Provides
//!   security against both classical and quantum attackers.
//! - **ML-KEM-1024 Only**: Pure post-quantum mode for deployments where
//!   classical crypto is considered compromised (e.g., nation-state
//!   quantum capability assumed). Skips X25519 entirely.
//!
//! The active KEM is selected via the `MILNET_PQ_KEM_ONLY` environment
//! variable. Ciphertexts are self-describing: each encoded ciphertext
//! begins with a 1-byte KEM tag.
//!
//! # Relationship to X-Wing (IETF draft-connolly-cfrg-xwing-kem)
//!
//! The standard X-Wing specification (draft-connolly-cfrg-xwing-kem) uses
//! **ML-KEM-768** as the post-quantum component. This implementation
//! **deviates** by using **ML-KEM-1024** instead, to achieve CNSA 2.0
//! Suite Level 5 compliance (NIST Security Level 5 / AES-256 equivalent).
//!
//! # Combiner
//!
//! The shared secret is derived via HKDF-SHA512 over the concatenation of
//! both sub-protocol shared secrets:
//!
//! ```text
//! shared_secret = HKDF-SHA512(salt="MILNET-XWING-v1", ikm=x25519_ss || mlkem_ss)
//! ```
//!
//! HKDF-SHA512 provides a robust dual-source randomness extraction that
//! ensures the output is indistinguishable from random even if one of the
//! two sub-protocols is completely broken.
//!
//! # Why ML-KEM-1024 instead of ML-KEM-768?
//!
//! CNSA 2.0 (CNSSP-15) mandates NIST Security Level 5 for classified
//! systems. ML-KEM-768 provides Level 3, which is insufficient for
//! this system's threat model. ML-KEM-1024 provides Level 5.
//!
//! # References
//!
//! - IETF draft-connolly-cfrg-xwing-kem (X-Wing specification)
//! - FIPS 203 (ML-KEM / CRYSTALS-Kyber)
//! - CNSA 2.0 / CNSSP-15 (NSA post-quantum algorithm requirements)

use hkdf::Hkdf;
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{EncodedSizeUser, KemCore, MlKem1024};
use sha2::Sha512;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Length of the X25519 public key in bytes.
const X25519_PK_LEN: usize = 32;

/// Length of the ML-KEM-1024 ciphertext in bytes.
const ML_KEM_CT_LEN: usize = 1568;

/// Length of the ML-KEM-1024 encapsulation key in bytes.
const ML_KEM_EK_LEN: usize = 1568;

/// HKDF salt for the X-Wing combiner.
const XWING_HKDF_SALT: &[u8] = b"MILNET-XWING-v1";

/// HKDF info string for shared secret extraction.
const XWING_HKDF_INFO: &[u8] = b"X-Wing-SharedSecret-v1";

/// Errors that can occur during X-Wing decapsulation.
#[derive(Debug)]
pub enum XWingError {
    /// The ML-KEM-1024 ciphertext was malformed or could not be decoded.
    MlKemCiphertextInvalid,
    /// ML-KEM-1024 decapsulation failed (implicit rejection triggered).
    MlKemDecapsulationFailed,
    /// The X25519 public key is a low-order point (identity or small subgroup).
    /// DH output was all zeros, indicating a key-compromise impersonation attempt.
    X25519LowOrderPoint,
}

impl std::fmt::Display for XWingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MlKemCiphertextInvalid => write!(f, "ML-KEM-1024 ciphertext invalid"),
            Self::MlKemDecapsulationFailed => write!(f, "ML-KEM-1024 decapsulation failed"),
            Self::X25519LowOrderPoint => write!(f, "X25519 low-order point rejected"),
        }
    }
}

impl std::error::Error for XWingError {}

/// A shared secret produced by the X-Wing HKDF-SHA512 combiner (64 bytes).
///
/// CNSA 2.0 Level 5 requires 256-bit security margin. The HKDF-SHA512
/// combiner naturally produces 64 bytes; storing the full output avoids
/// truncation and provides a 512-bit shared secret suitable for splitting
/// into encryption + MAC keys without an additional derivation step.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret([u8; 64]);

impl SharedSecret {
    /// Return the raw bytes of the shared secret (64 bytes).
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

impl AsRef<[u8]> for SharedSecret {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Length of the HKDF-derived session key in bytes (64 bytes = 512 bits).
pub const SESSION_KEY_LEN: usize = 64;

/// Curve25519 small-order public-key blacklist.
///
/// Every entry is a u-coordinate that yields a low-order point after the
/// Curve25519 clamping step. Sending one of these as the peer's public key
/// forces the resulting Diffie-Hellman shared secret into a small-subgroup
/// output (zero or a fixed structured value), enabling key-compromise
/// impersonation without observing the actual secret.
const X25519_SMALL_ORDER_BLACKLIST: [[u8; 32]; 7] = [
    // 0 (identity).
    [0; 32],
    // 1.
    [
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ],
    // 325606250916557431795983626356110631294008115727848805560023387167927233504
    [
        0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4,
        0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49,
        0xb8, 0x00,
    ],
    // 39382357235489614581723060781553021112529911719440698176882885853963445705823
    [
        0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef,
        0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f,
        0x11, 0x57,
    ],
    // p-1 (mod p)
    [
        0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    // p
    [
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    // p+1
    [
        0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
];

/// Constant-time check: does `pk` match a known small-order Curve25519
/// public key? Compares against every blacklist entry without short-
/// circuiting so that a malicious peer cannot infer which entry matched
/// from response timing.
pub fn is_x25519_small_order(pk: &[u8; 32]) -> bool {
    use subtle::{Choice, ConstantTimeEq};
    let mut hit = Choice::from(0u8);
    for entry in X25519_SMALL_ORDER_BLACKLIST.iter() {
        hit |= pk.ct_eq(entry);
    }
    hit.unwrap_u8() == 1
}

/// Derive a session encryption key from the X-Wing shared secret using
/// HKDF-SHA512.  The `context` parameter should uniquely bind the derivation
/// to the current session (e.g. concatenation of nonces from both sides).
///
/// Returns a 64-byte key suitable for splitting into encryption + MAC keys.
pub fn derive_session_key(
    shared_secret: &SharedSecret,
    context: &[u8],
) -> Result<[u8; SESSION_KEY_LEN], String> {
    let hk = Hkdf::<Sha512>::new(Some(context), shared_secret.as_bytes());
    let mut okm = [0u8; SESSION_KEY_LEN];
    hk.expand(b"X-Wing-Session-Key-v1", &mut okm).map_err(|e| {
        common::siem::emit_runtime_error(
            common::siem::category::CRYPTO_FAILURE,
            "HKDF-SHA512 expand failed for session key derivation",
            &format!("{e}"),
            file!(),
            line!(),
            column!(),
            module_path!(),
        );
        format!("HKDF-SHA512 session key derivation failed: {e}")
    })?;
    Ok(okm)
}

/// The public portion of an X-Wing key pair, containing both an X25519 public
/// key and an ML-KEM-1024 encapsulation key.
#[derive(Clone)]
pub struct XWingPublicKey {
    x25519_pk: PublicKey,
    ml_kem_ek: <MlKem1024 as KemCore>::EncapsulationKey,
}

impl XWingPublicKey {
    /// Serialize the public key to bytes (32 bytes X25519 || 1184 bytes ML-KEM EK).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(X25519_PK_LEN + ML_KEM_EK_LEN);
        out.extend_from_slice(self.x25519_pk.as_bytes());
        out.extend_from_slice(self.ml_kem_ek.as_bytes().as_slice());
        out
    }

    /// Deserialize a public key from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < X25519_PK_LEN + ML_KEM_EK_LEN {
            return None;
        }
        let mut x25519_bytes = [0u8; X25519_PK_LEN];
        x25519_bytes.copy_from_slice(&bytes[..X25519_PK_LEN]);
        let x25519_pk = PublicKey::from(x25519_bytes);

        let ek_bytes = ml_kem::Encoded::<<MlKem1024 as KemCore>::EncapsulationKey>::try_from(
            &bytes[X25519_PK_LEN..X25519_PK_LEN + ML_KEM_EK_LEN],
        )
        .ok()?;
        let ml_kem_ek =
            <MlKem1024 as KemCore>::EncapsulationKey::from_bytes(&ek_bytes);

        Some(Self {
            x25519_pk,
            ml_kem_ek,
        })
    }

    /// Return the raw X25519 public key bytes (32 bytes).
    pub fn x25519_bytes(&self) -> [u8; X25519_PK_LEN] {
        *self.x25519_pk.as_bytes()
    }
}

/// Ciphertext produced by X-Wing encapsulation.
///
/// Contains an ephemeral X25519 public key (32 bytes) and an ML-KEM-1024
/// ciphertext (1568 bytes).
#[derive(Clone)]
pub struct Ciphertext {
    /// Ephemeral X25519 public key from the client.
    x25519_pk_client: [u8; X25519_PK_LEN],
    /// ML-KEM-1024 ciphertext.
    ml_kem_ct: [u8; ML_KEM_CT_LEN],
}

impl Ciphertext {
    /// Serialize the ciphertext to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(X25519_PK_LEN + ML_KEM_CT_LEN);
        out.extend_from_slice(&self.x25519_pk_client);
        out.extend_from_slice(&self.ml_kem_ct);
        out
    }

    /// Deserialize a ciphertext from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < X25519_PK_LEN + ML_KEM_CT_LEN {
            return None;
        }
        let mut pk = [0u8; X25519_PK_LEN];
        pk.copy_from_slice(&bytes[..X25519_PK_LEN]);
        let mut ct = [0u8; ML_KEM_CT_LEN];
        ct.copy_from_slice(&bytes[X25519_PK_LEN..X25519_PK_LEN + ML_KEM_CT_LEN]);
        Some(Self {
            x25519_pk_client: pk,
            ml_kem_ct: ct,
        })
    }
}

/// An X-Wing key pair holding both X25519 and ML-KEM-1024 key material.
pub struct XWingKeyPair {
    x25519_secret: StaticSecret,
    x25519_public: PublicKey,
    ml_kem_dk: <MlKem1024 as KemCore>::DecapsulationKey,
    ml_kem_ek: <MlKem1024 as KemCore>::EncapsulationKey,
}

/// Generate a new X-Wing key pair (convenience wrapper).
///
/// Returns `(public_key, secret_key)` as `(XWingPublicKey, XWingKeyPair)`.
pub fn xwing_keygen() -> (XWingPublicKey, XWingKeyPair) {
    let kp = XWingKeyPair::generate();
    let pk = kp.public_key();
    (pk, kp)
}

impl XWingKeyPair {
    /// Generate a new random key pair.
    pub fn generate() -> Self {
        let mut rng = rand::rngs::OsRng;
        let x25519_secret = StaticSecret::random_from_rng(&mut rng);
        let x25519_public = PublicKey::from(&x25519_secret);
        let (ml_kem_dk, ml_kem_ek) = MlKem1024::generate(&mut rng);
        Self {
            x25519_secret,
            x25519_public,
            ml_kem_dk,
            ml_kem_ek,
        }
    }

    /// Return the combined public key.
    pub fn public_key(&self) -> XWingPublicKey {
        XWingPublicKey {
            x25519_pk: self.x25519_public,
            ml_kem_ek: self.ml_kem_ek.clone(),
        }
    }

    /// Return the X25519 public key bytes (32 bytes).
    pub fn public_key_bytes(&self) -> [u8; X25519_PK_LEN] {
        *self.x25519_public.as_bytes()
    }
}

/// Zeroize all secret key material on drop.
///
/// Both the X25519 static secret and the ML-KEM-1024 decapsulation key are
/// overwritten with zeros to prevent post-free disclosure of key material.
impl Drop for XWingKeyPair {
    fn drop(&mut self) {
        // Zeroize the X25519 secret key using the zeroize crate's
        // volatile-based implementation.
        self.x25519_secret.zeroize();
        // Zeroize the ML-KEM decapsulation key.  DecapsulationKey does not
        // implement Zeroize, so we use volatile writes to prevent the
        // compiler from eliding the zeroization as a dead store.
        // This is critical: leaking the PQ decapsulation key would allow an
        // attacker to recover all past shared secrets.
        unsafe {
            let ptr = &mut self.ml_kem_dk as *mut _ as *mut u8;
            let size = core::mem::size_of::<<MlKem1024 as KemCore>::DecapsulationKey>();
            for i in 0..size {
                core::ptr::write_volatile(ptr.add(i), 0u8);
            }
        }
        // Compiler fence to prevent reordering past the volatile writes.
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

/// Core X-Wing combiner using HKDF-SHA512.
///
/// Extracts a 64-byte shared secret from the concatenated X25519 and ML-KEM
/// shared secrets via:
///
/// ```text
/// HKDF-SHA512(salt="MILNET-XWING-v1", ikm=x25519_ss || mlkem_ss)
/// ```
///
/// This ensures the combined secret is indistinguishable from random even if
/// one of the two sub-protocols is completely broken (dual-PRF property).
fn combine(
    x25519_ss: &[u8],
    ml_kem_ss: &[u8],
) -> Result<SharedSecret, XWingError> {
    // Concatenate: x25519_ss || ml_kem_ss
    let mut ikm = Vec::with_capacity(x25519_ss.len() + ml_kem_ss.len());
    ikm.extend_from_slice(x25519_ss);
    ikm.extend_from_slice(ml_kem_ss);

    let hk = Hkdf::<Sha512>::new(Some(XWING_HKDF_SALT), &ikm);
    let mut okm = [0u8; 64];
    if hk.expand(XWING_HKDF_INFO, &mut okm).is_err() {
        common::siem::emit_runtime_error(
            common::siem::category::CRYPTO_FAILURE,
            "HKDF-SHA512 expand failed for X-Wing shared secret derivation",
            "InvalidPrkLength",
            file!(),
            line!(),
            column!(),
            module_path!(),
        );
        ikm.zeroize();
        return Err(XWingError::MlKemDecapsulationFailed);
    }

    // Zeroize the intermediate key material
    ikm.zeroize();

    Ok(SharedSecret(okm))
}

/// Client-side encapsulation.
///
/// Generates an ephemeral X25519 key pair, computes the DH shared secret
/// against the server's public key, performs ML-KEM-1024 encapsulation against
/// the server's encapsulation key, and combines both shared secrets through
/// HKDF-SHA512.
///
/// Returns `(shared_secret, ciphertext)`. The ciphertext must be sent to
/// the server so it can decapsulate and derive the same shared secret.
pub fn xwing_encapsulate(server_pk: &XWingPublicKey) -> Result<(SharedSecret, Ciphertext), XWingError> {
    let mut rng = rand::rngs::OsRng;

    // Ephemeral X25519 key pair for this session.
    let eph_secret = EphemeralSecret::random_from_rng(&mut rng);
    let eph_public = PublicKey::from(&eph_secret);

    // X25519 DH against the server's static public key.
    let x25519_ss = eph_secret.diffie_hellman(&server_pk.x25519_pk);

    let client_pk = *eph_public.as_bytes();

    // ML-KEM-1024 encapsulation against the server's encapsulation key.
    let (ml_kem_ct_arr, ml_kem_ss_arr) = server_pk
        .ml_kem_ek
        .encapsulate(&mut rng)
        .map_err(|_| {
            common::siem::emit_runtime_error(
                common::siem::category::CRYPTO_FAILURE,
                "ML-KEM-1024 encapsulation failed",
                "encapsulation error",
                file!(),
                line!(),
                column!(),
                module_path!(),
            );
            XWingError::MlKemCiphertextInvalid
        })?;

    let ml_kem_ss: &[u8] = ml_kem_ss_arr.as_slice();
    let ml_kem_ct: &[u8] = ml_kem_ct_arr.as_slice();

    // Combine both shared secrets via HKDF-SHA512.
    let ss = combine(x25519_ss.as_bytes(), ml_kem_ss)?;

    let mut ct_bytes = [0u8; ML_KEM_CT_LEN];
    ct_bytes.copy_from_slice(ml_kem_ct);

    let ct = Ciphertext {
        x25519_pk_client: client_pk,
        ml_kem_ct: ct_bytes,
    };

    Ok((ss, ct))
}

/// Server-side decapsulation.
///
/// Uses the server's key pair and the received ciphertext to recompute the
/// same shared secret the client derived during encapsulation.
///
/// Returns an error if the ML-KEM-1024 ciphertext is malformed or
/// decapsulation fails (implicit rejection).
pub fn xwing_decapsulate(
    server_kp: &XWingKeyPair,
    ciphertext: &Ciphertext,
) -> Result<SharedSecret, XWingError> {
    let client_public = PublicKey::from(ciphertext.x25519_pk_client);

    // CAT-I: explicit low-order point rejection on the *peer* public key,
    // BEFORE running the DH. The post-DH all-zero check stays as a
    // belt-and-suspenders second line, but several non-identity small-order
    // points produce structured-but-non-zero shared secrets that the
    // post-DH check alone would let through.
    if is_x25519_small_order(&ciphertext.x25519_pk_client) {
        return Err(XWingError::X25519LowOrderPoint);
    }

    // X25519 DH with the client's ephemeral public key.
    let x25519_ss = server_kp.x25519_secret.diffie_hellman(&client_public);

    // Belt-and-suspenders: also reject the all-zero post-DH output.
    if x25519_ss.as_bytes().iter().all(|&b| b == 0) {
        return Err(XWingError::X25519LowOrderPoint);
    }

    // ML-KEM-1024 decapsulation.
    let ml_kem_ct = ml_kem::Ciphertext::<MlKem1024>::try_from(ciphertext.ml_kem_ct.as_slice())
        .map_err(|_| XWingError::MlKemCiphertextInvalid)?;
    let ml_kem_ss = server_kp
        .ml_kem_dk
        .decapsulate(&ml_kem_ct)
        .map_err(|_| XWingError::MlKemDecapsulationFailed)?;

    // Combine both shared secrets via HKDF-SHA512.
    combine(x25519_ss.as_bytes(), ml_kem_ss.as_slice())
}

// ── KEM Agility: Runtime-Selectable KEM Algorithms ─────────────────────────
//
// CNSA 2.0 and FIPS 140-3 require crypto agility — the ability to switch
// algorithms without code changes. This section adds:
//
// 1. An enum of supported KEM algorithms (X-Wing hybrid vs. pure ML-KEM-1024).
// 2. Runtime algorithm selection via environment variable.
// 3. Self-describing tagged ciphertext format (1-byte tag + ciphertext).
// 4. Tagged encapsulate/decapsulate functions.

/// KEM algorithm tag bytes for the self-describing ciphertext format.
///
/// Each tagged ciphertext is encoded as: `KEM_TAG(1 byte) || ciphertext_bytes`
const KEM_TAG_XWING: u8 = 0x01;
const KEM_TAG_ML_KEM_1024_ONLY: u8 = 0x02;

/// HKDF salt for ML-KEM-1024-only mode.
const MLKEM_ONLY_HKDF_SALT: &[u8] = b"MILNET-MLKEM1024-v1";

/// HKDF info string for ML-KEM-1024-only shared secret extraction.
const MLKEM_ONLY_HKDF_INFO: &[u8] = b"ML-KEM-1024-SharedSecret-v1";

/// Supported KEM algorithms.
///
/// # Security Rationale
///
/// - **X-Wing (hybrid)**: Default. Combines classical (X25519) and post-quantum
///   (ML-KEM-1024) security. If either algorithm is broken, the other still
///   protects the shared secret. This is the conservative choice for most
///   deployments.
///
/// - **ML-KEM-1024 Only**: Pure post-quantum mode. Use when classical crypto
///   is considered compromised (e.g., operational intelligence indicates
///   adversary has quantum capability). Eliminates the X25519 component
///   entirely to remove all classical attack surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KemAlgorithm {
    /// X-Wing hybrid: ML-KEM-1024 + X25519 (default).
    XWing,
    /// Pure ML-KEM-1024 only: no classical crypto component.
    MlKem1024Only,
}

impl Default for KemAlgorithm {
    fn default() -> Self {
        Self::XWing
    }
}

impl KemAlgorithm {
    /// Return the 1-byte KEM tag for self-describing ciphertexts.
    pub fn tag(self) -> u8 {
        match self {
            Self::XWing => KEM_TAG_XWING,
            Self::MlKem1024Only => KEM_TAG_ML_KEM_1024_ONLY,
        }
    }

    /// Decode a KEM algorithm from a 1-byte tag.
    pub fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            KEM_TAG_XWING => Some(Self::XWing),
            KEM_TAG_ML_KEM_1024_ONLY => Some(Self::MlKem1024Only),
            _ => None,
        }
    }

    /// Human-readable name for logging and diagnostics.
    pub fn name(self) -> &'static str {
        match self {
            Self::XWing => "X-Wing (ML-KEM-1024 + X25519)",
            Self::MlKem1024Only => "ML-KEM-1024 Only",
        }
    }
}

/// Select the active KEM algorithm based on environment configuration.
///
/// If the `MILNET_PQ_KEM_ONLY` environment variable is set (to any value),
/// the pure ML-KEM-1024-only mode is activated. Otherwise, the default
/// X-Wing hybrid mode is used.
///
/// SECURITY: Switching to ML-KEM-1024-only mode should be done only when
/// there is a credible quantum threat to classical key exchange. The hybrid
/// mode provides defense-in-depth against both classical and quantum attacks.
pub fn active_kem_algorithm() -> KemAlgorithm {
    if std::env::var("MILNET_PQ_KEM_ONLY").is_ok() {
        KemAlgorithm::MlKem1024Only
    } else {
        KemAlgorithm::XWing
    }
}

/// ML-KEM-1024-only combiner using HKDF-SHA512.
///
/// Derives a 64-byte shared secret from the ML-KEM-1024 shared secret only
/// (no X25519 component). Uses a distinct HKDF salt to ensure domain separation
/// from the X-Wing combiner. Full 64-byte output for CNSA 2.0 Level 5.
fn combine_mlkem_only(ml_kem_ss: &[u8]) -> Result<SharedSecret, XWingError> {
    let hk = Hkdf::<Sha512>::new(Some(MLKEM_ONLY_HKDF_SALT), ml_kem_ss);
    let mut okm = [0u8; 64];
    if hk.expand(MLKEM_ONLY_HKDF_INFO, &mut okm).is_err() {
        common::siem::emit_runtime_error(
            common::siem::category::CRYPTO_FAILURE,
            "HKDF-SHA512 expand failed for ML-KEM-only shared secret derivation",
            "InvalidPrkLength",
            file!(),
            line!(),
            column!(),
            module_path!(),
        );
        return Err(XWingError::MlKemDecapsulationFailed);
    }
    Ok(SharedSecret(okm))
}

/// Tagged ciphertext that includes a KEM algorithm identifier.
///
/// Format: `KEM_TAG(1 byte) || ciphertext_bytes`
///
/// The tag enables the decapsulator to determine which algorithm was used
/// without out-of-band negotiation.
#[derive(Clone)]
pub struct TaggedCiphertext {
    /// The raw tagged bytes (tag + ciphertext).
    bytes: Vec<u8>,
}

impl TaggedCiphertext {
    /// Serialize the tagged ciphertext to bytes.
    pub fn to_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Deserialize a tagged ciphertext from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.is_empty() {
            return None;
        }
        // Verify the tag is known
        KemAlgorithm::from_tag(bytes[0])?;
        Some(Self {
            bytes: bytes.to_vec(),
        })
    }

    /// Return the KEM algorithm used.
    ///
    /// Returns `Err` if the tag byte is invalid (should not happen if
    /// constructed via `from_bytes()`, but defends against memory corruption).
    pub fn algorithm(&self) -> Result<KemAlgorithm, XWingError> {
        KemAlgorithm::from_tag(self.bytes[0]).ok_or_else(|| {
            common::siem::emit_runtime_error(
                common::siem::category::INTEGRITY_VIOLATION,
                "TaggedCiphertext contains invalid KEM tag — internal invariant violation",
                &format!("tag=0x{:02x}", self.bytes[0]),
                file!(),
                line!(),
                column!(),
                module_path!(),
            );
            XWingError::MlKemCiphertextInvalid
        })
    }

    /// Return the raw ciphertext bytes (without the tag).
    pub fn ciphertext_bytes(&self) -> &[u8] {
        &self.bytes[1..]
    }
}

/// Client-side encapsulation with KEM agility.
///
/// Selects the active KEM algorithm and produces a tagged ciphertext.
/// The shared secret derivation differs based on the algorithm:
///
/// - **X-Wing**: Full hybrid (X25519 DH + ML-KEM-1024 encapsulation + HKDF combiner).
/// - **ML-KEM-1024 Only**: Pure post-quantum (ML-KEM-1024 encapsulation + HKDF).
pub fn xwing_encapsulate_tagged(
    server_pk: &XWingPublicKey,
) -> Result<(SharedSecret, TaggedCiphertext), XWingError> {
    let algo = active_kem_algorithm();

    match algo {
        KemAlgorithm::XWing => {
            // Full X-Wing hybrid encapsulation
            let (ss, ct) = xwing_encapsulate(server_pk)?;
            let ct_bytes = ct.to_bytes();
            let mut tagged = Vec::with_capacity(1 + ct_bytes.len());
            tagged.push(KEM_TAG_XWING);
            tagged.extend_from_slice(&ct_bytes);
            Ok((ss, TaggedCiphertext { bytes: tagged }))
        }
        KemAlgorithm::MlKem1024Only => {
            // Pure ML-KEM-1024 encapsulation (no X25519)
            let mut rng = rand::rngs::OsRng;
            let (ml_kem_ct_arr, ml_kem_ss_arr) = server_pk
                .ml_kem_ek
                .encapsulate(&mut rng)
                .map_err(|_| {
                    common::siem::emit_runtime_error(
                        common::siem::category::CRYPTO_FAILURE,
                        "ML-KEM-1024 encapsulation failed (KEM-only mode)",
                        "encapsulation error",
                        file!(),
                        line!(),
                        column!(),
                        module_path!(),
                    );
                    XWingError::MlKemCiphertextInvalid
                })?;

            let ml_kem_ss: &[u8] = ml_kem_ss_arr.as_slice();
            let ml_kem_ct: &[u8] = ml_kem_ct_arr.as_slice();

            // Derive shared secret using ML-KEM-only HKDF (distinct salt)
            let ss = combine_mlkem_only(ml_kem_ss)?;

            let mut tagged = Vec::with_capacity(1 + ml_kem_ct.len());
            tagged.push(KEM_TAG_ML_KEM_1024_ONLY);
            tagged.extend_from_slice(ml_kem_ct);
            Ok((ss, TaggedCiphertext { bytes: tagged }))
        }
    }
}

/// Server-side decapsulation with KEM agility.
///
/// Reads the KEM tag from the tagged ciphertext and dispatches to the
/// appropriate decapsulation algorithm.
pub fn xwing_decapsulate_tagged(
    server_kp: &XWingKeyPair,
    tagged_ct: &TaggedCiphertext,
) -> Result<SharedSecret, XWingError> {
    let algo = tagged_ct.algorithm()?;
    let ct_bytes = tagged_ct.ciphertext_bytes();

    match algo {
        KemAlgorithm::XWing => {
            // Full X-Wing hybrid decapsulation
            let ct = Ciphertext::from_bytes(ct_bytes)
                .ok_or(XWingError::MlKemCiphertextInvalid)?;
            xwing_decapsulate(server_kp, &ct)
        }
        KemAlgorithm::MlKem1024Only => {
            // Pure ML-KEM-1024 decapsulation (no X25519)
            let ml_kem_ct =
                ml_kem::Ciphertext::<MlKem1024>::try_from(ct_bytes)
                    .map_err(|_| XWingError::MlKemCiphertextInvalid)?;
            let ml_kem_ss = server_kp
                .ml_kem_dk
                .decapsulate(&ml_kem_ct)
                .map_err(|_| XWingError::MlKemDecapsulationFailed)?;

            combine_mlkem_only(ml_kem_ss.as_slice())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn combine_is_deterministic() {
        let ss1 = combine(&[1u8; 32], &[0u8; 32]).expect("combine");
        let ss2 = combine(&[1u8; 32], &[0u8; 32]).expect("combine");
        assert_eq!(ss1.as_bytes(), ss2.as_bytes());
    }

    #[test]
    fn combine_differs_on_different_inputs() {
        let ss1 = combine(&[1u8; 32], &[0u8; 32]).expect("combine");
        let ss2 = combine(&[0u8; 32], &[1u8; 32]).expect("combine");
        assert_ne!(ss1.as_bytes(), ss2.as_bytes());
    }

    #[test]
    fn keygen_convenience_wrapper() {
        let (pk, kp) = xwing_keygen();
        assert_eq!(pk.x25519_bytes(), kp.public_key_bytes());
    }

    #[test]
    fn round_trip() {
        let server_kp = XWingKeyPair::generate();
        let server_pk = server_kp.public_key();

        let (client_ss, ct) = xwing_encapsulate(&server_pk).expect("encapsulate");
        let server_ss = xwing_decapsulate(&server_kp, &ct).expect("decapsulation should succeed");

        assert_eq!(client_ss.as_bytes(), server_ss.as_bytes());
    }

    #[test]
    fn decapsulate_with_wrong_key_produces_different_secret() {
        let server_kp = XWingKeyPair::generate();
        let server_pk = server_kp.public_key();

        let (client_ss, ct) = xwing_encapsulate(&server_pk).expect("encapsulate");

        // Decapsulate with a different keypair should yield a different secret
        // (ML-KEM implicit rejection returns a pseudorandom value).
        let wrong_kp = XWingKeyPair::generate();
        let wrong_ss = xwing_decapsulate(&wrong_kp, &ct);
        // ML-KEM implicit rejection may or may not return an error depending
        // on the implementation; either way the secret must differ.
        match wrong_ss {
            Ok(ss) => assert_ne!(client_ss.as_bytes(), ss.as_bytes()),
            Err(_) => { /* decapsulation correctly rejected */ }
        }
    }

    #[test]
    fn ciphertext_serialization() {
        let server_kp = XWingKeyPair::generate();
        let server_pk = server_kp.public_key();

        let (_ss, ct) = xwing_encapsulate(&server_pk).expect("encapsulate");
        let bytes = ct.to_bytes();
        assert_eq!(bytes.len(), X25519_PK_LEN + ML_KEM_CT_LEN);

        let ct2 = Ciphertext::from_bytes(&bytes).unwrap();
        assert_eq!(ct.x25519_pk_client, ct2.x25519_pk_client);
        assert_eq!(ct.ml_kem_ct, ct2.ml_kem_ct);
    }

    #[test]
    fn xwing_different_sessions_produce_different_secrets() {
        let kp = XWingKeyPair::generate();
        let pk = kp.public_key();
        let (ss1, _) = xwing_encapsulate(&pk).expect("encapsulate 1");
        let (ss2, _) = xwing_encapsulate(&pk).expect("encapsulate 2");
        assert_ne!(
            ss1.as_bytes(),
            ss2.as_bytes(),
            "each session must produce unique secrets"
        );
    }

    #[test]
    fn public_key_serialization() {
        let kp = XWingKeyPair::generate();
        let pk = kp.public_key();
        let bytes = pk.to_bytes();
        assert_eq!(bytes.len(), X25519_PK_LEN + ML_KEM_EK_LEN);

        let pk2 = XWingPublicKey::from_bytes(&bytes).unwrap();
        assert_eq!(pk.x25519_bytes(), pk2.x25519_bytes());
    }

    // ── KEM Agility Tests ─────────────────────────────────────────────

    #[test]
    fn kem_algorithm_default_is_xwing() {
        let algo = KemAlgorithm::default();
        assert_eq!(algo, KemAlgorithm::XWing);
        assert_eq!(algo.tag(), KEM_TAG_XWING);
    }

    #[test]
    fn kem_algorithm_tag_roundtrip() {
        for algo in [KemAlgorithm::XWing, KemAlgorithm::MlKem1024Only] {
            let tag = algo.tag();
            let decoded = KemAlgorithm::from_tag(tag).unwrap();
            assert_eq!(algo, decoded);
        }
    }

    #[test]
    fn kem_unknown_tag_returns_none() {
        assert!(KemAlgorithm::from_tag(0xFF).is_none());
        assert!(KemAlgorithm::from_tag(0x00).is_none());
    }

    #[test]
    fn tagged_ciphertext_from_invalid_empty() {
        assert!(TaggedCiphertext::from_bytes(&[]).is_none());
    }

    #[test]
    fn tagged_ciphertext_from_unknown_tag() {
        assert!(TaggedCiphertext::from_bytes(&[0xFF, 0x01, 0x02]).is_none());
    }

    #[test]
    fn tagged_xwing_round_trip() {
        // Default mode (X-Wing hybrid) tagged encapsulate/decapsulate
        let server_kp = XWingKeyPair::generate();
        let server_pk = server_kp.public_key();

        let (client_ss, tagged_ct) = xwing_encapsulate_tagged(&server_pk).expect("tagged encapsulate");
        assert_eq!(tagged_ct.algorithm().expect("algorithm"), KemAlgorithm::XWing);

        let server_ss = xwing_decapsulate_tagged(&server_kp, &tagged_ct)
            .expect("tagged decapsulation should succeed");
        assert_eq!(client_ss.as_bytes(), server_ss.as_bytes());
    }

    #[test]
    fn tagged_ciphertext_serialization() {
        let server_kp = XWingKeyPair::generate();
        let server_pk = server_kp.public_key();

        let (_ss, tagged_ct) = xwing_encapsulate_tagged(&server_pk).expect("tagged encapsulate");
        let bytes = tagged_ct.to_bytes();
        // First byte is the tag
        assert_eq!(bytes[0], KEM_TAG_XWING);

        let ct2 = TaggedCiphertext::from_bytes(bytes).unwrap();
        assert_eq!(ct2.algorithm().expect("algorithm"), KemAlgorithm::XWing);
    }

    #[test]
    fn mlkem_only_combiner_is_deterministic() {
        let ss1 = combine_mlkem_only(&[0x42u8; 32]).expect("combine");
        let ss2 = combine_mlkem_only(&[0x42u8; 32]).expect("combine");
        assert_eq!(ss1.as_bytes(), ss2.as_bytes());
    }

    #[test]
    fn mlkem_only_combiner_differs_from_xwing() {
        // Same ML-KEM shared secret should produce different output
        // when processed through ML-KEM-only vs X-Wing combiner
        let ml_kem_ss = [0x42u8; 32];
        let only_ss = combine_mlkem_only(&ml_kem_ss).expect("combine_mlkem_only");
        let xwing_ss = combine(&[0u8; 32], &ml_kem_ss).expect("combine");
        assert_ne!(
            only_ss.as_bytes(),
            xwing_ss.as_bytes(),
            "ML-KEM-only and X-Wing combiners must produce different secrets (domain separation)"
        );
    }
}
