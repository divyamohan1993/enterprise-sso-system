//! CNSA 2.0 adapted hybrid KEM using ML-KEM-1024 + X25519.
//!
//! This module implements a hybrid Key Encapsulation Mechanism (KEM) that
//! combines X25519 (classical ECDH) with ML-KEM-1024 (post-quantum lattice
//! KEM, FIPS 203) to produce a shared secret resistant to both classical
//! and quantum attacks.
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
}

impl std::fmt::Display for XWingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MlKemCiphertextInvalid => write!(f, "ML-KEM-1024 ciphertext invalid"),
            Self::MlKemDecapsulationFailed => write!(f, "ML-KEM-1024 decapsulation failed"),
        }
    }
}

impl std::error::Error for XWingError {}

/// A shared secret produced by the X-Wing HKDF-SHA512 combiner (32 bytes).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret([u8; 32]);

impl SharedSecret {
    /// Return the raw bytes of the shared secret.
    pub fn as_bytes(&self) -> &[u8; 32] {
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

/// Derive a session encryption key from the X-Wing shared secret using
/// HKDF-SHA512.  The `context` parameter should uniquely bind the derivation
/// to the current session (e.g. concatenation of nonces from both sides).
///
/// Returns a 64-byte key suitable for splitting into encryption + MAC keys.
pub fn derive_session_key(
    shared_secret: &SharedSecret,
    context: &[u8],
) -> [u8; SESSION_KEY_LEN] {
    let hk = Hkdf::<Sha512>::new(Some(context), shared_secret.as_bytes());
    let mut okm = [0u8; SESSION_KEY_LEN];
    hk.expand(b"X-Wing-Session-Key-v1", &mut okm)
        .expect("64 bytes is within HKDF-SHA512 output limit");
    okm
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
        // Zeroize the X25519 secret key by overwriting with the zero scalar.
        self.x25519_secret = StaticSecret::from([0u8; 32]);
        // Zeroize the ML-KEM decapsulation key.  DecapsulationKey does not
        // implement Zeroize, so we write zeros over the underlying bytes.
        // This is critical: leaking the PQ decapsulation key would allow an
        // attacker to recover all past shared secrets.
        unsafe {
            let ptr = &mut self.ml_kem_dk as *mut _ as *mut u8;
            let size = core::mem::size_of::<<MlKem1024 as KemCore>::DecapsulationKey>();
            core::ptr::write_bytes(ptr, 0, size);
        }
    }
}

/// Core X-Wing combiner using HKDF-SHA512.
///
/// Extracts a 32-byte shared secret from the concatenated X25519 and ML-KEM
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
) -> SharedSecret {
    // Concatenate: x25519_ss || ml_kem_ss
    let mut ikm = Vec::with_capacity(x25519_ss.len() + ml_kem_ss.len());
    ikm.extend_from_slice(x25519_ss);
    ikm.extend_from_slice(ml_kem_ss);

    let hk = Hkdf::<Sha512>::new(Some(XWING_HKDF_SALT), &ikm);
    let mut okm = [0u8; 32];
    hk.expand(XWING_HKDF_INFO, &mut okm)
        .expect("32 bytes is within HKDF-SHA512 output limit");

    // Zeroize the intermediate key material
    ikm.zeroize();

    SharedSecret(okm)
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
pub fn xwing_encapsulate(server_pk: &XWingPublicKey) -> (SharedSecret, Ciphertext) {
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
        .expect("ML-KEM-1024 encapsulation should not fail");

    let ml_kem_ss: &[u8] = ml_kem_ss_arr.as_slice();
    let ml_kem_ct: &[u8] = ml_kem_ct_arr.as_slice();

    // Combine both shared secrets via HKDF-SHA512.
    let ss = combine(x25519_ss.as_bytes(), ml_kem_ss);

    let mut ct_bytes = [0u8; ML_KEM_CT_LEN];
    ct_bytes.copy_from_slice(ml_kem_ct);

    let ct = Ciphertext {
        x25519_pk_client: client_pk,
        ml_kem_ct: ct_bytes,
    };

    (ss, ct)
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

    // X25519 DH with the client's ephemeral public key.
    let x25519_ss = server_kp.x25519_secret.diffie_hellman(&client_public);

    // ML-KEM-1024 decapsulation.
    let ml_kem_ct = ml_kem::Ciphertext::<MlKem1024>::try_from(ciphertext.ml_kem_ct.as_slice())
        .map_err(|_| XWingError::MlKemCiphertextInvalid)?;
    let ml_kem_ss = server_kp
        .ml_kem_dk
        .decapsulate(&ml_kem_ct)
        .map_err(|_| XWingError::MlKemDecapsulationFailed)?;

    // Combine both shared secrets via HKDF-SHA512.
    Ok(combine(x25519_ss.as_bytes(), ml_kem_ss.as_slice()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn combine_is_deterministic() {
        let ss1 = combine(&[1u8; 32], &[0u8; 32]);
        let ss2 = combine(&[1u8; 32], &[0u8; 32]);
        assert_eq!(ss1.as_bytes(), ss2.as_bytes());
    }

    #[test]
    fn combine_differs_on_different_inputs() {
        let ss1 = combine(&[1u8; 32], &[0u8; 32]);
        let ss2 = combine(&[0u8; 32], &[1u8; 32]);
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

        let (client_ss, ct) = xwing_encapsulate(&server_pk);
        let server_ss = xwing_decapsulate(&server_kp, &ct).expect("decapsulation should succeed");

        assert_eq!(client_ss.as_bytes(), server_ss.as_bytes());
    }

    #[test]
    fn decapsulate_with_wrong_key_produces_different_secret() {
        let server_kp = XWingKeyPair::generate();
        let server_pk = server_kp.public_key();

        let (client_ss, ct) = xwing_encapsulate(&server_pk);

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

        let (_ss, ct) = xwing_encapsulate(&server_pk);
        let bytes = ct.to_bytes();
        assert_eq!(bytes.len(), X25519_PK_LEN + ML_KEM_CT_LEN);

        let ct2 = Ciphertext::from_bytes(&bytes).unwrap();
        assert_eq!(ct.x25519_pk_client, ct2.x25519_pk_client);
        assert_eq!(ct.ml_kem_ct, ct2.ml_kem_ct);
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
}
