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
//! The combiner formula remains the same as the X-Wing draft:
//!
//! ```text
//! shared_secret = SHA3-256("X-Wing" || ml_kem_ss || ml_kem_ct || x25519_ss || x25519_pk_client || x25519_pk_server)
//! ```
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
use sha3::{Digest, Sha3_256};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Length of the X25519 public key in bytes.
const X25519_PK_LEN: usize = 32;

/// Length of the ML-KEM-1024 ciphertext in bytes.
const ML_KEM_CT_LEN: usize = 1568;

/// Length of the ML-KEM-1024 encapsulation key in bytes.
const ML_KEM_EK_LEN: usize = 1568;

/// Domain separator for the X-Wing combiner.
const XWING_LABEL: &[u8] = b"X-Wing";

/// A shared secret produced by the X-Wing combiner (32 bytes, SHA3-256 output).
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
/// ciphertext (1088 bytes).
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

/// Zeroize the secret key material on drop.
impl Drop for XWingKeyPair {
    fn drop(&mut self) {
        // Zeroize the X25519 secret key
        self.x25519_secret = StaticSecret::from([0u8; 32]);
        // Zeroize the ML-KEM decapsulation key (several KB of PQ private key material).
        // DecapsulationKey does not impl Zeroize, so we zero the underlying bytes via
        // pointer write. This is critical — leaking the PQ decapsulation key would
        // allow an attacker to recover all shared secrets.
        unsafe {
            let ptr = &mut self.ml_kem_dk as *mut _ as *mut u8;
            let size = core::mem::size_of::<<MlKem1024 as KemCore>::DecapsulationKey>();
            core::ptr::write_bytes(ptr, 0, size);
        }
    }
}

/// Core X-Wing combiner function.
///
/// ```text
/// SHA3-256("X-Wing" || ml_kem_ss || ml_kem_ct || x25519_ss || x25519_pk_client || x25519_pk_server)
/// ```
fn combine(
    ml_kem_ss: &[u8],
    ml_kem_ct: &[u8],
    x25519_ss: &[u8],
    x25519_pk_client: &[u8; 32],
    x25519_pk_server: &[u8; 32],
) -> SharedSecret {
    let mut hasher = Sha3_256::new();
    hasher.update(XWING_LABEL);
    hasher.update(ml_kem_ss);
    hasher.update(ml_kem_ct);
    hasher.update(x25519_ss);
    hasher.update(x25519_pk_client);
    hasher.update(x25519_pk_server);
    let hash = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&hash);
    SharedSecret(out)
}

/// Client-side encapsulation.
///
/// Generates an ephemeral X25519 key pair, computes the DH shared secret
/// against the server's public key, performs ML-KEM-1024 encapsulation against
/// the server's encapsulation key, and combines everything through the X-Wing
/// formula.
///
/// Returns `(shared_secret, ciphertext)`. The ciphertext must be sent to
/// the server so it can decapsulate.
pub fn xwing_encapsulate(server_pk: &XWingPublicKey) -> (SharedSecret, Ciphertext) {
    let mut rng = rand::rngs::OsRng;

    // Ephemeral X25519 key pair for this session.
    let eph_secret = EphemeralSecret::random_from_rng(&mut rng);
    let eph_public = PublicKey::from(&eph_secret);

    // X25519 DH.
    let x25519_ss = eph_secret.diffie_hellman(&server_pk.x25519_pk);

    let client_pk = *eph_public.as_bytes();

    // ML-KEM-1024 encapsulation.
    let (ml_kem_ct_arr, ml_kem_ss_arr) = server_pk
        .ml_kem_ek
        .encapsulate(&mut rng)
        .expect("ML-KEM-1024 encapsulation should not fail");

    let ml_kem_ss: &[u8] = ml_kem_ss_arr.as_slice();
    let ml_kem_ct: &[u8] = ml_kem_ct_arr.as_slice();

    let server_x25519_pk = server_pk.x25519_bytes();

    let ss = combine(
        ml_kem_ss,
        ml_kem_ct,
        x25519_ss.as_bytes(),
        &client_pk,
        &server_x25519_pk,
    );

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
/// same shared secret the client derived.
pub fn xwing_decapsulate(server_kp: &XWingKeyPair, ciphertext: &Ciphertext) -> SharedSecret {
    let client_public = PublicKey::from(ciphertext.x25519_pk_client);

    // X25519 DH with the client's ephemeral public key.
    let x25519_ss = server_kp.x25519_secret.diffie_hellman(&client_public);

    let server_pk = server_kp.public_key_bytes();

    // ML-KEM-1024 decapsulation.
    let ml_kem_ct = ml_kem::Ciphertext::<MlKem1024>::try_from(ciphertext.ml_kem_ct.as_slice())
        .expect("ML-KEM-1024 ciphertext should be the correct length");
    let ml_kem_ss = server_kp
        .ml_kem_dk
        .decapsulate(&ml_kem_ct)
        .expect("ML-KEM-1024 decapsulation should not fail");

    combine(
        ml_kem_ss.as_slice(),
        &ciphertext.ml_kem_ct,
        x25519_ss.as_bytes(),
        &ciphertext.x25519_pk_client,
        &server_pk,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn combine_is_deterministic() {
        let ss1 = combine(&[0u8; 32], &[0u8; 64], &[1u8; 32], &[2u8; 32], &[3u8; 32]);
        let ss2 = combine(&[0u8; 32], &[0u8; 64], &[1u8; 32], &[2u8; 32], &[3u8; 32]);
        assert_eq!(ss1.as_bytes(), ss2.as_bytes());
    }

    #[test]
    fn round_trip() {
        let server_kp = XWingKeyPair::generate();
        let server_pk = server_kp.public_key();

        let (client_ss, ct) = xwing_encapsulate(&server_pk);
        let server_ss = xwing_decapsulate(&server_kp, &ct);

        assert_eq!(client_ss.as_bytes(), server_ss.as_bytes());
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
