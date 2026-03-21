//! X-Wing hybrid KEM combiner per spec Errata C.8.
//!
//! Combines X25519 (classical) with ML-KEM-768 (post-quantum) to produce a
//! shared secret via:
//!
//! ```text
//! shared_secret = SHA3-256("X-Wing" || ml_kem_ss || ml_kem_ct || x25519_ss || x25519_pk_client || x25519_pk_server)
//! ```
//!
//! The ML-KEM-768 component is currently a placeholder (zeroed bytes) until
//! libcrux integration is complete.

use sha3::{Digest, Sha3_256};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Length of the X25519 public key in bytes.
const X25519_PK_LEN: usize = 32;

/// Domain separator for the X-Wing combiner.
const XWING_LABEL: &[u8] = b"X-Wing";

// TODO(libcrux): Replace ML-KEM placeholder constants with real ML-KEM-768
// key sizes once libcrux is integrated. The shared secret is 32 bytes and
// the ciphertext will be 1088 bytes for ML-KEM-768.
const ML_KEM_SS_PLACEHOLDER: [u8; 32] = [0u8; 32];
const ML_KEM_CT_PLACEHOLDER: &[u8] = &[];

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

/// Ciphertext produced by X-Wing encapsulation.
///
/// Currently contains only the ephemeral X25519 public key (32 bytes).
/// When ML-KEM is integrated this will also carry the ML-KEM ciphertext.
#[derive(Clone)]
pub struct Ciphertext {
    /// Ephemeral X25519 public key from the client.
    x25519_pk_client: [u8; X25519_PK_LEN],
    // TODO(libcrux): Add ml_kem_ct field (Vec<u8> or [u8; 1088]).
}

impl Ciphertext {
    /// Serialize the ciphertext to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.x25519_pk_client.to_vec()
    }

    /// Deserialize a ciphertext from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < X25519_PK_LEN {
            return None;
        }
        let mut pk = [0u8; X25519_PK_LEN];
        pk.copy_from_slice(&bytes[..X25519_PK_LEN]);
        Some(Self {
            x25519_pk_client: pk,
        })
    }
}

/// An X-Wing key pair holding an X25519 static secret and its public key.
pub struct XWingKeyPair {
    secret: StaticSecret,
    public: PublicKey,
}

impl XWingKeyPair {
    /// Generate a new random key pair.
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(rand::thread_rng());
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Return the public key bytes (32 bytes).
    pub fn public_key_bytes(&self) -> [u8; X25519_PK_LEN] {
        *self.public.as_bytes()
    }
}

/// Zeroize the secret key material on drop.
///
/// `StaticSecret` does not implement `Zeroize` from our perspective, so we
/// overwrite the secret bytes manually via its `to_bytes()` representation.
/// This is a best-effort defence-in-depth measure; the original `StaticSecret`
/// storage is owned by `x25519-dalek` and may or may not be zeroized by that
/// crate's own `Drop` implementation.
impl Drop for XWingKeyPair {
    fn drop(&mut self) {
        // Overwrite the secret by replacing it with a zeroed key.
        // StaticSecret::from([0u8; 32]) creates a secret with all-zero bytes.
        self.secret = StaticSecret::from([0u8; 32]);
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
/// against the server's public key, and combines everything through the
/// X-Wing formula.
///
/// Returns `(shared_secret, ciphertext)`. The ciphertext must be sent to
/// the server so it can decapsulate.
pub fn xwing_encapsulate(server_pk: &[u8; 32]) -> (SharedSecret, Ciphertext) {
    let server_public = PublicKey::from(*server_pk);

    // Ephemeral X25519 key pair for this session.
    let eph_secret = EphemeralSecret::random_from_rng(rand::thread_rng());
    let eph_public = PublicKey::from(&eph_secret);

    // X25519 DH.
    let x25519_ss = eph_secret.diffie_hellman(&server_public);

    let client_pk = *eph_public.as_bytes();

    // TODO(libcrux): Replace placeholders with real ML-KEM-768 encapsulation.
    let ss = combine(
        &ML_KEM_SS_PLACEHOLDER,
        ML_KEM_CT_PLACEHOLDER,
        x25519_ss.as_bytes(),
        &client_pk,
        server_pk,
    );

    let ct = Ciphertext {
        x25519_pk_client: client_pk,
    };

    (ss, ct)
}

/// Server-side decapsulation.
///
/// Uses the server's static key pair and the received ciphertext to
/// recompute the same shared secret the client derived.
pub fn xwing_decapsulate(server_kp: &XWingKeyPair, ciphertext: &Ciphertext) -> SharedSecret {
    let client_public = PublicKey::from(ciphertext.x25519_pk_client);

    // X25519 DH with the client's ephemeral public key.
    let x25519_ss = server_kp.secret.diffie_hellman(&client_public);

    let server_pk = server_kp.public_key_bytes();

    // TODO(libcrux): Replace placeholders with real ML-KEM-768 decapsulation.
    combine(
        &ML_KEM_SS_PLACEHOLDER,
        ML_KEM_CT_PLACEHOLDER,
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
        let ss1 = combine(&[0u8; 32], &[], &[1u8; 32], &[2u8; 32], &[3u8; 32]);
        let ss2 = combine(&[0u8; 32], &[], &[1u8; 32], &[2u8; 32], &[3u8; 32]);
        assert_eq!(ss1.as_bytes(), ss2.as_bytes());
    }
}
