//! Core ratchet chain — HKDF-SHA512 forward-secret key advancement (spec Section 8).

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use common::domain;
use sha2::Sha512;
use zeroize::{Zeroize, ZeroizeOnDrop};

type HmacSha512 = Hmac<Sha512>;

/// A single session's ratchet chain state.
///
/// Each advance derives a new chain key via HKDF-SHA512, mixing in both
/// client and server entropy (spec E.16). The previous chain key is securely
/// erased via `zeroize` to guarantee forward secrecy.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RatchetChain {
    chain_key: [u8; 64],
    epoch: u64,
    /// Maximum lifetime in epochs (8 hours at 30s/epoch = 960).
    max_epoch_lifetime: u64,
}

impl RatchetChain {
    /// Create a new chain from a master secret.
    pub fn new(master_secret: &[u8; 64]) -> Self {
        let hk = Hkdf::<Sha512>::new(None, master_secret);
        let mut chain_key = [0u8; 64];
        hk.expand(domain::RATCHET_ADVANCE, &mut chain_key)
            .expect("64-byte expand must succeed for HKDF-SHA512");
        Self {
            chain_key,
            epoch: 0,
            max_epoch_lifetime: 960,
        }
    }

    /// Advance the chain by one epoch.
    ///
    /// Uses both `client_entropy` and `server_entropy` per spec E.16 so
    /// that compromise of a single entropy source is insufficient.
    pub fn advance(&mut self, client_entropy: &[u8; 32], server_entropy: &[u8; 32]) {
        let hk = Hkdf::<Sha512>::new(Some(&self.chain_key), domain::RATCHET_ADVANCE);
        let mut info = Vec::with_capacity(64);
        info.extend_from_slice(client_entropy);
        info.extend_from_slice(server_entropy);
        let mut new_key = [0u8; 64];
        hk.expand(&info, &mut new_key)
            .expect("64-byte expand must succeed for HKDF-SHA512");
        self.chain_key.zeroize(); // securely erase old key
        self.chain_key = new_key;
        self.epoch += 1;
    }

    /// Generate a ratchet tag (HMAC-SHA512) for the current epoch.
    pub fn generate_tag(&self, claims_bytes: &[u8]) -> [u8; 64] {
        let mut mac = HmacSha512::new_from_slice(&self.chain_key)
            .expect("HMAC-SHA512 accepts any key length");
        mac.update(domain::TOKEN_TAG);
        mac.update(claims_bytes);
        mac.update(&self.epoch.to_le_bytes());
        mac.finalize().into_bytes().into()
    }

    /// Verify a ratchet tag, checking +/-3 epoch lookahead window for
    /// network jitter tolerance.
    ///
    /// Exact-epoch match is verified via constant-time comparison.
    /// For non-exact matches within the window, returns `false` for now
    /// (lookahead verification with cached epoch keys is a future
    /// enhancement).
    pub fn verify_tag(&self, claims_bytes: &[u8], tag: &[u8; 64], token_epoch: u64) -> bool {
        let epoch_diff = token_epoch.abs_diff(self.epoch);
        if epoch_diff > 3 {
            return false;
        }
        // For exact match, verify with constant-time comparison
        if token_epoch == self.epoch {
            let expected = self.generate_tag(claims_bytes);
            return crypto::ct::ct_eq_64(tag, &expected);
        }
        // For lookahead, we'd need cached epoch keys
        // TODO: implement lookahead verification with cached epoch keys
        false
    }

    /// Current epoch of this chain.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Whether this chain has exceeded its maximum lifetime.
    pub fn is_expired(&self) -> bool {
        self.epoch >= self.max_epoch_lifetime
    }
}
