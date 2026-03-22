//! Core ratchet chain — HKDF-SHA512 forward-secret key advancement (spec Section 8).

use common::domain;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha512;
use zeroize::{Zeroize, ZeroizeOnDrop};

type HmacSha512 = Hmac<Sha512>;

/// Maximum lookahead/lookbehind window for epoch verification.
const EPOCH_WINDOW: u64 = 3;

/// A single session's ratchet chain state.
///
/// Each advance derives a new chain key via HKDF-SHA512, mixing in both
/// client and server entropy (spec E.16). The previous chain key is securely
/// erased via `zeroize` to guarantee forward secrecy.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RatchetChain {
    chain_key: [u8; 64],
    epoch: u64,
    /// Maximum lifetime in epochs (8 hours at 10s/epoch = 2880).
    max_epoch_lifetime: u64,
    /// Recent chain keys for lookbehind verification (up to last 3 epochs).
    /// Each entry is (epoch, key). Oldest entries are evicted when the
    /// buffer exceeds `EPOCH_WINDOW` entries.
    recent_keys: Vec<(u64, [u8; 64])>,
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
            max_epoch_lifetime: 2880,
            recent_keys: Vec::new(),
        }
    }

    /// Advance the chain by one epoch.
    ///
    /// Uses both `client_entropy` and `server_entropy` per spec E.16 so
    /// that compromise of a single entropy source is insufficient.
    pub fn advance(&mut self, client_entropy: &[u8; 32], server_entropy: &[u8; 32]) {
        // Store current key in recent_keys before overwriting
        self.recent_keys.push((self.epoch, self.chain_key));
        // Evict oldest entries beyond the window
        while self.recent_keys.len() > EPOCH_WINDOW as usize {
            self.recent_keys[0].1.zeroize();
            self.recent_keys.remove(0);
        }

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
        Self::generate_tag_with_key(&self.chain_key, claims_bytes, self.epoch)
    }

    /// Generate a ratchet tag using an explicit key and epoch.
    fn generate_tag_with_key(key: &[u8; 64], claims_bytes: &[u8], epoch: u64) -> [u8; 64] {
        let mut mac = HmacSha512::new_from_slice(key).expect("HMAC-SHA512 accepts any key length");
        mac.update(domain::TOKEN_TAG);
        mac.update(claims_bytes);
        mac.update(&epoch.to_le_bytes());
        mac.finalize().into_bytes().into()
    }

    /// Derive what the chain key would be `steps` epochs into the future
    /// from the given starting key, WITHOUT advancing the actual chain.
    ///
    /// Uses a purpose-specific HKDF derivation with a distinct
    /// "forward-lookahead" domain separator instead of zero entropy.
    /// The forward entropy is derived from the chain key itself via HKDF,
    /// making it deterministic BUT requiring the actual chain key. This
    /// means an attacker who captures only the forward-derived key cannot
    /// re-derive the actual session keys (which use real client/server
    /// entropy), limiting lookahead to epoch verification only.
    fn derive_forward_key(starting_key: &[u8; 64], steps: u64) -> [u8; 64] {
        /// Domain separator for forward-lookahead key derivation.
        /// Distinct from RATCHET_ADVANCE to prevent cross-context misuse.
        const FORWARD_LOOKAHEAD_DOMAIN: &[u8] = b"MILNET-SSO-v1-RATCHET-FORWARD-LOOKAHEAD";

        let mut key = *starting_key;
        for step in 0..steps {
            // Derive forward entropy from the current key using HKDF with
            // the forward-lookahead domain separator and the step index.
            // This replaces the previous [0u8; 32] zero-entropy approach.
            let hk_entropy = Hkdf::<Sha512>::new(Some(&key), FORWARD_LOOKAHEAD_DOMAIN);
            let mut forward_client_entropy = [0u8; 32];
            let mut forward_server_entropy = [0u8; 32];
            let step_bytes = step.to_le_bytes();
            // Derive client-side forward entropy
            let mut client_info = Vec::with_capacity(40);
            client_info.extend_from_slice(b"client");
            client_info.extend_from_slice(&step_bytes);
            hk_entropy
                .expand(&client_info, &mut forward_client_entropy)
                .expect("32-byte expand must succeed for HKDF-SHA512");
            // Derive server-side forward entropy
            let mut server_info = Vec::with_capacity(40);
            server_info.extend_from_slice(b"server");
            server_info.extend_from_slice(&step_bytes);
            hk_entropy
                .expand(&server_info, &mut forward_server_entropy)
                .expect("32-byte expand must succeed for HKDF-SHA512");

            // Now advance using the standard RATCHET_ADVANCE derivation
            // but with the derived forward entropy instead of zeros.
            let hk = Hkdf::<Sha512>::new(Some(&key), domain::RATCHET_ADVANCE);
            let mut info = Vec::with_capacity(64);
            info.extend_from_slice(&forward_client_entropy);
            info.extend_from_slice(&forward_server_entropy);
            let mut new_key = [0u8; 64];
            hk.expand(&info, &mut new_key)
                .expect("64-byte expand must succeed for HKDF-SHA512");
            forward_client_entropy.zeroize();
            forward_server_entropy.zeroize();
            key.zeroize();
            key = new_key;
        }
        key
    }

    /// Verify a ratchet tag, checking +/-3 epoch lookahead window for
    /// network jitter tolerance (10s epochs → ±30s window).
    ///
    /// - Exact epoch match: verify with current chain key.
    /// - Past epochs (token_epoch < self.epoch, within 3): verify using
    ///   cached recent keys.
    /// - Future epochs (token_epoch > self.epoch, within 3): derive forward
    ///   keys temporarily without advancing the actual chain.
    ///
    /// All paths use constant-time comparison.
    pub fn verify_tag(&self, claims_bytes: &[u8], tag: &[u8; 64], token_epoch: u64) -> bool {
        let epoch_diff = token_epoch.abs_diff(self.epoch);
        if epoch_diff > EPOCH_WINDOW {
            return false;
        }

        // Exact match: verify with current key
        if token_epoch == self.epoch {
            let expected = self.generate_tag(claims_bytes);
            return crypto::ct::ct_eq_64(tag, &expected);
        }

        // Past epoch: look up in recent_keys cache
        if token_epoch < self.epoch {
            for (cached_epoch, cached_key) in &self.recent_keys {
                if *cached_epoch == token_epoch {
                    let expected =
                        Self::generate_tag_with_key(cached_key, claims_bytes, token_epoch);
                    return crypto::ct::ct_eq_64(tag, &expected);
                }
            }
            // Key not in cache (was evicted or chain was just created)
            return false;
        }

        // Future epoch: derive forward without advancing the real chain
        let steps = token_epoch - self.epoch;
        let mut forward_key = Self::derive_forward_key(&self.chain_key, steps);
        let expected = Self::generate_tag_with_key(&forward_key, claims_bytes, token_epoch);
        forward_key.zeroize();
        crypto::ct::ct_eq_64(tag, &expected)
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
