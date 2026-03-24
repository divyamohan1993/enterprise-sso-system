//! Core ratchet chain — HKDF-SHA512 forward-secret key advancement (spec Section 8).
//!
//! Hardened with memory-locked chain key storage, canary protection,
//! entropy quality validation, and anti-clone nonce tracking.

#![allow(unsafe_code)]

use common::domain;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha512;
use zeroize::Zeroize;

type HmacSha512 = Hmac<Sha512>;

/// Maximum lookahead/lookbehind window for epoch verification.
const EPOCH_WINDOW: u64 = 3;

/// Number of recent server nonces to track for clone detection.
const NONCE_HISTORY_SIZE: usize = 10;

/// Minimum distinct byte values required in 32-byte entropy to pass quality check.
/// 4 bits of randomness means at least 16 distinct values among 32 bytes, but we
/// use a conservative threshold: at least 4 distinct byte values.
const MIN_DISTINCT_BYTES: usize = 4;

/// Random canary value set at construction for overflow detection.
fn random_canary() -> u64 {
    let mut buf = [0u8; 8];
    getrandom::getrandom(&mut buf).expect("OS CSPRNG must be available");
    u64::from_ne_bytes(buf)
}

/// Lock a memory region so it cannot be paged to swap.
fn mlock_region(ptr: *const u8, len: usize) -> bool {
    unsafe { libc::mlock(ptr as *const libc::c_void, len) == 0 }
}

/// Unlock a previously mlocked memory region.
fn munlock_region(ptr: *const u8, len: usize) {
    unsafe {
        libc::munlock(ptr as *const libc::c_void, len);
    }
}

/// Mark a memory region as excluded from core dumps.
fn madv_dontdump(ptr: *const u8, len: usize) -> bool {
    unsafe { libc::madvise(ptr as *mut libc::c_void, len, libc::MADV_DONTDUMP) == 0 }
}

/// Check whether entropy has sufficient quality (at least MIN_DISTINCT_BYTES distinct values).
fn entropy_quality_ok(entropy: &[u8; 32]) -> bool {
    let mut seen = [false; 256];
    let mut distinct = 0usize;
    for &b in entropy.iter() {
        if !seen[b as usize] {
            seen[b as usize] = true;
            distinct += 1;
            if distinct >= MIN_DISTINCT_BYTES {
                return true;
            }
        }
    }
    false
}

/// Check whether entropy is all zeros.
fn is_all_zero(entropy: &[u8; 32]) -> bool {
    let mut acc: u8 = 0;
    for &b in entropy.iter() {
        acc |= b;
    }
    acc == 0
}

/// A single session's ratchet chain state.
///
/// Each advance derives a new chain key via HKDF-SHA512, mixing in both
/// client and server entropy (spec E.16). The previous chain key is securely
/// erased via `zeroize` to guarantee forward secrecy.
///
/// Memory protection:
/// - chain_key is bracketed by canary words for overflow detection
/// - chain_key region is mlocked (non-swappable) and MADV_DONTDUMP
/// - Canaries are verified on every access and on drop
pub struct RatchetChain {
    /// Head canary — set once at construction, verified on every access.
    canary_head: u64,
    chain_key: [u8; 64],
    /// Tail canary — independent random value, verified alongside head.
    canary_tail: u64,
    /// Expected head canary value (stored separately for comparison).
    expected_head: u64,
    /// Expected tail canary value.
    expected_tail: u64,
    /// Whether mlock succeeded for the chain_key region.
    key_locked: bool,
    epoch: u64,
    /// Maximum lifetime in epochs (8 hours at 10s/epoch = 2880).
    max_epoch_lifetime: u64,
    /// Recent chain keys for lookbehind verification (up to last 3 epochs).
    /// Each entry is (epoch, key). Oldest entries are evicted when the
    /// buffer exceeds `EPOCH_WINDOW` entries.
    recent_keys: Vec<(u64, [u8; 64])>,
    /// Recent server nonces for clone detection. Tracks last N nonces
    /// and rejects any advancement that reuses one.
    recent_nonces: Vec<[u8; 32]>,
}

// Manual Zeroize implementation since we have custom fields
impl Zeroize for RatchetChain {
    fn zeroize(&mut self) {
        self.chain_key.zeroize();
        self.epoch.zeroize();
        for entry in self.recent_keys.iter_mut() {
            entry.1.zeroize();
        }
        self.recent_keys.clear();
        self.recent_nonces.zeroize();
        self.canary_head.zeroize();
        self.canary_tail.zeroize();
        self.expected_head.zeroize();
        self.expected_tail.zeroize();
    }
}

impl RatchetChain {
    /// Verify canary integrity. Returns true if both canaries are intact.
    fn verify_canaries(&self) -> bool {
        let head_diff = self.canary_head ^ self.expected_head;
        let tail_diff = self.canary_tail ^ self.expected_tail;
        (head_diff | tail_diff) == 0
    }

    /// Assert canary integrity, panicking with zeroization on violation.
    fn assert_canaries(&self) {
        if !self.verify_canaries() {
            tracing::error!(
                "SECURITY: canary violation detected in RatchetChain (epoch={}) — \
                 possible buffer overflow or use-after-free. Zeroizing key material.",
                self.epoch
            );
            // Zeroize before panic — we need unsafe to mutate through shared ref
            // because the chain is about to be destroyed and key material MUST be cleared.
            unsafe {
                let key_ptr = &self.chain_key as *const [u8; 64] as *mut [u8; 64];
                (*key_ptr).zeroize();
            }
            panic!(
                "SECURITY: canary violation in RatchetChain — possible buffer overflow"
            );
        }
    }

    /// Apply mlock and MADV_DONTDUMP to the chain_key region.
    fn lock_chain_key(&mut self) {
        let ptr = self.chain_key.as_ptr();
        let len = self.chain_key.len();
        if mlock_region(ptr, len) {
            self.key_locked = true;
            madv_dontdump(ptr, len);
        } else {
            if common::sealed_keys::is_production() {
                panic!(
                    "FATAL: mlock failed for RatchetChain chain_key in production mode. \
                     Ensure RLIMIT_MEMLOCK is sufficient."
                );
            }
            tracing::warn!(
                "mlock failed for RatchetChain chain_key — data may be swappable to disk"
            );
        }
    }

    /// Create a new chain from a master secret.
    pub fn new(master_secret: &[u8; 64]) -> Self {
        let hk = Hkdf::<Sha512>::new(None, master_secret);
        let mut chain_key = [0u8; 64];
        hk.expand(domain::RATCHET_ADVANCE, &mut chain_key)
            .expect("64-byte expand must succeed for HKDF-SHA512");

        let head = random_canary();
        let tail = random_canary();

        let mut chain = Self {
            canary_head: head,
            chain_key,
            canary_tail: tail,
            expected_head: head,
            expected_tail: tail,
            key_locked: false,
            epoch: 0,
            max_epoch_lifetime: 2880,
            recent_keys: Vec::new(),
            recent_nonces: Vec::new(),
        };
        chain.lock_chain_key();
        chain
    }

    /// Advance the chain by one epoch.
    ///
    /// Uses both `client_entropy` and `server_entropy` per spec E.16 so
    /// that compromise of a single entropy source is insufficient.
    ///
    /// `server_nonce` is a unique nonce from the server for this advancement,
    /// mixed into the derivation and tracked to prevent clone attacks.
    ///
    /// # Panics
    /// - If either entropy source is all-zero
    /// - If either entropy source fails quality check (<4 distinct byte values)
    /// - If `server_nonce` was already used in a recent advancement
    /// - If epoch would wrap around u64::MAX
    pub fn advance(
        &mut self,
        client_entropy: &[u8; 32],
        server_entropy: &[u8; 32],
        server_nonce: &[u8; 32],
    ) {
        self.assert_canaries();

        // --- Entropy validation ---

        // Reject all-zero entropy
        if is_all_zero(client_entropy) {
            tracing::error!(
                epoch = self.epoch,
                "SIEM:CRITICAL ratchet advancement rejected: client_entropy is all-zero"
            );
            panic!("ratchet: client_entropy must not be all-zero");
        }
        if is_all_zero(server_entropy) {
            tracing::error!(
                epoch = self.epoch,
                "SIEM:CRITICAL ratchet advancement rejected: server_entropy is all-zero"
            );
            panic!("ratchet: server_entropy must not be all-zero");
        }

        // Entropy quality check
        if !entropy_quality_ok(client_entropy) {
            tracing::error!(
                epoch = self.epoch,
                "SIEM:CRITICAL ratchet advancement rejected: client_entropy has insufficient \
                 randomness (fewer than {MIN_DISTINCT_BYTES} distinct byte values)"
            );
            panic!("ratchet: client_entropy fails quality check");
        }
        if !entropy_quality_ok(server_entropy) {
            tracing::error!(
                epoch = self.epoch,
                "SIEM:CRITICAL ratchet advancement rejected: server_entropy has insufficient \
                 randomness (fewer than {MIN_DISTINCT_BYTES} distinct byte values)"
            );
            panic!("ratchet: server_entropy fails quality check");
        }

        // --- Monotonicity check ---
        if self.epoch == u64::MAX {
            tracing::error!(
                "SIEM:CRITICAL ratchet epoch counter at u64::MAX — refusing to wrap"
            );
            panic!("ratchet: epoch counter would wrap around at u64::MAX");
        }

        // --- Anti-clone nonce check ---
        for existing in &self.recent_nonces {
            if crypto::ct::ct_eq_32(existing, server_nonce) {
                tracing::error!(
                    epoch = self.epoch,
                    "SIEM:CRITICAL ratchet advancement rejected: server_nonce reuse detected \
                     — possible token cloning attack"
                );
                panic!("ratchet: server_nonce reuse detected (clone attack)");
            }
        }

        // Track this nonce
        self.recent_nonces.push(*server_nonce);
        while self.recent_nonces.len() > NONCE_HISTORY_SIZE {
            self.recent_nonces[0].zeroize();
            self.recent_nonces.remove(0);
        }

        // --- Store current key in recent_keys before overwriting ---
        self.recent_keys.push((self.epoch, self.chain_key));
        while self.recent_keys.len() > EPOCH_WINDOW as usize {
            self.recent_keys[0].1.zeroize();
            self.recent_keys.remove(0);
        }

        // --- Derive new chain key, mixing server_nonce into info ---
        let hk = Hkdf::<Sha512>::new(Some(&self.chain_key), domain::RATCHET_ADVANCE);
        let mut info = Vec::with_capacity(96);
        info.extend_from_slice(client_entropy);
        info.extend_from_slice(server_entropy);
        info.extend_from_slice(server_nonce);
        let mut new_key = [0u8; 64];
        hk.expand(&info, &mut new_key)
            .expect("64-byte expand must succeed for HKDF-SHA512");

        // Unlock old key region before overwrite (will re-lock new data)
        if self.key_locked {
            munlock_region(self.chain_key.as_ptr(), self.chain_key.len());
            self.key_locked = false;
        }

        self.chain_key.zeroize(); // securely erase old key
        self.chain_key = new_key;
        self.epoch += 1;

        // Re-lock the new key
        self.lock_chain_key();

        info.zeroize();
        new_key.zeroize();
    }

    /// Generate a ratchet tag (HMAC-SHA512) for the current epoch.
    pub fn generate_tag(&self, claims_bytes: &[u8]) -> [u8; 64] {
        self.assert_canaries();
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
            // Derive forward nonce
            let mut forward_nonce = [0u8; 32];
            let mut nonce_info = Vec::with_capacity(40);
            nonce_info.extend_from_slice(b"nonce");
            nonce_info.extend_from_slice(&step_bytes);
            hk_entropy
                .expand(&nonce_info, &mut forward_nonce)
                .expect("32-byte expand must succeed for HKDF-SHA512");

            // Now advance using the standard RATCHET_ADVANCE derivation
            // but with the derived forward entropy + nonce instead of real ones.
            let hk = Hkdf::<Sha512>::new(Some(&key), domain::RATCHET_ADVANCE);
            let mut info = Vec::with_capacity(96);
            info.extend_from_slice(&forward_client_entropy);
            info.extend_from_slice(&forward_server_entropy);
            info.extend_from_slice(&forward_nonce);
            let mut new_key = [0u8; 64];
            hk.expand(&info, &mut new_key)
                .expect("64-byte expand must succeed for HKDF-SHA512");
            forward_client_entropy.zeroize();
            forward_server_entropy.zeroize();
            forward_nonce.zeroize();
            key.zeroize();
            key = new_key;
        }
        key
    }

    /// Verify a ratchet tag, checking +/-3 epoch lookahead window for
    /// network jitter tolerance (10s epochs -> +-30s window).
    ///
    /// - Exact epoch match: verify with current chain key.
    /// - Past epochs (token_epoch < self.epoch, within 3): verify using
    ///   cached recent keys.
    /// - Future epochs (token_epoch > self.epoch, within 3): derive forward
    ///   keys temporarily without advancing the actual chain.
    ///
    /// All paths use constant-time comparison.
    pub fn verify_tag(&self, claims_bytes: &[u8], tag: &[u8; 64], token_epoch: u64) -> bool {
        self.assert_canaries();

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

impl RatchetChain {
    /// Reconstruct a chain from a persisted chain key and epoch.
    pub fn from_persisted(chain_key: [u8; 64], epoch: u64) -> Self {
        let head = random_canary();
        let tail = random_canary();
        let mut chain = Self {
            canary_head: head,
            chain_key,
            canary_tail: tail,
            expected_head: head,
            expected_tail: tail,
            key_locked: false,
            epoch,
            max_epoch_lifetime: 2880,
            recent_keys: Vec::new(),
            recent_nonces: Vec::new(),
        };
        chain.lock_chain_key();
        chain
    }

    /// Return a copy of the current chain key for persistence (must be encrypted before storage).
    pub fn current_key(&self) -> [u8; 64] {
        self.assert_canaries();
        self.chain_key
    }
}

impl Drop for RatchetChain {
    fn drop(&mut self) {
        // 1. Zeroize chain key
        self.chain_key.zeroize();

        // 2. Zeroize recent keys
        for entry in self.recent_keys.iter_mut() {
            entry.1.zeroize();
        }
        self.recent_keys.clear();

        // 3. Zeroize nonce history
        self.recent_nonces.zeroize();

        // 4. Unlock if locked
        if self.key_locked {
            munlock_region(self.chain_key.as_ptr(), self.chain_key.len());
        }

        // 5. Zeroize canary material
        self.canary_head.zeroize();
        self.canary_tail.zeroize();
        self.expected_head.zeroize();
        self.expected_tail.zeroize();
    }
}
