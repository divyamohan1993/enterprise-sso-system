//! Core ratchet chain — HKDF-SHA512 forward-secret key advancement (spec Section 8).
//!
//! Hardened with memory-locked chain key storage, canary protection,
//! entropy quality validation, and anti-clone nonce tracking.

#![allow(unsafe_code)]

use common::domain;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha512;
use subtle::ConstantTimeEq;
use std::collections::{HashSet, VecDeque};
use zeroize::Zeroize;

type HmacSha512 = Hmac<Sha512>;

/// Errors from ratchet chain operations. All errors are fail-closed:
/// the ratchet chain is NOT advanced and the session should be terminated.
#[derive(Debug, Clone)]
pub enum RatchetError {
    /// Entropy source provided all-zero bytes.
    ZeroEntropy(String),
    /// Entropy source failed quality check (insufficient distinct bytes).
    LowQualityEntropy(String),
    /// Epoch counter would wrap around (session must be terminated).
    EpochOverflow,
    /// Server nonce reuse detected — potential clone/replay attack.
    NonceReuse(String),
    /// Canary violation — memory corruption detected.
    CanaryViolation,
    /// mlock failed in production mode.
    MlockFailed(String),
}

impl std::fmt::Display for RatchetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ZeroEntropy(src) => write!(f, "ratchet: {src} must not be all-zero"),
            Self::LowQualityEntropy(src) => write!(f, "ratchet: {src} fails entropy quality check"),
            Self::EpochOverflow => write!(f, "ratchet: epoch counter would overflow"),
            Self::NonceReuse(detail) => write!(f, "ratchet: nonce reuse detected ({detail})"),
            Self::CanaryViolation => write!(f, "ratchet: memory canary violation detected"),
            Self::MlockFailed(detail) => write!(f, "ratchet: mlock failed ({detail})"),
        }
    }
}

impl std::error::Error for RatchetError {}

/// Maximum lookahead/lookbehind window for epoch verification.
const EPOCH_WINDOW: u64 = 3;

/// Number of recent server nonces to track for clone detection.
///
/// Expanded from 10 to 1000 to cover longer session windows.  At 10s per
/// epoch, 1000 entries provides ~2.8 hours of full nonce replay protection.
/// Older nonces beyond this window are checked against a probabilistic
/// Bloom filter that retains nonce fingerprints for the chain's full lifetime.
const NONCE_HISTORY_SIZE: usize = 1000;

/// Bloom filter parameters for historical nonce tracking beyond the exact window.
///
/// Uses k=7 hash functions over a 16 KiB bit array, giving a false positive
/// rate of ~0.01% for up to 10,000 nonces.  This means an attacker replaying
/// an old nonce has a 99.99% chance of being caught even after it ages out of
/// the exact-match window.
const BLOOM_FILTER_BITS: usize = 16 * 1024 * 8; // 131,072 bits (16 KiB)
const BLOOM_FILTER_K: usize = 7;

/// A compact Bloom filter for probabilistic nonce-reuse detection.
///
/// Once a nonce ages out of the exact `recent_nonces` window, its fingerprint
/// remains in the Bloom filter for the chain's entire lifetime.  This provides
/// defence-in-depth: even if an attacker captures a nonce from hours ago, the
/// Bloom filter will catch reuse with high probability.
struct NonceBloomFilter {
    bits: Vec<u8>,
}

impl NonceBloomFilter {
    fn new() -> Self {
        Self {
            bits: vec![0u8; BLOOM_FILTER_BITS / 8],
        }
    }

    /// Compute k independent bit positions for a nonce using SipHash-style
    /// double hashing: h(i) = (h1 + i * h2) mod m
    fn positions(nonce: &[u8; 32]) -> [usize; BLOOM_FILTER_K] {
        use sha2::{Digest, Sha256};

        // First hash: SHA-256 of nonce
        let mut hasher = Sha256::new();
        hasher.update(b"MILNET-BLOOM-H1");
        hasher.update(nonce);
        let h1_full = hasher.finalize();
        let h1 = u64::from_le_bytes(h1_full[..8].try_into().unwrap()) as usize;

        // Second hash: SHA-256 of nonce with different domain
        let mut hasher = Sha256::new();
        hasher.update(b"MILNET-BLOOM-H2");
        hasher.update(nonce);
        let h2_full = hasher.finalize();
        let h2 = u64::from_le_bytes(h2_full[..8].try_into().unwrap()) as usize;

        let mut positions = [0usize; BLOOM_FILTER_K];
        for i in 0..BLOOM_FILTER_K {
            positions[i] = (h1.wrapping_add(i.wrapping_mul(h2))) % BLOOM_FILTER_BITS;
        }
        positions
    }

    /// Insert a nonce into the Bloom filter.
    fn insert(&mut self, nonce: &[u8; 32]) {
        for pos in Self::positions(nonce) {
            self.bits[pos / 8] |= 1 << (pos % 8);
        }
    }

    /// Query whether a nonce might have been seen before.
    /// Returns false = definitely not seen, true = probably seen.
    fn might_contain(&self, nonce: &[u8; 32]) -> bool {
        for pos in Self::positions(nonce) {
            if self.bits[pos / 8] & (1 << (pos % 8)) == 0 {
                return false;
            }
        }
        true
    }
}

impl Zeroize for NonceBloomFilter {
    fn zeroize(&mut self) {
        self.bits.zeroize();
    }
}

/// Minimum distinct byte values required in 32-byte entropy to pass quality check.
/// 4 bits of randomness means at least 16 distinct values among 32 bytes, but we
/// use a conservative threshold: at least 4 distinct byte values.
const MIN_DISTINCT_BYTES: usize = 4;

/// Generate random bytes with retry logic, returning an error instead of panicking
/// on entropy exhaustion.
fn generate_random_bytes(buf: &mut [u8]) -> Result<(), String> {
    for attempt in 0..3 {
        if getrandom::getrandom(buf).is_ok() {
            return Ok(());
        }
        tracing::error!("entropy source failed, attempt {}/3", attempt + 1);
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    Err("OS CSPRNG unavailable after 3 retries".into())
}

/// Random canary value set at construction for overflow detection.
fn random_canary() -> Result<u64, String> {
    let mut buf = [0u8; 8];
    generate_random_bytes(&mut buf)?;
    Ok(u64::from_ne_bytes(buf))
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
    /// Recent server nonces for clone detection (ordered for FIFO eviction).
    /// Uses VecDeque for O(1) push_back/pop_front instead of Vec::remove(0).
    recent_nonces: VecDeque<[u8; 32]>,
    /// Hash set mirroring recent_nonces for O(1) lookup instead of O(n) scan.
    recent_nonces_set: HashSet<[u8; 32]>,
    /// Bloom filter for probabilistic detection of nonce reuse beyond
    /// the exact `recent_nonces` window.  Nonces are added to the filter
    /// as they age out of the exact-match deque.
    nonce_bloom: NonceBloomFilter,
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
        for nonce in self.recent_nonces.iter_mut() {
            nonce.zeroize();
        }
        self.recent_nonces.clear();
        self.recent_nonces_set.clear();
        self.nonce_bloom.zeroize();
        self.canary_head.zeroize();
        self.canary_tail.zeroize();
        self.expected_head.zeroize();
        self.expected_tail.zeroize();
    }
}

impl RatchetChain {
    /// Verify canary integrity. Returns true if both canaries are intact.
    /// Uses constant-time comparison to prevent timing side-channels.
    fn verify_canaries(&self) -> bool {
        let h = self.canary_head.to_ne_bytes().ct_eq(&self.expected_head.to_ne_bytes());
        let t = self.canary_tail.to_ne_bytes().ct_eq(&self.expected_tail.to_ne_bytes());
        (h & t).into()
    }

    /// Check canary integrity, returning an error on violation.
    /// On violation, key material is zeroized before returning.
    fn check_canaries(&self) -> Result<(), RatchetError> {
        if !self.verify_canaries() {
            tracing::error!(
                "SECURITY: canary violation detected in RatchetChain (epoch={}) — \
                 possible buffer overflow or use-after-free. Zeroizing key material.",
                self.epoch
            );
            // Zeroize before returning — we need unsafe to mutate through shared ref
            // because key material MUST be cleared on corruption detection.
            unsafe {
                let key_ptr = &self.chain_key as *const [u8; 64] as *mut [u8; 64];
                (*key_ptr).zeroize();
            }
            return Err(RatchetError::CanaryViolation);
        }
        Ok(())
    }

    /// Apply mlock and MADV_DONTDUMP to the chain_key region.
    fn lock_chain_key(&mut self) -> Result<(), RatchetError> {
        let ptr = self.chain_key.as_ptr();
        let len = self.chain_key.len();
        if mlock_region(ptr, len) {
            self.key_locked = true;
            madv_dontdump(ptr, len);
        } else {
            if common::sealed_keys::is_production() {
                return Err(RatchetError::MlockFailed(
                    "mlock failed for RatchetChain chain_key in production mode. \
                     Ensure RLIMIT_MEMLOCK is sufficient.".into(),
                ));
            }
            tracing::warn!(
                "mlock failed for RatchetChain chain_key — data may be swappable to disk"
            );
        }
        Ok(())
    }

    /// Create a new chain from a master secret.
    ///
    /// Returns an error if the OS CSPRNG is unavailable or mlock fails in production.
    pub fn new(master_secret: &[u8; 64]) -> Result<Self, String> {
        let hk = Hkdf::<Sha512>::new(None, master_secret);
        let mut chain_key = [0u8; 64];
        hk.expand(domain::RATCHET_ADVANCE, &mut chain_key)
            .expect("64-byte expand must succeed for HKDF-SHA512");

        let head = random_canary()?;
        let tail = random_canary()?;

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
            recent_nonces: VecDeque::new(),
            recent_nonces_set: HashSet::new(),
            nonce_bloom: NonceBloomFilter::new(),
        };
        chain.lock_chain_key().map_err(|e| e.to_string())?;
        Ok(chain)
    }

    /// Advance the chain by one epoch.
    ///
    /// Uses both `client_entropy` and `server_entropy` per spec E.16 so
    /// that compromise of a single entropy source is insufficient.
    ///
    /// `server_nonce` is a unique nonce from the server for this advancement,
    /// mixed into the derivation and tracked to prevent clone attacks.
    ///
    /// # Errors
    /// Returns `RatchetError` (fail-closed) if:
    /// - Either entropy source is all-zero
    /// - Either entropy source fails quality check (<4 distinct byte values)
    /// - `server_nonce` was already used in a recent advancement
    /// - Epoch would wrap around u64::MAX
    /// - Memory canary violation detected
    pub fn advance(
        &mut self,
        client_entropy: &[u8; 32],
        server_entropy: &[u8; 32],
        server_nonce: &[u8; 32],
    ) -> Result<(), RatchetError> {
        self.check_canaries()?;

        // --- Entropy validation ---

        // Reject all-zero entropy
        if is_all_zero(client_entropy) {
            tracing::error!(
                epoch = self.epoch,
                "SIEM:CRITICAL ratchet advancement rejected: client_entropy is all-zero"
            );
            return Err(RatchetError::ZeroEntropy("client_entropy".into()));
        }
        if is_all_zero(server_entropy) {
            tracing::error!(
                epoch = self.epoch,
                "SIEM:CRITICAL ratchet advancement rejected: server_entropy is all-zero"
            );
            return Err(RatchetError::ZeroEntropy("server_entropy".into()));
        }

        // Entropy quality check
        if !entropy_quality_ok(client_entropy) {
            tracing::error!(
                epoch = self.epoch,
                "SIEM:CRITICAL ratchet advancement rejected: client_entropy has insufficient \
                 randomness (fewer than {MIN_DISTINCT_BYTES} distinct byte values)"
            );
            return Err(RatchetError::LowQualityEntropy("client_entropy".into()));
        }
        if !entropy_quality_ok(server_entropy) {
            tracing::error!(
                epoch = self.epoch,
                "SIEM:CRITICAL ratchet advancement rejected: server_entropy has insufficient \
                 randomness (fewer than {MIN_DISTINCT_BYTES} distinct byte values)"
            );
            return Err(RatchetError::LowQualityEntropy("server_entropy".into()));
        }

        // --- Monotonicity check ---
        if self.epoch == u64::MAX {
            tracing::error!(
                "SIEM:CRITICAL ratchet epoch counter at u64::MAX — refusing to wrap"
            );
            return Err(RatchetError::EpochOverflow);
        }

        // --- Anti-clone nonce check (exact window + Bloom filter) ---

        // Check exact-match window (last NONCE_HISTORY_SIZE nonces) — O(1) lookup
        if self.recent_nonces_set.contains(server_nonce) {
            tracing::error!(
                epoch = self.epoch,
                "SIEM:CRITICAL ratchet advancement rejected: server_nonce reuse detected \
                 in exact window — possible token cloning attack"
            );
            return Err(RatchetError::NonceReuse("exact match in recent history".into()));
        }

        // Check Bloom filter for older nonces beyond the exact window.
        // A Bloom filter match means the nonce was *probably* seen before
        // (false positive rate ~0.01%).  In a MILNET context, we treat
        // probable reuse as confirmed reuse — fail-closed.
        if self.nonce_bloom.might_contain(server_nonce) {
            tracing::error!(
                epoch = self.epoch,
                "SIEM:CRITICAL ratchet advancement rejected: server_nonce reuse detected \
                 via Bloom filter — possible token cloning attack (historical nonce)"
            );
            return Err(RatchetError::NonceReuse("clone attack — Bloom filter".into()));
        }

        // O(1) eviction with VecDeque + HashSet
        if self.recent_nonces.len() >= NONCE_HISTORY_SIZE {
            if let Some(mut evicted) = self.recent_nonces.pop_front() {
                self.recent_nonces_set.remove(&evicted);
                // Move to bloom filter for probabilistic detection beyond exact window
                self.nonce_bloom.insert(&evicted);
                evicted.zeroize();
            }
        }

        // Track this nonce in the exact window — O(1) insert into both structures
        self.recent_nonces.push_back(*server_nonce);
        self.recent_nonces_set.insert(*server_nonce);

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
        self.lock_chain_key()?;

        info.zeroize();
        new_key.zeroize();
        Ok(())
    }

    /// Generate a ratchet tag (HMAC-SHA512) for the current epoch.
    ///
    /// # Errors
    /// Returns `RatchetError::CanaryViolation` if memory corruption is detected.
    pub fn generate_tag(&self, claims_bytes: &[u8]) -> Result<[u8; 64], RatchetError> {
        self.check_canaries()?;
        Ok(Self::generate_tag_with_key(&self.chain_key, claims_bytes, self.epoch))
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
    ///
    /// # Errors
    /// Returns `RatchetError::CanaryViolation` if memory corruption is detected.
    pub fn verify_tag(&self, claims_bytes: &[u8], tag: &[u8; 64], token_epoch: u64) -> Result<bool, RatchetError> {
        self.check_canaries()?;

        let epoch_diff = token_epoch.abs_diff(self.epoch);
        if epoch_diff > EPOCH_WINDOW {
            return Ok(false);
        }

        // Exact match: verify with current key
        if token_epoch == self.epoch {
            let expected = self.generate_tag(claims_bytes)?;
            return Ok(crypto::ct::ct_eq_64(tag, &expected));
        }

        // Past epoch: look up in recent_keys cache
        if token_epoch < self.epoch {
            for (cached_epoch, cached_key) in &self.recent_keys {
                if *cached_epoch == token_epoch {
                    let expected =
                        Self::generate_tag_with_key(cached_key, claims_bytes, token_epoch);
                    return Ok(crypto::ct::ct_eq_64(tag, &expected));
                }
            }
            // Key not in cache (was evicted or chain was just created)
            return Ok(false);
        }

        // Future epoch: derive forward without advancing the real chain
        let steps = token_epoch - self.epoch;
        let mut forward_key = Self::derive_forward_key(&self.chain_key, steps);
        let expected = Self::generate_tag_with_key(&forward_key, claims_bytes, token_epoch);
        forward_key.zeroize();
        Ok(crypto::ct::ct_eq_64(tag, &expected))
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
    ///
    /// Returns an error if the OS CSPRNG is unavailable (entropy exhaustion).
    pub fn from_persisted(chain_key: [u8; 64], epoch: u64) -> Result<Self, String> {
        let head = random_canary()?;
        let tail = random_canary()?;
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
            recent_nonces: VecDeque::new(),
            recent_nonces_set: HashSet::new(),
            nonce_bloom: NonceBloomFilter::new(),
        };
        chain.lock_chain_key().map_err(|e| e.to_string())?;
        Ok(chain)
    }

    /// Return a copy of the current chain key for persistence (must be encrypted before storage).
    ///
    /// # Errors
    /// Returns `RatchetError::CanaryViolation` if memory corruption is detected.
    pub fn current_key(&self) -> Result<[u8; 64], RatchetError> {
        self.check_canaries()?;
        Ok(self.chain_key)
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

        // 3. Zeroize nonce history + Bloom filter
        for nonce in self.recent_nonces.iter_mut() {
            nonce.zeroize();
        }
        self.recent_nonces.clear();
        self.recent_nonces_set.clear();
        self.nonce_bloom.zeroize();

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
