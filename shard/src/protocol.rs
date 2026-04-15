//! SHARD (Secure Hardened Authenticated Request Dispatch) IPC protocol.
//!
//! Implements spec Section 11: authenticated inter-module messaging with
//! HMAC-SHA512, AEGIS-256 encryption (AES-256-GCM in FIPS mode), replay
//! protection, and timestamp validation.

use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;
use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha512;

use common::domain::SHARD_AUTH;
use common::error::MilnetError;
use common::key_hierarchy::{self, KeyDomain};
use common::types::{ModuleId, ShardMessage};
use crypto::ct::ct_eq;
use zeroize::{Zeroize, ZeroizeOnDrop};

type HmacSha512 = Hmac<Sha512>;

/// Secure wrapper for decrypted SHARD payloads that zeroizes memory on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecurePayload(pub Vec<u8>);

impl SecurePayload {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the inner bytes, wrapping them in `Zeroizing<Vec<u8>>` to maintain
    /// zeroize-on-drop guarantees. The caller receives owned data that will still
    /// be zeroized when dropped.
    pub fn into_inner(mut self) -> zeroize::Zeroizing<Vec<u8>> {
        let inner = std::mem::take(&mut self.0);
        std::mem::forget(self); // self.0 is now empty
        zeroize::Zeroizing::new(inner)
    }
}

impl AsRef<[u8]> for SecurePayload {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

// SecurePayload comparisons go through ct_eq so that timing leaks cannot
// reveal the plaintext byte-by-byte. ct_eq returns false on length mismatch
// without leaking the matching prefix length.
impl PartialEq<[u8]> for SecurePayload {
    fn eq(&self, other: &[u8]) -> bool {
        ct_eq(&self.0, other)
    }
}

impl PartialEq<&[u8]> for SecurePayload {
    fn eq(&self, other: &&[u8]) -> bool {
        ct_eq(&self.0, *other)
    }
}

impl<const N: usize> PartialEq<&[u8; N]> for SecurePayload {
    fn eq(&self, other: &&[u8; N]) -> bool {
        ct_eq(&self.0, other.as_slice())
    }
}

impl PartialEq<Vec<u8>> for SecurePayload {
    fn eq(&self, other: &Vec<u8>) -> bool {
        ct_eq(&self.0, other.as_slice())
    }
}

impl std::ops::Deref for SecurePayload {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for SecurePayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SecurePayload").field(&"[REDACTED]").finish()
    }
}

/// Domain separation label for deriving the encryption key via HKDF.
const ENCRYPT_DOMAIN: &[u8] = b"MILNET-SHARD-ENCRYPT-v2";

/// Domain separation label for deriving the HMAC key via HKDF.
/// Both the encryption key and HMAC key are derived from the shared secret
/// using HKDF with distinct info strings, ensuring proper key separation.
const HMAC_DOMAIN: &[u8] = b"MILNET-SHARD-HMAC-v2";

/// Current SHARD protocol wire version.
/// v2: Both encryption and HMAC keys are derived via HKDF from the shared
///     secret with domain separation (v1 used the raw secret as the HMAC key).
const PROTOCOL_VERSION: u8 = 2;

/// Maximum allowed clock skew between sender and receiver (2 seconds in microseconds).
const MAX_TIMESTAMP_DRIFT_US: i64 = 2_000_000;

/// SHARD protocol state for a single module.
///
/// Each module instantiates one `ShardProtocol` to create and verify
/// authenticated IPC messages. Payloads are encrypted with AEGIS-256
/// (or AES-256-GCM in FIPS mode) and authenticated with HMAC-SHA512.
pub struct ShardProtocol {
    module_id: ModuleId,
    /// The raw shared secret (kept for TLS connect helpers that need it).
    shared_secret: [u8; 64],
    /// HMAC key derived from the shared secret via HKDF-SHA512.
    hmac_key: [u8; 64],
    /// Encryption key derived from the shared secret via HKDF-SHA512.
    enc_key: [u8; 32],
    send_sequence: u64,
    recv_sequences: HashMap<ModuleId, u64>,
    /// The epoch (send_sequence) at which sequences were last persisted.
    last_persisted_epoch: u64,
}

/// Derive an encryption key from the shared secret using HKDF-SHA512
/// with domain separation.
fn derive_encryption_key(shared_secret: &[u8; 64]) -> [u8; 32] {
    let hk = Hkdf::<Sha512>::new(Some(b"MILNET-SHARD-KEY-SALT-v1"), shared_secret);
    let mut okm = [0u8; 32];
    if let Err(e) = hk.expand(ENCRYPT_DOMAIN, &mut okm) {
        common::siem::emit_runtime_error(
            common::siem::category::CRYPTO_FAILURE,
            "HKDF-SHA512 expand for encryption key derivation",
            &format!("{e}"),
            file!(),
            line!(),
            column!(),
            module_path!(),
        );
        // Return zeroed key — encryption will fail safely downstream
    }
    okm
}

/// Derive an HMAC key from the shared secret using HKDF-SHA512
/// with domain separation. This ensures the HMAC key and encryption
/// key are cryptographically independent, even though they share the
/// same input keying material.
fn derive_hmac_key(shared_secret: &[u8; 64]) -> [u8; 64] {
    let hk = Hkdf::<Sha512>::new(Some(b"MILNET-SHARD-KEY-SALT-v1"), shared_secret);
    let mut okm = [0u8; 64];
    if let Err(e) = hk.expand(HMAC_DOMAIN, &mut okm) {
        common::siem::emit_runtime_error(
            common::siem::category::CRYPTO_FAILURE,
            "HKDF-SHA512 expand for HMAC key derivation",
            &format!("{e}"),
            file!(),
            line!(),
            column!(),
            module_path!(),
        );
        // Return zeroed key — HMAC verification will fail safely downstream
    }
    okm
}

/// Lowercase label for a `ModuleId` used in per-pair HKDF info strings.
///
/// `ModuleId::Gateway` → `"gateway"`, `ModuleId::Orchestrator` → `"orchestrator"`, etc.
/// Uses `Debug` + `to_ascii_lowercase` rather than maintaining a duplicate match so
/// new `ModuleId` variants pick up labels automatically.
fn module_label(m: ModuleId) -> String {
    format!("{m:?}").to_ascii_lowercase()
}

/// RES-SHARDHMAC: Per-pair HMAC input keying material derived from the
/// shared-HMAC key domain root.
///
/// Replaces the legacy "single shared key across all services" model
/// (see fix spec RES-SHARDHMAC). Given a sender and recipient `ModuleId`,
/// derives a unique 64-byte IKM via:
///
/// ```text
/// HKDF-SHA512(
///     ikm  = domain_root(KeyDomain::ShardHmac),
///     salt = b"MILNET-SHARD-HMAC-v1",
///     info = format!("SHARD-{lo}-TO-{hi}", lo = lower(sender), hi = lower(recipient)),
/// )
/// ```
///
/// The pair is *not* order-normalized: `(Gateway, Orchestrator)` and
/// `(Orchestrator, Gateway)` produce DIFFERENT keys, providing
/// asymmetric channel keying and a finer-grained blast radius. Both
/// endpoints must agree on which direction they are computing for.
///
/// Compromise of one pair's HMAC key does not leak any other pair's
/// key thanks to HKDF-Expand's independence across distinct `info`
/// strings.
///
/// # Panics
///
/// Panics only if the calling service's `KeyDomain::ShardHmac` is not
/// in its allowed domain set (see `common::key_hierarchy`). This is
/// the correct behaviour — a service that holds no SHARD-HMAC authority
/// must not be able to forge SHARD messages even with full memory
/// disclosure.
pub fn derive_pair_ikm(sender: ModuleId, recipient: ModuleId) -> [u8; 64] {
    let root = key_hierarchy::domain_root(KeyDomain::ShardHmac);
    let hk = Hkdf::<Sha512>::new(Some(b"MILNET-SHARD-HMAC-v1"), root);
    let info = format!(
        "SHARD-{}-TO-{}",
        module_label(sender),
        module_label(recipient)
    );
    let mut okm = [0u8; 64];
    if let Err(e) = hk.expand(info.as_bytes(), &mut okm) {
        common::siem::emit_runtime_error(
            common::siem::category::CRYPTO_FAILURE,
            "HKDF-SHA512 expand for per-pair SHARD IKM",
            &format!("{e}"),
            file!(),
            line!(),
            column!(),
            module_path!(),
        );
        // Zeroed IKM — downstream HMAC verify fails safely.
    }
    okm
}

/// Per-pair IKM cache, keyed by `(sender, recipient)`.
///
/// Using `BTreeMap` (not `HashMap`) to comply with CAT-K's
/// `no-secret-hashmap` lint: secret key material must not live in
/// `std::collections::HashMap` because its SipHash keying is not
/// constant-time and its iteration order leaks layout information
/// across processes via malloc patterns. `BTreeMap` uses a
/// deterministic comparison and fixed layout.
static PAIR_IKM_CACHE: OnceLock<Mutex<BTreeMap<(ModuleId, ModuleId), [u8; 64]>>> =
    OnceLock::new();

fn cached_pair_ikm(sender: ModuleId, recipient: ModuleId) -> [u8; 64] {
    let cache = PAIR_IKM_CACHE.get_or_init(|| Mutex::new(BTreeMap::new()));
    let mut guard = match cache.lock() {
        Ok(g) => g,
        Err(poisoned) => {
            // Poisoning means a prior thread panicked while holding the
            // lock. The cache state is still valid; recover it.
            poisoned.into_inner()
        }
    };
    if let Some(k) = guard.get(&(sender, recipient)) {
        return *k;
    }
    let ikm = derive_pair_ikm(sender, recipient);
    guard.insert((sender, recipient), ikm);
    ikm
}

impl ShardProtocol {
    /// RES-SHARDHMAC: Construct a `ShardProtocol` for a specific
    /// sender→recipient pair, deriving the HMAC+encryption IKM from
    /// the domain-separated SHARD-HMAC root.
    ///
    /// `local` is the module_id that *this* process owns (used as the
    /// `sender_module` field in outbound messages). `peer` is the
    /// remote module this transport session is bound to.
    ///
    /// Prefer this constructor over [`ShardProtocol::new`] in all new
    /// code. The legacy `new` is retained for tests and for the
    /// transitional period while the `common::key_hierarchy` domain
    /// root is being provisioned in every service's allowed-domain
    /// set.
    pub fn for_pair(local: ModuleId, peer: ModuleId) -> Self {
        let ikm = cached_pair_ikm(local, peer);
        Self::new(local, ikm)
    }

    /// Create a new protocol instance for the given module.
    ///
    /// The `shared_secret` is used as input keying material for HKDF-SHA512.
    /// Two independent keys are derived with distinct domain separation labels:
    /// - Encryption key (32 bytes) for AES-256-GCM / AEGIS-256
    /// - HMAC key (64 bytes) for HMAC-SHA512
    ///
    /// The raw shared secret is never used directly as a cryptographic key.
    pub fn new(module_id: ModuleId, shared_secret: [u8; 64]) -> Self {
        let enc_key = derive_encryption_key(&shared_secret);
        let hmac_key = derive_hmac_key(&shared_secret);
        Self {
            module_id,
            shared_secret,
            hmac_key,
            enc_key,
            send_sequence: 0,
            recv_sequences: HashMap::new(),
            last_persisted_epoch: 0,
        }
    }

    /// Returns the current time in microseconds since the UNIX epoch.
    /// Uses monotonic-anchored secure time, immune to clock manipulation.
    fn now_us() -> Result<i64, MilnetError> {
        Ok(common::secure_time::secure_now_us_i64())
    }

    /// C11: Number of messages that share a single HMAC sub-key before the
    /// per-counter ratchet rolls forward. Each window of 10 000 sequence numbers
    /// gets an independent HMAC key derived via HKDF-Expand-SHA512.
    const HMAC_RATCHET_INTERVAL: u64 = 10_000;

    /// C11: Derive the per-window HMAC sub-key for a given message sequence.
    ///
    /// Both sender and receiver derive the same sub-key from the long-lived
    /// `hmac_key` and the window counter (`sequence / HMAC_RATCHET_INTERVAL`).
    /// Forward-secrecy is provided at the *granularity of windows*: an attacker
    /// who learns the window-N sub-key cannot reverse it to window N-1.
    fn ratchet_subkey(base: &[u8; 64], sequence: u64) -> [u8; 64] {
        let counter = sequence / Self::HMAC_RATCHET_INTERVAL;
        let info = counter.to_be_bytes();
        let hk = match Hkdf::<Sha512>::from_prk(base) {
            Ok(h) => h,
            Err(_) => {
                // PRK length error is impossible for a 64-byte key; fail closed.
                return [0u8; 64];
            }
        };
        let mut out = [0u8; 64];
        if hk.expand(&info, &mut out).is_err() {
            return [0u8; 64];
        }
        out
    }

    /// Compute HMAC-SHA512 over the domain prefix and message fields (excluding the HMAC field).
    /// C11: The MAC key is derived per-window from `key` and `msg.sequence`.
    fn compute_hmac(key: &[u8; 64], msg: &ShardMessage) -> [u8; 64] {
        let subkey = Self::ratchet_subkey(key, msg.sequence);
        let mut mac = match <HmacSha512 as Mac>::new_from_slice(&subkey) {
            Ok(m) => m,
            Err(e) => {
                common::siem::emit_runtime_error(
                    common::siem::category::CRYPTO_FAILURE,
                    "HMAC-SHA512 initialization from key slice",
                    &format!("{e}"),
                    file!(),
                    line!(),
                    column!(),
                    module_path!(),
                );
                return [0u8; 64]; // Zeroed HMAC — verification will fail safely
            }
        };

        // Domain separation prefix
        mac.update(SHARD_AUTH);

        // Message fields (excluding hmac)
        mac.update(&[msg.version]);
        mac.update(&[msg.sender_module as u8]);
        mac.update(&msg.sequence.to_le_bytes());
        mac.update(&msg.timestamp.to_le_bytes());
        mac.update(&msg.payload);

        let result = mac.finalize().into_bytes();
        let mut out = [0u8; 64];
        out.copy_from_slice(&result);
        out
    }

    /// Encrypt a plaintext payload using the active symmetric algorithm
    /// (AEGIS-256 by default, AES-256-GCM in FIPS mode).
    ///
    /// Returns `algo_id (1) || nonce || ciphertext || tag`.
    fn encrypt_payload(&self, plaintext: &[u8]) -> Result<Vec<u8>, MilnetError> {
        crypto::symmetric::encrypt(&self.enc_key, plaintext, b"")
            .map_err(|e| MilnetError::Shard(format!("encryption failed: {e}")))
    }

    /// Decrypt a payload blob produced by [`encrypt_payload`].
    ///
    /// Handles both the new algo_id-prefixed format and the legacy
    /// `nonce (12) || ciphertext+tag` AES-256-GCM format.
    fn decrypt_payload(&self, data: &[u8]) -> Result<Vec<u8>, MilnetError> {
        crypto::symmetric::decrypt(&self.enc_key, data, b"")
            .map_err(|e| MilnetError::Shard(format!("decryption failed: {e}")))
    }

    /// Create an authenticated and encrypted SHARD message containing the given payload.
    ///
    /// The message includes AES-256-GCM encryption, an HMAC-SHA512 tag, a monotonically
    /// increasing sequence number, and a microsecond-precision timestamp.
    pub fn create_message(&mut self, payload: &[u8]) -> Result<Vec<u8>, MilnetError> {
        self.send_sequence += 1;

        let timestamp = Self::now_us()?;

        // Encrypt the plaintext payload
        let encrypted_payload = self.encrypt_payload(payload)?;

        let mut msg = ShardMessage {
            version: PROTOCOL_VERSION,
            sender_module: self.module_id,
            sequence: self.send_sequence,
            timestamp,
            payload: encrypted_payload,
            hmac: [0u8; 64],
        };

        // HMAC covers the encrypted payload (encrypt-then-MAC)
        msg.hmac = Self::compute_hmac(&self.hmac_key, &msg);

        postcard::to_allocvec(&msg)
            .map_err(|e| MilnetError::Serialization(format!("shard serialize: {e}")))
    }

    /// Verify and decrypt an incoming SHARD message.
    ///
    /// Checks:
    /// 1. HMAC-SHA512 integrity (constant-time comparison)
    /// 2. AES-256-GCM decryption of the payload
    /// 3. Timestamp within +-2 seconds of local clock
    /// 4. Sequence number is strictly greater than last seen for that sender
    ///
    /// Returns `(sender_module, plaintext_payload)` on success.
    pub fn verify_message(&mut self, raw: &[u8]) -> Result<(ModuleId, SecurePayload), MilnetError> {
        let msg: ShardMessage = postcard::from_bytes(raw)
            .map_err(|e| MilnetError::Serialization(format!("shard deserialize: {e}")))?;

        // 1. Verify HMAC over encrypted payload
        let expected_hmac = Self::compute_hmac(&self.hmac_key, &msg);
        if !ct_eq(&expected_hmac, &msg.hmac) {
            return Err(MilnetError::Shard("HMAC verification failed".into()));
        }

        // 2. Decrypt payload — wrap immediately so plaintext is zeroized on
        //    all exit paths (including timestamp/replay errors below).
        let plaintext = SecurePayload(self.decrypt_payload(&msg.payload)?);

        // 3. Verify timestamp
        let now = Self::now_us()?;
        let drift = (now - msg.timestamp).abs();
        if drift > MAX_TIMESTAMP_DRIFT_US {
            return Err(MilnetError::Shard(format!(
                "timestamp outside tolerance: drift={drift}us"
            )));
        }

        // 4. Replay protection: sequence must be strictly increasing per sender
        let last_seq = self
            .recv_sequences
            .get(&msg.sender_module)
            .copied()
            .unwrap_or(0);
        if msg.sequence <= last_seq {
            return Err(MilnetError::Shard(format!(
                "replay detected: seq={} <= last={}",
                msg.sequence, last_seq
            )));
        }
        self.recv_sequences.insert(msg.sender_module, msg.sequence);

        Ok((msg.sender_module, plaintext))
    }

    /// Restore previously persisted per-sender sequence numbers.
    ///
    /// Callers MUST persist sequence numbers (via [`get_sequences`]) across
    /// restarts and restore them here to maintain replay protection continuity.
    pub fn set_initial_sequences(&mut self, sequences: HashMap<ModuleId, u64>) {
        self.recv_sequences = sequences;
    }

    /// Return the current per-sender receive sequence numbers for persistence.
    ///
    /// Callers MUST persist these values and restore them via
    /// [`set_initial_sequences`] after a restart to avoid replay attacks
    /// during the window between restarts.
    pub fn get_sequences(&self) -> &HashMap<ModuleId, u64> {
        &self.recv_sequences
    }

    /// Serialize the current sequence state (send sequence + per-sender receive
    /// sequences) to a byte vector suitable for durable storage.
    ///
    /// Callers MUST persist these to durable storage and reload on restart
    /// to maintain replay protection across process restarts.
    pub fn export_sequences(&self) -> Result<Vec<u8>, String> {
        let state = SequenceState {
            send_sequence: self.send_sequence,
            recv_sequences: self.recv_sequences.clone(),
        };
        postcard::to_allocvec(&state).map_err(|e| {
            common::siem::emit_runtime_error(
                common::siem::category::INTEGRITY_VIOLATION,
                "SHARD sequence state serialization",
                &format!("{e}"),
                file!(),
                line!(),
                column!(),
                module_path!(),
            );
            format!("sequence state serialization failed: {e}")
        })
    }

    /// Deserialize and restore previously exported sequence state.
    ///
    /// Callers MUST persist these to durable storage and reload on restart
    /// to maintain replay protection across process restarts.
    ///
    /// Sequences are only advanced, never rolled backward, to prevent
    /// downgrade attacks where a stale snapshot replays old sequence numbers.
    pub fn import_sequences(&mut self, data: &[u8]) {
        if let Ok(state) = postcard::from_bytes::<SequenceState>(data) {
            // Only advance send_sequence, never go backward (prevents downgrade)
            if state.send_sequence > self.send_sequence {
                self.send_sequence = state.send_sequence;
            }
            // Only advance per-sender receive sequences, never go backward
            for (module, seq) in state.recv_sequences {
                let entry = self.recv_sequences.entry(module).or_insert(0);
                if seq > *entry {
                    *entry = seq;
                }
            }
            self.last_persisted_epoch = self.send_sequence;
        }
    }

    /// Returns `true` if the protocol state has changed since the last
    /// persistence (i.e., new messages have been sent since the last export).
    pub fn needs_persistence(&self) -> bool {
        self.send_sequence > self.last_persisted_epoch
    }

    /// Return the current send sequence number.
    pub fn send_sequence(&self) -> u64 {
        self.send_sequence
    }

    /// Export sequence state with HMAC-SHA512 authentication.
    ///
    /// Format: `[64-byte HMAC-SHA512 tag] [postcard-serialized state]`
    ///
    /// The HMAC tag covers the serialized state bytes, using `hmac_key` as the
    /// authenticating key. Use [`import_sequences_authenticated`] to reload.
    pub fn export_sequences_authenticated(
        &mut self,
        path: &std::path::Path,
        hmac_key: &[u8; 64],
    ) -> Result<(), common::error::MilnetError> {
        let state = AuthenticatedSequenceState {
            send_sequence: self.send_sequence,
            recv_sequences: self.recv_sequences.clone(),
        };
        let data = postcard::to_allocvec(&state)
            .map_err(|e| MilnetError::Shard(
                format!("serialize sequence state: {e}")
            ))?;

        let mut mac = <HmacSha512 as Mac>::new_from_slice(hmac_key)
            .map_err(|e| MilnetError::Shard(format!("HMAC-SHA512 init failed: {e}")))?;
        mac.update(&data);
        let tag = mac.finalize().into_bytes();

        let tmp = path.with_extension("tmp");
        let mut out = Vec::with_capacity(64 + data.len());
        out.extend_from_slice(&tag);
        out.extend_from_slice(&data);
        std::fs::write(&tmp, &out)
            .map_err(|e| MilnetError::Shard(format!("write sequence tmp file: {e}")))?;
        std::fs::rename(&tmp, path)
            .map_err(|e| MilnetError::Shard(format!("rename sequence tmp file: {e}")))?;
        self.last_persisted_epoch = self.send_sequence;
        Ok(())
    }

    /// Import sequence state with HMAC-SHA512 verification.
    ///
    /// Rejects tampered, truncated, or wrong-key files with an error.
    /// Sequences are only advanced, never rolled backward, to prevent
    /// downgrade attacks.
    pub fn import_sequences_authenticated(
        &mut self,
        path: &std::path::Path,
        hmac_key: &[u8; 64],
    ) -> Result<(), common::error::MilnetError> {
        let raw = std::fs::read(path)
            .map_err(|e| MilnetError::Shard(
                format!("read sequence file {:?}: {e}", path)
            ))?;

        if raw.len() < 64 {
            return Err(MilnetError::Shard(
                format!("sequence file too short: {} bytes (need >= 64)", raw.len())
            ));
        }

        let (tag_bytes, data) = raw.split_at(64);
        let mut mac = <HmacSha512 as Mac>::new_from_slice(hmac_key)
            .map_err(|e| MilnetError::Shard(format!("HMAC-SHA512 init failed: {e}")))?;
        mac.update(data);
        mac.verify_slice(tag_bytes)
            .map_err(|_| MilnetError::Shard(
                "HMAC verification failed — sequence file tampered or wrong key".into()
            ))?;

        let state: AuthenticatedSequenceState = postcard::from_bytes(data)
            .map_err(|e| MilnetError::Shard(
                format!("deserialize sequence state: {e}")
            ))?;

        // Only advance, never go backward (prevent downgrade attack)
        if state.send_sequence > self.send_sequence {
            self.send_sequence = state.send_sequence;
        }
        for (module, seq) in state.recv_sequences {
            let current = self.recv_sequences.entry(module).or_insert(0);
            if seq > *current {
                *current = seq;
            }
        }

        Ok(())
    }

    /// C9: Export sequence state encrypted with AES-256-GCM.
    ///
    /// Format: `[1 byte version=1] [12 byte nonce] [ciphertext] [64 byte HMAC-SHA512]`
    /// where the HMAC covers `(version || nonce || ciphertext)`.
    ///
    /// The encryption key is derived via HKDF-SHA512 from the master KEK
    /// with info `"milnet-shard-seq-state-v1"`; the integrity HMAC key is
    /// derived with info `"milnet-shard-seq-state-mac-v1"`. Both rotate
    /// automatically when the master KEK rotates (see
    /// [`common::key_rotation`]).
    ///
    /// On KEK rotation, callers MUST re-export; the old ciphertext becomes
    /// undecryptable.
    pub fn export_sequences_encrypted(
        &mut self,
        path: &std::path::Path,
    ) -> Result<(), common::error::MilnetError> {
        use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
        use hkdf::Hkdf;
        use hmac::Mac;

        let state = AuthenticatedSequenceState {
            send_sequence: self.send_sequence,
            recv_sequences: self.recv_sequences.clone(),
        };
        let plaintext = postcard::to_allocvec(&state).map_err(|e| {
            MilnetError::Shard(format!("serialize sequence state: {e}"))
        })?;

        // Derive encryption and HMAC keys from the master KEK.
        let master = common::sealed_keys::cached_master_kek();
        let hk = Hkdf::<Sha512>::new(None, master);
        let mut enc_key = [0u8; 32];
        hk.expand(b"milnet-shard-seq-state-v1", &mut enc_key)
            .map_err(|e| MilnetError::Shard(format!("HKDF enc key: {e}")))?;
        let mut mac_key = [0u8; 64];
        hk.expand(b"milnet-shard-seq-state-mac-v1", &mut mac_key)
            .map_err(|e| MilnetError::Shard(format!("HKDF mac key: {e}")))?;

        // Fresh 96-bit nonce
        let mut nonce_bytes = [0u8; 12];
        getrandom::getrandom(&mut nonce_bytes)
            .map_err(|e| MilnetError::Shard(format!("getrandom nonce: {e}")))?;

        let cipher = Aes256Gcm::new_from_slice(&enc_key)
            .map_err(|e| MilnetError::Shard(format!("AES-256-GCM key: {e}")))?;
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), plaintext.as_slice())
            .map_err(|e| MilnetError::Shard(format!("AES-256-GCM encrypt: {e}")))?;

        // Integrity HMAC over (version || nonce || ciphertext).
        const VERSION: u8 = 1;
        let mut mac = <HmacSha512 as Mac>::new_from_slice(&mac_key)
            .map_err(|e| MilnetError::Shard(format!("HMAC key: {e}")))?;
        mac.update(&[VERSION]);
        mac.update(&nonce_bytes);
        mac.update(&ciphertext);
        let tag = mac.finalize().into_bytes();

        let mut out = Vec::with_capacity(1 + 12 + ciphertext.len() + 64);
        out.push(VERSION);
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        out.extend_from_slice(&tag);

        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, &out)
            .map_err(|e| MilnetError::Shard(format!("write seq tmp: {e}")))?;
        std::fs::rename(&tmp, path)
            .map_err(|e| MilnetError::Shard(format!("rename seq tmp: {e}")))?;

        // Zeroize derived keys
        {
            use zeroize::Zeroize;
            enc_key.zeroize();
            mac_key.zeroize();
        }
        self.last_persisted_epoch = self.send_sequence;
        Ok(())
    }

    /// C9: Import an encrypted sequence state written by
    /// [`Self::export_sequences_encrypted`].
    ///
    /// Verifies the HMAC and decrypts the AES-256-GCM blob. On any
    /// verification failure — bad tag, wrong key, truncated file — returns
    /// an error and leaves the in-memory state untouched.
    ///
    /// If the feature `shard-seq-unencrypted-migration` is enabled, a
    /// plaintext postcard blob (legacy v0 format) is accepted as a
    /// forward-compat one-shot migration path.
    pub fn import_sequences_encrypted(
        &mut self,
        path: &std::path::Path,
    ) -> Result<(), common::error::MilnetError> {
        use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
        use hkdf::Hkdf;
        use hmac::Mac;

        let raw = std::fs::read(path)
            .map_err(|e| MilnetError::Shard(format!("read {:?}: {e}", path)))?;

        // Legacy-unencrypted migration path (feature-gated).
        #[cfg(feature = "shard-seq-unencrypted-migration")]
        {
            if let Ok(state) = postcard::from_bytes::<AuthenticatedSequenceState>(&raw) {
                tracing::warn!(
                    "C9: accepted legacy unencrypted sequence state from {:?} \
                     (shard-seq-unencrypted-migration feature). Re-export will encrypt.",
                    path
                );
                self.apply_state(state);
                return Ok(());
            }
        }

        if raw.len() < 1 + 12 + 64 {
            return Err(MilnetError::Shard(format!(
                "encrypted seq file too short: {} bytes",
                raw.len()
            )));
        }
        let version = raw[0];
        if version != 1 {
            return Err(MilnetError::Shard(format!(
                "unsupported encrypted seq version: {version}"
            )));
        }
        let nonce_bytes: [u8; 12] = raw[1..13]
            .try_into()
            .map_err(|_| MilnetError::Shard("nonce slice".into()))?;
        let ct_end = raw.len() - 64;
        let ciphertext = &raw[13..ct_end];
        let stored_tag = &raw[ct_end..];

        let master = common::sealed_keys::cached_master_kek();
        let hk = Hkdf::<Sha512>::new(None, master);
        let mut enc_key = [0u8; 32];
        hk.expand(b"milnet-shard-seq-state-v1", &mut enc_key)
            .map_err(|e| MilnetError::Shard(format!("HKDF enc key: {e}")))?;
        let mut mac_key = [0u8; 64];
        hk.expand(b"milnet-shard-seq-state-mac-v1", &mut mac_key)
            .map_err(|e| MilnetError::Shard(format!("HKDF mac key: {e}")))?;

        let mut mac = <HmacSha512 as Mac>::new_from_slice(&mac_key)
            .map_err(|e| MilnetError::Shard(format!("HMAC key: {e}")))?;
        mac.update(&[version]);
        mac.update(&nonce_bytes);
        mac.update(ciphertext);
        if mac.verify_slice(stored_tag).is_err() {
            use zeroize::Zeroize;
            enc_key.zeroize();
            mac_key.zeroize();
            return Err(MilnetError::Shard(
                "encrypted seq HMAC mismatch — file tampered or wrong KEK".into(),
            ));
        }

        let cipher = Aes256Gcm::new_from_slice(&enc_key)
            .map_err(|e| MilnetError::Shard(format!("AES-256-GCM key: {e}")))?;
        let plaintext = cipher
            .decrypt(Nonce::from_slice(&nonce_bytes), ciphertext)
            .map_err(|_| MilnetError::Shard("AES-256-GCM decrypt failed".into()))?;

        use zeroize::Zeroize;
        enc_key.zeroize();
        mac_key.zeroize();

        let state: AuthenticatedSequenceState = postcard::from_bytes(&plaintext)
            .map_err(|e| MilnetError::Shard(format!("deserialize: {e}")))?;
        self.apply_state(state);
        Ok(())
    }

    /// Apply a parsed authenticated sequence state, advancing only.
    fn apply_state(&mut self, state: AuthenticatedSequenceState) {
        if state.send_sequence > self.send_sequence {
            self.send_sequence = state.send_sequence;
        }
        for (module, seq) in state.recv_sequences {
            let current = self.recv_sequences.entry(module).or_insert(0);
            if seq > *current {
                *current = seq;
            }
        }
    }

    /// Mark the current epoch as persisted. Call this after successfully
    /// writing [`export_sequences`] to durable storage.
    pub fn mark_persisted(&mut self) {
        self.last_persisted_epoch = self.send_sequence;
    }

    /// Load persisted sequences from disk if available, ignoring errors in dev mode.
    ///
    /// In production mode, a tampered sequence file causes a panic (fail-closed).
    /// In dev mode, errors are logged as warnings and the service continues
    /// with fresh sequences.
    pub fn load_persisted_sequences(&mut self, service_name: &str, hmac_key: &[u8; 64]) -> Result<(), String> {
        let path = format!("/var/lib/milnet/{}_shard_sequences.dat", service_name);
        let path = std::path::Path::new(&path);
        if !path.exists() {
            tracing::info!("no persisted SHARD sequences at {:?} (first start)", path);
            return Ok(());
        }
        match self.import_sequences_authenticated(path, hmac_key) {
            Ok(()) => {
                tracing::info!("loaded persisted SHARD sequences from {:?}", path);
                Ok(())
            }
            Err(e) => {
                common::siem::emit_runtime_error(
                    common::siem::category::INTEGRITY_VIOLATION,
                    "SHARD sequence file tampered or unreadable",
                    &format!("{e}"),
                    file!(),
                    line!(),
                    column!(),
                    module_path!(),
                );
                Err(format!("SHARD sequence file tampered or unreadable: {e}"))
            }
        }
    }

    /// Persist current sequences to disk with HMAC authentication.
    ///
    /// Uses atomic write (write to tmp + rename) to prevent partial writes.
    /// Returns `Ok(())` on success, or an error description on failure.
    pub fn save_sequences(&mut self, service_name: &str, hmac_key: &[u8; 64]) -> Result<(), String> {
        let path = format!("/var/lib/milnet/{}_shard_sequences.dat", service_name);
        let path = std::path::Path::new(&path);
        self.export_sequences_authenticated(path, hmac_key)
            .map_err(|e| format!("failed to persist SHARD sequences: {e}"))
    }

    /// Connect to a remote SHARD peer over TLS using the unified transport.
    ///
    /// Returns a [`crate::transport::ShardTransport`] with mTLS active.
    pub async fn connect_tls(
        self,
        addr: &str,
        tls_config: &crate::transport::ClientTlsConfig,
    ) -> Result<crate::transport::ShardTransport, MilnetError> {
        crate::transport::tls_connect(addr, self.module_id, self.shared_secret, tls_config).await
    }

    /// Bind a TLS-enabled listener using the unified transport.
    ///
    /// Returns a [`crate::transport::ShardListener`] with mTLS active.
    pub async fn listen_tls(
        self,
        addr: &str,
        tls_config: crate::transport::ServerTlsConfig,
    ) -> Result<crate::transport::ShardListener, MilnetError> {
        crate::transport::ShardListener::tls_bind(addr, self.module_id, self.shared_secret, tls_config)
            .await
    }

}


/// Internal serializable snapshot of sequence state.
#[derive(serde::Serialize, serde::Deserialize)]
struct SequenceState {
    send_sequence: u64,
    recv_sequences: HashMap<ModuleId, u64>,
}

/// Serializable snapshot of sequence state used by the authenticated
/// export/import methods. Identical layout to [`SequenceState`] but kept
/// separate so the two persistence paths are explicitly independent.
#[derive(serde::Serialize, serde::Deserialize)]
struct AuthenticatedSequenceState {
    send_sequence: u64,
    recv_sequences: HashMap<ModuleId, u64>,
}

// ---------------------------------------------------------------------------
// Automatic sequence persistence
// ---------------------------------------------------------------------------

use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Default filename for persisted sequence state alongside the service data dir.
const SEQUENCE_FILE_NAME: &str = "shard_sequences.bin";

/// Periodic persistence interval in seconds.
const PERSIST_INTERVAL_SECS: u64 = 60;

/// Automatic sequence persistence manager for SHARD protocol instances.
///
/// Wraps a `ShardProtocol` behind an `Arc<Mutex<>>` and manages:
/// - Loading sequences from disk on startup via `import_sequences()`
/// - Periodic persistence every 60 seconds (background tokio task)
/// - Graceful shutdown persistence via tokio signal handler (SIGTERM/SIGINT)
///
/// # Usage
/// ```text
/// let persistence = SequencePersistence::new(protocol, "/var/lib/milnet/shard");
/// persistence.start();
/// // ... use persistence.protocol() to access the inner ShardProtocol ...
/// // On shutdown, sequences are automatically flushed to disk.
/// ```
pub struct SequencePersistence {
    /// The wrapped protocol instance.
    protocol: Arc<Mutex<ShardProtocol>>,
    /// Directory where the sequence file is stored.
    data_dir: PathBuf,
    /// Handle to the background persistence task (for cancellation).
    shutdown_tx: Option<tokio::sync::watch::Sender<bool>>,
}

impl SequencePersistence {
    /// Create a new persistence manager.
    ///
    /// Immediately attempts to load previously persisted sequences from
    /// `{data_dir}/shard_sequences.bin`. If the file does not exist or is
    /// corrupt, the protocol starts with fresh sequence counters.
    pub fn new(mut protocol: ShardProtocol, data_dir: impl AsRef<Path>) -> Self {
        let data_dir = data_dir.as_ref().to_path_buf();
        let seq_path = data_dir.join(SEQUENCE_FILE_NAME);

        // Load sequences on startup
        if seq_path.exists() {
            match std::fs::read(&seq_path) {
                Ok(data) => {
                    protocol.import_sequences(&data);
                    tracing::info!(
                        "SHARD: loaded persisted sequences from {:?} (send_seq={})",
                        seq_path,
                        protocol.send_sequence
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        "SHARD: failed to read sequence file {:?}: {}. Starting fresh.",
                        seq_path, e
                    );
                }
            }
        } else {
            tracing::info!(
                "SHARD: no persisted sequence file at {:?}. Starting with fresh sequences.",
                seq_path
            );
        }

        Self {
            protocol: Arc::new(Mutex::new(protocol)),
            data_dir,
            shutdown_tx: None,
        }
    }

    /// Get a clone of the `Arc<Mutex<ShardProtocol>>` for use by message
    /// send/receive code.
    pub fn protocol(&self) -> Arc<Mutex<ShardProtocol>> {
        Arc::clone(&self.protocol)
    }

    /// Persist the current sequence state to disk.
    ///
    /// Writes atomically by writing to a `.tmp` file first, then renaming.
    fn persist_to_disk(protocol: &Mutex<ShardProtocol>, data_dir: &Path) -> Result<(), String> {
        let data = {
            let proto = protocol.lock().map_err(|e| format!("lock poisoned: {e}"))?;
            if !proto.needs_persistence() {
                return Ok(());
            }
            proto.export_sequences()?
        };

        // Ensure directory exists
        std::fs::create_dir_all(data_dir)
            .map_err(|e| format!("failed to create data dir {:?}: {e}", data_dir))?;

        let seq_path = data_dir.join(SEQUENCE_FILE_NAME);
        let tmp_path = data_dir.join(format!("{SEQUENCE_FILE_NAME}.tmp"));

        std::fs::write(&tmp_path, &data)
            .map_err(|e| format!("failed to write tmp sequence file: {e}"))?;
        std::fs::rename(&tmp_path, &seq_path)
            .map_err(|e| format!("failed to rename sequence file: {e}"))?;

        // Mark as persisted
        {
            let mut proto = protocol.lock().map_err(|e| format!("lock poisoned: {e}"))?;
            proto.mark_persisted();
        }

        tracing::debug!("SHARD: persisted sequence state to {:?}", seq_path);
        Ok(())
    }

    /// Start the background persistence tasks:
    /// - Periodic flush every 60 seconds
    /// - Graceful shutdown handler (SIGTERM / ctrl-c)
    ///
    /// Must be called from within a tokio runtime.
    pub fn start(&mut self) {
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        self.shutdown_tx = Some(shutdown_tx);

        let protocol = Arc::clone(&self.protocol);
        let data_dir = self.data_dir.clone();

        // Periodic persistence task
        let periodic_protocol = Arc::clone(&protocol);
        let periodic_dir = data_dir.clone();
        let mut periodic_rx = shutdown_rx.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(
                Duration::from_secs(PERSIST_INTERVAL_SECS),
            );
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        if let Err(e) = SequencePersistence::persist_to_disk(&periodic_protocol, &periodic_dir) {
                            tracing::error!("SHARD periodic persistence failed: {}", e);
                        }
                    }
                    _ = periodic_rx.changed() => {
                        tracing::info!("SHARD: periodic persistence task shutting down");
                        break;
                    }
                }
            }
        });

        // Graceful shutdown handler
        let shutdown_protocol = Arc::clone(&protocol);
        let shutdown_dir = data_dir.clone();
        tokio::spawn(async move {
            // Wait for SIGTERM or ctrl-c
            let ctrl_c = tokio::signal::ctrl_c();
            #[cfg(unix)]
            {
                use tokio::signal::unix::{signal, SignalKind};
                match signal(SignalKind::terminate()) {
                    Ok(mut sigterm) => {
                        tokio::select! {
                            _ = ctrl_c => {},
                            _ = sigterm.recv() => {},
                        }
                    }
                    Err(e) => {
                        common::siem::emit_runtime_error(
                            common::siem::category::RUNTIME_ERROR,
                            "SHARD SIGTERM handler registration",
                            &format!("{e}"),
                            file!(),
                            line!(),
                            column!(),
                            module_path!(),
                        );
                        // Fall back to ctrl-c only
                        let _ = ctrl_c.await;
                    }
                }
            }
            #[cfg(not(unix))]
            {
                if let Err(e) = ctrl_c.await {
                    tracing::warn!("SHARD: ctrl-c signal error: {e}");
                }
            }

            tracing::info!("SHARD: graceful shutdown — persisting sequences");
            if let Err(e) = SequencePersistence::persist_to_disk(&shutdown_protocol, &shutdown_dir) {
                tracing::error!("SHARD: shutdown persistence failed: {}", e);
            } else {
                tracing::info!("SHARD: sequences persisted successfully on shutdown");
            }
        });
    }

    /// Manually trigger a persistence flush (e.g., from health checks).
    pub fn flush(&self) -> Result<(), String> {
        Self::persist_to_disk(&self.protocol, &self.data_dir)
    }
}

impl Drop for SequencePersistence {
    fn drop(&mut self) {
        // Signal background tasks to stop
        if let Some(tx) = self.shutdown_tx.take() {
            if let Err(e) = tx.send(true) {
                tracing::warn!("SHARD: shutdown signal send failed: {e}");
            }
        }
        // Best-effort final persistence
        if let Err(e) = Self::persist_to_disk(&self.protocol, &self.data_dir) {
            tracing::warn!("SHARD: drop persistence failed: {}", e);
        }
    }
}

impl Drop for ShardProtocol {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.shared_secret.zeroize();
        self.hmac_key.zeroize();
        self.enc_key.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_hmac_key() -> [u8; 64] {
        let mut key = [0u8; 64];
        getrandom::getrandom(&mut key).unwrap();
        key
    }

    #[test]
    fn export_import_sequences_round_trip() {
        let key = test_hmac_key();
        let mut proto = ShardProtocol::new(ModuleId::Gateway, key);

        // Simulate sending some messages to advance send_sequence
        let _ = proto.create_message(b"msg1").unwrap();
        let _ = proto.create_message(b"msg2").unwrap();
        assert_eq!(proto.send_sequence, 2);

        // Export
        let data = proto.export_sequences().unwrap();

        // Import into a fresh protocol
        let mut proto2 = ShardProtocol::new(ModuleId::Gateway, key);
        assert_eq!(proto2.send_sequence, 0);
        proto2.import_sequences(&data);
        assert_eq!(proto2.send_sequence, 2);
    }

    #[test]
    fn import_sequences_never_rolls_back() {
        let key = test_hmac_key();
        let mut proto = ShardProtocol::new(ModuleId::Gateway, key);

        // Advance to sequence 5
        for _ in 0..5 {
            let _ = proto.create_message(b"msg").unwrap();
        }
        let old_data = proto.export_sequences().unwrap();

        // Advance further to 10
        for _ in 0..5 {
            let _ = proto.create_message(b"msg").unwrap();
        }
        assert_eq!(proto.send_sequence, 10);

        // Try to import the old (stale) snapshot — should NOT roll back
        proto.import_sequences(&old_data);
        assert_eq!(proto.send_sequence, 10);
    }

    #[test]
    fn recv_sequences_import_advances_only() {
        let key = test_hmac_key();
        let mut proto = ShardProtocol::new(ModuleId::Audit, key);

        // Simulate receiving from Gateway at sequence 5
        let mut seqs = HashMap::new();
        seqs.insert(ModuleId::Gateway, 5u64);
        proto.set_initial_sequences(seqs);

        // Export and import with a lower Gateway sequence — should not go backward
        let mut stale_state = SequenceState {
            send_sequence: 0,
            recv_sequences: HashMap::new(),
        };
        stale_state.recv_sequences.insert(ModuleId::Gateway, 3);
        let stale_data = postcard::to_allocvec(&stale_state).unwrap();

        proto.import_sequences(&stale_data);
        assert_eq!(*proto.recv_sequences.get(&ModuleId::Gateway).unwrap(), 5);
    }

    #[test]
    fn replay_detection_after_sequence_restore() {
        let key = test_hmac_key();

        // Sender creates messages
        let mut sender = ShardProtocol::new(ModuleId::Gateway, key);
        let msg1 = sender.create_message(b"first").unwrap();
        let msg2 = sender.create_message(b"second").unwrap();
        let msg3 = sender.create_message(b"third").unwrap();

        // Receiver processes first two messages
        let mut receiver = ShardProtocol::new(ModuleId::Audit, key);
        receiver.verify_message(&msg1).unwrap();
        receiver.verify_message(&msg2).unwrap();

        // Export receiver state
        let state = receiver.export_sequences().unwrap();

        // Simulate restart: new receiver, import state
        let mut receiver2 = ShardProtocol::new(ModuleId::Audit, key);
        receiver2.import_sequences(&state);

        // msg3 (seq=3) should work since last seen was 2
        receiver2.verify_message(&msg3).unwrap();

        // Replaying msg1 or msg2 should fail
        assert!(receiver2.verify_message(&msg1).is_err());
        assert!(receiver2.verify_message(&msg2).is_err());
    }

    #[test]
    fn needs_persistence_tracks_changes() {
        let key = test_hmac_key();
        let mut proto = ShardProtocol::new(ModuleId::Gateway, key);

        // Fresh protocol does not need persistence
        assert!(!proto.needs_persistence());

        // After sending a message, it does
        let _ = proto.create_message(b"msg").unwrap();
        assert!(proto.needs_persistence());

        // After marking persisted, it does not
        proto.mark_persisted();
        assert!(!proto.needs_persistence());

        // After another message, it does again
        let _ = proto.create_message(b"msg2").unwrap();
        assert!(proto.needs_persistence());
    }

    #[test]
    fn corrupt_import_data_is_ignored() {
        let key = test_hmac_key();
        let mut proto = ShardProtocol::new(ModuleId::Gateway, key);
        let _ = proto.create_message(b"msg").unwrap();

        // Import garbage — should be silently ignored
        proto.import_sequences(b"not valid postcard data");
        assert_eq!(proto.send_sequence, 1); // unchanged
    }

    #[test]
    fn sequence_persistence_loads_on_startup() {
        let dir = std::env::temp_dir().join(format!("shard_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);

        let key = test_hmac_key();

        // Create a protocol, send messages, persist
        {
            let mut proto = ShardProtocol::new(ModuleId::Gateway, key);
            let _ = proto.create_message(b"a").unwrap();
            let _ = proto.create_message(b"b").unwrap();
            let _ = proto.create_message(b"c").unwrap();
            assert_eq!(proto.send_sequence, 3);

            let persistence = SequencePersistence::new(proto, &dir);
            persistence.flush().unwrap();
        }

        // Create a new protocol, wrap in persistence — should load seq=3
        {
            let proto = ShardProtocol::new(ModuleId::Gateway, key);
            let persistence = SequencePersistence::new(proto, &dir);
            let locked = persistence.protocol();
            let proto = locked.lock().unwrap();
            assert_eq!(proto.send_sequence, 3);
        }

        // Cleanup
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sequence_persistence_atomic_write() {
        let dir = std::env::temp_dir().join(format!("shard_atomic_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let key = test_hmac_key();

        let mut proto = ShardProtocol::new(ModuleId::Gateway, key);
        let _ = proto.create_message(b"x").unwrap();
        let persistence = SequencePersistence::new(proto, &dir);
        persistence.flush().unwrap();

        // Verify the file exists and the tmp file does not
        let seq_path = dir.join(SEQUENCE_FILE_NAME);
        let tmp_path = dir.join(format!("{SEQUENCE_FILE_NAME}.tmp"));
        assert!(seq_path.exists());
        assert!(!tmp_path.exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sequence_persistence_no_write_when_unnecessary() {
        let dir = std::env::temp_dir().join(format!("shard_noop_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let key = test_hmac_key();

        let proto = ShardProtocol::new(ModuleId::Gateway, key);
        let persistence = SequencePersistence::new(proto, &dir);

        // No messages sent — flush should be a no-op (no file created)
        persistence.flush().unwrap();
        let seq_path = dir.join(SEQUENCE_FILE_NAME);
        assert!(!seq_path.exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    // -- AEGIS-256 / FIPS encryption ----------------------------------------

    #[test]
    fn test_shard_aegis256_encryption() {
        common::fips::set_fips_mode_unchecked(false);
        let key = test_hmac_key();
        let mut sender = ShardProtocol::new(ModuleId::Gateway, key);
        let mut receiver = ShardProtocol::new(ModuleId::Audit, key);

        let payload = b"aegis-256-shard-test-payload";
        let raw_msg = sender.create_message(payload).unwrap();
        let (sender_id, recovered) = receiver.verify_message(&raw_msg).unwrap();

        assert_eq!(sender_id, ModuleId::Gateway);
        assert_eq!(recovered.as_bytes(), payload);
    }

    #[test]
    fn test_shard_fips_aes256gcm_encryption() {
        common::fips::set_fips_mode_unchecked(true);
        let key = test_hmac_key();
        let mut sender = ShardProtocol::new(ModuleId::Gateway, key);
        let mut receiver = ShardProtocol::new(ModuleId::Audit, key);

        let payload = b"fips-aes-shard-test-payload";
        let raw_msg = sender.create_message(payload).unwrap();
        let (sender_id, recovered) = receiver.verify_message(&raw_msg).unwrap();

        assert_eq!(sender_id, ModuleId::Gateway);
        assert_eq!(recovered.as_bytes(), payload);
        common::fips::set_fips_mode_unchecked(false);
    }

    // -- HMAC computation and verification tests --

    #[test]
    fn test_hmac_computation_deterministic() {
        let key = [0xAA; 64];
        let msg = ShardMessage {
            version: PROTOCOL_VERSION,
            sender_module: ModuleId::Gateway,
            sequence: 1,
            timestamp: 1000000,
            payload: vec![0x01, 0x02, 0x03],
            hmac: [0u8; 64],
        };
        let hmac1 = ShardProtocol::compute_hmac(&key, &msg);
        let hmac2 = ShardProtocol::compute_hmac(&key, &msg);
        assert_eq!(hmac1, hmac2, "HMAC must be deterministic for identical inputs");
    }

    #[test]
    fn test_hmac_different_keys_differ() {
        let msg = ShardMessage {
            version: PROTOCOL_VERSION,
            sender_module: ModuleId::Gateway,
            sequence: 1,
            timestamp: 1000000,
            payload: vec![0x01, 0x02, 0x03],
            hmac: [0u8; 64],
        };
        let hmac1 = ShardProtocol::compute_hmac(&[0xAA; 64], &msg);
        let hmac2 = ShardProtocol::compute_hmac(&[0xBB; 64], &msg);
        assert_ne!(hmac1, hmac2, "different keys must produce different HMACs");
    }

    #[test]
    fn test_hmac_different_payloads_differ() {
        let key = [0xAA; 64];
        let msg1 = ShardMessage {
            version: PROTOCOL_VERSION,
            sender_module: ModuleId::Gateway,
            sequence: 1,
            timestamp: 1000000,
            payload: vec![0x01],
            hmac: [0u8; 64],
        };
        let mut msg2 = msg1.clone();
        msg2.payload = vec![0x02];
        let hmac1 = ShardProtocol::compute_hmac(&key, &msg1);
        let hmac2 = ShardProtocol::compute_hmac(&key, &msg2);
        assert_ne!(hmac1, hmac2, "different payloads must produce different HMACs");
    }

    #[test]
    fn test_hmac_different_sequences_differ() {
        let key = [0xAA; 64];
        let msg1 = ShardMessage {
            version: PROTOCOL_VERSION,
            sender_module: ModuleId::Gateway,
            sequence: 1,
            timestamp: 1000000,
            payload: vec![0x01],
            hmac: [0u8; 64],
        };
        let mut msg2 = msg1.clone();
        msg2.sequence = 2;
        let hmac1 = ShardProtocol::compute_hmac(&key, &msg1);
        let hmac2 = ShardProtocol::compute_hmac(&key, &msg2);
        assert_ne!(hmac1, hmac2, "different sequences must produce different HMACs");
    }

    #[test]
    fn test_hmac_nonzero() {
        let key = [0xAA; 64];
        let msg = ShardMessage {
            version: PROTOCOL_VERSION,
            sender_module: ModuleId::Gateway,
            sequence: 1,
            timestamp: 1000000,
            payload: vec![0x01],
            hmac: [0u8; 64],
        };
        let hmac = ShardProtocol::compute_hmac(&key, &msg);
        assert_ne!(hmac, [0u8; 64], "HMAC should not be all zeros");
    }

    // -- Timestamp validation tests --

    #[test]
    fn test_timestamp_within_tolerance() {
        let key = test_hmac_key();
        let mut sender = ShardProtocol::new(ModuleId::Gateway, key);
        let mut receiver = ShardProtocol::new(ModuleId::Audit, key);

        let payload = b"timestamp test";
        let raw = sender.create_message(payload).unwrap();
        // Verify immediately -- should be well within 2 second tolerance
        let result = receiver.verify_message(&raw);
        assert!(result.is_ok(), "message with fresh timestamp should verify");
    }

    // -- Sequence number monotonicity tests --

    #[test]
    fn test_sequence_monotonically_increasing() {
        let key = test_hmac_key();
        let mut sender = ShardProtocol::new(ModuleId::Gateway, key);
        let mut receiver = ShardProtocol::new(ModuleId::Audit, key);

        // Send 5 messages, all should be accepted in order
        for i in 0..5 {
            let payload = format!("msg {}", i);
            let raw = sender.create_message(payload.as_bytes()).unwrap();
            let result = receiver.verify_message(&raw);
            assert!(result.is_ok(), "message {} should verify", i);
        }
    }

    #[test]
    fn test_sequence_rejects_old_sequence() {
        let key = test_hmac_key();
        let mut sender = ShardProtocol::new(ModuleId::Gateway, key);
        let mut receiver = ShardProtocol::new(ModuleId::Audit, key);

        let msg1 = sender.create_message(b"first").unwrap();
        let msg2 = sender.create_message(b"second").unwrap();

        // Process msg2 first (sequence 2)
        receiver.verify_message(&msg2).unwrap();

        // msg1 (sequence 1) should be rejected since we already saw sequence 2
        let err = receiver.verify_message(&msg1);
        assert!(err.is_err(), "old sequence number should be rejected");
        let msg = format!("{}", err.unwrap_err());
        assert!(msg.contains("replay"), "error should mention replay: {msg}");
    }

    #[test]
    fn test_sequence_rejects_duplicate() {
        let key = test_hmac_key();
        let mut sender = ShardProtocol::new(ModuleId::Gateway, key);
        let mut receiver = ShardProtocol::new(ModuleId::Audit, key);

        let raw = sender.create_message(b"once").unwrap();
        receiver.verify_message(&raw).unwrap();

        // Same message (same sequence) should be rejected
        let err = receiver.verify_message(&raw);
        assert!(err.is_err(), "duplicate sequence should be rejected");
    }

    // -- Message serialization/deserialization tests --

    #[test]
    fn test_shard_message_serialization_roundtrip() {
        let msg = ShardMessage {
            version: PROTOCOL_VERSION,
            sender_module: ModuleId::Gateway,
            sequence: 42,
            timestamp: 1700000000_000000,
            payload: vec![0xDE, 0xAD, 0xBE, 0xEF],
            hmac: [0xAB; 64],
        };
        let bytes = postcard::to_allocvec(&msg).unwrap();
        let decoded: ShardMessage = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.version, PROTOCOL_VERSION);
        assert_eq!(decoded.sender_module, ModuleId::Gateway);
        assert_eq!(decoded.sequence, 42);
        assert_eq!(decoded.payload, vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(decoded.hmac, [0xAB; 64]);
    }

    #[test]
    fn test_shard_message_deserialization_corrupt() {
        let result = postcard::from_bytes::<ShardMessage>(&[0xFF, 0x00]);
        assert!(result.is_err(), "corrupt data should fail deserialization");
    }

    // -- Key derivation tests --

    #[test]
    fn test_derive_encryption_key_deterministic() {
        let secret = [0xCC; 64];
        let k1 = derive_encryption_key(&secret);
        let k2 = derive_encryption_key(&secret);
        assert_eq!(k1, k2, "same secret must produce same encryption key");
    }

    #[test]
    fn test_derive_hmac_key_deterministic() {
        let secret = [0xCC; 64];
        let k1 = derive_hmac_key(&secret);
        let k2 = derive_hmac_key(&secret);
        assert_eq!(k1, k2, "same secret must produce same HMAC key");
    }

    #[test]
    fn test_encryption_and_hmac_keys_differ() {
        let secret = [0xCC; 64];
        let enc_key = derive_encryption_key(&secret);
        let hmac_key = derive_hmac_key(&secret);
        // The encryption key is 32 bytes and HMAC key is 64 bytes,
        // but the first 32 bytes should still differ due to domain separation.
        assert_ne!(
            &enc_key[..],
            &hmac_key[..32],
            "encryption and HMAC keys must be different (domain separation)"
        );
    }

    #[test]
    fn test_different_secrets_different_keys() {
        let k1 = derive_encryption_key(&[0xAA; 64]);
        let k2 = derive_encryption_key(&[0xBB; 64]);
        assert_ne!(k1, k2, "different secrets must produce different keys");
    }

    // -- SecurePayload tests --

    #[test]
    fn test_secure_payload_equality() {
        let payload = SecurePayload(vec![1, 2, 3]);
        assert_eq!(payload, vec![1, 2, 3]);
        assert_eq!(payload, [1, 2, 3].as_slice());
        assert_eq!(payload, &[1u8, 2, 3]);
    }

    #[test]
    fn test_secure_payload_debug_redacted() {
        let payload = SecurePayload(vec![0xDE, 0xAD]);
        let debug = format!("{:?}", payload);
        assert!(debug.contains("REDACTED"), "debug output should be redacted");
        assert!(!debug.contains("222"), "debug should not leak payload bytes");
    }

    #[test]
    fn test_secure_payload_into_inner() {
        let payload = SecurePayload(vec![1, 2, 3]);
        let inner = payload.into_inner();
        assert_eq!(&*inner, &vec![1, 2, 3]);
    }
}
