//! SHARD (Secure Hardened Authenticated Request Dispatch) IPC protocol.
//!
//! Implements spec Section 11: authenticated inter-module messaging with
//! HMAC-SHA512, AES-256-GCM encryption, replay protection, and timestamp validation.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha512;

use common::domain::SHARD_AUTH;
use common::error::MilnetError;
use common::types::{ModuleId, ShardMessage};
use crypto::ct::ct_eq;

type HmacSha512 = Hmac<Sha512>;

/// Domain separation label for deriving the encryption key via HKDF.
const ENCRYPT_DOMAIN: &[u8] = b"MILNET-SHARD-ENCRYPT-v1";

/// AES-256-GCM nonce length in bytes.
const NONCE_LEN: usize = 12;

/// Maximum allowed clock skew between sender and receiver (2 seconds in microseconds).
const MAX_TIMESTAMP_DRIFT_US: i64 = 2_000_000;

/// SHARD protocol state for a single module.
///
/// Each module instantiates one `ShardProtocol` to create and verify
/// authenticated IPC messages. Payloads are encrypted with AES-256-GCM
/// and authenticated with HMAC-SHA512.
pub struct ShardProtocol {
    module_id: ModuleId,
    hmac_key: [u8; 64],
    /// AES-256-GCM cipher derived once from the HMAC key via HKDF.
    cipher: Aes256Gcm,
    send_sequence: u64,
    recv_sequences: HashMap<ModuleId, u64>,
    /// The epoch (send_sequence) at which sequences were last persisted.
    last_persisted_epoch: u64,
}

/// Derive an AES-256 encryption key from the HMAC key using HKDF-SHA512
/// with domain separation.
fn derive_encryption_key(hmac_key: &[u8; 64]) -> [u8; 32] {
    let hk = Hkdf::<Sha512>::new(None, hmac_key);
    let mut okm = [0u8; 32];
    hk.expand(ENCRYPT_DOMAIN, &mut okm)
        .expect("32 bytes is a valid HKDF-SHA512 output length");
    okm
}

impl ShardProtocol {
    /// Create a new protocol instance for the given module.
    pub fn new(module_id: ModuleId, hmac_key: [u8; 64]) -> Self {
        let enc_key = derive_encryption_key(&hmac_key);
        let cipher = Aes256Gcm::new_from_slice(&enc_key)
            .expect("32-byte key is valid for AES-256-GCM");
        Self {
            module_id,
            hmac_key,
            cipher,
            send_sequence: 0,
            recv_sequences: HashMap::new(),
            last_persisted_epoch: 0,
        }
    }

    /// Returns the current time in microseconds since the UNIX epoch.
    fn now_us() -> Result<i64, MilnetError> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_micros() as i64)
            .map_err(|e| MilnetError::Shard(format!("system clock error: {e}")))
    }

    /// Compute HMAC-SHA512 over the domain prefix and message fields (excluding the HMAC field).
    fn compute_hmac(key: &[u8; 64], msg: &ShardMessage) -> [u8; 64] {
        let mut mac = <HmacSha512 as Mac>::new_from_slice(key).expect("HMAC-SHA512 accepts any key size");

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

    /// Encrypt a plaintext payload with AES-256-GCM.
    ///
    /// Returns `nonce || ciphertext` (12 bytes nonce prepended).
    fn encrypt_payload(&self, plaintext: &[u8]) -> Result<Vec<u8>, MilnetError> {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        getrandom::getrandom(&mut nonce_bytes)
            .map_err(|e| MilnetError::Shard(format!("rng failed: {e}")))?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| MilnetError::Shard(format!("encryption failed: {e}")))?;
        let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Decrypt a `nonce || ciphertext` blob with AES-256-GCM.
    fn decrypt_payload(&self, data: &[u8]) -> Result<Vec<u8>, MilnetError> {
        if data.len() < NONCE_LEN {
            return Err(MilnetError::Shard("encrypted payload too short".into()));
        }
        let (nonce_bytes, ciphertext) = data.split_at(NONCE_LEN);
        let nonce = Nonce::from_slice(nonce_bytes);
        self.cipher
            .decrypt(nonce, ciphertext)
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
            version: 1,
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
    pub fn verify_message(&mut self, raw: &[u8]) -> Result<(ModuleId, Vec<u8>), MilnetError> {
        let msg: ShardMessage = postcard::from_bytes(raw)
            .map_err(|e| MilnetError::Serialization(format!("shard deserialize: {e}")))?;

        // 1. Verify HMAC over encrypted payload
        let expected_hmac = Self::compute_hmac(&self.hmac_key, &msg);
        if !ct_eq(&expected_hmac, &msg.hmac) {
            return Err(MilnetError::Shard("HMAC verification failed".into()));
        }

        // 2. Decrypt payload
        let plaintext = self.decrypt_payload(&msg.payload)?;

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
    pub fn export_sequences(&self) -> Vec<u8> {
        let state = SequenceState {
            send_sequence: self.send_sequence,
            recv_sequences: self.recv_sequences.clone(),
        };
        postcard::to_allocvec(&state).expect("sequence state serialization should not fail")
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

    /// Mark the current epoch as persisted. Call this after successfully
    /// writing [`export_sequences`] to durable storage.
    pub fn mark_persisted(&mut self) {
        self.last_persisted_epoch = self.send_sequence;
    }

    /// Connect to a remote SHARD peer over TLS.
    pub async fn connect_tls(self, addr: &str, connector: &tokio_rustls::TlsConnector, server_name: &str) -> Result<crate::tls_transport::TlsShardTransport, MilnetError> {
        crate::tls_transport::tls_connect(addr, self.module_id, self.hmac_key, connector, server_name).await
    }
    /// Bind a TLS-enabled listener.
    pub async fn listen_tls(self, addr: &str, tls_config: std::sync::Arc<rustls::ServerConfig>) -> Result<crate::tls_transport::TlsShardListener, MilnetError> {
        crate::tls_transport::TlsShardListener::bind(addr, self.module_id, self.hmac_key, tls_config).await
    }
    /// Connect with TLS in production or plain TCP in development.
    pub async fn connect_auto(self, addr: &str, production: bool, connector: Option<&tokio_rustls::TlsConnector>, server_name: &str) -> Result<TransportKind, MilnetError> {
        if production {
            let c = connector.ok_or_else(|| MilnetError::Shard("TLS required in production".into()))?;
            Ok(TransportKind::Tls(crate::tls_transport::tls_connect(addr, self.module_id, self.hmac_key, c, server_name).await?))
        } else {
            Ok(TransportKind::Plain(crate::transport::connect(addr, self.module_id, self.hmac_key).await?))
        }
    }
}


/// Unified transport for production (TLS) and development (plain TCP).
pub enum TransportKind {
    Tls(crate::tls_transport::TlsShardTransport),
    Plain(crate::transport::ShardTransport),
}
impl TransportKind {
    pub async fn send(&mut self, payload: &[u8]) -> Result<(), MilnetError> {
        match self { TransportKind::Tls(t) => t.send(payload).await, TransportKind::Plain(t) => t.send(payload).await }
    }
    pub async fn recv(&mut self) -> Result<(ModuleId, Vec<u8>), MilnetError> {
        match self { TransportKind::Tls(t) => t.recv().await, TransportKind::Plain(t) => t.recv().await }
    }
}


/// Internal serializable snapshot of sequence state.
#[derive(serde::Serialize, serde::Deserialize)]
struct SequenceState {
    send_sequence: u64,
    recv_sequences: HashMap<ModuleId, u64>,
}
