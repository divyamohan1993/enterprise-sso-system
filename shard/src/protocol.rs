//! SHARD (Secure Hardened Authenticated Request Dispatch) IPC protocol.
//!
//! Implements spec Section 11: authenticated inter-module messaging with
//! HMAC-SHA512, AES-256-GCM encryption, replay protection, and timestamp validation.

use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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

    /// Connect to a remote SHARD peer over TLS using the unified transport.
    ///
    /// Returns a [`crate::transport::ShardTransport`] with mTLS active.
    pub async fn connect_tls(
        self,
        addr: &str,
        tls_config: &crate::transport::ClientTlsConfig,
    ) -> Result<crate::transport::ShardTransport, MilnetError> {
        crate::transport::tls_connect(addr, self.module_id, self.hmac_key, tls_config).await
    }

    /// Bind a TLS-enabled listener using the unified transport.
    ///
    /// Returns a [`crate::transport::ShardListener`] with mTLS active.
    pub async fn listen_tls(
        self,
        addr: &str,
        tls_config: crate::transport::ServerTlsConfig,
    ) -> Result<crate::transport::ShardListener, MilnetError> {
        crate::transport::ShardListener::tls_bind(addr, self.module_id, self.hmac_key, tls_config)
            .await
    }

    /// Connect with TLS in production or plain TCP in development.
    ///
    /// Returns a unified [`crate::transport::ShardTransport`] that works
    /// identically regardless of whether TLS is active.
    pub async fn connect_auto(
        self,
        addr: &str,
        tls_config: Option<&crate::transport::ClientTlsConfig>,
    ) -> Result<crate::transport::ShardTransport, MilnetError> {
        crate::transport::connect_auto(addr, self.module_id, self.hmac_key, tls_config).await
    }
}


/// Internal serializable snapshot of sequence state.
#[derive(serde::Serialize, serde::Deserialize)]
struct SequenceState {
    send_sequence: u64,
    recv_sequences: HashMap<ModuleId, u64>,
}

// ---------------------------------------------------------------------------
// Automatic sequence persistence
// ---------------------------------------------------------------------------

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

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
/// ```ignore
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
            proto.export_sequences()
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
                let mut sigterm = signal(SignalKind::terminate())
                    .expect("failed to register SIGTERM handler");
                tokio::select! {
                    _ = ctrl_c => {},
                    _ = sigterm.recv() => {},
                }
            }
            #[cfg(not(unix))]
            {
                let _ = ctrl_c.await;
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
            let _ = tx.send(true);
        }
        // Best-effort final persistence
        if let Err(e) = Self::persist_to_disk(&self.protocol, &self.data_dir) {
            tracing::warn!("SHARD: drop persistence failed: {}", e);
        }
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
        let data = proto.export_sequences();

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
        let old_data = proto.export_sequences();

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
        let state = receiver.export_sequences();

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
}
