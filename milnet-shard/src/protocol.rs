//! SHARD (Secure Hardened Authenticated Request Dispatch) IPC protocol.
//!
//! Implements spec Section 11: authenticated inter-module messaging with
//! HMAC-SHA512, replay protection, and timestamp validation.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use sha2::Sha512;

use milnet_common::domain::SHARD_AUTH;
use milnet_common::error::MilnetError;
use milnet_common::types::{ModuleId, ShardMessage};
use milnet_crypto::ct::ct_eq;

type HmacSha512 = Hmac<Sha512>;

/// Maximum allowed clock skew between sender and receiver (2 seconds in microseconds).
const MAX_TIMESTAMP_DRIFT_US: i64 = 2_000_000;

/// SHARD protocol state for a single module.
///
/// Each module instantiates one `ShardProtocol` to create and verify
/// authenticated IPC messages.
pub struct ShardProtocol {
    module_id: ModuleId,
    hmac_key: [u8; 64],
    send_sequence: u64,
    recv_sequences: HashMap<ModuleId, u64>,
}

impl ShardProtocol {
    /// Create a new protocol instance for the given module.
    pub fn new(module_id: ModuleId, hmac_key: [u8; 64]) -> Self {
        Self {
            module_id,
            hmac_key,
            send_sequence: 0,
            recv_sequences: HashMap::new(),
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
        let mut mac = HmacSha512::new_from_slice(key).expect("HMAC-SHA512 accepts any key size");

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

    /// Create an authenticated SHARD message containing the given payload.
    ///
    /// The message includes an HMAC-SHA512 tag, a monotonically increasing
    /// sequence number, and a microsecond-precision timestamp.
    pub fn create_message(&mut self, payload: &[u8]) -> Result<Vec<u8>, MilnetError> {
        self.send_sequence += 1;

        let timestamp = Self::now_us()?;

        let mut msg = ShardMessage {
            version: 1,
            sender_module: self.module_id,
            sequence: self.send_sequence,
            timestamp,
            payload: payload.to_vec(),
            hmac: [0u8; 64],
        };

        msg.hmac = Self::compute_hmac(&self.hmac_key, &msg);

        postcard::to_allocvec(&msg)
            .map_err(|e| MilnetError::Serialization(format!("shard serialize: {e}")))
    }

    /// Verify an incoming SHARD message.
    ///
    /// Checks:
    /// 1. HMAC-SHA512 integrity (constant-time comparison)
    /// 2. Timestamp within +-2 seconds of local clock
    /// 3. Sequence number is strictly greater than last seen for that sender
    ///
    /// Returns `(sender_module, payload)` on success.
    pub fn verify_message(&mut self, raw: &[u8]) -> Result<(ModuleId, Vec<u8>), MilnetError> {
        let msg: ShardMessage = postcard::from_bytes(raw)
            .map_err(|e| MilnetError::Serialization(format!("shard deserialize: {e}")))?;

        // 1. Verify HMAC
        let expected_hmac = Self::compute_hmac(&self.hmac_key, &msg);
        if !ct_eq(&expected_hmac, &msg.hmac) {
            return Err(MilnetError::Shard("HMAC verification failed".into()));
        }

        // 2. Verify timestamp
        let now = Self::now_us()?;
        let drift = (now - msg.timestamp).abs();
        if drift > MAX_TIMESTAMP_DRIFT_US {
            return Err(MilnetError::Shard(format!(
                "timestamp outside tolerance: drift={drift}us"
            )));
        }

        // 3. Replay protection: sequence must be strictly increasing per sender
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

        Ok((msg.sender_module, msg.payload))
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
}
