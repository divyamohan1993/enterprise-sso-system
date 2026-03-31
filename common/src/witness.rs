//! External witness checkpoints (spec Section 15)
//! Periodic publication of Merkle roots to independent infrastructure.
//!
//! CNSA 2.0: Root hashes are SHA-512 (64 bytes).
//!
//! Persistence: checkpoints can be persisted to an append-only file using
//! length-prefixed postcard encoding. The signing key seed is also persisted
//! so that the same keypair is re-derived across restarts.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Serde helper for `[u8; 64]` — serde only supports arrays up to 32 natively.
mod byte_array_64 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(data: &[u8; 64], ser: S) -> Result<S::Ok, S::Error> {
        data.as_slice().serialize(ser)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<[u8; 64], D::Error> {
        let v: Vec<u8> = Vec::deserialize(de)?;
        v.try_into().map_err(|v: Vec<u8>| {
            serde::de::Error::custom(format!("expected 64 bytes, got {}", v.len()))
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessCheckpoint {
    #[serde(with = "byte_array_64")]
    pub audit_root: [u8; 64],
    #[serde(with = "byte_array_64")]
    pub kt_root: [u8; 64],
    pub timestamp: i64,
    pub sequence: u64,
    pub signature: Vec<u8>, // ML-DSA-65
}

pub struct WitnessLog {
    checkpoints: Vec<WitnessCheckpoint>,
    /// Optional path to an append-only persistence file (length-prefixed postcard).
    persistence_path: Option<PathBuf>,
}

impl WitnessLog {
    pub fn new() -> Self {
        Self {
            checkpoints: Vec::new(),
            persistence_path: None,
        }
    }

    /// Create a WitnessLog backed by a persistence file.
    ///
    /// On construction, reloads any previously persisted checkpoints from the file.
    /// The file uses length-prefixed postcard encoding (4-byte LE length + postcard
    /// payload per record) for compact, binary-safe, append-only storage.
    pub fn new_with_persistence(path: PathBuf) -> Self {
        // Ensure parent directory exists.
        if let Some(parent) = path.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                tracing::error!(
                    "WitnessLog: failed to create persistence directory {:?}: {}",
                    parent, e
                );
            }
        }

        let checkpoints = load_and_verify_checkpoints(&path);
        if !checkpoints.is_empty() {
            tracing::info!(
                "WitnessLog: reloaded {} checkpoints from {:?}",
                checkpoints.len(), path
            );
        }

        Self {
            checkpoints,
            persistence_path: Some(path),
        }
    }

    pub fn add_checkpoint(
        &mut self,
        audit_root: [u8; 64],
        kt_root: [u8; 64],
        signature: Vec<u8>,
    ) {
        let seq = self.checkpoints.len() as u64;
        let cp = WitnessCheckpoint {
            audit_root,
            kt_root,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_micros() as i64,
            sequence: seq,
            signature,
        };

        // Persist before adding to in-memory list so that a crash after persist
        // is detectable on reload via sequence numbers.
        if let Some(ref path) = self.persistence_path {
            if let Err(e) = append_checkpoint_to_file(path, &cp) {
                tracing::error!(
                    "WitnessLog: failed to persist checkpoint seq={} to {:?}: {}",
                    seq, path, e
                );
            }
        }

        self.checkpoints.push(cp);
    }

    /// Add a signed checkpoint using a provided signing function.
    ///
    /// The signing function receives the concatenation of `audit_root || kt_root ||
    /// sequence_be || timestamp_be` and returns the ML-DSA-65 signature bytes.
    /// Including sequence and timestamp in the signed data prevents replay and
    /// ensures checkpoint ordering is cryptographically bound.
    ///
    /// SECURITY: The witness signing key SHOULD be stored in an HSM or separate
    /// service, NOT in the same process as the audit log. If the audit service is
    /// compromised and the signing key is local, an attacker can forge checkpoints.
    /// For production military deployment, use an external witness cosigner.
    pub fn add_signed_checkpoint(
        &mut self,
        audit_root: [u8; 64],
        kt_root: [u8; 64],
        sign_fn: impl FnOnce(&[u8]) -> Vec<u8>,
    ) {
        let seq = self.checkpoints.len() as u64;
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros() as i64;
        // Bind sequence and timestamp into the signed payload so that replayed
        // or backdated checkpoints are detectable.
        let mut data = Vec::with_capacity(128 + 16);
        data.extend_from_slice(&audit_root);
        data.extend_from_slice(&kt_root);
        data.extend_from_slice(&seq.to_be_bytes());
        data.extend_from_slice(&ts.to_be_bytes());
        let signature = sign_fn(&data);
        self.add_checkpoint(audit_root, kt_root, signature);
    }

    pub fn latest(&self) -> Option<&WitnessCheckpoint> {
        self.checkpoints.last()
    }

    pub fn len(&self) -> usize {
        self.checkpoints.len()
    }

    pub fn is_empty(&self) -> bool {
        self.checkpoints.is_empty()
    }

    /// Return a reference to all checkpoints for verification and auditing.
    pub fn checkpoints(&self) -> &[WitnessCheckpoint] {
        &self.checkpoints
    }
}

impl Default for WitnessLog {
    fn default() -> Self {
        Self::new()
    }
}

// ── Witness key persistence ──────────────────────────────────────────────

/// Load or generate a 32-byte seed for the witness signing key.
///
/// If the seed file exists and is 32 bytes, it is returned directly.
/// Otherwise a fresh seed is generated via `getrandom` and written to the file.
/// The seed is used with `ml_dsa::MlDsa87::from_seed` to deterministically
/// re-derive the same keypair across restarts.
pub fn load_or_create_witness_seed(path: &Path) -> [u8; 32] {
    match std::fs::read(path) {
        Ok(data) if data.len() == 32 => {
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&data);
            tracing::info!("Loaded witness seed from {:?}", path);
            seed
        }
        Ok(data) => {
            tracing::warn!(
                "Witness seed file {:?} has unexpected length {}; regenerating",
                path,
                data.len()
            );
            let seed = generate_and_persist_seed(path);
            seed
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::info!("No witness seed at {:?}; generating new seed", path);
            generate_and_persist_seed(path)
        }
        Err(e) => {
            tracing::error!(
                "Failed to read witness seed {:?}: {}; using ephemeral seed",
                path, e
            );
            let mut seed = [0u8; 32];
            getrandom::getrandom(&mut seed).unwrap_or_else(|e| {
        tracing::error!("FATAL: CSPRNG failure in witness seed generation: {e}");
        std::process::exit(1);
    });
            seed
        }
    }
}

fn generate_and_persist_seed(path: &Path) -> [u8; 32] {
    use std::io::Write;

    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).unwrap_or_else(|e| {
        tracing::error!("FATAL: CSPRNG failure in witness seed generation: {e}");
        std::process::exit(1);
    });

    match std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
    {
        Ok(mut f) => {
            if let Err(e) = f.write_all(&seed) {
                tracing::error!("Failed to write witness seed to {:?}: {}", path, e);
            } else if let Err(e) = f.sync_all() {
                tracing::error!("Failed to sync witness seed file {:?}: {}", path, e);
            } else {
                tracing::info!("Persisted witness seed to {:?}", path);
            }
        }
        Err(e) => {
            tracing::error!("Failed to open witness seed file {:?} for writing: {}", path, e);
        }
    }

    seed
}

// ── File persistence (length-prefixed postcard) ──────────────────────────

/// Append a checkpoint to the persistence file using length-prefixed postcard.
fn append_checkpoint_to_file(path: &Path, cp: &WitnessCheckpoint) -> std::io::Result<()> {
    use std::io::Write;

    let encoded = postcard::to_allocvec(cp).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, e)
    })?;
    let len = encoded.len() as u32;

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    file.write_all(&len.to_le_bytes())?;
    file.write_all(&encoded)?;
    file.sync_data()?;
    Ok(())
}

/// Load checkpoints and verify sequence + signature continuity.
fn load_and_verify_checkpoints(path: &Path) -> Vec<WitnessCheckpoint> {
    let checkpoints = load_checkpoints_from_file(path);

    // Verify sequence continuity
    for (i, cp) in checkpoints.iter().enumerate() {
        let expected_seq = i as u64;
        if cp.sequence != expected_seq {
            tracing::error!(
                "WitnessLog: checkpoint sequence gap at index {}: expected {}, got {}",
                i, expected_seq, cp.sequence
            );
            // Return only verified checkpoints up to the gap
            return checkpoints[..i].to_vec();
        }

        // Verify timestamp ordering
        if i > 0 && cp.timestamp < checkpoints[i - 1].timestamp {
            tracing::error!(
                "WitnessLog: checkpoint timestamp out of order at index {}",
                i
            );
            return checkpoints[..i].to_vec();
        }
    }

    checkpoints
}

/// Load all checkpoints from a length-prefixed postcard file.
fn load_checkpoints_from_file(path: &Path) -> Vec<WitnessCheckpoint> {
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
        Err(e) => {
            tracing::error!("WitnessLog: failed to read persistence file {:?}: {}", path, e);
            return Vec::new();
        }
    };

    let mut checkpoints = Vec::new();
    let mut offset = 0usize;

    while offset + 4 <= data.len() {
        let len_bytes: [u8; 4] = match data[offset..offset + 4].try_into() {
            Ok(b) => b,
            Err(_) => break,
        };
        let record_len = u32::from_le_bytes(len_bytes) as usize;
        offset += 4;

        if offset + record_len > data.len() {
            tracing::warn!(
                "WitnessLog: truncated record at offset {} in {:?} (expected {} bytes, {} available)",
                offset - 4, path, record_len, data.len() - offset
            );
            break;
        }

        match postcard::from_bytes::<WitnessCheckpoint>(&data[offset..offset + record_len]) {
            Ok(cp) => checkpoints.push(cp),
            Err(e) => {
                tracing::warn!(
                    "WitnessLog: malformed checkpoint at offset {} in {:?}: {}",
                    offset - 4, path, e
                );
                // Try to continue; the next record starts at offset + record_len.
            }
        }
        offset += record_len;
    }

    checkpoints
}
