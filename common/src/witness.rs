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
#[serde(deny_unknown_fields)]
pub struct WitnessCheckpoint {
    #[serde(with = "byte_array_64")]
    pub audit_root: [u8; 64],
    #[serde(with = "byte_array_64")]
    pub kt_root: [u8; 64],
    pub timestamp: i64,
    pub sequence: u64,
    pub signature: Vec<u8>, // ML-DSA-87
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
    /// The signing function receives the per-checkpoint `seq` and the
    /// concatenation of `audit_root || kt_root || sequence_be || timestamp_be`,
    /// and returns the ML-DSA-87 signature bytes. The seq is exposed
    /// explicitly because the audit-witness binary uses it to enforce a
    /// strict-monotonic counter on its side (replay / equivocation defense)
    /// and binds it into the signed payload independently of the data hash.
    ///
    /// SECURITY (D1): The witness signing key MUST live in a separate process.
    /// Production deploys the dedicated `audit-witness` binary (under
    /// `services/audit-witness/`) which owns its own ML-DSA-87 key, listens
    /// on `/run/milnet/audit-witness.sock`, and authenticates connecting
    /// clients via SO_PEERCRED. The `sign_fn` closure passed here should
    /// dispatch to that UDS, never to a local key in the audit process.
    /// Co-locating the key would let any compromise of the audit service
    /// forge witness checkpoints.
    pub fn add_signed_checkpoint(
        &mut self,
        audit_root: [u8; 64],
        kt_root: [u8; 64],
        sign_fn: impl FnOnce(u64, &[u8]) -> Vec<u8>,
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
        let signature = sign_fn(seq, &data);
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
            // Legacy unencrypted seed (32 bytes plaintext)
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&data);
            tracing::info!("Loaded plaintext witness seed from {:?} (legacy format)", path);
            seed
        }
        Ok(data) if data.len() > 12 => {
            // Encrypted seed: nonce (12 bytes) || ciphertext+tag
            use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead, Nonce};

            let seal_key = derive_seed_seal_key();
            let cipher = match Aes256Gcm::new_from_slice(&seal_key) {
                Ok(c) => c,
                Err(e) => {
                    tracing::error!(
                        "SIEM:CRITICAL witness seed decryption key init failed: {e} -- TAMPER INDICATOR"
                    );
                    std::process::exit(199);
                }
            };
            let nonce = Nonce::from_slice(&data[..12]);
            match cipher.decrypt(nonce, &data[12..]) {
                Ok(plaintext) if plaintext.len() == 32 => {
                    let mut seed = [0u8; 32];
                    seed.copy_from_slice(&plaintext);
                    tracing::info!("Loaded and decrypted witness seed from {:?}", path);
                    seed
                }
                Ok(plaintext) => {
                    tracing::error!(
                        "SIEM:CRITICAL witness seed decrypted to unexpected length {} -- \
                         TAMPER INDICATOR",
                        plaintext.len()
                    );
                    std::process::exit(199);
                }
                Err(_) => {
                    tracing::error!(
                        "SIEM:CRITICAL witness seed decryption FAILED for {:?} -- \
                         TAMPER DETECTED, seed file may have been modified",
                        path
                    );
                    std::process::exit(199);
                }
            }
        }
        Ok(data) => {
            tracing::warn!(
                "Witness seed file {:?} has unexpected length {}; regenerating",
                path,
                data.len()
            );
            generate_and_persist_seed(path)
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

/// Derive an AES-256-GCM key from the master KEK for witness seed encryption.
fn derive_seed_seal_key() -> [u8; 32] {
    use sha2::Sha512;
    let kek = crate::sealed_keys::cached_master_kek();
    let hk = hkdf::Hkdf::<Sha512>::new(Some(b"MILNET-WITNESS-SALT-v1"), kek);
    let mut okm = [0u8; 32];
    hk.expand(b"MILNET-WITNESS-SEED-SEAL-v1", &mut okm)
        .unwrap_or_else(|e| {
            tracing::error!("FATAL: HKDF expansion failed for witness seed seal key: {e}");
            std::process::exit(199);
        });
    okm
}

fn generate_and_persist_seed(path: &Path) -> [u8; 32] {
    use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead, Nonce};
    use std::io::Write;

    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).unwrap_or_else(|e| {
        tracing::error!("FATAL: CSPRNG failure in witness seed generation: {e}");
        std::process::exit(1);
    });

    // Encrypt seed with AES-256-GCM using key derived from master KEK
    let seal_key = derive_seed_seal_key();
    let cipher = Aes256Gcm::new_from_slice(&seal_key).unwrap_or_else(|e| {
        tracing::error!("FATAL: AES-256-GCM key init failed for witness seed seal: {e}");
        std::process::exit(199);
    });

    let mut nonce_bytes = [0u8; 12];
    getrandom::getrandom(&mut nonce_bytes).unwrap_or_else(|e| {
        tracing::error!("FATAL: CSPRNG failure for witness seed nonce: {e}");
        std::process::exit(1);
    });
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, seed.as_ref()).unwrap_or_else(|e| {
        tracing::error!("FATAL: AES-256-GCM encryption failed for witness seed: {e}");
        std::process::exit(199);
    });

    // Write format: nonce (12 bytes) || ciphertext+tag
    match std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
    {
        Ok(mut f) => {
            let mut sealed = Vec::with_capacity(12 + ciphertext.len());
            sealed.extend_from_slice(&nonce_bytes);
            sealed.extend_from_slice(&ciphertext);
            if let Err(e) = f.write_all(&sealed) {
                tracing::error!("Failed to write witness seed to {:?}: {}", path, e);
            } else if let Err(e) = f.sync_all() {
                tracing::error!("Failed to sync witness seed file {:?}: {}", path, e);
            } else {
                tracing::info!("Persisted encrypted witness seed to {:?}", path);
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
    // SECURITY (D7): full fsync of the file AND parent directory. sync_data
    // alone leaves metadata vulnerable to power-loss and the directory entry
    // for newly created files may not be persisted otherwise.
    file.sync_all()?;
    drop(file);
    if let Some(parent) = path.parent() {
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

/// Load checkpoints and verify sequence, timestamp, and ML-DSA-87 signature continuity.
///
/// For each checkpoint, the signature is verified against the witness verifying key
/// (derived from the seed at the standard seed path). If verification fails, a
/// CRITICAL SIEM event is emitted and the checkpoint is skipped. If more than 1
/// checkpoint fails verification, loading is aborted entirely (tamper detected).
fn load_and_verify_checkpoints(path: &Path) -> Vec<WitnessCheckpoint> {
    let checkpoints = load_checkpoints_from_file(path);

    // Attempt to load the witness verifying key for signature verification.
    // Derive from the seed file path (sibling of the checkpoint file).
    let vk_bytes: Option<Vec<u8>> = path.parent().map(|dir| {
        let seed_path = dir.join("witness_seed.bin");
        match load_or_create_witness_seed(&seed_path) {
            seed => {
                use ml_dsa::{KeyGen, MlDsa87, EncodedVerifyingKey};
                let kp = MlDsa87::from_seed(&seed.into());
                let encoded: EncodedVerifyingKey<MlDsa87> = kp.verifying_key().encode();
                AsRef::<[u8]>::as_ref(&encoded).to_vec()
            }
        }
    });

    let mut verified = Vec::new();
    let mut sig_failures: u32 = 0;

    for (i, cp) in checkpoints.iter().enumerate() {
        let expected_seq = i as u64;
        if cp.sequence != expected_seq {
            tracing::error!(
                "WitnessLog: checkpoint sequence gap at index {}: expected {}, got {}",
                i, expected_seq, cp.sequence
            );
            return verified;
        }

        // Verify timestamp ordering
        if i > 0 && cp.timestamp < checkpoints[i - 1].timestamp {
            tracing::error!(
                "WitnessLog: checkpoint timestamp out of order at index {}",
                i
            );
            return verified;
        }

        // X-K: verify the audit-witness ML-DSA-87 signature using the same
        // domain-tagged composition the witness uses on the signing side:
        //   payload = seq_be || SHA-256(audit_root || kt_root || seq_be || ts_be)
        // FIPS 204 ctx is `MILNET-RAW-SIGN-v1 || 0x1F || AUDIT_WITNESS_DOMAIN`.
        if let Some(ref vk) = vk_bytes {
            let mut audit_data = Vec::with_capacity(128 + 16);
            audit_data.extend_from_slice(&cp.audit_root);
            audit_data.extend_from_slice(&cp.kt_root);
            audit_data.extend_from_slice(&cp.sequence.to_be_bytes());
            audit_data.extend_from_slice(&cp.timestamp.to_be_bytes());
            use sha2::{Digest, Sha256};
            let pre_hash: [u8; 32] = Sha256::digest(&audit_data).into();
            let mut signed_data = [0u8; 40];
            signed_data[0..8].copy_from_slice(&cp.sequence.to_be_bytes());
            signed_data[8..40].copy_from_slice(&pre_hash);

            if !verify_checkpoint_signature(vk, &signed_data, &cp.signature) {
                sig_failures += 1;
                tracing::error!(
                    "SIEM:CRITICAL WitnessLog: ML-DSA-87 signature verification FAILED \
                     for checkpoint seq={} -- possible tamper (failure count: {})",
                    cp.sequence, sig_failures
                );
                if sig_failures > 1 {
                    tracing::error!(
                        "SIEM:CRITICAL WitnessLog: multiple signature failures detected -- \
                         TAMPER DETECTED, aborting checkpoint loading entirely"
                    );
                    return verified;
                }
                // Skip this corrupted checkpoint but continue loading
                continue;
            }
        }

        verified.push(cp.clone());
    }

    verified
}

/// X-K: domain separator for ML-DSA-87 audit-witness checkpoint signatures.
/// Must match `audit_witness::AUDIT_WITNESS_DOMAIN` byte-for-byte. We
/// duplicate the constant here rather than introduce a `crypto` dep on
/// `common` (which would cycle: `crypto` -> `common`) or a `services/*`
/// dep on `common` (which is layering inversion).
const AUDIT_WITNESS_DOMAIN: &[u8; 32] = b"AUDIT-WITNESS-CHECKPOINT-v1\0\0\0\0\0";

/// FIPS 204 raw-sign context used by `crypto::pq_sign::pq_sign_raw_domain` —
/// kept in sync here so we can verify without a `crypto` dep cycle.
const CTX_RAW_SIGN: &[u8] = b"MILNET-RAW-SIGN-v1";

/// Verify an ML-DSA-87 audit-witness signature, using the same FIPS 204
/// domain-tagged context the witness signs with. `data` is the 40-byte
/// payload `seq_be || SHA-256(audit_root || kt_root || seq_be || ts_be)`.
fn verify_checkpoint_signature(vk_bytes: &[u8], data: &[u8], sig_bytes: &[u8]) -> bool {
    use ml_dsa::{EncodedVerifyingKey, MlDsa87, VerifyingKey};

    let vk_enc = match EncodedVerifyingKey::<MlDsa87>::try_from(vk_bytes) {
        Ok(enc) => enc,
        Err(_) => return false,
    };
    let vk = VerifyingKey::<MlDsa87>::decode(&vk_enc);
    let sig = match ml_dsa::Signature::<MlDsa87>::try_from(sig_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let mut ctx = Vec::with_capacity(CTX_RAW_SIGN.len() + 1 + AUDIT_WITNESS_DOMAIN.len());
    ctx.extend_from_slice(CTX_RAW_SIGN);
    ctx.push(0x1F);
    ctx.extend_from_slice(AUDIT_WITNESS_DOMAIN);
    vk.verify_with_context(data, &ctx, &sig)
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
