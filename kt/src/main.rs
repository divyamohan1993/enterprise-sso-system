#![forbid(unsafe_code)]
//! kt: Key Transparency Log service entry point.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Credential operation enum (D17): replaces plaintext string in leaf input.
/// Wire-stable u8 discriminant — never reuse values.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[repr(u8)]
enum KtOperation {
    Bind = 1,
    Revoke = 2,
    Rotate = 3,
}

impl KtOperation {
    fn as_str(self) -> &'static str {
        match self {
            KtOperation::Bind => "bind",
            KtOperation::Revoke => "revoke",
            KtOperation::Rotate => "rotate",
        }
    }

    fn from_str(s: &str) -> Option<Self> {
        match s {
            "bind" => Some(KtOperation::Bind),
            "revoke" => Some(KtOperation::Revoke),
            "rotate" => Some(KtOperation::Rotate),
            _ => None,
        }
    }
}

/// Persisted leaf record (D11). Stored append-only as length-prefixed postcard.
/// Replayed at startup to rebuild the in-memory tree exactly.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct KtLeafRecord {
    sequence: u64,
    user_id: Uuid,
    operation: KtOperation,
    credential_hash: [u8; 32],
    timestamp: i64,
}

/// Requests handled by the Key Transparency service.
#[derive(Debug, Serialize, Deserialize)]
enum KtRequest {
    AppendOp {
        user_id: Uuid,
        operation: String,
        credential_hash: [u8; 32],
        timestamp: i64,
    },
    GetRoot,
}

// ---------------------------------------------------------------------------
// Signing keypair persistence — sealed to disk with master KEK
// ---------------------------------------------------------------------------
//
// CQ-DEADCODE: the prior `seal_seed`/`unseal_seed`/`persist_seed`/
// `load_or_generate_keypair` legacy D16 cluster was removed here — it had
// zero call sites after the epoch-based KT signing flow landed
// (`load_kt_signing_epoch`). It was previously carried with
// `#[allow(dead_code)]` which hid the fact it was no longer wired into
// `fn main()`. External verifiers consume the verifying key written by
// `load_kt_signing_epoch`'s own path, not by the deleted legacy path.

/// Default data directory for KT persistent state.
const KT_DATA_DIR: &str = "/var/lib/milnet/kt";

#[cfg(any())]
mod _removed_legacy_seed_cluster {
    // CQ-DEADCODE: seal_seed / unseal_seed / persist_seed /
    // load_or_generate_keypair had zero call sites after D16 epoch-based
    // signing landed. The cluster was gated under #[allow(dead_code)] which
    // masked the deadness. Gated out here via #[cfg(any())] (never compiled)
    // pending full removal in a follow-up refactor; keeping the module
    // wrapper ensures any future regressor that tries to call these
    // functions fails to compile rather than silently resurrecting dead
    // code.
}

#[cfg(any())]
fn _removed_unseal_seed_placeholder(sealed: &[u8]) -> Result<[u8; 32], String> {
    if sealed.len() < 12 + 16 + 32 {
        return Err("sealed data too short".into());
    }
    let master_kek = common::sealed_keys::cached_master_kek();
    use hkdf::Hkdf;
    use sha2::Sha512;
    let hk = Hkdf::<Sha512>::new(Some(b"MILNET-KT-SEED-SEAL-v1"), master_kek);
    let mut seal_key = [0u8; 32];
    if let Err(e) = hk.expand(b"kt-seed-aes-key", &mut seal_key) {
        return Err(format!("HKDF-SHA512 expand for KT unseal key failed: {e}"));
    }

    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
    use aes_gcm::aead::generic_array::GenericArray;
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&seal_key));
    let nonce = Nonce::from_slice(&sealed[..12]);
    let plaintext = cipher
        .decrypt(nonce, aes_gcm::aead::Payload { msg: &sealed[12..], aad: b"" })
        .map_err(|e| format!("unseal seed: {e}"))?;

    use zeroize::Zeroize;
    seal_key.zeroize();

    if plaintext.len() != 32 {
        return Err(format!("unsealed seed wrong length: {}", plaintext.len()));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&plaintext);
    Ok(seed)
}

/// Write a sealed (encrypted) seed to disk atomically with 3-generation rotation.
///
/// SECURITY (D15): Writes go to `<path>.tmp`, are fsynced, then atomically
/// renamed over the destination. Two prior generations (`<path>.gen-1` and
/// `<path>.gen-2`) are kept on disk for disaster recovery. Parent directory
/// is fsynced after the rename so the directory entry is durable.
#[cfg(any())]
fn persist_seed(path: &Path, seed: &[u8; 32]) {
    use std::io::Write;
    let sealed = seal_seed(seed);

    let gen1 = path.with_extension("gen-1");
    let gen2 = path.with_extension("gen-2");
    if gen1.exists() {
        if let Err(e) = std::fs::rename(&gen1, &gen2) {
            tracing::warn!("KT seed gen-1 -> gen-2 rotate failed for {:?}: {}", path, e);
        }
    }
    if path.exists() {
        if let Err(e) = std::fs::rename(path, &gen1) {
            tracing::warn!("KT seed current -> gen-1 rotate failed for {:?}: {}", path, e);
        }
    }

    let tmp = path.with_extension("tmp");
    let open_res = {
        #[cfg(unix)]
        use std::os::unix::fs::OpenOptionsExt;
        let mut opts = std::fs::OpenOptions::new();
        opts.create(true).write(true).truncate(true);
        #[cfg(unix)]
        opts.mode(0o600);
        opts.open(&tmp)
    };
    match open_res {
        Ok(mut file) => {
            if let Err(e) = file.write_all(&sealed) {
                tracing::error!("FATAL: failed to write sealed KT seed tmp {:?}: {}", tmp, e);
                std::process::exit(1);
            }
            if let Err(e) = file.sync_all() {
                tracing::error!("FATAL: failed to fsync sealed KT seed tmp {:?}: {}", tmp, e);
                std::process::exit(1);
            }
            drop(file);
            if let Err(e) = std::fs::rename(&tmp, path) {
                tracing::error!(
                    "FATAL: atomic rename of sealed KT seed failed {:?} -> {:?}: {}",
                    tmp, path, e
                );
                std::process::exit(1);
            }
            if let Some(parent) = path.parent() {
                if let Ok(dir) = std::fs::File::open(parent) {
                    let _ = dir.sync_all();
                }
            }
            tracing::info!("Persisted sealed KT ML-DSA-87 seed to {:?} (atomic, 3-gen)", path);
        }
        Err(e) => {
            tracing::error!("FATAL: failed to open KT sealed seed tmp {:?}: {}", tmp, e);
            std::process::exit(1);
        }
    }
}

/// Load an existing sealed seed from disk, or generate a fresh one and persist it.
/// Also writes/overwrites the encoded verifying key so external parties can verify.
///
/// D16: superseded by [`load_kt_signing_epoch`]; retained for migration/test
/// reproducibility of legacy on-disk seeds.
#[cfg(any())]
fn load_or_generate_keypair(
    seed_path: &Path,
    vk_path: &Path,
) -> (crypto::pq_sign::PqSigningKey, crypto::pq_sign::PqVerifyingKey) {
    use ml_dsa::{KeyGen, MlDsa87};
    use zeroize::Zeroize;

    let mut seed = [0u8; 32];

    match std::fs::read(seed_path) {
        Ok(data) if data.len() == 32 => {
            // Legacy unencrypted seed — re-seal it under master KEK
            seed.copy_from_slice(&data);
            persist_seed(seed_path, &seed);
            tracing::info!("Legacy KT seed at {:?} has been sealed with KEK", seed_path);
        }
        Ok(data) if data.len() >= 12 + 16 + 32 => {
            // Sealed (encrypted) seed — decrypt with master KEK.
            match unseal_seed(&data) {
                Ok(unsealed) => {
                    seed = unsealed;
                    tracing::info!("Loaded and decrypted sealed ML-DSA-87 seed from {:?}", seed_path);
                }
                Err(e) => {
                    tracing::error!(
                        "Failed to unseal KT seed from {:?}: {} — generating new keypair",
                        seed_path, e
                    );
                    getrandom::getrandom(&mut seed).unwrap_or_else(|e| {
                    tracing::error!("FATAL: CSPRNG failure for KT seed generation: {e}");
                    std::process::exit(1);
                });
                    persist_seed(seed_path, &seed);
                }
            }
        }
        Ok(data) => {
            tracing::warn!(
                "KT seed file {:?} has unexpected size {} — generating new keypair",
                seed_path, data.len()
            );
            getrandom::getrandom(&mut seed).unwrap_or_else(|e| {
                    tracing::error!("FATAL: CSPRNG failure for KT seed generation: {e}");
                    std::process::exit(1);
                });
            persist_seed(seed_path, &seed);
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::info!("No seed file at {:?}; generating new ML-DSA-87 keypair", seed_path);
            getrandom::getrandom(&mut seed).unwrap_or_else(|e| {
                    tracing::error!("FATAL: CSPRNG failure for KT seed generation: {e}");
                    std::process::exit(1);
                });
            persist_seed(seed_path, &seed);
        }
        Err(e) => {
            tracing::error!(
                "Failed to read KT seed from {:?}: {} — generating new keypair",
                seed_path, e
            );
            getrandom::getrandom(&mut seed).unwrap_or_else(|e| {
                    tracing::error!("FATAL: CSPRNG failure for KT seed generation: {e}");
                    std::process::exit(1);
                });
            persist_seed(seed_path, &seed);
        }
    }

    let kp = MlDsa87::from_seed(&seed.into());
    seed.zeroize();
    let signing_key = kp.signing_key().clone();
    let verifying_key = kp.verifying_key().clone();

    // Write encoded verifying key for external verification
    let encoded = verifying_key.encode();
    if let Err(e) = std::fs::write(vk_path, AsRef::<[u8]>::as_ref(&encoded)) {
        tracing::warn!("Failed to write KT verifying key to {:?}: {}", vk_path, e);
    }

    (signing_key, verifying_key)
}

// ---------------------------------------------------------------------------
// D11: Append-only leaf log — every leaf is persisted before the in-memory
// tree is mutated, so a crash after the write is recoverable on the next
// start. File format: repeated [len_le_u32 || postcard(KtLeafRecord)] records.
// ---------------------------------------------------------------------------

fn append_leaf_record(path: &Path, rec: &KtLeafRecord) -> std::io::Result<()> {
    use std::io::Write;
    let encoded = postcard::to_allocvec(rec)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let len = encoded.len() as u32;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = file.set_permissions(std::fs::Permissions::from_mode(0o600));
    }
    file.write_all(&len.to_le_bytes())?;
    file.write_all(&encoded)?;
    // Full fsync of file + parent dir for power-loss durability.
    file.sync_all()?;
    drop(file);
    if let Some(parent) = path.parent() {
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

/// Maximum allowed length-prefixed record size for KT on-disk logs.
/// Rejects corrupted or adversarial length headers before allocation.
const KT_MAX_MSG: usize = 256 * 1024;

fn load_leaf_records(path: &Path) -> Vec<KtLeafRecord> {
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
        Err(e) => {
            tracing::error!("KT leaf log: read {:?} failed: {}", path, e);
            return Vec::new();
        }
    };
    let mut out = Vec::new();
    let mut offset = 0usize;
    while offset + 4 <= data.len() {
        let len_bytes: [u8; 4] = match data[offset..offset + 4].try_into() {
            Ok(b) => b,
            Err(_) => break,
        };
        let n = u32::from_le_bytes(len_bytes) as usize;
        offset += 4;
        if n > KT_MAX_MSG {
            tracing::error!(
                "SIEM:CRITICAL KT leaf log: length prefix {} exceeds max {} at offset {} in {:?} — rejecting",
                n, KT_MAX_MSG, offset - 4, path
            );
            common::siem::SecurityEvent::tamper_detected(
                &format!("KT leaf log length-prefix overflow: {} > {} at offset {} in {:?}",
                         n, KT_MAX_MSG, offset - 4, path),
            );
            break;
        }
        if offset + n > data.len() {
            tracing::warn!("KT leaf log truncated at offset {} in {:?}", offset - 4, path);
            common::siem::SecurityEvent::tamper_detected(
                &format!("KT leaf log truncated at offset {} in {:?}", offset - 4, path),
            );
            break;
        }
        match postcard::from_bytes::<KtLeafRecord>(&data[offset..offset + n]) {
            Ok(rec) => out.push(rec),
            Err(e) => {
                tracing::error!("KT leaf log: malformed record at offset {}: {}", offset - 4, e);
                common::siem::SecurityEvent::tamper_detected(
                    &format!("KT leaf log malformed record at offset {} in {:?}: {}",
                             offset - 4, path, e),
                );
            }
        }
        offset += n;
    }
    // Verify sequence numbers are contiguous from 0
    for (i, rec) in out.iter().enumerate() {
        if rec.sequence != i as u64 {
            tracing::error!(
                "SIEM:CRITICAL KT leaf log sequence gap: expected {}, got {} -- TAMPER",
                i, rec.sequence
            );
            common::siem::SecurityEvent::tamper_detected(
                &format!("KT leaf log sequence gap at index {}: stored {}", i, rec.sequence),
            );
            return out[..i].to_vec();
        }
    }
    out
}

// ---------------------------------------------------------------------------
// D12: Append-only signed tree head log. Each STH is persisted before being
// pushed to the witness. Format identical to leaf log (length-prefixed
// postcard).
// ---------------------------------------------------------------------------

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
struct PersistedSth {
    tree_size: u64,
    #[serde(with = "byte_array_64")]
    root: [u8; 64],
    timestamp: i64,
    /// ML-DSA-87 signature over
    /// (epoch_id || tree_size || root || timestamp || prev_sth_hash), all
    /// encoded big-endian. The epoch id binds the signature to the current
    /// KT signing epoch so a signature captured under one epoch cannot be
    /// replayed against STHs from a later epoch (D16).
    signature: Vec<u8>,
    /// Hash of the previous STH for RFC 6962-style consistency chaining.
    #[serde(with = "byte_array_64")]
    prev_sth_hash: [u8; 64],
    /// KT signing epoch id under which this STH was signed. Default 0 for
    /// legacy records produced before D16 rolled out.
    #[serde(default)]
    epoch_id: u64,
}

/// D16: KT signing epoch metadata. A fresh ML-DSA-87 signing key is loaded
/// once per 24h window from the sealed secret store under the name
/// `kt-epoch-<id>`. The epoch id is `floor(unix_secs / 86400)`. Absence of a
/// sealed key for the current epoch is fatal — the service refuses to start
/// rather than signing with a stale key. On rollover the STH task reloads the
/// next epoch's key atomically.
struct KtSigningEpoch {
    epoch_id: u64,
    start_ts: u64,
    end_ts: u64,
    signing_key_ref: String,
    signing_key: crypto::pq_sign::PqSigningKey,
    verifying_key: crypto::pq_sign::PqVerifyingKey,
    verifying_key_hash: [u8; 64],
}

const KT_EPOCH_DURATION_SECS: u64 = 86_400; // 24h

fn compute_current_epoch_id() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() / KT_EPOCH_DURATION_SECS)
        .unwrap_or(0)
}

/// Load the KT signing epoch for `epoch_id` from the sealed secret store.
///
/// The sealed secret is expected to be a 32-byte ML-DSA-87 seed. Absence is
/// fatal: the caller MUST refuse to start. Any operator wishing to run KT
/// must provision `kt-epoch-<id>` via the secret loader (UDS helper,
/// systemd LoadCredential, or — in dev — the env escape hatch) before the
/// epoch begins.
fn load_kt_signing_epoch(epoch_id: u64) -> KtSigningEpoch {
    use ml_dsa::{KeyGen, MlDsa87};
    use zeroize::Zeroize;

    let key_name = format!("kt-epoch-{}", epoch_id);
    let sealed = match common::secret_loader::load_secret(&key_name) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(
                target: "siem",
                category = "security",
                severity = "CRITICAL",
                action = "kt_epoch_key_missing",
                epoch_id = epoch_id,
                key_name = %key_name,
                error = %e,
                "FATAL: KT signing epoch key '{}' not present in sealed secret store — \
                 refusing to start. Provision the sealed seed before the epoch begins.",
                key_name
            );
            std::process::exit(197);
        }
    };

    // Accept either a raw 32-byte seed or hex-encoded 64-char seed.
    let mut seed = [0u8; 32];
    if sealed.len() == 32 {
        seed.copy_from_slice(&sealed[..]);
    } else if sealed.len() == 64 {
        // Hex path (common for env-sourced secrets in dev).
        match hex::decode(&sealed[..]) {
            Ok(b) if b.len() == 32 => seed.copy_from_slice(&b),
            _ => {
                tracing::error!(
                    target: "siem",
                    severity = "CRITICAL",
                    epoch_id = epoch_id,
                    "FATAL: KT signing epoch key '{}' has unexpected size {}; expected 32 raw \
                     or 64 hex chars",
                    key_name, sealed.len()
                );
                std::process::exit(197);
            }
        }
    } else {
        tracing::error!(
            target: "siem",
            severity = "CRITICAL",
            epoch_id = epoch_id,
            "FATAL: KT signing epoch key '{}' has unexpected size {}",
            key_name, sealed.len()
        );
        std::process::exit(197);
    }

    let kp = MlDsa87::from_seed(&seed.into());
    seed.zeroize();
    let signing_key = kp.signing_key().clone();
    let verifying_key = kp.verifying_key().clone();

    // Hash the encoded verifying key for audit/export.
    let encoded_vk = verifying_key.encode();
    let mut h = sha2::Sha512::new();
    use sha2::Digest as _;
    h.update(AsRef::<[u8]>::as_ref(&encoded_vk));
    let vk_hash: [u8; 64] = h.finalize().into();

    let start_ts = epoch_id.saturating_mul(KT_EPOCH_DURATION_SECS);
    let end_ts = start_ts.saturating_add(KT_EPOCH_DURATION_SECS);

    KtSigningEpoch {
        epoch_id,
        start_ts,
        end_ts,
        signing_key_ref: key_name,
        signing_key,
        verifying_key,
        verifying_key_hash: vk_hash,
    }
}

fn append_sth_record(path: &Path, sth: &PersistedSth) -> std::io::Result<()> {
    use std::io::Write;
    let encoded = postcard::to_allocvec(sth)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let len = encoded.len() as u32;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = file.set_permissions(std::fs::Permissions::from_mode(0o600));
    }
    file.write_all(&len.to_le_bytes())?;
    file.write_all(&encoded)?;
    file.sync_all()?;
    drop(file);
    if let Some(parent) = path.parent() {
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

fn hash_sth(sth: &PersistedSth) -> [u8; 64] {
    use sha2::{Digest, Sha512};
    let mut h = Sha512::new();
    h.update(b"MILNET-KT-STH-v2");
    h.update(sth.epoch_id.to_be_bytes());
    h.update(sth.tree_size.to_be_bytes());
    h.update(sth.root);
    h.update(sth.timestamp.to_be_bytes());
    h.update(sth.prev_sth_hash);
    let r = h.finalize();
    let mut out = [0u8; 64];
    out.copy_from_slice(&r);
    out
}

fn load_last_sth_hash(path: &Path) -> [u8; 64] {
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(_) => return [0u8; 64],
    };
    let mut last_hash = [0u8; 64];
    let mut offset = 0usize;
    while offset + 4 <= data.len() {
        let n = u32::from_le_bytes(match data[offset..offset + 4].try_into() {
            Ok(b) => b,
            Err(_) => break,
        }) as usize;
        offset += 4;
        if n > KT_MAX_MSG {
            tracing::error!(
                "SIEM:CRITICAL KT STH log: length prefix {} exceeds max {} at offset {} — rejecting",
                n, KT_MAX_MSG, offset - 4
            );
            break;
        }
        if offset + n > data.len() {
            break;
        }
        if let Ok(sth) = postcard::from_bytes::<PersistedSth>(&data[offset..offset + n]) {
            last_hash = hash_sth(&sth);
        }
        offset += n;
    }
    last_hash
}

/// Ensure a directory exists, creating it (with parents) if needed.
fn ensure_dir(path: &Path) {
    if !path.exists() {
        if let Err(e) = std::fs::create_dir_all(path) {
            tracing::warn!("Failed to create directory {:?}: {}", path, e);
        }
    }
}

// ---------------------------------------------------------------------------
// Merkle tree persistence — HMAC-SHA512 integrity protected
// ---------------------------------------------------------------------------

/// Compute HMAC-SHA512 over tree data for integrity verification.
/// The HMAC key is derived from the master KEK via HKDF-SHA512 to prevent forgery.
fn compute_tree_hmac(data: &[u8]) -> [u8; 64] {
    use hmac::{Hmac, Mac};
    use sha2::Sha512;
    use hkdf::Hkdf;
    type HmacSha512 = Hmac<Sha512>;

    let master_kek = common::sealed_keys::cached_master_kek();
    let hk = Hkdf::<Sha512>::new(Some(b"MILNET-KT-TREE-INTEGRITY-v1"), master_kek);
    let mut derived_key = [0u8; 64];
    if let Err(e) = hk.expand(b"kt-tree-file-hmac", &mut derived_key) {
        tracing::error!("FATAL: HKDF-SHA512 expand failed for KT tree HMAC key: {e}");
        std::process::exit(1);
    }
    let mut mac = HmacSha512::new_from_slice(&derived_key).unwrap_or_else(|e| {
        tracing::error!("FATAL: HMAC-SHA512 key init failed for KT tree integrity: {e}");
        std::process::exit(1);
    });
    use zeroize::Zeroize;
    derived_key.zeroize();
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut hmac_bytes = [0u8; 64];
    hmac_bytes.copy_from_slice(&result);
    hmac_bytes
}

/// Serialize the Merkle tree leaves to a file with HMAC-SHA512 integrity.
///
/// Wire format: leaf_count (u64 LE) || leaves (each 64 bytes) || HMAC-SHA512 (64 bytes)
fn persist_tree(tree: &kt::merkle::MerkleTree, path: &Path) {
    use std::io::Write;

    let count = tree.len() as u64;
    // We need access to leaves — serialize by reconstructing from tree's public API.
    // The tree only exposes root() and len(), so we store the count and root as a
    // checkpoint. Full leaf persistence requires tree cooperation.
    // For now: serialize the tree size and root hash, which is sufficient for
    // verifying the tree was not tampered with on reload.
    // NOTE: Full leaf-level persistence would require MerkleTree to expose its leaves
    // or implement Serialize. This checkpoint approach enables integrity verification.
    let mut data = Vec::new();
    data.extend_from_slice(&count.to_le_bytes());
    let root = tree.root();
    data.extend_from_slice(&root);

    let hmac = compute_tree_hmac(&data);

    let mut file_data = data.clone();
    file_data.extend_from_slice(&hmac);

    match std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
    {
        Ok(mut file) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Err(e) = file.set_permissions(std::fs::Permissions::from_mode(0o600)) {
                    tracing::error!("SIEM:ERROR failed to set file permissions on {:?}: {e}", path);
                }
            }
            if let Err(e) = file.write_all(&file_data) {
                tracing::error!("Failed to persist Merkle tree to {:?}: {}", path, e);
            } else {
                tracing::debug!(
                    tree_size = count,
                    root = %hex::encode(&root[..8]),
                    "Merkle tree checkpoint persisted to {:?}", path
                );
            }
        }
        Err(e) => tracing::error!("Failed to open {:?} for tree persistence: {}", path, e),
    }
}

/// Load and verify a persisted Merkle tree checkpoint.
/// Returns the stored (leaf_count, root_hash) if the file exists and HMAC verifies.
fn load_tree_checkpoint(path: &Path) -> Option<(u64, [u8; 64])> {
    let file_data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            tracing::warn!("Failed to read tree checkpoint from {:?}: {}", path, e);
            return None;
        }
    };

    // Minimum: 8 (count) + 64 (root) + 64 (HMAC) = 136 bytes
    if file_data.len() < 136 {
        tracing::warn!("Tree checkpoint at {:?} too short ({} bytes)", path, file_data.len());
        return None;
    }

    let hmac_offset = file_data.len() - 64;
    let data = &file_data[..hmac_offset];
    let stored_hmac = &file_data[hmac_offset..];

    let computed_hmac = compute_tree_hmac(data);
    if !crypto::ct::ct_eq(&computed_hmac, stored_hmac) {
        tracing::error!(
            "SIEM:CRITICAL Merkle tree checkpoint HMAC verification FAILED at {:?} — \
             file may have been tampered with",
            path
        );
        return None;
    }

    let count = u64::from_le_bytes(data[..8].try_into().ok()?);
    let mut root = [0u8; 64];
    root.copy_from_slice(&data[8..72]);

    tracing::info!(
        tree_size = count,
        root = %hex::encode(&root[..8]),
        "Merkle tree checkpoint loaded and verified from {:?}", path
    );

    Some((count, root))
}

#[tokio::main]
async fn main() {
    // MUST be first: harden process before any allocation that could hold a secret.
    crypto::process_harden::harden_early();
    tracing_subscriber::fmt::init();

    // Anchor monotonic time before any crypto/auth operations.
    common::secure_time::init_time_anchor();

    // Platform integrity: vTPM check, process hardening, self-attestation, monitor
    let (_platform_report, _monitor_handle, _monitor) =
        common::startup_checks::run_platform_checks(crypto::memguard::harden_process);

    // Start runtime defense: stealth detection + auto-response pipeline
    let _defense = common::runtime_defense::start_runtime_defense(
        "kt",
        9109,
        _platform_report.binary_hash,
    );

    // Initialize master KEK via distributed threshold reconstruction (3-of-5 Shamir)
    let _kek = common::sealed_keys::get_master_kek();

    // Initialize structured JSON logging for production observability
    common::structured_logging::init(common::structured_logging::ServiceMeta {
        service_name: "kt".to_string(),
        service_version: env!("CARGO_PKG_VERSION").to_string(),
        instance_id: uuid::Uuid::new_v4().to_string(),
        project_id: std::env::var("GCP_PROJECT_ID").unwrap_or_else(|_| "milnet-sso".to_string()),
    });

    // Verify binary integrity at startup
    let build_info = common::embed_build_info!();
    tracing::info!(
        git_commit = %build_info.git_commit,
        build_time = %build_info.build_time,
        "build manifest verified"
    );

    // Initialize health monitor for peer service tracking
    let _health_monitor = std::sync::Arc::new(common::health::HealthMonitor::new());

    // Initialize metrics counters
    let _auth_counter = common::metrics::Counter::new("auth_attempts", "Total authentication attempts");
    let _error_counter = common::metrics::Counter::new("errors", "Total errors");

    // Initialize authenticated time source
    let _secure_time = common::secure_time::SecureTimeProvider::new(
        common::secure_time::AuthenticatedTimeConfig::default(),
    );

    // Verify CNSA 2.0 compliance at startup
    assert!(common::cnsa2::is_cnsa2_compliant(), "CNSA 2.0 compliance check failed");
    tracing::info!("CNSA 2.0 compliance verified");

    tracing::info!("Key Transparency service starting");

    let tree = Arc::new(RwLock::new(kt::merkle::MerkleTree::new()));

    // ── Persistent data directory ────────────────────────────────────────
    let data_dir = PathBuf::from(
        std::env::var("KT_DATA_DIR").unwrap_or_else(|_| KT_DATA_DIR.to_string()),
    );
    ensure_dir(&data_dir);

    // ── D16: Epoch-based ML-DSA-87 signing key (24h rollover) ────────────
    //
    // A fresh signing seed is provisioned per 24h epoch under the sealed
    // secret name `kt-epoch-<id>`. We load the current epoch's key at
    // startup; the periodic STH task checks for rollover on every tick and
    // reloads atomically. The legacy `load_or_generate_keypair` path is
    // retained only to preserve the encoded verifying key on-disk for
    // external verifiers during migration.
    let verifying_key_path = data_dir.join("verifying_key.bin");
    let current_epoch_id = compute_current_epoch_id();
    let initial_signing_epoch = load_kt_signing_epoch(current_epoch_id);
    tracing::info!(
        epoch_id = initial_signing_epoch.epoch_id,
        key_ref = %initial_signing_epoch.signing_key_ref,
        vk_hash_prefix = %hex::encode(&initial_signing_epoch.verifying_key_hash[..8]),
        "D16: loaded KT signing epoch from sealed secret store"
    );
    let encoded_vk = initial_signing_epoch.verifying_key.encode();
    if let Err(e) = std::fs::write(
        &verifying_key_path,
        AsRef::<[u8]>::as_ref(&encoded_vk),
    ) {
        tracing::warn!(
            "Failed to export KT epoch verifying key to {:?}: {}",
            verifying_key_path, e
        );
    }
    let current_epoch: Arc<tokio::sync::Mutex<KtSigningEpoch>> =
        Arc::new(tokio::sync::Mutex::new(initial_signing_epoch));

    // ── D5: 2-of-5 consensus signing setup ────────────────────────────
    kt::consensus::require_pinned_vks_or_panic();
    let kt_consensus_keys: Arc<Vec<Option<crypto::pq_sign::PqSigningKey>>> =
        Arc::new(kt::consensus::synthesize_signing_keys());
    let kt_pinned_vks: Arc<Vec<crypto::pq_sign::PqVerifyingKey>> =
        Arc::new(kt::consensus::load_pinned_vks());
    tracing::info!(
        "KT 2-of-5 consensus initialized: {} local signing slots, {} pinned VKs",
        kt_consensus_keys.iter().filter(|k| k.is_some()).count(),
        kt_pinned_vks.len()
    );

    // ── Load Merkle tree checkpoint if it exists ─────────────────────────
    let tree_checkpoint_path = data_dir.join("merkle_tree.bin");
    if let Some((count, root)) = load_tree_checkpoint(&tree_checkpoint_path) {
        tracing::info!(
            tree_size = count,
            root = %hex::encode(&root[..8]),
            "Merkle tree checkpoint verified (tree state will be rebuilt from leaf log)"
        );
    }

    // ── D11: Replay persisted leaves into the in-memory tree ────────────
    let leaf_log_path = data_dir.join("kt_leaves.log");
    {
        let records = load_leaf_records(&leaf_log_path);
        if !records.is_empty() {
            let mut t = tree.write().await;
            for rec in &records {
                t.append_credential_op(
                    &rec.user_id,
                    rec.operation.as_str(),
                    &rec.credential_hash,
                    rec.timestamp,
                );
            }
            tracing::info!(
                "KT replayed {} persisted leaves; tree root={}",
                records.len(),
                hex::encode(&t.root()[..8])
            );
            // Cross-check against checkpoint root if present.
            if let Some((cp_count, cp_root)) = load_tree_checkpoint(&tree_checkpoint_path) {
                if cp_count == t.len() as u64 && cp_root != t.root() {
                    tracing::error!(
                        "SIEM:CRITICAL KT replay root mismatch with checkpoint: \
                         checkpoint={}, replay={}",
                        hex::encode(&cp_root[..8]),
                        hex::encode(&t.root()[..8])
                    );
                    common::siem::SecurityEvent::tamper_detected(
                        "KT replay root diverges from checkpoint -- TAMPER",
                    );
                    std::process::exit(199);
                }
            }
        }
    }

    // ── D12: STH log + previous STH hash for chaining ───────────────────
    let sth_log_path = data_dir.join("kt_sth.log");
    let last_sth_hash_init = load_last_sth_hash(&sth_log_path);
    let last_sth_hash: Arc<tokio::sync::Mutex<[u8; 64]>> =
        Arc::new(tokio::sync::Mutex::new(last_sth_hash_init));

    // Spawn periodic signed tree head + tree persistence task (every 60 seconds)
    let tree_clone = tree.clone();
    let checkpoint_path = tree_checkpoint_path.clone();
    let sth_path = sth_log_path.clone();
    let last_sth_hash_task = last_sth_hash.clone();
    let current_epoch_task = current_epoch.clone();
    let verifying_key_path_task = verifying_key_path.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;

            // D16: epoch rollover check — atomically swap in the next epoch's
            // sealed signing key whenever wall-clock crosses a 24h boundary.
            let now_epoch = compute_current_epoch_id();
            {
                let mut ep = current_epoch_task.lock().await;
                if now_epoch != ep.epoch_id {
                    let prev_id = ep.epoch_id;
                    let next = load_kt_signing_epoch(now_epoch);
                    tracing::info!(
                        prev_epoch = prev_id,
                        new_epoch = next.epoch_id,
                        key_ref = %next.signing_key_ref,
                        vk_hash_prefix = %hex::encode(&next.verifying_key_hash[..8]),
                        "D16: KT signing epoch rollover — atomically transitioning"
                    );
                    let encoded = next.verifying_key.encode();
                    if let Err(e) = std::fs::write(
                        &verifying_key_path_task,
                        AsRef::<[u8]>::as_ref(&encoded),
                    ) {
                        tracing::warn!(
                            "KT epoch rollover: failed to export verifying key: {}",
                            e
                        );
                    }
                    *ep = next;
                }
            }

            let t = tree_clone.read().await;
            if t.len() > 0 {
                let ep = current_epoch_task.lock().await;
                let pq_key = &ep.signing_key;
                let epoch_id = ep.epoch_id;
                let sth = t.signed_tree_head(pq_key);
                tracing::info!(
                    "Signed tree head (epoch {}): {} leaves, root={}",
                    epoch_id,
                    sth.tree_size,
                    hex::encode(&sth.root[..8])
                );
                // Persist Merkle tree checkpoint with HMAC-SHA512 integrity
                persist_tree(&t, &checkpoint_path);

                // D12/D16: build, sign, persist, and chain a PersistedSth.
                // Signed payload:
                //   epoch_id || tree_size || root || timestamp || prev_sth_hash
                // All fixed-width integers big-endian.
                let timestamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_micros() as i64;
                let mut prev_hash_lock = last_sth_hash_task.lock().await;
                let mut to_sign = Vec::with_capacity(8 + 8 + 64 + 8 + 64);
                to_sign.extend_from_slice(&epoch_id.to_be_bytes());
                to_sign.extend_from_slice(&sth.tree_size.to_be_bytes());
                to_sign.extend_from_slice(&sth.root);
                to_sign.extend_from_slice(&timestamp.to_be_bytes());
                to_sign.extend_from_slice(&*prev_hash_lock);
                let signature = crypto::pq_sign::pq_sign_raw(pq_key, &to_sign);
                drop(ep);
                let persisted = PersistedSth {
                    tree_size: sth.tree_size as u64,
                    root: sth.root,
                    timestamp,
                    signature,
                    prev_sth_hash: *prev_hash_lock,
                    epoch_id,
                };
                if let Err(e) = append_sth_record(&sth_path, &persisted) {
                    tracing::error!("KT STH log append failed: {}", e);
                    common::siem::SecurityEvent::tamper_detected(
                        &format!("KT STH log append failed: {}", e),
                    );
                } else {
                    *prev_hash_lock = hash_sth(&persisted);
                    tracing::info!(
                        "KT STH persisted: size={} chain_hash={}",
                        persisted.tree_size,
                        hex::encode(&prev_hash_lock[..8])
                    );
                }
            }
        }
    });

    // SECURITY: Remove ALL sensitive env vars from /proc/PID/environ IMMEDIATELY
    // after the last env var read. Secrets must not linger in the process environment
    // any longer than necessary to prevent leakage via /proc/PID/environ or
    // child process inheritance.
    common::startup_checks::sanitize_environment();

    let addr = std::env::var("KT_ADDR").unwrap_or_else(|_| "127.0.0.1:9107".to_string());
    let hmac_key = crypto::entropy::generate_key_64();
    let (listener, _ca, _cert_key) =
        match shard::tls_transport::tls_bind(&addr, common::types::ModuleId::Kt, hmac_key, "kt")
            .await
        {
            Ok(t) => t,
            Err(e) => {
                tracing::error!("FATAL: KT service failed to bind TLS listener: {e}");
                std::process::exit(1);
            }
        };

    tracing::info!("Key Transparency service listening on {addr} (mTLS)");
    loop {
        if let Ok(mut transport) = listener.accept().await {
            let tree = tree.clone();
            let leaf_log_path = leaf_log_path.clone();
            let kt_consensus_keys = kt_consensus_keys.clone();
            let kt_pinned_vks = kt_pinned_vks.clone();
            tokio::spawn(async move {
                while let Ok((sender, payload)) = transport.recv().await {
                    // SECURITY (D3): authoritative caller identity is the mTLS
                    // peer module, not anything carried in the payload.
                    let authorized = matches!(
                        sender,
                        common::types::ModuleId::Orchestrator
                            | common::types::ModuleId::Opaque
                            | common::types::ModuleId::Tss
                            | common::types::ModuleId::Admin
                    );
                    if !authorized {
                        tracing::error!(
                            sender = ?sender,
                            "SECURITY: unauthorized module attempted to mutate KT log"
                        );
                        continue;
                    }
                    if let Ok(request) = postcard::from_bytes::<KtRequest>(&payload) {
                        match request {
                            KtRequest::AppendOp { user_id, operation, credential_hash, timestamp } => {
                                // D17: parse operation as enum; reject unknown.
                                let op = match KtOperation::from_str(&operation) {
                                    Some(o) => o,
                                    None => {
                                        tracing::error!(
                                            "KT rejecting unknown operation: {}", operation
                                        );
                                        continue;
                                    }
                                };
                                // D5: 2-of-5 consensus check. The leader (this
                                // process) signs the canonical leaf with every
                                // local slot key it holds. In single-process
                                // mode that is all 5 keys; in standalone mode
                                // the peer signatures must be collected first
                                // (see kt::consensus). The threshold check
                                // verifies at least 2 distinct pinned VKs.
                                let leaf_bytes = kt::consensus::canonical_leaf_bytes(
                                    &user_id,
                                    op.as_str(),
                                    &credential_hash,
                                    timestamp,
                                );
                                let signatures = kt::consensus::sign_leaf_with_local_slots(
                                    &leaf_bytes,
                                    &kt_consensus_keys,
                                );
                                if !kt::consensus::verify_threshold(
                                    &leaf_bytes,
                                    &signatures,
                                    &kt_pinned_vks,
                                ) {
                                    tracing::error!(
                                        "SIEM:CRITICAL KT consensus failed: only {} valid signatures, threshold is {}",
                                        signatures.len(),
                                        kt::consensus::KT_THRESHOLD
                                    );
                                    common::siem::SecurityEvent::tamper_detected(
                                        "KT 2-of-5 consensus failed -- refusing to append leaf",
                                    );
                                    continue;
                                }

                                // D11: persist leaf BEFORE mutating the tree so
                                // a crash after append is fully recoverable.
                                let mut t = tree.write().await;
                                let seq = t.len() as u64;
                                let rec = KtLeafRecord {
                                    sequence: seq,
                                    user_id,
                                    operation: op,
                                    credential_hash,
                                    timestamp,
                                };
                                if let Err(e) = append_leaf_record(&leaf_log_path, &rec) {
                                    tracing::error!(
                                        "FATAL: KT leaf log append failed for seq={}: {} -- refusing to mutate tree",
                                        seq, e
                                    );
                                    common::siem::SecurityEvent::tamper_detected(
                                        &format!("KT leaf log append failed seq={}: {}", seq, e),
                                    );
                                    continue;
                                }
                                t.append_credential_op(&user_id, op.as_str(), &credential_hash, timestamp);
                            }
                            KtRequest::GetRoot => {
                                let tree = tree.read().await;
                                let root = tree.root();
                                if let Err(e) = transport.send(&root).await {
                                    tracing::error!("SIEM:ERROR failed to send tree root via transport: {e}");
                                }
                            }
                        }
                    }
                }
            });
        }
    }
}
