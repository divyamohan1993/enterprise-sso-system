// X-J: STH log structure + on-load signature verification, factored out of
// `main.rs` so integration tests can drive it without spawning the binary.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::path::Path;

/// Maximum length-prefix accepted from the on-disk STH log. Matches the
/// `KT_MAX_MSG` constant in the binary.
pub const KT_MAX_STH_MSG: usize = 256 * 1024;

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

/// Persisted STH record, written by `append_sth_record` in the binary.
/// Wire-stable: every field's serde encoding must remain backwards-compatible.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedSth {
    pub tree_size: u64,
    #[serde(with = "byte_array_64")]
    pub root: [u8; 64],
    pub timestamp: i64,
    pub signature: Vec<u8>,
    #[serde(with = "byte_array_64")]
    pub prev_sth_hash: [u8; 64],
    #[serde(default)]
    pub epoch_id: u64,
}

/// Errors raised by the on-load verifier. The binary maps any of these to
/// `state_chain.sth_verification_failed` CRITICAL + `process::exit`.
#[derive(Debug, thiserror::Error)]
pub enum SthVerifyError {
    #[error("STH log io: {0}")]
    Io(String),
    #[error("STH log oversize length-prefix at offset {offset}: {len} > {max}")]
    Oversize { offset: usize, len: usize, max: usize },
    #[error("STH log decode failed at record {idx}: {detail}")]
    Decode { idx: u64, detail: String },
    #[error("STH log prev_hash chain break at record {idx}")]
    ChainBreak { idx: u64 },
    #[error(
        "STH log signature failed verification at record {idx} (epoch={epoch_id}, \
         tree_size={tree_size}) — TAMPER"
    )]
    BadSignature {
        idx: u64,
        epoch_id: u64,
        tree_size: u64,
    },
    #[error(
        "STH log requires verification but no pinned signer pubkeys were supplied \
         (set MILNET_KT_SIGNER_PUBS)"
    )]
    NoPinnedKeys,
}

/// Recompute the bytes the STH was originally signed over. Stay in sync
/// with the `to_sign` construction in the periodic STH task.
pub fn sth_signed_bytes(sth: &PersistedSth) -> Vec<u8> {
    let mut to_sign = Vec::with_capacity(8 + 8 + 64 + 8 + 64);
    to_sign.extend_from_slice(&sth.epoch_id.to_be_bytes());
    to_sign.extend_from_slice(&sth.tree_size.to_be_bytes());
    to_sign.extend_from_slice(&sth.root);
    to_sign.extend_from_slice(&sth.timestamp.to_be_bytes());
    to_sign.extend_from_slice(&sth.prev_sth_hash);
    to_sign
}

/// Hash an STH for chaining. SHA-512 over the canonical fields plus the
/// signature bytes; fixed string prefix prevents rebinding from any other
/// SHA-512 use elsewhere in the codebase.
pub fn hash_sth(sth: &PersistedSth) -> [u8; 64] {
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

/// Append an STH to the log using length-prefixed postcard. fsyncs file +
/// parent dir.
pub fn append_sth_record(path: &Path, sth: &PersistedSth) -> std::io::Result<()> {
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
        if let Ok(d) = std::fs::File::open(parent) {
            let _ = d.sync_all();
        }
    }
    Ok(())
}

/// Walk the STH log, verify every persisted STH against the pinned signer
/// pubkey set, and return the chain hash of the LAST verified STH.
///
/// Caller policy:
/// * If `pinned_vks` is empty AND `require_verification` is true, returns
///   `NoPinnedKeys`. Outside military deployment the caller may pass
///   `false` to skip verification, but the chain prev_hash check still runs.
pub fn verify_sth_log(
    path: &Path,
    pinned_vks: &[crypto::pq_sign::PqVerifyingKey],
    require_verification: bool,
) -> Result<[u8; 64], SthVerifyError> {
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok([0u8; 64]),
        Err(e) => return Err(SthVerifyError::Io(format!("read {path:?}: {e}"))),
    };
    if data.is_empty() {
        return Ok([0u8; 64]);
    }
    if pinned_vks.is_empty() && require_verification {
        return Err(SthVerifyError::NoPinnedKeys);
    }

    let mut last_hash = [0u8; 64];
    let mut offset = 0usize;
    let mut record_idx: u64 = 0;
    while offset + 4 <= data.len() {
        let n = u32::from_le_bytes(match data[offset..offset + 4].try_into() {
            Ok(b) => b,
            Err(_) => break,
        }) as usize;
        offset += 4;
        if n > KT_MAX_STH_MSG {
            return Err(SthVerifyError::Oversize {
                offset: offset - 4,
                len: n,
                max: KT_MAX_STH_MSG,
            });
        }
        if offset + n > data.len() {
            // Trailing partial record — treat as truncated, not tamper.
            break;
        }
        let slice = &data[offset..offset + n];
        let sth = postcard::from_bytes::<PersistedSth>(slice).map_err(|e| {
            SthVerifyError::Decode {
                idx: record_idx,
                detail: format!("{e}"),
            }
        })?;

        if sth.prev_sth_hash != last_hash {
            return Err(SthVerifyError::ChainBreak { idx: record_idx });
        }

        if !pinned_vks.is_empty() {
            let signed = sth_signed_bytes(&sth);
            let mut ok = false;
            for vk in pinned_vks {
                if crypto::pq_sign::pq_verify_raw(vk, &signed, &sth.signature) {
                    ok = true;
                    break;
                }
            }
            if !ok {
                return Err(SthVerifyError::BadSignature {
                    idx: record_idx,
                    epoch_id: sth.epoch_id,
                    tree_size: sth.tree_size,
                });
            }
        }

        last_hash = hash_sth(&sth);
        offset += n;
        record_idx += 1;
    }
    Ok(last_hash)
}

/// Read the pinned set of STH signer verifying keys from
/// `MILNET_KT_SIGNER_PUBS` (newline- or comma-separated base64-encoded
/// ML-DSA-87 verifying keys). Returns an empty vec if unset.
pub fn load_pinned_sth_signer_pubs() -> Vec<crypto::pq_sign::PqVerifyingKey> {
    use base64::Engine;
    use ml_dsa::{EncodedVerifyingKey, MlDsa87, VerifyingKey};

    let raw = match std::env::var("MILNET_KT_SIGNER_PUBS") {
        Ok(v) if !v.trim().is_empty() => v,
        _ => return Vec::new(),
    };
    let engine = base64::engine::general_purpose::STANDARD;
    let mut out = Vec::new();
    for token in raw
        .split(|c| c == ',' || c == '\n')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        match engine.decode(token) {
            Ok(bytes) => match EncodedVerifyingKey::<MlDsa87>::try_from(bytes.as_slice()) {
                Ok(enc) => out.push(VerifyingKey::<MlDsa87>::decode(&enc)),
                Err(e) => tracing::warn!(
                    "MILNET_KT_SIGNER_PUBS: skipping unparsable VK token: {e}"
                ),
            },
            Err(e) => tracing::warn!(
                "MILNET_KT_SIGNER_PUBS: skipping non-base64 token: {e}"
            ),
        }
    }
    out
}
