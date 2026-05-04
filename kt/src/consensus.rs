//! D5: KT leaf consensus — 2-of-5 rotating ML-DSA-87 signatures on every
//! append before the leaf is persisted or reflected in the Merkle tree.
//!
//! The KT service historically had a single proposer: any process with the
//! signing key could mint arbitrary leaves. The D5 consensus layer removes
//! that single point of compromise by requiring a leader to collect at least
//! 2 out of 5 node signatures over the leaf bytes before committing.
//!
//! Verifying-key pinning mirrors the D4 audit design: `build.rs` produces
//! `OUT_DIR/pinned_vks.bin` and the runtime loader parses it once at startup.
//!
//! Signing-key derivation (X-J): controlled by `MILNET_KT_DEPLOYMENT_MODE`.
//! * `distributed` (the only mode permitted in `MILNET_MILITARY_DEPLOYMENT=1`)
//!   reads ONLY the local slot's seed from `MILNET_KT_SIGNER_<i>_SEAL` (a
//!   TPM-sealed 32-byte hex). Peer signatures arrive over the consensus
//!   protocol before `verify_threshold` is called.
//! * `single` (dev / local integration only) synthesises all 5 keys from the
//!   master KEK via HKDF-SHA512. STARTUP CRITICAL is logged on activation;
//!   the binary refuses to start in this mode under
//!   `MILNET_MILITARY_DEPLOYMENT=1` because a single-host compromise yields
//!   full forgery capability.

use crypto::pq_sign;
use ml_dsa::{KeyGen, MlDsa87};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

/// Total KT consensus nodes.
pub const KT_NODES: usize = 5;

/// Threshold of valid signatures required to commit a leaf.
pub const KT_THRESHOLD: usize = 2;

/// Pinned verifying keys packed at compile time from the release-ceremony
/// `pinned_vks.bin`. See `kt/build.rs`.
const PINNED_VKS_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/pinned_vks.bin"));

/// Decoded pinned verifying keys loaded from `PINNED_VKS_BYTES`.
pub fn load_pinned_vks() -> Vec<pq_sign::PqVerifyingKey> {
    use ml_dsa::{EncodedVerifyingKey, VerifyingKey};
    let bytes = PINNED_VKS_BYTES;
    if bytes.len() < 4 {
        return Vec::new();
    }
    let n = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    let mut out = Vec::with_capacity(n);
    let mut offset = 4usize;
    for _ in 0..n {
        if offset + 4 > bytes.len() {
            return out;
        }
        let len = u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]) as usize;
        offset += 4;
        if offset + len > bytes.len() {
            return out;
        }
        if let Ok(enc) = EncodedVerifyingKey::<MlDsa87>::try_from(&bytes[offset..offset + len]) {
            out.push(VerifyingKey::<MlDsa87>::decode(&enc));
        }
        offset += len;
    }
    out
}

/// Assert 5 pinned VKs are available; panics in production if not.
pub fn require_pinned_vks_or_panic() {
    let vks = load_pinned_vks();
    if vks.len() != KT_NODES {
        let is_prod = std::env::var("MILNET_PRODUCTION").is_ok()
            || std::env::var("MILNET_MILITARY_DEPLOYMENT").is_ok();
        if is_prod {
            panic!(
                "FATAL: kt/pinned_vks.bin has {} keys, expected {}. \
                 Regenerate via release ceremony.",
                vks.len(),
                KT_NODES
            );
        } else {
            tracing::warn!(
                "kt pinned_vks.bin has {} keys (expected {}) — non-production placeholder",
                vks.len(),
                KT_NODES
            );
        }
    }
}

/// X-J: KT signing-key deployment mode. The 2-of-5 consensus property only
/// holds when each signer slot lives in a separate process on a separate
/// failure domain. Single-process mode synthesises all 5 keys from one
/// master KEK, which is operationally equivalent to a 1-of-1 system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KtDeploymentMode {
    /// One process per slot; only the local slot's seed is loaded, sourced
    /// from a TPM-sealed env var (`MILNET_KT_SIGNER_<i>_SEAL`). This is the
    /// only mode permitted in `MILNET_MILITARY_DEPLOYMENT=1`.
    Distributed,
    /// One process synthesises all 5 keys from `master_kek`. Dev / local
    /// integration tests only — emits STARTUP CRITICAL on activation, and
    /// is refused outright in `MILNET_MILITARY_DEPLOYMENT=1`.
    Single,
}

#[derive(Debug, thiserror::Error)]
pub enum KtKeyError {
    #[error("MILNET_KT_DEPLOYMENT_MODE={0:?} not recognized; expected `single` or `distributed`")]
    BadMode(String),
    #[error(
        "MILNET_KT_DEPLOYMENT_MODE=single is forbidden in MILNET_MILITARY_DEPLOYMENT=1: a \
         single-host derivation of all 5 signer keys defeats the 2-of-5 consensus property"
    )]
    SingleInMilitary,
    #[error("MILNET_KT_DEPLOYMENT_MODE=distributed requires MILNET_KT_NODE_INDEX in 0..{KT_NODES}")]
    NodeIndexMissing,
    #[error(
        "MILNET_KT_DEPLOYMENT_MODE=distributed: signer seed env `MILNET_KT_SIGNER_{0}_SEAL` \
         is unset (must be a TPM-sealed 32-byte hex seed)"
    )]
    SealMissing(usize),
    #[error("MILNET_KT_SIGNER_{slot}_SEAL is malformed: {detail}")]
    SealMalformed { slot: usize, detail: String },
}

const SINGLE_MODE_CRITICAL_LOG: &str =
    "kt_consensus.SINGLE_HOST_MODE_NOT_FOR_PRODUCTION single-process mode synthesises all 5 \
     KT consensus signer keys from one master KEK; a single-host compromise yields full \
     forgery capability. Refuse to deploy this in production.";

/// Determine the deployment mode from env. Must be called by every entry
/// path that loads consensus signing keys, including tests, so the same
/// production-strict logic is exercised everywhere.
pub fn select_deployment_mode() -> Result<KtDeploymentMode, KtKeyError> {
    // Production gating mirrors the rest of the workspace: literal "1".
    let military = std::env::var("MILNET_MILITARY_DEPLOYMENT").as_deref() == Ok("1");
    let raw = std::env::var("MILNET_KT_DEPLOYMENT_MODE")
        .unwrap_or_else(|_| {
            if military {
                "distributed".to_string()
            } else {
                "single".to_string()
            }
        });
    let mode = match raw.as_str() {
        "single" => KtDeploymentMode::Single,
        "distributed" => KtDeploymentMode::Distributed,
        other => return Err(KtKeyError::BadMode(other.to_string())),
    };
    if mode == KtDeploymentMode::Single && military {
        return Err(KtKeyError::SingleInMilitary);
    }
    Ok(mode)
}

/// X-J: Derive the per-node signing keys for the active deployment mode.
///
/// * `Distributed`: read TPM-sealed seed for the local slot only from
///   `MILNET_KT_SIGNER_<i>_SEAL` (32-byte hex) and refuse to derive any
///   other slot's key.
/// * `Single`: synthesise all 5 keys from the master KEK (legacy path).
///   Emits STARTUP CRITICAL via `tracing::error!` and is the only path
///   that retains the prior single-host derivation behaviour.
pub fn try_synthesize_signing_keys(
    mode: KtDeploymentMode,
) -> Result<Vec<Option<pq_sign::PqSigningKey>>, KtKeyError> {
    use hkdf::Hkdf;
    use sha2::Sha512;
    use zeroize::Zeroize;

    let mut keys: Vec<Option<pq_sign::PqSigningKey>> = (0..KT_NODES).map(|_| None).collect();
    let test_mode = cfg!(test);

    match mode {
        KtDeploymentMode::Distributed => {
            let local_slot: usize = std::env::var("MILNET_KT_NODE_INDEX")
                .ok()
                .and_then(|s| s.parse::<usize>().ok())
                .ok_or(KtKeyError::NodeIndexMissing)?;
            if local_slot >= KT_NODES {
                return Err(KtKeyError::NodeIndexMissing);
            }
            let env = format!("MILNET_KT_SIGNER_{}_SEAL", local_slot);
            let hex_seed = std::env::var(&env)
                .map_err(|_| KtKeyError::SealMissing(local_slot))?;
            let mut seed = [0u8; 32];
            let raw = hex::decode(hex_seed.trim()).map_err(|e| KtKeyError::SealMalformed {
                slot: local_slot,
                detail: format!("hex: {e}"),
            })?;
            if raw.len() != 32 {
                return Err(KtKeyError::SealMalformed {
                    slot: local_slot,
                    detail: format!("expected 32 bytes, got {}", raw.len()),
                });
            }
            seed.copy_from_slice(&raw);
            let kp = MlDsa87::from_seed(&seed.into());
            seed.zeroize();
            keys[local_slot] = Some(kp.signing_key().clone());
            tracing::info!(
                slot = local_slot,
                "KT distributed mode: loaded local signer seed from {env} (TPM-sealed)"
            );
        }
        KtDeploymentMode::Single => {
            // STARTUP CRITICAL — the security property ("2-of-5 quorum") is
            // forfeit until each slot moves to its own host.
            tracing::error!(
                target: "siem",
                severity = "CRITICAL",
                action = "kt_consensus.single_host_mode_not_for_production",
                "{}",
                SINGLE_MODE_CRITICAL_LOG
            );
            for slot in 0..KT_NODES {
                let mut seed = [0u8; 32];
                if test_mode {
                    use sha2::Digest;
                    let h = Sha512::digest(format!("TEST-KT-SLOT-{}", slot).as_bytes());
                    seed.copy_from_slice(&h[..32]);
                } else {
                    let kek = common::sealed_keys::cached_master_kek();
                    let hk = Hkdf::<Sha512>::new(Some(b"MILNET-KT-NODE-SIGN-v1"), kek);
                    let info = format!("kt-node-signing-{}", slot);
                    hk.expand(info.as_bytes(), &mut seed)
                        .expect("HKDF expand for KT node signing seed");
                }
                let kp = MlDsa87::from_seed(&seed.into());
                seed.zeroize();
                keys[slot] = Some(kp.signing_key().clone());
            }
        }
    }
    Ok(keys)
}

/// X-J: Convenience wrapper that selects the deployment mode and derives
/// the keys, exiting fatally on any configuration violation. This is the
/// only entry point the binary should call at startup; tests should call
/// `try_synthesize_signing_keys` directly with an explicit mode so they
/// can assert the error variants.
pub fn synthesize_signing_keys() -> Vec<Option<pq_sign::PqSigningKey>> {
    let mode = match select_deployment_mode() {
        Ok(m) => m,
        Err(e) => {
            tracing::error!(
                target: "siem",
                severity = "CRITICAL",
                action = "kt_consensus.deployment_mode_invalid",
                "FATAL: KT deployment mode invalid: {e}"
            );
            std::process::exit(198);
        }
    };
    match try_synthesize_signing_keys(mode) {
        Ok(k) => k,
        Err(e) => {
            tracing::error!(
                target: "siem",
                severity = "CRITICAL",
                action = "kt_consensus.signer_keys_unavailable",
                "FATAL: KT signer keys unavailable: {e}"
            );
            std::process::exit(198);
        }
    }
}

/// A single signer-slot signature over the leaf canonical bytes.
#[derive(Debug, Clone)]
pub struct LeafSignature {
    pub slot: usize,
    pub signature: Vec<u8>,
}

/// D5 leader consensus: given the canonical leaf bytes, sign with every
/// locally-held slot key. The returned signatures can be broadcast to peers
/// (standalone) or fed directly into `verify_threshold` (single-process).
pub fn sign_leaf_with_local_slots(
    leaf_bytes: &[u8],
    local_keys: &[Option<pq_sign::PqSigningKey>],
) -> Vec<LeafSignature> {
    let mut out = Vec::new();
    for (slot, key) in local_keys.iter().enumerate() {
        if let Some(sk) = key {
            out.push(LeafSignature {
                slot,
                signature: pq_sign::pq_sign_raw(sk, leaf_bytes),
            });
        }
    }
    out
}

/// Verify that at least `KT_THRESHOLD` distinct slot signatures are valid
/// against the pinned VK list. Returns `true` on success.
pub fn verify_threshold(
    leaf_bytes: &[u8],
    signatures: &[LeafSignature],
    pinned_vks: &[pq_sign::PqVerifyingKey],
) -> bool {
    if pinned_vks.len() != KT_NODES {
        return false;
    }
    let mut seen = [false; KT_NODES];
    let mut valid = 0usize;
    for sig in signatures {
        if sig.slot >= KT_NODES || seen[sig.slot] {
            continue;
        }
        let vk = &pinned_vks[sig.slot];
        if pq_sign::pq_verify_raw(vk, leaf_bytes, &sig.signature) {
            seen[sig.slot] = true;
            valid += 1;
            if valid >= KT_THRESHOLD {
                return true;
            }
        }
    }
    false
}

/// Canonicalize a leaf's consensus payload: `user_id || op || cred_hash || timestamp_be`.
/// Stable across restarts — never change the format without bumping a version tag.
pub fn canonical_leaf_bytes(
    user_id: &uuid::Uuid,
    operation: &str,
    credential_hash: &[u8; 32],
    timestamp: i64,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + operation.len() + 32 + 8 + 4);
    out.extend_from_slice(b"MILNET-KT-LEAF-v1");
    out.extend_from_slice(user_id.as_bytes());
    out.extend_from_slice(&(operation.len() as u32).to_le_bytes());
    out.extend_from_slice(operation.as_bytes());
    out.extend_from_slice(credential_hash);
    out.extend_from_slice(&timestamp.to_be_bytes());
    out
}

// ---------------------------------------------------------------------------
// External checkpoint publication — append-only hash-chained JSONL log
// ---------------------------------------------------------------------------

/// Default path for the append-only KT checkpoint log.
pub const DEFAULT_CHECKPOINT_LOG_PATH: &str = "/var/lib/milnet/kt_checkpoints.jsonl";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    pub tree_size: u64,
    pub range_start: u64,
    pub range_end: u64,
    #[serde(with = "hex_64")]
    pub root: [u8; 64],
    pub epoch_id: u64,
    pub timestamp_us: i64,
    #[serde(with = "hex_64")]
    pub prev_hash: [u8; 64],
    pub signatures: Vec<CheckpointSignature>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointSignature {
    pub slot: usize,
    #[serde(with = "hex_vec")]
    pub signature: Vec<u8>,
}

pub fn canonical_checkpoint_bytes(cp: &Checkpoint) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + 8 + 8 + 64 + 8 + 8 + 64);
    out.extend_from_slice(b"MILNET-KT-CHECKPOINT-v1");
    out.extend_from_slice(&cp.tree_size.to_be_bytes());
    out.extend_from_slice(&cp.range_start.to_be_bytes());
    out.extend_from_slice(&cp.range_end.to_be_bytes());
    out.extend_from_slice(&cp.root);
    out.extend_from_slice(&cp.epoch_id.to_be_bytes());
    out.extend_from_slice(&cp.timestamp_us.to_be_bytes());
    out.extend_from_slice(&cp.prev_hash);
    out
}

pub fn hash_checkpoint(cp: &Checkpoint) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(canonical_checkpoint_bytes(cp));
    for s in &cp.signatures {
        h.update((s.slot as u32).to_be_bytes());
        h.update(&s.signature);
    }
    let mut out = [0u8; 64];
    out.copy_from_slice(&h.finalize());
    out
}

pub fn verify_checkpoint(cp: &Checkpoint, pinned_vks: &[pq_sign::PqVerifyingKey]) -> bool {
    if pinned_vks.len() != KT_NODES {
        return false;
    }
    let msg = canonical_checkpoint_bytes(cp);
    let mut seen = [false; KT_NODES];
    let mut valid = 0usize;
    for s in &cp.signatures {
        if s.slot >= KT_NODES || seen[s.slot] {
            continue;
        }
        if pq_sign::pq_verify_raw(&pinned_vks[s.slot], &msg, &s.signature) {
            seen[s.slot] = true;
            valid += 1;
            if valid >= KT_THRESHOLD {
                return true;
            }
        }
    }
    false
}

pub fn sign_checkpoint(
    cp_no_sigs: &Checkpoint,
    local_keys: &[Option<pq_sign::PqSigningKey>],
) -> Vec<CheckpointSignature> {
    let msg = canonical_checkpoint_bytes(cp_no_sigs);
    let mut out = Vec::new();
    for (slot, key) in local_keys.iter().enumerate() {
        if let Some(sk) = key {
            out.push(CheckpointSignature {
                slot,
                signature: pq_sign::pq_sign_raw(sk, &msg),
            });
        }
    }
    out
}

pub fn append_checkpoint(
    path: &std::path::Path,
    cp: &Checkpoint,
) -> Result<(), std::io::Error> {
    use std::io::Write;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let expected_prev = last_hash_in_log(path)?;
    if cp.prev_hash != expected_prev {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "checkpoint prev_hash does not match last row hash",
        ));
    }
    let mut line = serde_json::to_string(cp)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    line.push('\n');
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    f.write_all(line.as_bytes())?;
    f.sync_all()?;
    Ok(())
}

pub fn last_hash_in_log(path: &std::path::Path) -> Result<[u8; 64], std::io::Error> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok([0u8; 64]),
        Err(e) => return Err(e),
    };
    let text = std::str::from_utf8(&bytes).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, format!("utf8: {e}"))
    })?;
    let mut last: [u8; 64] = [0u8; 64];
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        let cp: Checkpoint = serde_json::from_str(line).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, format!("row: {e}"))
        })?;
        last = hash_checkpoint(&cp);
    }
    Ok(last)
}

pub fn publish_checkpoint(
    log_path: Option<&std::path::Path>,
    tree_size: u64,
    range_start: u64,
    range_end: u64,
    root: [u8; 64],
    epoch_id: u64,
    signatures: Vec<CheckpointSignature>,
) -> Result<Checkpoint, std::io::Error> {
    let default_path_buf = std::path::PathBuf::from(
        std::env::var("MILNET_KT_CHECKPOINT_LOG")
            .unwrap_or_else(|_| DEFAULT_CHECKPOINT_LOG_PATH.to_string()),
    );
    let path: &std::path::Path = match log_path {
        Some(p) => p,
        None => default_path_buf.as_path(),
    };
    let prev_hash = last_hash_in_log(path)?;
    let timestamp_us = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as i64;
    let cp = Checkpoint {
        tree_size,
        range_start,
        range_end,
        root,
        epoch_id,
        timestamp_us,
        prev_hash,
        signatures,
    };
    append_checkpoint(path, &cp)?;
    gossip_checkpoint_best_effort(&cp);
    Ok(cp)
}

fn gossip_checkpoint_best_effort(cp: &Checkpoint) {
    let addrs = match std::env::var("MILNET_KT_WITNESSES") {
        Ok(v) if !v.is_empty() => v,
        _ => return,
    };
    let payload = match serde_json::to_vec(cp) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(error = %e, "kt: failed to serialize checkpoint for gossip");
            return;
        }
    };
    for addr in addrs.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
        let sock: std::net::SocketAddr = match addr.parse() {
            Ok(s) => s,
            Err(_) => {
                tracing::warn!(addr = %addr, "kt: invalid witness address");
                continue;
            }
        };
        match std::net::TcpStream::connect_timeout(&sock, std::time::Duration::from_secs(2)) {
            Ok(mut s) => {
                use std::io::Write as _;
                let _ = s.set_write_timeout(Some(std::time::Duration::from_secs(2)));
                if let Err(e) = s.write_all(&payload) {
                    tracing::warn!(addr = %addr, error = %e, "kt: witness gossip write failed");
                }
            }
            Err(e) => {
                tracing::warn!(addr = %addr, error = %e, "kt: witness gossip connect failed");
            }
        }
    }
}

pub fn prove_inclusion(
    tree: &crate::merkle::MerkleTree,
    leaf_idx: usize,
) -> Option<Vec<[u8; 64]>> {
    tree.inclusion_proof(leaf_idx)
}

mod hex_64 {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(bytes: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let s = String::deserialize(d)?;
        let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if v.len() != 64 {
            return Err(serde::de::Error::custom("expected 64 bytes"));
        }
        let mut out = [0u8; 64];
        out.copy_from_slice(&v);
        Ok(out)
    }
}

mod hex_vec {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_threshold() {
        // Build 5 test VKs by signing deterministically and verifying ourselves.
        let keys = synthesize_signing_keys();
        let vks: Vec<pq_sign::PqVerifyingKey> =
            keys.iter().map(|k| k.as_ref().unwrap().verifying_key().clone()).collect();

        let leaf = canonical_leaf_bytes(
            &uuid::Uuid::nil(),
            "bind",
            &[0u8; 32],
            123,
        );
        let sigs = sign_leaf_with_local_slots(&leaf, &keys);
        assert_eq!(sigs.len(), KT_NODES);
        assert!(verify_threshold(&leaf, &sigs, &vks));

        // Below threshold fails.
        assert!(!verify_threshold(&leaf, &sigs[..1], &vks));
    }
}
