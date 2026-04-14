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
//! Signing-key derivation: in single-process mode all 5 keys are derived from
//! `master_kek` via HKDF-SHA512 with per-slot info strings, so the local
//! service can synthesize its own 2-of-5 signatures for local dev/test. In
//! standalone deployments (one process per VM) only the local slot is
//! populated and the other signatures must arrive from peers before
//! `commit_leaf` is called.

use crypto::pq_sign;
use ml_dsa::{KeyGen, MlDsa87};

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

/// Derive the 5 per-node signing keys. In single-process mode all 5 slots
/// are populated from HKDF(master_kek, slot_info). In standalone mode only
/// the slot matching `MILNET_KT_NODE_INDEX` is populated.
pub fn synthesize_signing_keys() -> Vec<Option<pq_sign::PqSigningKey>> {
    use hkdf::Hkdf;
    use sha2::Sha512;
    use zeroize::Zeroize;

    let standalone = std::env::var("MILNET_KT_STANDALONE").as_deref() == Ok("1")
        || std::env::var("MILNET_KT_NODE_INDEX").is_ok();
    let local_slot: Option<usize> = std::env::var("MILNET_KT_NODE_INDEX")
        .ok()
        .and_then(|s| s.parse::<usize>().ok());

    let mut keys: Vec<Option<pq_sign::PqSigningKey>> = (0..KT_NODES).map(|_| None).collect();
    let test_mode = cfg!(test);

    for slot in 0..KT_NODES {
        if standalone && Some(slot) != local_slot {
            continue;
        }
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
    keys
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
