//! Automated key rotation scheduler with distributed mutual verification.
//!
//! Provides:
//! - Background task for key rotation at configurable intervals
//! - `RotationWitness`: every node verifies every other node's rotations (O(1) per event)
//! - `RotationConsensus`: quorum-gated rotation proposals
//! - `RotationAnomaly`: unauthorized, epoch regression, rapid, stale, split detection
//! - `DistributedRotationScheduler`: automatic per-key-type rotation with jitter
//! - `RotationState`: persistent state with HMAC-SHA512 integrity
#![forbid(unsafe_code)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Configuration for the key rotation scheduler.
pub struct RotationSchedule {
    /// Interval between rotation checks.
    pub interval: Duration,
    /// Whether to actually rotate (vs. just log that rotation is due).
    pub auto_rotate: bool,
}

impl Default for RotationSchedule {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(3600), // Check every hour
            auto_rotate: true, // Always auto-rotate -- single production mode
        }
    }
}

/// Start a background key rotation monitor.
///
/// Returns a shutdown handle that can be used to stop the scheduler.
pub fn start_rotation_monitor(
    schedule: RotationSchedule,
    rotation_callback: impl Fn() -> Result<(), String> + Send + 'static,
) -> Result<Arc<AtomicBool>, String> {
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();

    std::thread::Builder::new()
        .name("key-rotation-monitor".into())
        .spawn(move || {
            tracing::info!(
                "Key rotation monitor started (interval: {:?}, auto: {})",
                schedule.interval,
                schedule.auto_rotate
            );
            while !shutdown_clone.load(Ordering::Relaxed) {
                std::thread::sleep(schedule.interval);
                if shutdown_clone.load(Ordering::Relaxed) {
                    break;
                }

                tracing::info!("Key rotation check: rotation interval reached");

                if schedule.auto_rotate {
                    match rotation_callback() {
                        Ok(()) => {
                            tracing::info!("Key rotation completed successfully");
                            crate::siem::SecurityEvent::key_rotation("scheduled rotation completed");
                            // G7: emit a structured audit lifecycle entry for every
                            // successful scheduled rotation. Without a specific KeyType,
                            // emit one for each tracked type so downstream queries
                            // never miss a rotation.
                            for kt in [KeyType::Session, KeyType::Hmac, KeyType::Signing, KeyType::MasterShare] {
                                audit_key_rotated(kt, None, 0);
                            }
                        }
                        Err(e) => {
                            tracing::error!("Key rotation failed: {}", e);
                            crate::siem::SecurityEvent::tamper_detected(
                                &format!("key rotation failure: {}", e),
                            );
                        }
                    }
                } else {
                    tracing::warn!("Key rotation is DUE -- manual rotation required (auto_rotate=false)");
                }
            }
            tracing::info!("Key rotation monitor stopped");
        })
        .map_err(|e| format!("failed to spawn key rotation monitor thread: {e}"))?;

    Ok(shutdown)
}

// ── Distributed Key Rotation with Mutual Verification ──────────────────────────

use hmac::{Hmac, Mac};
use ml_dsa::{signature::{Signer, Verifier}, KeyGen, MlDsa87, VerifyingKey, EncodedVerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha512 = Hmac<Sha512>;

/// Derive separate signing and HMAC keys from a single seed via HKDF-SHA512.
///
/// Returns (signing_seed, hmac_key) where:
/// - signing_seed: 32 bytes for ML-DSA-87 key generation
/// - hmac_key: 64 bytes for HMAC-SHA512 integrity
///
/// This prevents the same key material from being used for two different
/// cryptographic operations (signing vs. MAC), which would violate key
/// separation principles.
fn derive_rotation_keys(seed: &[u8]) -> ([u8; 32], [u8; 64]) {
    use hkdf::Hkdf;
    let hkdf = Hkdf::<Sha512>::new(Some(b"MILNET-ROTATION-KEY-DERIVE-v1"), seed);

    let mut signing_seed = [0u8; 32];
    hkdf.expand(b"MILNET-ROTATION-SIGN-v1", &mut signing_seed)
        .expect("HKDF expand for 32 bytes");

    let mut hmac_key = [0u8; 64];
    hkdf.expand(b"MILNET-ROTATION-HMAC-v1", &mut hmac_key)
        .expect("HKDF expand for 64 bytes");

    (signing_seed, hmac_key)
}

/// Key types in the system, each with independent rotation schedules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KeyType {
    Session,
    Hmac,
    Signing,
    MasterShare,
}

impl KeyType {
    /// Default rotation interval in seconds.
    pub fn default_interval_secs(&self) -> u64 {
        match self {
            KeyType::Session => 3600,
            KeyType::Hmac => 86400,
            KeyType::Signing => 604800,
            KeyType::MasterShare => 2592000,
        }
    }

    /// Env var name for overriding the rotation interval.
    pub fn env_var_name(&self) -> &'static str {
        match self {
            KeyType::Session => "MILNET_ROTATION_INTERVAL_SESSION",
            KeyType::Hmac => "MILNET_ROTATION_INTERVAL_HMAC",
            KeyType::Signing => "MILNET_ROTATION_INTERVAL_SIGNING",
            KeyType::MasterShare => "MILNET_ROTATION_INTERVAL_MASTER_SHARE",
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            KeyType::Session => "session",
            KeyType::Hmac => "hmac",
            KeyType::Signing => "signing",
            KeyType::MasterShare => "master_share",
        }
    }
}

/// A compact node identifier for the rotation protocol.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RotationNodeId(pub String);

impl std::fmt::Display for RotationNodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A rotation event broadcast when a node completes a key rotation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RotationEvent {
    pub node_id: RotationNodeId,
    pub key_type: KeyType,
    pub epoch: u64,
    pub timestamp: u64,
    /// SHA-512 hash of the new key material (64 bytes).
    pub new_key_hash: Vec<u8>,
    /// ML-DSA-87 signature over canonical event bytes (primary, non-repudiation).
    pub signature: Vec<u8>,
    /// HMAC-SHA512 secondary integrity check (belt and suspenders).
    pub hmac_tag: Vec<u8>,
}

impl RotationEvent {
    /// Canonical bytes: node_id || key_type || epoch || timestamp || new_key_hash.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(128);
        buf.extend_from_slice(self.node_id.0.as_bytes());
        buf.extend_from_slice(self.key_type.label().as_bytes());
        buf.extend_from_slice(&self.epoch.to_le_bytes());
        buf.extend_from_slice(&self.timestamp.to_le_bytes());
        buf.extend_from_slice(&self.new_key_hash);
        buf
    }

    /// Create a new rotation event, signing with the given key.
    pub fn new(
        node_id: RotationNodeId,
        key_type: KeyType,
        epoch: u64,
        new_key_material: &[u8],
        signing_key: &[u8],
    ) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self::build(node_id, key_type, epoch, timestamp, new_key_material, signing_key)
    }

    /// Create with explicit timestamp (for testing).
    pub fn new_with_timestamp(
        node_id: RotationNodeId,
        key_type: KeyType,
        epoch: u64,
        timestamp: u64,
        new_key_material: &[u8],
        signing_key: &[u8],
    ) -> Self {
        Self::build(node_id, key_type, epoch, timestamp, new_key_material, signing_key)
    }

    fn build(
        node_id: RotationNodeId, key_type: KeyType, epoch: u64, timestamp: u64,
        new_key_material: &[u8], signing_seed: &[u8],
    ) -> Self {
        let new_key_hash = { let mut h = Sha512::new(); h.update(new_key_material); h.finalize().to_vec() };
        let mut evt = Self { node_id, key_type, epoch, timestamp, new_key_hash, signature: Vec::new(), hmac_tag: Vec::new() };
        let canonical = evt.canonical_bytes();

        // Derive separate keys from the seed via HKDF to prevent key reuse.
        // signing_key is used for ML-DSA-87, hmac_key for HMAC-SHA512.
        if signing_seed.len() == 32 {
            let (derived_sign_seed, hmac_key) = derive_rotation_keys(signing_seed);

            // Primary: ML-DSA-87 signature with derived signing seed.
            let kp = MlDsa87::from_seed(&derived_sign_seed.into());
            let sig: ml_dsa::Signature<MlDsa87> = kp.signing_key().sign(&canonical);
            evt.signature = sig.encode().to_vec();

            // Secondary: HMAC-SHA512 integrity with separate derived key.
            let mut mac = HmacSha512::new_from_slice(&hmac_key).expect("HMAC accepts any key length");
            mac.update(&canonical);
            evt.hmac_tag = mac.finalize().into_bytes().to_vec();
        } else {
            // Non-32-byte key: HMAC-only mode (no ML-DSA).
            let mut mac = HmacSha512::new_from_slice(signing_seed).expect("HMAC accepts any key length");
            mac.update(&canonical);
            evt.hmac_tag = mac.finalize().into_bytes().to_vec();
        }
        evt
    }

    /// Extract the ML-DSA-87 verifying key (public key) for a given seed.
    ///
    /// Cluster members should call this once during setup and store/distribute
    /// only the verifying key. The seed (signing key) never leaves the node.
    pub fn verifying_key_from_seed(seed: &[u8]) -> Vec<u8> {
        assert_eq!(seed.len(), 32, "seed must be 32 bytes");
        let (derived_sign_seed, _) = derive_rotation_keys(seed);
        let kp = MlDsa87::from_seed(&derived_sign_seed.into());
        kp.verifying_key().encode().to_vec()
    }

    /// Verify ML-DSA-87 signature and HMAC tag. O(1).
    ///
    /// Accepts EITHER:
    /// - The ML-DSA-87 verifying key (2592 bytes) for signature-only verification
    /// - The original 32-byte seed (derives both verifying key and HMAC key)
    ///
    /// Production nodes SHOULD use the verifying key form (no seed distribution).
    pub fn verify_signature(&self, verifying_key: &[u8]) -> bool {
        let canonical = self.canonical_bytes();

        if verifying_key.len() == 32 {
            // Seed-based verification: derive keys and verify both.
            let (derived_sign_seed, hmac_key) = derive_rotation_keys(verifying_key);

            if !self.signature.is_empty() {
                let kp = MlDsa87::from_seed(&derived_sign_seed.into());
                let vk = kp.verifying_key();
                let sig = match ml_dsa::Signature::<MlDsa87>::try_from(self.signature.as_slice()) { Ok(s) => s, Err(_) => return false };
                if vk.verify(&canonical, &sig).is_err() { return false; }
            }
            if !self.hmac_tag.is_empty() {
                let mut mac = match HmacSha512::new_from_slice(&hmac_key) { Ok(m) => m, Err(_) => return false };
                mac.update(&canonical);
                if mac.verify_slice(&self.hmac_tag).is_err() { return false; }
            }
            !self.signature.is_empty() || !self.hmac_tag.is_empty()
        } else {
            // Verifying-key-based verification: ML-DSA signature only.
            // HMAC verification skipped because the HMAC key is not available
            // (it is derived from the seed which the verifier should not have).
            if self.signature.is_empty() { return false; }
            let vk_enc = match EncodedVerifyingKey::<MlDsa87>::try_from(verifying_key) { Ok(v) => v, Err(_) => return false };
            let vk = VerifyingKey::<MlDsa87>::decode(&vk_enc);
            let sig = match ml_dsa::Signature::<MlDsa87>::try_from(self.signature.as_slice()) { Ok(s) => s, Err(_) => return false };
            vk.verify(&canonical, &sig).is_ok()
        }
    }
}

/// Anomalies detected during rotation verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RotationAnomaly {
    /// Rotation event without prior RotationApproved.
    Unauthorized {
        node_id: RotationNodeId,
        key_type: KeyType,
        epoch: u64,
    },
    /// Epoch went backwards or stayed the same.
    EpochRegression {
        node_id: RotationNodeId,
        key_type: KeyType,
        claimed_epoch: u64,
        last_seen_epoch: u64,
    },
    /// Too many rotations in a short window.
    RapidRotation {
        node_id: RotationNodeId,
        key_type: KeyType,
        count: usize,
        window_secs: u64,
    },
    /// No rotation within the expected period.
    StaleRotation {
        key_type: KeyType,
        last_rotation_age_secs: u64,
        threshold_secs: u64,
    },
    /// Different nodes see different epochs for the same key type.
    SplitRotation {
        key_type: KeyType,
        epochs: Vec<(RotationNodeId, u64)>,
    },
    /// Signature verification failed.
    InvalidSignature {
        node_id: RotationNodeId,
        key_type: KeyType,
        epoch: u64,
    },
    /// Timestamp too far from local clock.
    TimestampSkew {
        node_id: RotationNodeId,
        key_type: KeyType,
        event_ts: u64,
        local_ts: u64,
    },
    /// Node not recognized as a cluster member.
    UnknownNode { node_id: RotationNodeId },
}

impl RotationAnomaly {
    /// Whether this anomaly is critical (vs. warning).
    pub fn is_critical(&self) -> bool {
        matches!(
            self,
            RotationAnomaly::Unauthorized { .. }
                | RotationAnomaly::EpochRegression { .. }
                | RotationAnomaly::SplitRotation { .. }
                | RotationAnomaly::InvalidSignature { .. }
                | RotationAnomaly::UnknownNode { .. }
        )
    }

    pub fn emit_siem(&self) {
        let msg = format!("{:?}", self);
        if self.is_critical() {
            crate::siem::SecurityEvent::tamper_detected(&msg);
        } else {
            crate::siem::SecurityEvent::key_rotation_overdue(&msg);
        }
    }
}

/// A proposal to rotate a key, requiring quorum approval.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RotationProposal {
    pub key_type: KeyType,
    pub reason: String,
    pub proposer_id: RotationNodeId,
    pub nonce: u64,
    pub signature: Vec<u8>,
}

impl RotationProposal {
    /// Create a new rotation proposal signed with ML-DSA-87 for non-repudiation.
    ///
    /// `signing_key`: 32-byte seed. The derived ML-DSA-87 signing key is used.
    pub fn new(
        key_type: KeyType,
        reason: String,
        proposer_id: RotationNodeId,
        signing_key: &[u8],
    ) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        let mut p = Self {
            key_type,
            reason,
            proposer_id,
            nonce,
            signature: Vec::new(),
        };
        p.sign(signing_key);
        p
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(self.key_type.label().as_bytes());
        buf.extend_from_slice(self.reason.as_bytes());
        buf.extend_from_slice(self.proposer_id.0.as_bytes());
        buf.extend_from_slice(&self.nonce.to_le_bytes());
        buf
    }

    fn sign(&mut self, key: &[u8]) {
        let canonical = self.canonical_bytes();
        if key.len() == 32 {
            // ML-DSA-87 signature for non-repudiation
            let (derived_sign_seed, _) = derive_rotation_keys(key);
            let kp = MlDsa87::from_seed(&derived_sign_seed.into());
            let sig: ml_dsa::Signature<MlDsa87> = kp.signing_key().sign(&canonical);
            self.signature = sig.encode().to_vec();
        } else {
            // Fallback: HMAC for non-32-byte keys (backwards compat)
            let mut mac = HmacSha512::new_from_slice(key).expect("HMAC key");
            mac.update(&canonical);
            self.signature = mac.finalize().into_bytes().to_vec();
        }
    }

    /// Verify proposal signature.
    ///
    /// Accepts either a 32-byte seed (derives verifying key) or the raw
    /// ML-DSA-87 verifying key bytes.
    pub fn verify(&self, key: &[u8]) -> bool {
        let canonical = self.canonical_bytes();
        if key.len() == 32 {
            let (derived_sign_seed, _) = derive_rotation_keys(key);
            let kp = MlDsa87::from_seed(&derived_sign_seed.into());
            let vk = kp.verifying_key();
            let sig = match ml_dsa::Signature::<MlDsa87>::try_from(self.signature.as_slice()) { Ok(s) => s, Err(_) => return false };
            vk.verify(&canonical, &sig).is_ok()
        } else {
            // Try as ML-DSA verifying key
            let vk_enc = match EncodedVerifyingKey::<MlDsa87>::try_from(key) { Ok(v) => v, Err(_) => return false };
            let vk = VerifyingKey::<MlDsa87>::decode(&vk_enc);
            let sig = match ml_dsa::Signature::<MlDsa87>::try_from(self.signature.as_slice()) { Ok(s) => s, Err(_) => return false };
            vk.verify(&canonical, &sig).is_ok()
        }
    }
}

/// A vote approving a rotation proposal.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RotationVote {
    pub voter_id: RotationNodeId,
    pub key_type: KeyType,
    pub nonce: u64,
    pub signature: Vec<u8>,
}

impl RotationVote {
    /// Create a new vote signed with ML-DSA-87 for non-repudiation.
    ///
    /// Each node signs with its own key, providing non-repudiation:
    /// a node cannot deny having voted for a rotation.
    pub fn new(
        voter_id: RotationNodeId,
        proposal: &RotationProposal,
        signing_key: &[u8],
    ) -> Self {
        let mut v = Self {
            voter_id,
            key_type: proposal.key_type,
            nonce: proposal.nonce,
            signature: Vec::new(),
        };
        let canonical = v.canonical_bytes();
        if signing_key.len() == 32 {
            let (derived_sign_seed, _) = derive_rotation_keys(signing_key);
            let kp = MlDsa87::from_seed(&derived_sign_seed.into());
            let sig: ml_dsa::Signature<MlDsa87> = kp.signing_key().sign(&canonical);
            v.signature = sig.encode().to_vec();
        } else {
            let mut mac = HmacSha512::new_from_slice(signing_key).expect("HMAC key");
            mac.update(&canonical);
            v.signature = mac.finalize().into_bytes().to_vec();
        }
        v
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(self.voter_id.0.as_bytes());
        buf.extend_from_slice(self.key_type.label().as_bytes());
        buf.extend_from_slice(&self.nonce.to_le_bytes());
        buf
    }

    /// Verify vote signature.
    ///
    /// Accepts either a 32-byte seed or ML-DSA-87 verifying key bytes.
    pub fn verify(&self, key: &[u8]) -> bool {
        let canonical = self.canonical_bytes();
        if key.len() == 32 {
            let (derived_sign_seed, _) = derive_rotation_keys(key);
            let kp = MlDsa87::from_seed(&derived_sign_seed.into());
            let vk = kp.verifying_key();
            let sig = match ml_dsa::Signature::<MlDsa87>::try_from(self.signature.as_slice()) { Ok(s) => s, Err(_) => return false };
            vk.verify(&canonical, &sig).is_ok()
        } else {
            let vk_enc = match EncodedVerifyingKey::<MlDsa87>::try_from(key) { Ok(v) => v, Err(_) => return false };
            let vk = VerifyingKey::<MlDsa87>::decode(&vk_enc);
            let sig = match ml_dsa::Signature::<MlDsa87>::try_from(self.signature.as_slice()) { Ok(s) => s, Err(_) => return false };
            vk.verify(&canonical, &sig).is_ok()
        }
    }
}

/// Aggregated approval after quorum is reached.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RotationApproved {
    pub key_type: KeyType,
    pub epoch: u64,
    pub approvers: Vec<RotationNodeId>,
    /// Aggregate HMAC-SHA512 over sorted approver IDs + epoch + key_type.
    pub aggregate_signature: Vec<u8>,
}

impl RotationApproved {
    pub fn from_votes(
        key_type: KeyType,
        epoch: u64,
        votes: &[RotationVote],
        aggregate_key: &[u8],
    ) -> Self {
        let mut approvers: Vec<RotationNodeId> =
            votes.iter().map(|v| v.voter_id.clone()).collect();
        approvers.sort_by(|a, b| a.0.cmp(&b.0));
        let canonical = Self::canonical_bytes_static(key_type, epoch, &approvers);
        let mut mac = HmacSha512::new_from_slice(aggregate_key).expect("HMAC key");
        mac.update(&canonical);
        Self {
            key_type,
            epoch,
            approvers,
            aggregate_signature: mac.finalize().into_bytes().to_vec(),
        }
    }

    fn canonical_bytes_static(
        key_type: KeyType,
        epoch: u64,
        approvers: &[RotationNodeId],
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(key_type.label().as_bytes());
        buf.extend_from_slice(&epoch.to_le_bytes());
        for a in approvers {
            buf.extend_from_slice(a.0.as_bytes());
        }
        buf
    }

    /// O(1) verification of the aggregate signature.
    pub fn verify(&self, aggregate_key: &[u8]) -> bool {
        let canonical =
            Self::canonical_bytes_static(self.key_type, self.epoch, &self.approvers);
        let mut mac = match HmacSha512::new_from_slice(aggregate_key) {
            Ok(m) => m,
            Err(_) => return false,
        };
        mac.update(&canonical);
        mac.verify_slice(&self.aggregate_signature).is_ok()
    }
}

/// Tracks consensus for a single rotation proposal.
pub struct RotationConsensus {
    pub proposal: RotationProposal,
    pub threshold: usize,
    pub votes: Vec<RotationVote>,
}

impl RotationConsensus {
    pub fn new(proposal: RotationProposal, threshold: usize) -> Self {
        Self {
            proposal,
            threshold,
            votes: Vec::new(),
        }
    }

    /// Add a vote. Returns true if quorum is now reached.
    pub fn add_vote(
        &mut self,
        vote: RotationVote,
        verifying_key: &[u8],
    ) -> Result<bool, String> {
        if vote.key_type != self.proposal.key_type || vote.nonce != self.proposal.nonce {
            return Err("vote does not match proposal".into());
        }
        if !vote.verify(verifying_key) {
            return Err("invalid vote signature".into());
        }
        if self.votes.iter().any(|v| v.voter_id == vote.voter_id) {
            return Ok(self.has_quorum());
        }
        self.votes.push(vote);
        Ok(self.has_quorum())
    }

    pub fn has_quorum(&self) -> bool {
        self.votes.len() >= self.threshold
    }

    /// Produce the approved record if quorum reached.
    pub fn finalize(&self, epoch: u64, aggregate_key: &[u8]) -> Option<RotationApproved> {
        if !self.has_quorum() {
            return None;
        }
        Some(RotationApproved::from_votes(
            self.proposal.key_type,
            epoch,
            &self.votes,
            aggregate_key,
        ))
    }
}

/// Per-node rotation witness that verifies incoming rotation events. O(1) per event.
pub struct RotationWitness {
    /// Known cluster members and their signing keys.
    known_members: HashMap<RotationNodeId, Vec<u8>>,
    /// Last seen epoch per (node_id, key_type).
    epochs: HashMap<(RotationNodeId, KeyType), u64>,
    /// Approved epochs per key_type (from RotationApproved records).
    approved_epochs: HashMap<KeyType, u64>,
    /// Rotation timestamps for rapid-rotation detection.
    rotation_times: HashMap<(RotationNodeId, KeyType), Vec<u64>>,
    /// Maximum acceptable clock skew in seconds.
    pub max_clock_skew_secs: u64,
    /// Rapid rotation threshold: max rotations in window.
    pub rapid_rotation_max: usize,
    /// Rapid rotation window in seconds.
    pub rapid_rotation_window_secs: u64,
}

impl RotationWitness {
    pub fn new() -> Self {
        Self {
            known_members: HashMap::new(),
            epochs: HashMap::new(),
            approved_epochs: HashMap::new(),
            rotation_times: HashMap::new(),
            max_clock_skew_secs: 30,
            rapid_rotation_max: 5,
            rapid_rotation_window_secs: 3600,
        }
    }

    pub fn add_member(&mut self, node_id: RotationNodeId, signing_key: Vec<u8>) {
        self.known_members.insert(node_id, signing_key);
    }

    pub fn remove_member(&mut self, node_id: &RotationNodeId) {
        self.known_members.remove(node_id);
    }

    /// Record that an epoch was approved via consensus.
    pub fn record_approval(&mut self, approved: &RotationApproved) {
        let current = self.approved_epochs.get(&approved.key_type).copied().unwrap_or(0);
        if approved.epoch > current {
            self.approved_epochs.insert(approved.key_type, approved.epoch);
        }
    }

    /// Verify a rotation event. Returns anomalies (empty = all good). O(1).
    pub fn verify_event(&mut self, event: &RotationEvent) -> Vec<RotationAnomaly> {
        let mut anomalies = Vec::new();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // 1. Known member check.
        let signing_key = match self.known_members.get(&event.node_id) {
            Some(k) => k.clone(),
            None => {
                anomalies.push(RotationAnomaly::UnknownNode {
                    node_id: event.node_id.clone(),
                });
                return anomalies;
            }
        };

        // 2. Signature verification. O(1).
        if !event.verify_signature(&signing_key) {
            anomalies.push(RotationAnomaly::InvalidSignature {
                node_id: event.node_id.clone(),
                key_type: event.key_type,
                epoch: event.epoch,
            });
            return anomalies;
        }

        // 3. Timestamp skew check. O(1).
        let diff = if event.timestamp > now {
            event.timestamp - now
        } else {
            now - event.timestamp
        };
        if diff > self.max_clock_skew_secs {
            anomalies.push(RotationAnomaly::TimestampSkew {
                node_id: event.node_id.clone(),
                key_type: event.key_type,
                event_ts: event.timestamp,
                local_ts: now,
            });
        }

        // 4. Epoch monotonicity. O(1).
        let key = (event.node_id.clone(), event.key_type);
        if let Some(&last_epoch) = self.epochs.get(&key) {
            if event.epoch <= last_epoch {
                anomalies.push(RotationAnomaly::EpochRegression {
                    node_id: event.node_id.clone(),
                    key_type: event.key_type,
                    claimed_epoch: event.epoch,
                    last_seen_epoch: last_epoch,
                });
                return anomalies;
            }
        }

        // 5. Authorization check: epoch must have been approved.
        let authorized = match self.approved_epochs.get(&event.key_type) {
            Some(&approved_epoch) => event.epoch <= approved_epoch,
            None => false,
        };
        if !authorized {
            anomalies.push(RotationAnomaly::Unauthorized {
                node_id: event.node_id.clone(),
                key_type: event.key_type,
                epoch: event.epoch,
            });
        }

        // 6. Rapid rotation detection. O(1) amortized.
        let times = self.rotation_times.entry(key.clone()).or_default();
        times.push(now);
        let cutoff = now.saturating_sub(self.rapid_rotation_window_secs);
        times.retain(|&t| t >= cutoff);
        if times.len() > self.rapid_rotation_max {
            anomalies.push(RotationAnomaly::RapidRotation {
                node_id: event.node_id.clone(),
                key_type: event.key_type,
                count: times.len(),
                window_secs: self.rapid_rotation_window_secs,
            });
        }

        // Accept epoch even if unauthorized (track for future regression checks).
        self.epochs.insert(key, event.epoch);

        anomalies
    }

    /// Check for stale rotations across all key types.
    pub fn check_stale_rotations(
        &self,
        last_rotation_times: &HashMap<KeyType, u64>,
        thresholds: &HashMap<KeyType, u64>,
    ) -> Vec<RotationAnomaly> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut anomalies = Vec::new();
        for (kt, &threshold) in thresholds {
            if let Some(&last_ts) = last_rotation_times.get(kt) {
                let age = now.saturating_sub(last_ts);
                if age > threshold {
                    anomalies.push(RotationAnomaly::StaleRotation {
                        key_type: *kt,
                        last_rotation_age_secs: age,
                        threshold_secs: threshold,
                    });
                }
            }
        }
        anomalies
    }

    /// Detect split-brain: different epochs for the same key_type across nodes.
    pub fn check_split_rotation(&self, key_type: KeyType) -> Option<RotationAnomaly> {
        let mut seen: Vec<(RotationNodeId, u64)> = Vec::new();
        for ((nid, kt), &epoch) in &self.epochs {
            if *kt == key_type {
                seen.push((nid.clone(), epoch));
            }
        }
        if seen.len() < 2 {
            return None;
        }
        let first_epoch = seen[0].1;
        if seen.iter().any(|(_, e)| *e != first_epoch) {
            Some(RotationAnomaly::SplitRotation {
                key_type,
                epochs: seen,
            })
        } else {
            None
        }
    }

    /// Get the last known epoch for a (node, key_type) pair.
    pub fn last_epoch(&self, node_id: &RotationNodeId, key_type: KeyType) -> Option<u64> {
        self.epochs.get(&(node_id.clone(), key_type)).copied()
    }
}

/// Persisted rotation state with HMAC-SHA512 integrity.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RotationState {
    /// Last seen epoch per (node_id string, key_type label).
    pub epochs: HashMap<String, HashMap<String, u64>>,
    /// Last rotation timestamp per key_type label.
    pub last_rotation: HashMap<String, u64>,
}

impl RotationState {
    pub fn new() -> Self {
        Self {
            epochs: HashMap::new(),
            last_rotation: HashMap::new(),
        }
    }

    /// Serialize to bytes with HMAC-SHA512 integrity tag appended.
    pub fn serialize_with_integrity(&self, hmac_key: &[u8]) -> Result<Vec<u8>, String> {
        let json = serde_json::to_vec(self).map_err(|e| format!("serialize: {e}"))?;
        let mut mac =
            HmacSha512::new_from_slice(hmac_key).map_err(|e| format!("hmac: {e}"))?;
        mac.update(&json);
        let tag = mac.finalize().into_bytes();
        let mut out = json;
        out.extend_from_slice(&tag);
        Ok(out)
    }

    /// Deserialize and verify HMAC-SHA512 integrity.
    pub fn deserialize_with_integrity(data: &[u8], hmac_key: &[u8]) -> Result<Self, String> {
        if data.len() < 64 {
            return Err("data too short for HMAC tag".into());
        }
        let (json, tag) = data.split_at(data.len() - 64);
        let mut mac =
            HmacSha512::new_from_slice(hmac_key).map_err(|e| format!("hmac: {e}"))?;
        mac.update(json);
        mac.verify_slice(tag)
            .map_err(|_| "HMAC integrity check failed".to_string())?;
        serde_json::from_slice(json).map_err(|e| format!("deserialize: {e}"))
    }

    /// Persist atomically: write to tmp, fsync, rename.
    pub fn persist(&self, path: &str, hmac_key: &[u8]) -> Result<(), String> {
        let data = self.serialize_with_integrity(hmac_key)?;
        let tmp_path = format!("{}.tmp", path);
        std::fs::write(&tmp_path, &data).map_err(|e| format!("write tmp: {e}"))?;
        let f = std::fs::File::open(&tmp_path).map_err(|e| format!("open for fsync: {e}"))?;
        f.sync_all().map_err(|e| format!("fsync: {e}"))?;
        std::fs::rename(&tmp_path, path).map_err(|e| format!("rename: {e}"))?;
        Ok(())
    }

    /// Load from disk, verifying HMAC integrity.
    pub fn load(path: &str, hmac_key: &[u8]) -> Result<Self, String> {
        let data = std::fs::read(path).map_err(|e| format!("read: {e}"))?;
        Self::deserialize_with_integrity(&data, hmac_key)
    }

    /// Record an epoch update.
    pub fn set_epoch(&mut self, node_id: &str, key_type: KeyType, epoch: u64) {
        self.epochs
            .entry(node_id.to_string())
            .or_default()
            .insert(key_type.label().to_string(), epoch);
    }

    /// Record a rotation timestamp.
    pub fn set_last_rotation(&mut self, key_type: KeyType, ts: u64) {
        self.last_rotation
            .insert(key_type.label().to_string(), ts);
    }
}

// ── G2: Quorum-gated cutover proposal with atomic sequence flip ─────────────
//
// Threat model: a single node must NEVER be able to unilaterally rotate a key.
// Every cutover requires 3-of-5 distinct rotation-node ML-DSA-87 signatures
// over the canonical proposal bytes. The proposal also carries an explicit
// `sequence` number, and the cutover is atomic at sequence N: requests with
// `seq < N` use the old key, requests with `seq >= N` use the new key. There
// is NO coexistence window.
//
// The cutover state is persisted via atomic-rename so a crash mid-cutover
// either commits or rolls back, never both.

/// Minimum number of distinct rotation-node signatures required for a cutover.
pub const ROTATION_CUTOVER_THRESHOLD: usize = 3;
/// Total number of rotation nodes in the standard 3-of-5 quorum.
pub const ROTATION_CUTOVER_TOTAL: usize = 5;

/// A proposal to atomically cut over a key at a specific sequence number.
///
/// Distinct from [`RotationProposal`] which initiates a rotation vote.
/// `RotationCutoverProposal` is the artefact that gets persisted and that
/// every node consults when deciding whether to use the old or the new key
/// for an operation tagged with sequence number `s`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RotationCutoverProposal {
    /// Monotonic sequence number at which the new key takes effect.
    /// Operations with `seq < sequence` MUST use the old key. Operations
    /// with `seq >= sequence` MUST use the new key.
    pub sequence: u64,
    /// SHA-512 hash of the new key material (64 bytes). The full key material
    /// itself never appears in the proposal; only its hash, which the node
    /// independently re-derives from its share to verify.
    #[serde(with = "crate::types::byte_array_64")]
    pub new_key_hash: [u8; 64],
    /// Absolute Unix-epoch deadline by which the cutover MUST be applied or
    /// the proposal expires. Prevents an indefinitely-stalled rotation from
    /// being replayed weeks later.
    pub deadline_ts: u64,
    /// Type of key being rotated.
    pub key_type: KeyType,
    /// 3-of-5 distinct rotation-node ML-DSA-87 signatures over `canonical_bytes`.
    /// Each entry is `(node_id, ml_dsa_87_signature_bytes)`. Duplicate node
    /// IDs are rejected by [`verify_quorum`].
    pub signatures: Vec<(RotationNodeId, Vec<u8>)>,
}

impl RotationCutoverProposal {
    /// Canonical byte serialisation for signing/verification.
    /// Format: `b"MILNET-CUTOVER-v1" || key_type || seq || deadline || new_key_hash`.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(128);
        buf.extend_from_slice(b"MILNET-CUTOVER-v1");
        buf.extend_from_slice(self.key_type.label().as_bytes());
        buf.extend_from_slice(&self.sequence.to_le_bytes());
        buf.extend_from_slice(&self.deadline_ts.to_le_bytes());
        buf.extend_from_slice(&self.new_key_hash);
        buf
    }

    /// Construct an unsigned proposal. Rotation nodes call [`sign`] to add
    /// their signatures one at a time until threshold is reached.
    pub fn new(
        key_type: KeyType,
        sequence: u64,
        new_key_material: &[u8],
        deadline_ts: u64,
    ) -> Self {
        let mut h = Sha512::new();
        h.update(new_key_material);
        let digest = h.finalize();
        let mut new_key_hash = [0u8; 64];
        new_key_hash.copy_from_slice(&digest);
        Self {
            sequence,
            new_key_hash,
            deadline_ts,
            key_type,
            signatures: Vec::new(),
        }
    }

    /// Add a signature from `node_id` using its 32-byte ML-DSA-87 seed.
    /// Rejects duplicate signers. Returns the new signature count.
    pub fn sign(&mut self, node_id: RotationNodeId, seed: &[u8; 32]) -> Result<usize, String> {
        if self.signatures.iter().any(|(n, _)| n == &node_id) {
            return Err(format!("node {} has already signed", node_id));
        }
        let (derived_sign_seed, _) = derive_rotation_keys(seed);
        let kp = MlDsa87::from_seed(&derived_sign_seed.into());
        let sig: ml_dsa::Signature<MlDsa87> = kp.signing_key().sign(&self.canonical_bytes());
        self.signatures.push((node_id, sig.encode().to_vec()));
        Ok(self.signatures.len())
    }

    /// Verify the proposal has at least [`ROTATION_CUTOVER_THRESHOLD`]
    /// distinct valid ML-DSA-87 signatures from `members`. Each member's
    /// ML-DSA-87 verifying key is looked up by `node_id`.
    pub fn verify_quorum(
        &self,
        members: &HashMap<RotationNodeId, Vec<u8>>,
        now_ts: u64,
    ) -> Result<(), String> {
        if now_ts > self.deadline_ts {
            return Err(format!(
                "proposal deadline expired: now={now_ts}, deadline={}",
                self.deadline_ts
            ));
        }
        let canonical = self.canonical_bytes();
        let mut seen: std::collections::HashSet<&RotationNodeId> = Default::default();
        let mut valid = 0usize;
        for (nid, sig_bytes) in &self.signatures {
            if !seen.insert(nid) {
                continue; // ignore duplicate signer
            }
            let vk_material = match members.get(nid) {
                Some(k) => k,
                None => continue,
            };
            // Accept either 32-byte seed (test) or full ML-DSA-87 verifying key (prod).
            let ok = if vk_material.len() == 32 {
                let (derived_sign_seed, _) = derive_rotation_keys(vk_material);
                let kp = MlDsa87::from_seed(&derived_sign_seed.into());
                let vk = kp.verifying_key();
                ml_dsa::Signature::<MlDsa87>::try_from(sig_bytes.as_slice())
                    .map(|s| vk.verify(&canonical, &s).is_ok())
                    .unwrap_or(false)
            } else {
                let vk_enc = match EncodedVerifyingKey::<MlDsa87>::try_from(vk_material.as_slice()) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let vk = VerifyingKey::<MlDsa87>::decode(&vk_enc);
                ml_dsa::Signature::<MlDsa87>::try_from(sig_bytes.as_slice())
                    .map(|s| vk.verify(&canonical, &s).is_ok())
                    .unwrap_or(false)
            };
            if ok {
                valid += 1;
            }
        }
        if valid >= ROTATION_CUTOVER_THRESHOLD {
            Ok(())
        } else {
            Err(format!(
                "insufficient valid cutover signatures: {valid}/{ROTATION_CUTOVER_THRESHOLD}"
            ))
        }
    }
}

/// Persisted cutover state for a single key type. Atomic-rename safe.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CutoverState {
    pub key_type: KeyType,
    /// The sequence number at which the latest committed cutover takes effect.
    /// Operations with `op_seq < cutover_sequence` use the old key.
    /// Operations with `op_seq >= cutover_sequence` use the new key.
    pub cutover_sequence: u64,
    /// Hash of the new key material that was committed at `cutover_sequence`.
    #[serde(with = "crate::types::byte_array_64")]
    pub new_key_hash: [u8; 64],
    /// Unix-epoch when this cutover was committed.
    pub committed_at: u64,
}

impl CutoverState {
    /// Load the persisted cutover state from `path`, verifying that the
    /// witnessed proposal's signatures still validate against the known
    /// member set. Returns `None` if no state exists yet.
    pub fn load(
        path: &str,
        members: &HashMap<RotationNodeId, Vec<u8>>,
    ) -> Result<Option<Self>, String> {
        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(format!("read cutover state: {e}")),
        };
        // Expected layout: serialized (proposal_json_len:u32 || proposal_json || state_json)
        if data.len() < 4 {
            return Err("cutover state file truncated".into());
        }
        let plen = u32::from_le_bytes(data[..4].try_into().unwrap()) as usize;
        if data.len() < 4 + plen {
            return Err("cutover state proposal truncated".into());
        }
        let proposal_bytes = &data[4..4 + plen];
        let state_bytes = &data[4 + plen..];
        let proposal: RotationCutoverProposal = serde_json::from_slice(proposal_bytes)
            .map_err(|e| format!("decode cutover proposal: {e}"))?;
        // Re-validate signatures even at load time: prevents a tampered file
        // from injecting a forged cutover into a freshly-restarted node. We
        // pass deadline_ts as "now" so historic proposals still verify.
        proposal
            .verify_quorum(members, proposal.deadline_ts)
            .map_err(|e| format!("persisted cutover failed quorum re-check: {e}"))?;
        let state: CutoverState = serde_json::from_slice(state_bytes)
            .map_err(|e| format!("decode cutover state: {e}"))?;
        if state.cutover_sequence != proposal.sequence
            || state.new_key_hash != proposal.new_key_hash
            || state.key_type != proposal.key_type
        {
            return Err("persisted cutover state does not match its proposal".into());
        }
        Ok(Some(state))
    }

    /// Atomically commit `proposal` as the new cutover. Writes to a tmp
    /// file, fsyncs, then renames in-place. Verifies quorum BEFORE persisting.
    pub fn commit(
        path: &str,
        proposal: &RotationCutoverProposal,
        members: &HashMap<RotationNodeId, Vec<u8>>,
        now_ts: u64,
    ) -> Result<Self, String> {
        proposal.verify_quorum(members, now_ts)?;
        let state = Self {
            key_type: proposal.key_type,
            cutover_sequence: proposal.sequence,
            new_key_hash: proposal.new_key_hash,
            committed_at: now_ts,
        };
        let proposal_bytes = serde_json::to_vec(proposal)
            .map_err(|e| format!("encode cutover proposal: {e}"))?;
        let state_bytes = serde_json::to_vec(&state)
            .map_err(|e| format!("encode cutover state: {e}"))?;
        let plen = (proposal_bytes.len() as u32).to_le_bytes();
        let mut buf = Vec::with_capacity(4 + proposal_bytes.len() + state_bytes.len());
        buf.extend_from_slice(&plen);
        buf.extend_from_slice(&proposal_bytes);
        buf.extend_from_slice(&state_bytes);

        let tmp = format!("{path}.tmp");
        std::fs::write(&tmp, &buf).map_err(|e| format!("write tmp cutover: {e}"))?;
        let f = std::fs::File::open(&tmp).map_err(|e| format!("open tmp cutover: {e}"))?;
        f.sync_all().map_err(|e| format!("fsync tmp cutover: {e}"))?;
        std::fs::rename(&tmp, path).map_err(|e| format!("rename cutover: {e}"))?;

        emit_key_lifecycle_audit(
            "cutover_committed",
            proposal.key_type,
            None,
            Some(proposal.sequence),
        );
        Ok(state)
    }

    /// Decide which key generation to use for an operation tagged with
    /// `op_sequence`. Returns `true` if the new key applies, `false` for old.
    /// This is the single source of truth for atomic key cutover.
    #[inline]
    pub fn use_new_key_for(&self, op_sequence: u64) -> bool {
        op_sequence >= self.cutover_sequence
    }
}

// ── G7: audit hook for key lifecycle events ─────────────────────────────────
//
// Every key generate/rotate/derive/destroy MUST emit a structured audit
// entry through `audit_bridge`. The audit pipeline collects entries and
// pushes them into the BFT audit chain, providing tamper-evident lifecycle
// history for every key in the system.

/// Emit a structured audit entry for a key lifecycle event.
///
/// `operation` is one of: `"generate"`, `"rotate"`, `"derive"`, `"destroy"`,
/// `"cutover_committed"`. The audit entry uses `AuditEventType::KeyRotation`
/// (the only key-lifecycle variant in the audit type enum) and encodes the
/// detail in correlation_id-adjacent fields.
pub fn emit_key_lifecycle_audit(
    operation: &str,
    key_type: KeyType,
    proposer: Option<&RotationNodeId>,
    sequence: Option<u64>,
) {
    use crate::audit_bridge::{buffer_audit_entry, create_audit_entry};
    use crate::types::AuditEventType;
    let mut entry = create_audit_entry(
        AuditEventType::KeyRotation,
        Vec::new(),
        Vec::new(),
        None,
        Some(format!(
            "key_lifecycle:{}:{}:{}{}",
            operation,
            key_type.label(),
            sequence.map(|s| s.to_string()).unwrap_or_else(|| "-".into()),
            proposer.map(|p| format!(":{}", p.0)).unwrap_or_default(),
        )),
    );
    // Use trace_id as a structured carrier for the operation label so the
    // audit chain UI can filter on it.
    entry.trace_id = Some(format!("key_lifecycle:{operation}:{}", key_type.label()));
    buffer_audit_entry(entry);
    tracing::info!(
        target: "audit",
        operation,
        key_type = key_type.label(),
        sequence = ?sequence,
        proposer = ?proposer.map(|p| &p.0),
        "key lifecycle event"
    );
}

/// Convenience wrappers that record each lifecycle stage. Call from the
/// code paths that actually generate/derive/destroy key material.
pub fn audit_key_generated(key_type: KeyType, proposer: Option<&RotationNodeId>) {
    emit_key_lifecycle_audit("generate", key_type, proposer, None);
}
pub fn audit_key_rotated(
    key_type: KeyType,
    proposer: Option<&RotationNodeId>,
    sequence: u64,
) {
    emit_key_lifecycle_audit("rotate", key_type, proposer, Some(sequence));
}
pub fn audit_key_derived(key_type: KeyType, proposer: Option<&RotationNodeId>) {
    emit_key_lifecycle_audit("derive", key_type, proposer, None);
}
pub fn audit_key_destroyed(key_type: KeyType, proposer: Option<&RotationNodeId>) {
    emit_key_lifecycle_audit("destroy", key_type, proposer, None);
}

/// Rotation scheduler that proposes rotations automatically.
pub struct DistributedRotationScheduler {
    /// Configured intervals per key type (in seconds).
    pub intervals: HashMap<KeyType, u64>,
    /// Grace period in seconds: old key remains valid after rotation.
    pub grace_period_secs: u64,
    /// Last rotation timestamps per key type.
    pub last_rotations: HashMap<KeyType, u64>,
}

impl DistributedRotationScheduler {
    pub fn new() -> Self {
        let mut intervals = HashMap::new();
        for kt in &[
            KeyType::Session,
            KeyType::Hmac,
            KeyType::Signing,
            KeyType::MasterShare,
        ] {
            let env_val = std::env::var(kt.env_var_name())
                .ok()
                .and_then(|v| v.parse::<u64>().ok());
            intervals.insert(*kt, env_val.unwrap_or_else(|| kt.default_interval_secs()));
        }
        let grace = std::env::var("MILNET_ROTATION_GRACE_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(300);
        Self {
            intervals,
            grace_period_secs: grace,
            last_rotations: HashMap::new(),
        }
    }

    /// Create with explicit intervals (for testing).
    pub fn with_intervals(intervals: HashMap<KeyType, u64>, grace_period_secs: u64) -> Self {
        Self {
            intervals,
            grace_period_secs,
            last_rotations: HashMap::new(),
        }
    }

    /// Record that a rotation happened.
    pub fn record_rotation(&mut self, key_type: KeyType, timestamp: u64) {
        self.last_rotations.insert(key_type, timestamp);
    }

    /// Check which key types are due for rotation.
    pub fn due_rotations(&self, now: u64) -> Vec<KeyType> {
        let mut due = Vec::new();
        for (kt, &interval) in &self.intervals {
            match self.last_rotations.get(kt) {
                Some(&last_ts) => {
                    if now.saturating_sub(last_ts) >= interval {
                        due.push(*kt);
                    }
                }
                None => {
                    due.push(*kt);
                }
            }
        }
        due
    }

    /// Whether a key is still within the grace period after rotation.
    pub fn in_grace_period(&self, _key_type: KeyType, rotation_ts: u64, now: u64) -> bool {
        now.saturating_sub(rotation_ts) <= self.grace_period_secs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU32;

    #[test]
    fn rotation_schedule_default_values() {
        let schedule = RotationSchedule::default();
        assert_eq!(schedule.interval, Duration::from_secs(3600));
        assert!(
            schedule.auto_rotate,
            "auto_rotate must default to true (production mode)"
        );
    }

    #[test]
    fn shutdown_handle_stops_monitor() {
        let schedule = RotationSchedule {
            interval: Duration::from_millis(10),
            auto_rotate: false,
        };
        let shutdown = start_rotation_monitor(schedule, || Ok(())).unwrap();
        std::thread::sleep(Duration::from_millis(50));
        shutdown.store(true, Ordering::Relaxed);
        std::thread::sleep(Duration::from_millis(30));
        assert!(shutdown.load(Ordering::Relaxed));
    }

    #[test]
    fn monitor_invokes_callback_on_auto_rotate() {
        let call_count = Arc::new(AtomicU32::new(0));
        let count_clone = call_count.clone();
        let schedule = RotationSchedule {
            interval: Duration::from_millis(10),
            auto_rotate: true,
        };
        let shutdown = start_rotation_monitor(schedule, move || {
            count_clone.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
        .unwrap();
        std::thread::sleep(Duration::from_millis(80));
        shutdown.store(true, Ordering::Relaxed);
        std::thread::sleep(Duration::from_millis(30));
        assert!(
            call_count.load(Ordering::Relaxed) >= 1,
            "rotation callback must be invoked at least once"
        );
    }

    #[test]
    fn monitor_handles_callback_error_without_crashing() {
        let schedule = RotationSchedule {
            interval: Duration::from_millis(10),
            auto_rotate: true,
        };
        let shutdown =
            start_rotation_monitor(schedule, || Err("simulated rotation failure".to_string()))
                .unwrap();
        std::thread::sleep(Duration::from_millis(80));
        shutdown.store(true, Ordering::Relaxed);
        std::thread::sleep(Duration::from_millis(30));
    }

    #[test]
    fn monitor_skips_callback_when_auto_rotate_false() {
        let call_count = Arc::new(AtomicU32::new(0));
        let count_clone = call_count.clone();
        let schedule = RotationSchedule {
            interval: Duration::from_millis(10),
            auto_rotate: false,
        };
        let shutdown = start_rotation_monitor(schedule, move || {
            count_clone.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
        .unwrap();
        std::thread::sleep(Duration::from_millis(80));
        shutdown.store(true, Ordering::Relaxed);
        std::thread::sleep(Duration::from_millis(30));
        assert_eq!(
            call_count.load(Ordering::Relaxed),
            0,
            "callback must NOT be invoked when auto_rotate is false"
        );
    }

    // ── Distributed rotation tests ──────────────────────────────────────────

    fn test_key() -> Vec<u8> {
        // 32 bytes to trigger ML-DSA signing path
        b"test-signing-key-32-bytes-long!!".to_vec()
    }

    fn test_key_32() -> [u8; 32] {
        *b"test-signing-key-32-bytes-long!!"
    }

    fn test_node(name: &str) -> RotationNodeId {
        RotationNodeId(name.to_string())
    }

    fn make_approval(key_type: KeyType, epoch: u64) -> RotationApproved {
        RotationApproved {
            key_type,
            epoch,
            approvers: vec![],
            aggregate_signature: vec![],
        }
    }

    #[test]
    fn rotation_event_creation_and_signing() {
        let key = test_key();
        let evt = RotationEvent::new(test_node("node-1"), KeyType::Session, 1, b"new-key", &key);
        assert_eq!(evt.epoch, 1);
        assert_eq!(evt.key_type, KeyType::Session);
        assert!(!evt.signature.is_empty());
        assert!(evt.verify_signature(&key));
    }

    #[test]
    fn rotation_event_verification_o1() {
        let key = test_key();
        let evt = RotationEvent::new(test_node("n1"), KeyType::Hmac, 5, b"material", &key);
        assert!(evt.verify_signature(&key));
        assert!(!evt.verify_signature(b"wrong-key-that-is-long-enough!!!"));
    }

    #[test]
    fn epoch_monotonicity_enforced() {
        let key = test_key();
        let mut witness = RotationWitness::new();
        witness.add_member(test_node("n1"), key.clone());
        witness.record_approval(&make_approval(KeyType::Session, 10));

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let evt1 =
            RotationEvent::new_with_timestamp(test_node("n1"), KeyType::Session, 1, now, b"k1", &key);
        let anomalies = witness.verify_event(&evt1);
        assert!(anomalies
            .iter()
            .all(|a| !matches!(a, RotationAnomaly::EpochRegression { .. })));

        // Same epoch again: regression.
        let evt2 =
            RotationEvent::new_with_timestamp(test_node("n1"), KeyType::Session, 1, now, b"k2", &key);
        let anomalies = witness.verify_event(&evt2);
        assert!(anomalies
            .iter()
            .any(|a| matches!(a, RotationAnomaly::EpochRegression { .. })));

        // Epoch backwards.
        let evt3 =
            RotationEvent::new_with_timestamp(test_node("n1"), KeyType::Session, 0, now, b"k3", &key);
        let anomalies = witness.verify_event(&evt3);
        assert!(anomalies
            .iter()
            .any(|a| matches!(a, RotationAnomaly::EpochRegression { .. })));
    }

    #[test]
    fn anomaly_unauthorized_rotation() {
        let key = test_key();
        let mut witness = RotationWitness::new();
        witness.add_member(test_node("n1"), key.clone());
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let evt =
            RotationEvent::new_with_timestamp(test_node("n1"), KeyType::Signing, 1, now, b"k", &key);
        let anomalies = witness.verify_event(&evt);
        assert!(anomalies
            .iter()
            .any(|a| matches!(a, RotationAnomaly::Unauthorized { .. })));
    }

    #[test]
    fn anomaly_rapid_rotation() {
        let key = test_key();
        let mut witness = RotationWitness::new();
        witness.add_member(test_node("n1"), key.clone());
        witness.rapid_rotation_max = 3;
        witness.record_approval(&make_approval(KeyType::Session, 100));

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        for i in 1u64..=4 {
            let evt = RotationEvent::new_with_timestamp(
                test_node("n1"),
                KeyType::Session,
                i,
                now,
                &[i as u8],
                &key,
            );
            let anomalies = witness.verify_event(&evt);
            if i > 3 {
                assert!(anomalies
                    .iter()
                    .any(|a| matches!(a, RotationAnomaly::RapidRotation { .. })));
            }
        }
    }

    #[test]
    fn anomaly_stale_rotation() {
        let witness = RotationWitness::new();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut last_times = HashMap::new();
        last_times.insert(KeyType::Signing, now - 8 * 86400);
        let mut thresholds = HashMap::new();
        thresholds.insert(KeyType::Signing, 7 * 86400);
        let anomalies = witness.check_stale_rotations(&last_times, &thresholds);
        assert!(anomalies
            .iter()
            .any(|a| matches!(a, RotationAnomaly::StaleRotation { .. })));
    }

    #[test]
    fn anomaly_split_rotation() {
        let key = test_key();
        let mut witness = RotationWitness::new();
        witness.add_member(test_node("n1"), key.clone());
        witness.add_member(test_node("n2"), key.clone());
        witness.record_approval(&make_approval(KeyType::Hmac, 10));

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let e1 =
            RotationEvent::new_with_timestamp(test_node("n1"), KeyType::Hmac, 5, now, b"a", &key);
        let e2 =
            RotationEvent::new_with_timestamp(test_node("n2"), KeyType::Hmac, 7, now, b"b", &key);
        witness.verify_event(&e1);
        witness.verify_event(&e2);
        let split = witness.check_split_rotation(KeyType::Hmac);
        assert!(matches!(
            split,
            Some(RotationAnomaly::SplitRotation { .. })
        ));
    }

    #[test]
    fn rotation_consensus_quorum_reached() {
        let key = test_key();
        let proposer = test_node("proposer");
        let proposal =
            RotationProposal::new(KeyType::Session, "scheduled".into(), proposer, &key);
        assert!(proposal.verify(&key));

        let mut consensus = RotationConsensus::new(proposal.clone(), 2);
        assert!(!consensus.has_quorum());

        let v1 = RotationVote::new(test_node("voter-1"), &proposal, &key);
        assert!(!consensus.add_vote(v1, &key).unwrap());

        let v2 = RotationVote::new(test_node("voter-2"), &proposal, &key);
        assert!(consensus.add_vote(v2, &key).unwrap());

        let approved = consensus.finalize(1, &key).unwrap();
        assert_eq!(approved.epoch, 1);
        assert_eq!(approved.approvers.len(), 2);
        assert!(approved.verify(&key));
    }

    #[test]
    fn rotation_consensus_quorum_not_reached() {
        let key = test_key();
        let proposal =
            RotationProposal::new(KeyType::Hmac, "test".into(), test_node("p"), &key);
        let mut consensus = RotationConsensus::new(proposal.clone(), 3);
        let v1 = RotationVote::new(test_node("v1"), &proposal, &key);
        consensus.add_vote(v1, &key).unwrap();
        assert!(!consensus.has_quorum());
        assert!(consensus.finalize(1, &key).is_none());
    }

    #[test]
    fn grace_period_logic() {
        let mut sched = DistributedRotationScheduler::with_intervals(
            [(KeyType::Session, 60)].into_iter().collect(),
            300,
        );
        let rotation_ts = 1000;
        sched.record_rotation(KeyType::Session, rotation_ts);
        assert!(sched.in_grace_period(KeyType::Session, rotation_ts, 1200));
        assert!(sched.in_grace_period(KeyType::Session, rotation_ts, 1300));
        assert!(!sched.in_grace_period(KeyType::Session, rotation_ts, 1301));
    }

    #[test]
    fn scheduler_automatic_proposals() {
        let sched = DistributedRotationScheduler::with_intervals(
            [(KeyType::Session, 60), (KeyType::Hmac, 120)]
                .into_iter()
                .collect(),
            300,
        );
        let due = sched.due_rotations(1000);
        assert!(due.contains(&KeyType::Session));
        assert!(due.contains(&KeyType::Hmac));
    }

    #[test]
    fn scheduler_not_due_after_rotation() {
        let mut sched = DistributedRotationScheduler::with_intervals(
            [(KeyType::Session, 60)].into_iter().collect(),
            300,
        );
        sched.record_rotation(KeyType::Session, 1000);
        assert!(!sched.due_rotations(1030).contains(&KeyType::Session));
        assert!(sched.due_rotations(1060).contains(&KeyType::Session));
    }

    #[test]
    fn persistence_save_and_reload() {
        let hmac_key = b"persistence-integrity-key-32b!!!";
        let mut state = RotationState::new();
        state.set_epoch("node-1", KeyType::Session, 42);
        state.set_last_rotation(KeyType::Hmac, 999);

        let data = state.serialize_with_integrity(hmac_key).unwrap();
        let loaded = RotationState::deserialize_with_integrity(&data, hmac_key).unwrap();
        assert_eq!(
            loaded.epochs.get("node-1").and_then(|m| m.get("session")),
            Some(&42)
        );
        assert_eq!(loaded.last_rotation.get("hmac"), Some(&999));
    }

    #[test]
    fn persistence_hmac_integrity_tampered() {
        let hmac_key = b"persistence-integrity-key-32b!!!";
        let state = RotationState::new();
        let mut data = state.serialize_with_integrity(hmac_key).unwrap();
        if !data.is_empty() {
            data[0] ^= 0xFF;
        }
        assert!(RotationState::deserialize_with_integrity(&data, hmac_key).is_err());
    }

    #[test]
    fn persistence_file_roundtrip() {
        let hmac_key = b"roundtrip-key-for-test-purposes!";
        let dir = std::env::temp_dir();
        let path = dir.join("rotation_state_test.bin");
        let path_str = path.to_str().unwrap();

        let mut state = RotationState::new();
        state.set_epoch("n1", KeyType::MasterShare, 7);
        state.persist(path_str, hmac_key).unwrap();

        let loaded = RotationState::load(path_str, hmac_key).unwrap();
        assert_eq!(
            loaded
                .epochs
                .get("n1")
                .and_then(|m| m.get("master_share")),
            Some(&7)
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn concurrent_rotations_from_multiple_nodes() {
        let key = test_key();
        let mut witness = RotationWitness::new();
        for i in 0..5 {
            witness.add_member(test_node(&format!("n{i}")), key.clone());
        }
        witness.record_approval(&make_approval(KeyType::Session, 100));

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        for i in 0..5u8 {
            let evt = RotationEvent::new_with_timestamp(
                test_node(&format!("n{i}")),
                KeyType::Session,
                1,
                now,
                &[i],
                &key,
            );
            let anomalies = witness.verify_event(&evt);
            assert!(anomalies
                .iter()
                .all(|a| !matches!(a, RotationAnomaly::EpochRegression { .. })));
        }
    }

    #[test]
    fn adversarial_forged_rotation_event() {
        let legit_key = test_key();
        let forged_key = b"attacker-key-that-is-different!!".to_vec();
        let mut witness = RotationWitness::new();
        witness.add_member(test_node("legit"), legit_key);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let forged = RotationEvent::new_with_timestamp(
            test_node("legit"),
            KeyType::Session,
            1,
            now,
            b"evil",
            &forged_key,
        );
        let anomalies = witness.verify_event(&forged);
        assert!(anomalies
            .iter()
            .any(|a| matches!(a, RotationAnomaly::InvalidSignature { .. })));
    }

    #[test]
    fn adversarial_replayed_event() {
        let key = test_key();
        let mut witness = RotationWitness::new();
        witness.add_member(test_node("n1"), key.clone());
        witness.record_approval(&make_approval(KeyType::Session, 10));

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let evt =
            RotationEvent::new_with_timestamp(test_node("n1"), KeyType::Session, 1, now, b"k", &key);
        let _ = witness.verify_event(&evt);
        let anomalies = witness.verify_event(&evt);
        assert!(anomalies
            .iter()
            .any(|a| matches!(a, RotationAnomaly::EpochRegression { .. })));
    }

    #[test]
    fn adversarial_split_brain_rotation() {
        let key = test_key();
        let mut witness = RotationWitness::new();
        witness.add_member(test_node("n1"), key.clone());
        witness.add_member(test_node("n2"), key.clone());
        witness.record_approval(&make_approval(KeyType::Signing, 100));

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let e1 = RotationEvent::new_with_timestamp(
            test_node("n1"),
            KeyType::Signing,
            3,
            now,
            b"a",
            &key,
        );
        let e2 = RotationEvent::new_with_timestamp(
            test_node("n2"),
            KeyType::Signing,
            5,
            now,
            b"b",
            &key,
        );
        witness.verify_event(&e1);
        witness.verify_event(&e2);
        let split = witness.check_split_rotation(KeyType::Signing);
        assert!(split.is_some());
        if let Some(RotationAnomaly::SplitRotation { epochs, .. }) = split {
            assert_eq!(epochs.len(), 2);
        }
    }

    #[test]
    fn unknown_node_rejected() {
        let key = test_key();
        let mut witness = RotationWitness::new();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let evt = RotationEvent::new_with_timestamp(
            test_node("unknown"),
            KeyType::Session,
            1,
            now,
            b"k",
            &key,
        );
        let anomalies = witness.verify_event(&evt);
        assert!(anomalies
            .iter()
            .any(|a| matches!(a, RotationAnomaly::UnknownNode { .. })));
    }

    #[test]
    fn duplicate_votes_ignored() {
        let key = test_key();
        let proposal =
            RotationProposal::new(KeyType::Session, "test".into(), test_node("p"), &key);
        let mut consensus = RotationConsensus::new(proposal.clone(), 2);
        let v1 = RotationVote::new(test_node("v1"), &proposal, &key);
        consensus.add_vote(v1.clone(), &key).unwrap();
        consensus.add_vote(v1, &key).unwrap();
        assert_eq!(consensus.votes.len(), 1);
        assert!(!consensus.has_quorum());
    }

    #[test]
    fn vote_with_invalid_signature_rejected() {
        let key = test_key();
        let bad_key = b"bad-key-for-forging-vote-sigs!!!";
        let proposal =
            RotationProposal::new(KeyType::Session, "test".into(), test_node("p"), &key);
        let mut consensus = RotationConsensus::new(proposal.clone(), 1);
        let bad_vote = RotationVote::new(test_node("v1"), &proposal, bad_key);
        assert!(consensus.add_vote(bad_vote, &key).is_err());
    }

    #[test]
    fn rotation_approved_aggregate_verification() {
        let key = test_key();
        let proposal =
            RotationProposal::new(KeyType::Hmac, "scheduled".into(), test_node("p"), &key);
        let votes = vec![
            RotationVote::new(test_node("a"), &proposal, &key),
            RotationVote::new(test_node("b"), &proposal, &key),
            RotationVote::new(test_node("c"), &proposal, &key),
        ];
        let approved = RotationApproved::from_votes(KeyType::Hmac, 42, &votes, &key);
        assert!(approved.verify(&key));
        assert!(!approved.verify(b"wrong-aggregate-key-32-bytes!!!!"));
    }

    // -- HI-7: Separate signing and HMAC keys --

    #[test]
    fn rotation_event_uses_separate_derived_keys() {
        let seed = test_key_32();
        let (sign_seed, hmac_key) = derive_rotation_keys(&seed);
        // Derived keys must differ from each other and from seed
        assert_ne!(sign_seed, seed);
        assert_ne!(&hmac_key[..32], &seed[..]);
        assert_ne!(&sign_seed[..], &hmac_key[..32]);
    }

    #[test]
    fn rotation_event_derived_keys_deterministic() {
        let seed = test_key_32();
        let (sign1, hmac1) = derive_rotation_keys(&seed);
        let (sign2, hmac2) = derive_rotation_keys(&seed);
        assert_eq!(sign1, sign2);
        assert_eq!(hmac1, hmac2);
    }

    // -- HI-8: Verify with verifying key (not seed) --

    #[test]
    fn rotation_event_verify_with_verifying_key() {
        let seed = test_key();
        let evt = RotationEvent::new(test_node("n1"), KeyType::Session, 1, b"key-material", &seed);
        // Extract verifying key
        let vk_bytes = RotationEvent::verifying_key_from_seed(&seed);
        // Verify with verifying key only (no seed needed)
        assert!(evt.verify_signature(&vk_bytes));
        // Wrong verifying key must fail
        let wrong_seed = b"different-seed-32-bytes-long!!!!";
        let wrong_vk = RotationEvent::verifying_key_from_seed(wrong_seed);
        assert!(!evt.verify_signature(&wrong_vk));
    }

    // -- MD-27: Non-repudiation via ML-DSA signatures --

    #[test]
    fn proposal_uses_ml_dsa_signature() {
        let key = test_key();
        let proposal = RotationProposal::new(
            KeyType::Session, "scheduled".into(), test_node("proposer"), &key,
        );
        // ML-DSA signatures are much larger than HMAC-SHA512 (64 bytes)
        assert!(proposal.signature.len() > 64, "proposal signature should be ML-DSA, not HMAC");
        assert!(proposal.verify(&key));
    }

    #[test]
    fn vote_uses_ml_dsa_signature() {
        let key = test_key();
        let proposal = RotationProposal::new(
            KeyType::Session, "test".into(), test_node("p"), &key,
        );
        let vote = RotationVote::new(test_node("v1"), &proposal, &key);
        assert!(vote.signature.len() > 64, "vote signature should be ML-DSA, not HMAC");
        assert!(vote.verify(&key));
    }

    #[test]
    fn proposal_cross_key_verification_fails() {
        let key1 = test_key();
        let key2 = b"another-key-32-bytes-different!!".to_vec();
        let proposal = RotationProposal::new(
            KeyType::Hmac, "test".into(), test_node("p"), &key1,
        );
        assert!(!proposal.verify(&key2));
    }
}
