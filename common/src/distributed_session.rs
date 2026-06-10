//! Distributed session persistence with encryption at rest.
//!
//! Replaces memory-only sessions with encrypted PostgreSQL-backed sessions.
//! Sessions are:
//! - Encrypted at rest (AES-256-GCM per-session DEK)
//! - Replicated across database nodes via PostgreSQL streaming replication
//! - Automatically expired based on tier-specific TTLs
//! - Bound to device fingerprint for additional security

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha512;
use subtle::ConstantTimeEq;
use uuid::Uuid;
use zeroize::Zeroize;

use crate::raft::NodeId;

/// HMAC key for computing device fingerprint blind indices.
/// Persisted across restarts via MILNET_FP_BLIND_KEY env var or derived from
/// master KEK via HKDF-SHA512 with info="MILNET-FP-BLIND-KEY-v1".
/// Falls back to OS CSPRNG only in dev/test mode (not military).
static FP_BLIND_KEY: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();

fn fp_blind_key() -> &'static [u8; 32] {
    FP_BLIND_KEY.get_or_init(|| {
        // Priority 1: Explicit env var (hex-encoded 32-byte key).
        if let Ok(hex_key) = std::env::var("MILNET_FP_BLIND_KEY") {
            if let Ok(bytes) = hex::decode(hex_key.trim()) {
                if bytes.len() == 32 {
                    let mut key = [0u8; 32];
                    key.copy_from_slice(&bytes);
                    tracing::info!("FP_BLIND_KEY loaded from MILNET_FP_BLIND_KEY env var");
                    return key;
                }
                tracing::error!("MILNET_FP_BLIND_KEY must be exactly 32 bytes (64 hex chars), got {}", bytes.len());
            } else {
                tracing::error!("MILNET_FP_BLIND_KEY is not valid hex");
            }
        }

        // Priority 2: Derive from master KEK via HKDF-SHA512.
        if let Ok(kek_hex) = std::env::var("MILNET_MASTER_KEK") {
            if let Ok(kek_bytes) = hex::decode(kek_hex.trim()) {
                if kek_bytes.len() == 32 {
                    use hkdf::Hkdf;
                    use sha2::Sha512;
                    let hk = Hkdf::<Sha512>::new(
                        Some(b"MILNET-FP-BLIND-KEY-SALT-v1"),
                        &kek_bytes,
                    );
                    let mut key = [0u8; 32];
                    if hk.expand(b"MILNET-FP-BLIND-KEY-v1", &mut key).is_ok() {
                        tracing::info!("FP_BLIND_KEY derived from MILNET_MASTER_KEK via HKDF-SHA512");
                        return key;
                    }
                    tracing::error!("HKDF-SHA512 derivation failed for FP_BLIND_KEY");
                }
            }
        }

        // Priority 3: In military mode, we must have a deterministic key.
        if std::env::var("MILNET_MILITARY_DEPLOYMENT").is_ok() {
            tracing::error!(
                "CRITICAL: No persistent FP_BLIND_KEY available in military mode. \
                 Set MILNET_FP_BLIND_KEY (hex) or MILNET_MASTER_KEK for HKDF derivation. \
                 Random key would break existing sessions on restart."
            );
            std::process::exit(1);
        }

        // Priority 4: Dev/test fallback -- random key (not restart-safe).
        let mut key = [0u8; 32];
        if let Err(e) = getrandom::getrandom(&mut key) {
            tracing::error!("CRITICAL: OS CSPRNG failure during blind key init: {e}");
            std::process::exit(1);
        }
        tracing::warn!(
            "FP_BLIND_KEY generated from CSPRNG (not persistent). \
             Sessions will be invalidated on restart. Set MILNET_FP_BLIND_KEY for persistence."
        );
        key
    })
}

/// Compute an HMAC-SHA512 blind index over a device fingerprint (CNSA 2.0).
/// This allows equality lookups without storing the raw fingerprint.
/// Returns the first 32 bytes of HMAC-SHA512 output for DB column compatibility.
pub fn blind_device_fingerprint(fp: &[u8; 32]) -> [u8; 32] {
    type HmacSha512 = Hmac<Sha512>;
    // HMAC-SHA512 accepts any key length per RFC 2104; this cannot fail.
    let Ok(mut mac) = HmacSha512::new_from_slice(fp_blind_key()) else {
        // Unreachable: HMAC-SHA512 accepts any key length.
        return [0u8; 32];
    };
    mac.update(fp);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result[..32]);
    out
}

/// Session state for distributed storage.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DistributedSession {
    /// Unique session identifier.
    pub session_id: Uuid,
    /// User identifier.
    pub user_id: Uuid,
    /// Device tier (1=Sovereign, 2=Operational, 3=Sensor, 4=Emergency).
    pub tier: u8,
    /// Session creation time (microseconds since epoch).
    pub created_at: i64,
    /// Session expiry time (microseconds since epoch).
    pub expires_at: i64,
    /// Last activity time (microseconds since epoch).
    pub last_activity: i64,
    /// Current ratchet epoch for this session.
    pub ratchet_epoch: u64,
    /// Encrypted ratchet chain key (AES-256-GCM sealed).
    pub encrypted_chain_key: Vec<u8>,
    /// Device fingerprint for binding (HMAC-SHA512 blind index, truncated to 32 bytes).
    /// The raw fingerprint is never stored — only its HMAC blind index.
    pub device_fingerprint: [u8; 32],
    /// Classification level for MAC enforcement.
    pub classification: u8,
    /// Whether the session has been terminated.
    pub terminated: bool,
}

/// Custom Debug for DistributedSession — redacts sensitive cryptographic fields.
impl std::fmt::Debug for DistributedSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DistributedSession")
            .field("session_id", &self.session_id)
            .field("user_id", &self.user_id)
            .field("tier", &self.tier)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("last_activity", &self.last_activity)
            .field("ratchet_epoch", &self.ratchet_epoch)
            .field("encrypted_chain_key", &"[ENCRYPTED]")
            .field("device_fingerprint", &"[REDACTED]")
            .field("classification", &self.classification)
            .field("terminated", &self.terminated)
            .finish()
    }
}

/// Zeroize sensitive fields on drop to prevent memory forensics.
impl Drop for DistributedSession {
    fn drop(&mut self) {
        self.device_fingerprint.zeroize();
        self.encrypted_chain_key.zeroize();
        let mut buf = *self.session_id.as_bytes();
        buf.zeroize();
        self.session_id = Uuid::from_bytes(buf);
        let mut buf = *self.user_id.as_bytes();
        buf.zeroize();
        self.user_id = Uuid::from_bytes(buf);
    }
}

/// Configuration for the distributed session store.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionStoreConfig {
    /// Maximum session duration per tier (microseconds).
    pub max_duration_by_tier: [i64; 4],
    /// Idle timeout (microseconds).
    pub idle_timeout_us: i64,
    /// Maximum concurrent sessions per user.
    pub max_sessions_per_user: usize,
    /// Session cleanup interval (seconds).
    pub cleanup_interval_secs: u64,
}

impl Default for SessionStoreConfig {
    fn default() -> Self {
        Self {
            // Tier 1: 8h, Tier 2: 4h, Tier 3: 1h, Tier 4: 15m
            max_duration_by_tier: [
                8 * 60 * 60 * 1_000_000,  // Sovereign: 8 hours
                4 * 60 * 60 * 1_000_000,  // Operational: 4 hours
                1 * 60 * 60 * 1_000_000,  // Sensor: 1 hour
                15 * 60 * 1_000_000,       // Emergency: 15 minutes
            ],
            idle_timeout_us: 30 * 60 * 1_000_000, // 30 minutes
            max_sessions_per_user: 5,
            cleanup_interval_secs: 60,
        }
    }
}

/// Default upper tier bound (inclusive) that FAILS CLOSED under partition.
/// Tier 1 (Sovereign) and Tier 2 (Operational) sessions are denied on a node
/// that cannot confirm non-revocation; Tier 3/4 degrade gracefully. See
/// [`DistributedSessionStore::set_partitioned`] for the rationale.
const DEFAULT_FAIL_CLOSED_MAX_TIER: u8 = 2;

/// In-memory distributed session store (backed by encrypted persistence).
pub struct DistributedSessionStore {
    /// Active sessions indexed by session_id.
    sessions: std::collections::HashMap<Uuid, DistributedSession>,
    /// Sessions indexed by user_id for concurrent session limits.
    user_sessions: std::collections::HashMap<Uuid, Vec<Uuid>>,
    /// Encryption key for session data at rest.
    encryption_key: [u8; 32],
    /// Configuration.
    config: SessionStoreConfig,
    /// Cross-node revocation watermarks (F3): user_id -> "not-before" timestamp
    /// (microseconds). A session for this user is denied iff it was created at
    /// or before the watermark, i.e. `watermark >= session.created_at`. This
    /// honors a revocation that arrived from ANOTHER node even when this node's
    /// local cache still holds the session as non-terminated (or never held it
    /// at all). A session created AFTER the watermark (a fresh re-auth) survives.
    /// This is the standard per-subject revocation-watermark pattern
    /// (NIST SP 800-63B session revocation; OIDC `iat` vs. not-before).
    invalidated_users: std::collections::HashMap<Uuid, i64>,
    /// Whether this node is currently partitioned from the revocation authority
    /// / quorum and therefore CANNOT confirm a session has not been revoked
    /// cluster-wide. Drives fail-closed behavior for privileged tiers.
    partitioned: bool,
    /// Inclusive upper tier bound that fails closed under partition. Sessions
    /// whose tier number is <= this value are DENIED while `partitioned` is true.
    fail_closed_max_tier: u8,
}

impl DistributedSessionStore {
    pub fn new(encryption_key: [u8; 32], config: SessionStoreConfig) -> Self {
        Self {
            sessions: std::collections::HashMap::new(),
            user_sessions: std::collections::HashMap::new(),
            encryption_key,
            config,
            invalidated_users: std::collections::HashMap::new(),
            partitioned: false,
            fail_closed_max_tier: DEFAULT_FAIL_CLOSED_MAX_TIER,
        }
    }

    /// Create a new session. Returns error if user has too many concurrent sessions.
    pub fn create_session(
        &mut self,
        user_id: Uuid,
        tier: u8,
        device_fingerprint: [u8; 32],
        chain_key: &[u8],
        classification: u8,
    ) -> Result<Uuid, String> {
        // Check concurrent session limit
        let now = now_us();

        // Clean up expired sessions for this user first
        let user_sessions = self.user_sessions.entry(user_id).or_default();
        let sessions_ref = &self.sessions;
        user_sessions.retain(|sid| {
            sessions_ref
                .get(sid)
                .map(|s| !s.terminated && s.expires_at > now)
                .unwrap_or(false)
        });

        if user_sessions.len() >= self.config.max_sessions_per_user {
            return Err(format!(
                "concurrent session limit reached ({}/{})",
                user_sessions.len(),
                self.config.max_sessions_per_user
            ));
        }

        let tier_idx = (tier.saturating_sub(1) as usize).min(3);
        let max_duration = self.config.max_duration_by_tier[tier_idx];

        let session_id = Uuid::new_v4();
        let encrypted_chain_key =
            encrypt_session_data(&self.encryption_key, &session_id, chain_key)?;

        // Store the HMAC-SHA256 blind index of the fingerprint, not the raw value.
        let fp_blind = blind_device_fingerprint(&device_fingerprint);

        let session = DistributedSession {
            session_id,
            user_id,
            tier,
            created_at: now,
            expires_at: now + max_duration,
            last_activity: now,
            ratchet_epoch: 1,
            encrypted_chain_key,
            device_fingerprint: fp_blind,
            classification,
            terminated: false,
        };

        self.sessions.insert(session_id, session);
        user_sessions.push(session_id);

        Ok(session_id)
    }

    /// Get a session by ID. Returns None if expired or terminated.
    /// This is a convenience wrapper around `get_session_bound` with no device fingerprint check.
    pub fn get_session(&self, session_id: &Uuid) -> Option<&DistributedSession> {
        self.get_session_bound(session_id, None)
    }

    /// Get a session, enforcing device binding and expiry.
    /// `requesting_device_fingerprint` is the fingerprint of the device making the request.
    /// If provided, it MUST match the session's stored fingerprint.
    pub fn get_session_bound(
        &self,
        session_id: &Uuid,
        requesting_device_fingerprint: Option<&[u8; 32]>,
    ) -> Option<&DistributedSession> {
        let session = self.sessions.get(session_id)?;

        // Check termination
        if session.terminated {
            return None;
        }

        // F3: honor a cross-node revocation watermark. A revoke that arrived
        // from another node terminates the local cache entry when present, but
        // the watermark is the authoritative gate — it denies any session for
        // this user created at/before the revocation even if the local
        // `terminated` flag was never set on this node.
        if self.is_user_invalidated(&session.user_id, session.created_at) {
            tracing::info!(
                target: "siem",
                session_id = %session_id,
                user_id = %session.user_id,
                "SIEM:INFO session denied by cross-node revocation watermark"
            );
            return None;
        }

        // Check expiry
        let now = now_us();
        if session.expires_at <= now {
            return None;
        }

        // Step 3: FAIL CLOSED under partition for privileged tiers. If this node
        // cannot currently confirm non-revocation cluster-wide (it is cut off
        // from the revocation authority/quorum), a high-tier session must be
        // DENIED rather than honored to its TTL — a revoke issued elsewhere may
        // not have reached us. Lower tiers degrade gracefully (served). This is
        // the zero-trust answer to the audit's "fails OPEN under partition"
        // verdict (NIST SP 800-207 §2: deny by default when trust cannot be
        // continually verified).
        if self.partitioned && session.tier <= self.fail_closed_max_tier {
            tracing::warn!(
                target: "siem",
                session_id = %session_id,
                user_id = %session.user_id,
                tier = session.tier,
                "SIEM:WARNING high-tier session DENIED — partitioned from revocation quorum (fail-closed)"
            );
            return None;
        }

        // Enforce device binding — session MUST be used from the same device.
        // The stored fingerprint is an HMAC blind index, so we blind the
        // requesting fingerprint before constant-time comparison.
        if let Some(requesting_fp) = requesting_device_fingerprint {
            let requesting_blind = blind_device_fingerprint(requesting_fp);
            if session.device_fingerprint.ct_eq(&requesting_blind).unwrap_u8() == 0 {
                tracing::warn!(
                    session_id = %session_id,
                    "SECURITY: device fingerprint mismatch — possible session theft"
                );
                return None;
            }
        }

        // Check idle timeout
        if now - session.last_activity > self.config.idle_timeout_us {
            return None;
        }

        Some(session)
    }

    /// Update session activity and ratchet epoch.
    pub fn touch_session(&mut self, session_id: &Uuid, new_epoch: u64) -> Result<(), String> {
        let session = self
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| "session not found".to_string())?;
        let now = now_us();
        if session.terminated || session.expires_at <= now {
            return Err("session expired or terminated".to_string());
        }
        session.last_activity = now;
        session.ratchet_epoch = new_epoch;
        Ok(())
    }

    /// Terminate a session (revoke). Zeroizes sensitive key material immediately.
    pub fn terminate_session(&mut self, session_id: &Uuid) -> bool {
        if let Some(session) = self.sessions.get_mut(session_id) {
            session.terminated = true;
            session.encrypted_chain_key.zeroize();
            session.device_fingerprint.zeroize();
            tracing::info!(
                session_id = %session_id,
                "session terminated and keys zeroized"
            );
            true
        } else {
            false
        }
    }

    /// Terminate all sessions for a user.
    pub fn terminate_user_sessions(&mut self, user_id: &Uuid) -> usize {
        let session_ids: Vec<Uuid> = self
            .user_sessions
            .get(user_id)
            .cloned()
            .unwrap_or_default();
        let mut count = 0;
        for sid in &session_ids {
            if self.terminate_session(sid) {
                count += 1;
            }
        }
        count
    }

    /// Clean up expired/terminated sessions.
    pub fn cleanup(&mut self) -> usize {
        let now = now_us();
        let expired: Vec<Uuid> = self
            .sessions
            .iter()
            .filter(|(_, s)| s.terminated || s.expires_at <= now)
            .map(|(id, _)| *id)
            .collect();
        let count = expired.len();
        for id in &expired {
            if let Some(session) = self.sessions.remove(id) {
                if let Some(user_sessions) = self.user_sessions.get_mut(&session.user_id) {
                    user_sessions.retain(|sid| sid != id);
                }
            }
        }
        count
    }

    /// Get the count of active (non-expired, non-terminated) sessions.
    pub fn active_count(&self) -> usize {
        let now = now_us();
        self.sessions
            .values()
            .filter(|s| !s.terminated && s.expires_at > now)
            .count()
    }

    /// Get all active sessions for a user.
    ///
    /// F3: sessions denied by a cross-node revocation watermark are excluded,
    /// so a remote revoke is honored on this read path too (not just at TTL).
    pub fn user_active_sessions(&self, user_id: &Uuid) -> Vec<&DistributedSession> {
        let now = now_us();
        // A revocation watermark for this user invalidates every session created
        // at/before it; if every active session predates the watermark this
        // returns empty without touching per-session state.
        self.user_sessions
            .get(user_id)
            .map(|sids| {
                sids.iter()
                    .filter_map(|sid| self.sessions.get(sid))
                    .filter(|s| !s.terminated && s.expires_at > now)
                    .filter(|s| !self.is_user_invalidated(&s.user_id, s.created_at))
                    .collect()
            })
            .unwrap_or_default()
    }

    // NOTE: a pair of `#[cfg(feature = "persistence")]`-gated `persist_session` /
    // `load_session` methods (writing a `distributed_sessions` table) once lived
    // here. `common` has no `persistence` feature, so they were ALWAYS compiled
    // out (dead) — and they duplicated the real, used durability layer in
    // `crate::persistent_session::PersistentSessionStore` (the `persistent_sessions`
    // table, write-through + failover hydration). They were removed to eliminate
    // the dead-feature gate (which would fail CI under `-D warnings`) and the
    // misleading duplicate persistence surface. Durable persistence = use
    // `PersistentSessionStore`.
}

impl Drop for DistributedSessionStore {
    fn drop(&mut self) {
        self.encryption_key.zeroize();
        for session in self.sessions.values_mut() {
            session.encrypted_chain_key.zeroize();
            session.device_fingerprint.zeroize();
        }
    }
}

// ---------------------------------------------------------------------------
// Distributed Session Invalidation Events
// ---------------------------------------------------------------------------

/// Reason for session invalidation, propagated across cluster nodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InvalidationReason {
    PasswordChanged,
    RoleChanged,
    PermissionEscalation,
    SecurityIncident,
    AdminAction,
}

impl InvalidationReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PasswordChanged => "password_changed",
            Self::RoleChanged => "role_changed",
            Self::PermissionEscalation => "permission_escalation",
            Self::SecurityIncident => "security_incident",
            Self::AdminAction => "admin_action",
        }
    }
}

/// A signed session invalidation event for cross-node propagation.
///
/// `node_id` is the cluster's [`NodeId`] (raft) of the ORIGINATING node — the
/// same identity the Raft transport and attestation share. A receiver looks up
/// this node's PINNED verifying key in the one cluster registry
/// (`crate::distributed_startup::NodeIdentityRegistry`) and verifies the
/// signature against it (type-enforced single-registry attribution; no String
/// parsing on the verification path).
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionInvalidationEvent {
    pub user_id: Uuid,
    pub reason: InvalidationReason,
    pub timestamp: i64,
    pub node_id: NodeId,
    pub signature: Vec<u8>,
}

/// Custom Debug for SessionInvalidationEvent -- redacts signature to prevent
/// HMAC material leaking into logs.
impl std::fmt::Debug for SessionInvalidationEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionInvalidationEvent")
            .field("user_id", &self.user_id)
            .field("reason", &self.reason)
            .field("timestamp", &self.timestamp)
            .field("node_id", &self.node_id)
            .field("signature", &"[REDACTED]")
            .finish()
    }
}

/// Processes invalidation events with signature verification and replay protection.
///
/// DEPRECATED / INSECURE (audit F9): this uses a single CLUSTER-SHARED HMAC key
/// and signs an attacker-settable `node_id`, so ANY node holding the shared key
/// can mint valid invalidation events for ARBITRARY users attributed to ANY
/// node (mass-revoke availability DoS + zero origin attribution). Production
/// code MUST use [`RevocationCoordinator`] with [`NodeDsaSigner::from_node_identity`]
/// over the cluster's single per-node identity
/// (`crate::distributed_startup::NodeIdentity`), which signs per node with
/// ML-DSA-87 and verifies against the ORIGINATING node's PINNED verifying key.
/// Retained only as a test/dev helper and for backward source compatibility; do
/// NOT wire it into any revocation path.
#[deprecated(
    note = "shared-HMAC signing (F9) — use RevocationCoordinator + NodeDsaSigner::from_node_identity (per-node ML-DSA-87 over NodeIdentity)"
)]
pub struct InvalidationEventProcessor {
    hmac_key: Vec<u8>,
    seen_events: std::collections::HashMap<NodeId, Vec<i64>>,
    replay_window_us: i64,
}

/// Custom Debug for InvalidationEventProcessor -- redacts HMAC key.
#[allow(deprecated)]
impl std::fmt::Debug for InvalidationEventProcessor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InvalidationEventProcessor")
            .field("hmac_key", &"[REDACTED]")
            .field("seen_events_count", &self.seen_events.len())
            .field("replay_window_us", &self.replay_window_us)
            .finish()
    }
}

#[allow(deprecated)]
impl InvalidationEventProcessor {
    const DEFAULT_REPLAY_WINDOW_US: i64 = 60 * 1_000_000;

    pub fn new(hmac_key: [u8; 64]) -> Self {
        Self {
            hmac_key: hmac_key.to_vec(),
            seen_events: std::collections::HashMap::new(),
            replay_window_us: Self::DEFAULT_REPLAY_WINDOW_US,
        }
    }

    /// Create and sign an invalidation event for broadcast.
    pub fn create_event(
        &self,
        user_id: Uuid,
        reason: InvalidationReason,
        node_id: NodeId,
    ) -> SessionInvalidationEvent {
        let timestamp = now_us();
        let signature = self.compute_signature(&user_id, reason, timestamp, node_id);
        SessionInvalidationEvent {
            user_id,
            reason,
            timestamp,
            node_id,
            signature,
        }
    }

    /// Verify and process an incoming invalidation event.
    pub fn verify_and_accept(
        &mut self,
        event: &SessionInvalidationEvent,
    ) -> Result<Uuid, String> {
        let now = now_us();

        if (now - event.timestamp).abs() > self.replay_window_us {
            tracing::warn!(
                target: "siem",
                node_id = %event.node_id,
                user_id = %event.user_id,
                "SIEM:WARNING Invalidation event outside replay window"
            );
            return Err("invalidation event outside replay window".to_string());
        }

        let expected = self.compute_signature(
            &event.user_id,
            event.reason,
            event.timestamp,
            event.node_id,
        );
        if expected.ct_eq(&event.signature).unwrap_u8() == 0 {
            tracing::error!(
                target: "siem",
                node_id = %event.node_id,
                user_id = %event.user_id,
                "SIEM:CRITICAL Invalidation event signature mismatch"
            );
            return Err("invalidation event signature invalid".to_string());
        }

        let node_events = self.seen_events.entry(event.node_id).or_default();
        if node_events.contains(&event.timestamp) {
            tracing::warn!(
                target: "siem",
                node_id = %event.node_id,
                "SIEM:WARNING Duplicate invalidation event rejected"
            );
            return Err("duplicate invalidation event".to_string());
        }
        node_events.push(event.timestamp);
        node_events.retain(|ts| (now - ts).abs() <= self.replay_window_us);

        tracing::info!(
            target: "siem",
            user_id = %event.user_id,
            reason = event.reason.as_str(),
            source_node = %event.node_id,
            "SIEM:INFO Verified invalidation event accepted"
        );

        Ok(event.user_id)
    }

    fn compute_signature(
        &self,
        user_id: &Uuid,
        reason: InvalidationReason,
        timestamp: i64,
        node_id: NodeId,
    ) -> Vec<u8> {
        type HmacSha512 = Hmac<Sha512>;
        let mut mac = HmacSha512::new_from_slice(&self.hmac_key)
            .expect("HMAC-SHA512 accepts any key length");
        mac.update(user_id.as_bytes());
        mac.update(reason.as_str().as_bytes());
        mac.update(&timestamp.to_be_bytes());
        mac.update(node_id.0.as_bytes());
        mac.finalize().into_bytes().to_vec()
    }

    /// Prune replay-protection state older than the window.
    pub fn cleanup_replay_state(&mut self) {
        let now = now_us();
        self.seen_events.retain(|_, timestamps| {
            timestamps.retain(|ts| (now - ts).abs() <= self.replay_window_us);
            !timestamps.is_empty()
        });
    }
}

#[allow(deprecated)]
impl Drop for InvalidationEventProcessor {
    fn drop(&mut self) {
        self.hmac_key.zeroize();
    }
}

impl DistributedSessionStore {
    /// Handle a verified invalidation event: record the cross-node revocation
    /// watermark for the user AND terminate any locally-cached sessions.
    ///
    /// F3: recording the watermark is what makes the read path honor a remote
    /// revoke. `terminate_user_sessions` only zeroizes sessions THIS node is
    /// currently caching; the watermark additionally denies any matching session
    /// this node holds (now or later, e.g. after a cache reload) without it
    /// having been individually terminated. Returns the number of locally-cached
    /// sessions terminated.
    pub fn apply_invalidation_event(
        &mut self,
        event: &SessionInvalidationEvent,
    ) -> usize {
        // Watermark = the revocation instant. Any session created at/before this
        // is denied; a later re-auth is unaffected. Keep the latest watermark.
        self.record_user_invalidation(event.user_id, event.timestamp);

        let count = self.terminate_user_sessions(&event.user_id);
        tracing::info!(
            target: "siem",
            user_id = %event.user_id,
            reason = event.reason.as_str(),
            sessions_terminated = count,
            watermark_us = event.timestamp,
            source_node = %event.node_id,
            "SIEM:INFO Cross-node invalidation applied (watermark recorded)"
        );
        count
    }

    /// Record a per-user revocation watermark (microseconds). Idempotent and
    /// monotonic: only advances the watermark, never moves it backward.
    pub fn record_user_invalidation(&mut self, user_id: Uuid, watermark_us: i64) {
        self.invalidated_users
            .entry(user_id)
            .and_modify(|w| {
                if watermark_us > *w {
                    *w = watermark_us;
                }
            })
            .or_insert(watermark_us);
    }

    /// Whether a session for `user_id` created at `session_created_at` is denied
    /// by a recorded revocation watermark (`watermark >= created_at`).
    pub fn is_user_invalidated(&self, user_id: &Uuid, session_created_at: i64) -> bool {
        match self.invalidated_users.get(user_id) {
            Some(&watermark) => watermark >= session_created_at,
            None => false,
        }
    }

    /// Set this node's partition state with respect to the revocation quorum.
    ///
    /// When `true`, this node cannot confirm that a session has not been revoked
    /// elsewhere in the cluster, so privileged-tier reads FAIL CLOSED (see
    /// [`Self::get_session_bound`]). The cluster's failure detector / consensus
    /// layer drives this: loss of quorum or isolation from the revocation
    /// authority sets it true; restored connectivity sets it false.
    pub fn set_partitioned(&mut self, partitioned: bool) {
        if self.partitioned != partitioned {
            tracing::warn!(
                target: "siem",
                partitioned,
                fail_closed_max_tier = self.fail_closed_max_tier,
                "SIEM:WARNING revocation-quorum partition state changed"
            );
        }
        self.partitioned = partitioned;
    }

    /// Whether this node is currently partitioned from the revocation quorum.
    pub fn is_partitioned(&self) -> bool {
        self.partitioned
    }

    /// Override the inclusive upper tier bound that fails closed under partition.
    /// Tiers with number <= `max_tier` are denied while partitioned. Lower
    /// (numerically higher) tiers degrade gracefully.
    pub fn set_fail_closed_max_tier(&mut self, max_tier: u8) {
        self.fail_closed_max_tier = max_tier;
    }

    /// Prune revocation watermarks older than the maximum session lifetime, since
    /// any session they could invalidate has expired by then. Bounds memory under
    /// a sustained revocation rate. `max_session_lifetime_us` should be the
    /// largest tier TTL (Tier 1 / Sovereign).
    pub fn cleanup_invalidations(&mut self, max_session_lifetime_us: i64) {
        let cutoff = now_us().saturating_sub(max_session_lifetime_us);
        self.invalidated_users.retain(|_, &mut watermark| watermark > cutoff);
    }

    /// Number of recorded revocation watermarks (for metrics/tests).
    pub fn invalidated_user_count(&self) -> usize {
        self.invalidated_users.len()
    }
}

// ---------------------------------------------------------------------------
// Cross-node revocation propagation (F3) + per-node signing (F9)
// ---------------------------------------------------------------------------

/// Canonical, signer-independent byte payload for a session invalidation event.
///
/// Layout: `DOMAIN || user_id(16) || reason_str || timestamp_be(8) || node_id(16)`.
/// `node_id` is the raw 16-byte cluster [`NodeId`] (its UUID bytes). This is THE
/// signing domain — both the legacy cluster-shared HMAC signer and the per-node
/// ML-DSA-87 signer sign/verify exactly these bytes, so a signature is bound to
/// (subject, reason, instant, originating node) and cannot be replayed under a
/// different node_id or reason.
///
/// DOMAIN SEPARATION (mandatory): the per-node ML-DSA-87 key that signs these
/// events is the SAME key the Raft transport signs with (its domain is
/// `MILNET-RAFT-TRANSPORT-ML-DSA-87-v1`). The distinct `MILNET-SESSION-REVOKE-v1`
/// prefix below binds the signature to the session-revocation domain so a
/// signature minted for one protocol can NEVER be replayed as the other (e.g. a
/// Raft entry signature presented as a session revoke). Keep this prefix unique
/// across every signing domain that shares the per-node key.
pub fn invalidation_signing_payload(
    user_id: &Uuid,
    reason: InvalidationReason,
    timestamp: i64,
    node_id: NodeId,
) -> Vec<u8> {
    const DOMAIN: &[u8] = b"MILNET-SESSION-REVOKE-v1";
    let mut out = Vec::with_capacity(DOMAIN.len() + 16 + 24 + 8 + 16);
    out.extend_from_slice(DOMAIN);
    out.extend_from_slice(user_id.as_bytes());
    out.extend_from_slice(reason.as_str().as_bytes());
    out.extend_from_slice(&timestamp.to_be_bytes());
    out.extend_from_slice(node_id.0.as_bytes());
    out
}

/// Pluggable signature backend for invalidation events.
///
/// This is the seam (dependency inversion) that lets the propagation logic stay
/// independent of the crypto primitive. The production implementation is
/// [`NodeDsaSigner`], which delegates to the cluster's PER-NODE ML-DSA-87
/// identity (raft-identity's `node_sign` / `verify_node_sig` over a NodeId ->
/// pinned-VK registry). This closes F9: a signature is attributable to exactly
/// one node and NO node can mint an invalidation attributed to another, because
/// `verify` checks against the ORIGINATING node's pinned verifying key.
pub trait InvalidationSigner: Send + Sync {
    /// Sign `payload` as originating from THIS node. The returned signature must
    /// verify under this node's pinned verifying key via [`Self::verify`] with
    /// this node's id.
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, String>;

    /// Verify a `signature` claimed to originate from `origin_node_id` (cluster
    /// [`NodeId`]) over `payload`, against that node's PINNED verifying key in the
    /// shared registry. Returns `true` only on a valid signature from the claimed
    /// origin; an unknown/unpinned NodeId returns `false` (fail-closed).
    fn verify(&self, origin_node_id: NodeId, payload: &[u8], signature: &[u8]) -> bool;
}

/// Per-node ML-DSA-87 signer (F9) — delegates to two closures that the wiring
/// site fills with the cluster's per-node identity primitive (raft-identity's
/// `node_sign` / `verify_node_sig`). Using closures keeps this crate decoupled
/// from where the identity registry lives (raft-identity owns those files); we
/// do not duplicate the key material or the registry here.
pub struct NodeDsaSigner {
    /// Sign `payload` with THIS node's ML-DSA-87 key. Wired to `node_sign`.
    sign_fn: Box<dyn Fn(&[u8]) -> Result<Vec<u8>, String> + Send + Sync>,
    /// Verify `(origin_node_id, payload, sig)` against the origin's pinned VK.
    /// Wired to the shared `NodeId -> pinned-VK` registry's verify.
    verify_fn: Box<dyn Fn(NodeId, &[u8], &[u8]) -> bool + Send + Sync>,
}

impl NodeDsaSigner {
    /// Construct from the per-node identity primitive.
    ///
    /// - `sign_fn`: this node's `node_sign(msg) -> sig` (ML-DSA-87 over its
    ///   sealed seed). MUST sign with the key whose VK is pinned for this node.
    /// - `verify_fn`: verifies `(origin_node_id, msg, sig)` against the shared
    ///   pinned-VK registry (e.g. `NodeIdentityRegistry::verify`). MUST return
    ///   `false` for an unknown/unpinned NodeId (fail-closed).
    pub fn new(
        sign_fn: Box<dyn Fn(&[u8]) -> Result<Vec<u8>, String> + Send + Sync>,
        verify_fn: Box<dyn Fn(NodeId, &[u8], &[u8]) -> bool + Send + Sync>,
    ) -> Self {
        Self { sign_fn, verify_fn }
    }

    /// Convenience wiring over raft-identity's [`crate::distributed_startup::NodeIdentity`]
    /// + the SHARED [`crate::distributed_startup::NodeIdentityRegistry`] pinned at
    /// cluster join. This is the RECOMMENDED production constructor: it keeps the
    /// cluster on ONE source of per-node key truth — the SAME registry + verifying
    /// keys that authenticate the Raft transport — and verifies via the shared
    /// `NodeIdentityRegistry::verify` primitive, fail-closed on an unpinned origin.
    ///
    /// `registry` MUST be the cluster's join-time registry (pin self via
    /// `identity.verifying_key()` and peers via their PUBLISHED VKs; in military
    /// mode a peer's VK is TPM-sealed and not locally computable, so reuse the
    /// transport's pinned set). The sending coordinator must stamp
    /// `SessionInvalidationEvent.node_id = identity.node_id()`.
    pub fn from_node_identity(
        identity: std::sync::Arc<crate::distributed_startup::NodeIdentity>,
        registry: std::sync::Arc<crate::distributed_startup::NodeIdentityRegistry>,
    ) -> Self {
        Self {
            // node_sign is infallible (returns Vec); adapt to Result. The sign
            // closure takes sole ownership of the identity Arc; the verify
            // closure only needs the registry. NodeIdentityRegistry::verify is
            // itself fail-closed on an unknown/unpinned NodeId.
            sign_fn: Box::new(move |msg: &[u8]| Ok(identity.node_sign(msg))),
            verify_fn: Box::new(move |origin: NodeId, msg: &[u8], sig: &[u8]| {
                registry.verify(origin, msg, sig)
            }),
        }
    }
}

impl InvalidationSigner for NodeDsaSigner {
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, String> {
        (self.sign_fn)(payload)
    }
    fn verify(&self, origin_node_id: NodeId, payload: &[u8], signature: &[u8]) -> bool {
        (self.verify_fn)(origin_node_id, payload, signature)
    }
}

/// Self-contained per-node ML-DSA-87 signer (F9) for invalidation events.
///
/// ⚠️ TEST DOUBLE ONLY — DO NOT WIRE IN PRODUCTION. This type derives its OWN
/// ML-DSA-87 keypair from a seed passed to [`Self::new`]. Using it in production
/// would create a SECOND per-node identity divergent from the cluster's single
/// per-node identity (`common::distributed_startup::NodeIdentity`, which also
/// authenticates the Raft transport). Two divergent identities means a peer
/// cannot pin ONE verifying key per node — re-opening the very "every node has a
/// separate keypair" finding F9/the consensus audit closed. PRODUCTION MUST use
/// [`NodeDsaSigner::from_node_identity`], which signs/verifies via the shared
/// `NodeIdentity` + `verify_node_sig` so the SAME pinned VK authenticates both
/// Raft messages and revoke events.
///
/// Retained because it exercises the REAL `ml-dsa` crypto end-to-end in the F9
/// unit tests (the alternative `TestSigner` is only a SHA-512 stand-in). It
/// implements the same [`InvalidationSigner`] contract as the production
/// `NodeDsaSigner`, so the tests validate the actual per-node sign/verify +
/// origin-pinning behavior with post-quantum signatures. Uses the exact `ml-dsa`
/// API as `distributed_startup`.
pub struct MlDsaNodeSigner {
    /// This node's identifier (used to reject "signing as someone else").
    this_node_id: NodeId,
    /// This node's 32-byte ML-DSA-87 signing seed.
    signing_seed: [u8; 32],
    /// NodeId -> pinned ML-DSA-87 verifying-key bytes, populated during
    /// distributed startup (after attestation pins each peer's VK).
    pinned_vks: std::collections::HashMap<NodeId, Vec<u8>>,
}

impl std::fmt::Debug for MlDsaNodeSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MlDsaNodeSigner")
            .field("this_node_id", &self.this_node_id)
            .field("signing_seed", &"[REDACTED]")
            .field("pinned_nodes", &self.pinned_vks.len())
            .finish()
    }
}

impl MlDsaNodeSigner {
    /// Create a TEST signer for `this_node_id` from a 32-byte ML-DSA-87 seed.
    /// Pin peer verifying keys with [`Self::pin_node`]. TEST DOUBLE ONLY — see the
    /// type-level warning; production wires [`NodeDsaSigner::from_node_identity`].
    pub fn new(this_node_id: NodeId, signing_seed: [u8; 32]) -> Self {
        let mut signer = Self {
            this_node_id,
            signing_seed,
            pinned_vks: std::collections::HashMap::new(),
        };
        // Pin our own VK so self-originated events verify locally too.
        let own_vk = Self::pq_verifying_key(&signer.signing_seed);
        signer.pinned_vks.insert(this_node_id, own_vk);
        signer
    }

    /// Pin a peer node's ML-DSA-87 verifying key (raw encoded bytes). Call this
    /// for every peer during distributed startup once its attestation VK is
    /// known. Re-pinning overwrites (e.g. after a verified key rotation).
    pub fn pin_node(&mut self, node_id: NodeId, verifying_key: Vec<u8>) {
        self.pinned_vks.insert(node_id, verifying_key);
    }

    /// Number of pinned nodes (including self).
    pub fn pinned_count(&self) -> usize {
        self.pinned_vks.len()
    }

    /// This node's verifying-key bytes (to hand to peers for pinning).
    pub fn own_verifying_key(&self) -> Vec<u8> {
        Self::pq_verifying_key(&self.signing_seed)
    }

    // ML-DSA-87 primitives — identical pattern to distributed_startup.rs.

    fn pq_sign(seed: &[u8; 32], data: &[u8]) -> Vec<u8> {
        use ml_dsa::signature::Signer;
        use ml_dsa::{KeyGen, MlDsa87};
        let kp = MlDsa87::from_seed(&(*seed).into());
        let sig: ml_dsa::Signature<MlDsa87> = kp.signing_key().sign(data);
        sig.encode().to_vec()
    }

    fn pq_verifying_key(seed: &[u8; 32]) -> Vec<u8> {
        use ml_dsa::{EncodedVerifyingKey, KeyGen, MlDsa87};
        let kp = MlDsa87::from_seed(&(*seed).into());
        let encoded: EncodedVerifyingKey<MlDsa87> = kp.verifying_key().encode();
        AsRef::<[u8]>::as_ref(&encoded).to_vec()
    }

    fn pq_verify(vk_bytes: &[u8], data: &[u8], sig_bytes: &[u8]) -> bool {
        use ml_dsa::signature::Verifier;
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
        vk.verify(data, &sig).is_ok()
    }
}

impl Drop for MlDsaNodeSigner {
    fn drop(&mut self) {
        self.signing_seed.zeroize();
    }
}

impl InvalidationSigner for MlDsaNodeSigner {
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, String> {
        Ok(Self::pq_sign(&self.signing_seed, payload))
    }

    fn verify(&self, origin_node_id: NodeId, payload: &[u8], signature: &[u8]) -> bool {
        // Look up the CLAIMED origin's pinned VK. Unknown origin => reject
        // (fail-closed: we never trust a key we did not pin at startup).
        match self.pinned_vks.get(&origin_node_id) {
            Some(vk) => Self::pq_verify(vk, payload, signature),
            None => {
                tracing::error!(
                    target: "siem",
                    origin_node_id = %origin_node_id,
                    "SIEM:CRITICAL invalidation from node with NO pinned verifying key — rejected"
                );
                false
            }
        }
    }
}

/// A broadcaster that disseminates a signed invalidation event to all cluster
/// peers over the existing transport (SHARD / gossip / Raft). The wiring site
/// supplies the real fan-out; the propagation logic does not care how delivery
/// happens (dependency inversion — keeps `cluster.rs` untouched).
pub trait InvalidationBroadcaster: Send + Sync {
    /// Disseminate `event` to all peers. Best-effort; transient transport
    /// failures should be retried by the caller's transport layer. Returns the
    /// number of peers the event was dispatched to (0 is allowed, e.g. solo).
    fn broadcast(&self, event: &SessionInvalidationEvent) -> Result<usize, String>;
}

/// Coordinates cross-node revocation: on a local revoke it SIGNS (per-node
/// ML-DSA-87) and BROADCASTS a [`SessionInvalidationEvent`]; on receipt it
/// VERIFIES the originating node's signature, enforces replay protection, and
/// applies the revocation watermark to the local [`DistributedSessionStore`].
///
/// This is the production call site the audit found MISSING (F3): wire it into
/// the `terminate_*_session` path so a revoke on node A becomes effective on
/// node B, not local-only-until-TTL.
pub struct RevocationCoordinator {
    /// This node's cluster [`NodeId`] (the attributed origin of local events).
    node_id: NodeId,
    /// Signature backend (per-node ML-DSA-87 in production).
    signer: std::sync::Arc<dyn InvalidationSigner>,
    /// Transport fan-out to peers.
    broadcaster: std::sync::Arc<dyn InvalidationBroadcaster>,
    /// Replay protection: origin NodeId -> recently-seen timestamps.
    seen_events: std::sync::Mutex<std::collections::HashMap<NodeId, Vec<i64>>>,
    /// Replay acceptance window (microseconds).
    replay_window_us: i64,
}

impl std::fmt::Debug for RevocationCoordinator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RevocationCoordinator")
            .field("node_id", &self.node_id)
            .field("replay_window_us", &self.replay_window_us)
            .finish_non_exhaustive()
    }
}

impl RevocationCoordinator {
    const DEFAULT_REPLAY_WINDOW_US: i64 = 60 * 1_000_000;

    /// Construct a coordinator for this node (identified by its cluster [`NodeId`]).
    pub fn new(
        node_id: NodeId,
        signer: std::sync::Arc<dyn InvalidationSigner>,
        broadcaster: std::sync::Arc<dyn InvalidationBroadcaster>,
    ) -> Self {
        Self {
            node_id,
            signer,
            broadcaster,
            seen_events: std::sync::Mutex::new(std::collections::HashMap::new()),
            replay_window_us: Self::DEFAULT_REPLAY_WINDOW_US,
        }
    }

    /// This node's cluster [`NodeId`].
    pub fn node_id(&self) -> NodeId {
        self.node_id
    }

    /// Build a signed invalidation event attributed to THIS node.
    pub fn create_signed_event(
        &self,
        user_id: Uuid,
        reason: InvalidationReason,
    ) -> Result<SessionInvalidationEvent, String> {
        let timestamp = now_us();
        let payload =
            invalidation_signing_payload(&user_id, reason, timestamp, self.node_id);
        let signature = self.signer.sign(&payload)?;
        Ok(SessionInvalidationEvent {
            user_id,
            reason,
            timestamp,
            node_id: self.node_id,
            signature,
        })
    }

    /// Fan a pre-built (already locally-applied) event out to peers.
    ///
    /// Used by callers that must make a side effect durable (e.g. a DB write)
    /// BEFORE the network fan-out, so the local state is authoritative even if
    /// the broadcast fails. Returns the number of peers dispatched to.
    pub fn broadcast_event(
        &self,
        event: &SessionInvalidationEvent,
    ) -> Result<usize, String> {
        self.broadcaster.broadcast(event)
    }

    /// PRODUCTION CALL SITE (F3): revoke a user cluster-wide.
    ///
    /// Signs the event, applies the watermark + terminates local sessions
    /// immediately (so the issuing node is consistent even if broadcast is slow),
    /// then broadcasts so every other node honors the revoke. Returns the signed
    /// event so the caller can also persist it if desired.
    ///
    /// FAIL-CLOSED: if signing fails the error propagates and NOTHING is applied
    /// (there is no signed event to honor) — the caller MUST treat a revoke error
    /// as "deny", never as "continue serving". A broadcast failure, by contrast,
    /// is non-fatal: the local revoke already happened and peers converge via
    /// anti-entropy; we surface it in SIEM but keep the local revoke in force.
    pub fn revoke_user(
        &self,
        store: &mut DistributedSessionStore,
        user_id: Uuid,
        reason: InvalidationReason,
    ) -> Result<SessionInvalidationEvent, String> {
        let event = self.create_signed_event(user_id, reason)?;
        // Apply locally first (authoritative for this node).
        store.apply_invalidation_event(&event);
        // Then fan out. A broadcast failure is surfaced but does NOT roll back
        // the local revoke (revocation must never be weaker than requested).
        match self.broadcaster.broadcast(&event) {
            Ok(peers) => {
                tracing::info!(
                    target: "siem",
                    user_id = %user_id,
                    reason = reason.as_str(),
                    peers,
                    "SIEM:INFO revocation broadcast to peers"
                );
            }
            Err(e) => {
                tracing::error!(
                    target: "siem",
                    user_id = %user_id,
                    error = %e,
                    "SIEM:CRITICAL revocation broadcast FAILED — applied locally, peers may lag until anti-entropy"
                );
            }
        }
        Ok(event)
    }

    /// Verify an incoming event's per-node signature + freshness + replay, then
    /// apply its watermark to `store`. Returns the user_id on success.
    ///
    /// Verification order (fail-closed): freshness window -> per-node signature
    /// against the ORIGINATING node's pinned VK -> replay/dedup. Only then is the
    /// watermark recorded. A signature that does not verify under the claimed
    /// origin node is rejected (F9: no node can mint events attributed to another).
    pub fn accept_event(
        &self,
        store: &mut DistributedSessionStore,
        event: &SessionInvalidationEvent,
    ) -> Result<Uuid, String> {
        let now = now_us();

        // 1. Freshness — reject events outside the replay window.
        if (now - event.timestamp).abs() > self.replay_window_us {
            tracing::warn!(
                target: "siem",
                node_id = %event.node_id,
                user_id = %event.user_id,
                "SIEM:WARNING invalidation event outside replay window"
            );
            return Err("invalidation event outside replay window".to_string());
        }

        // 2. Per-node signature over the canonical payload, verified against the
        //    ORIGINATING node's pinned verifying key. This is the F9 fix.
        let payload = invalidation_signing_payload(
            &event.user_id,
            event.reason,
            event.timestamp,
            event.node_id,
        );
        if !self.signer.verify(event.node_id, &payload, &event.signature) {
            tracing::error!(
                target: "siem",
                node_id = %event.node_id,
                user_id = %event.user_id,
                "SIEM:CRITICAL invalidation event signature invalid for claimed origin — possible spoofing"
            );
            return Err("invalidation event signature invalid".to_string());
        }

        // 3. Replay/dedup per origin node.
        {
            let mut seen = self
                .seen_events
                .lock()
                .map_err(|_| "replay-state lock poisoned".to_string())?;
            let node_events = seen.entry(event.node_id).or_default();
            if node_events.contains(&event.timestamp) {
                tracing::warn!(
                    target: "siem",
                    node_id = %event.node_id,
                    "SIEM:WARNING duplicate invalidation event rejected"
                );
                return Err("duplicate invalidation event".to_string());
            }
            node_events.push(event.timestamp);
            node_events.retain(|ts| (now - ts).abs() <= self.replay_window_us);
        }

        // 4. Apply: record watermark + terminate local sessions.
        store.apply_invalidation_event(event);
        tracing::info!(
            target: "siem",
            user_id = %event.user_id,
            reason = event.reason.as_str(),
            source_node = %event.node_id,
            "SIEM:INFO verified cross-node invalidation accepted and applied"
        );
        Ok(event.user_id)
    }

    /// Prune replay-protection state older than the window.
    pub fn cleanup_replay_state(&self) {
        let now = now_us();
        if let Ok(mut seen) = self.seen_events.lock() {
            seen.retain(|_, timestamps| {
                timestamps.retain(|ts| (now - ts).abs() <= self.replay_window_us);
                !timestamps.is_empty()
            });
        }
    }
}

/// Encrypt session data (chain key) for at-rest storage.
fn encrypt_session_data(
    key: &[u8; 32],
    session_id: &Uuid,
    data: &[u8],
) -> Result<Vec<u8>, String> {
    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

    let mut nonce_bytes = [0u8; 12];
    getrandom::getrandom(&mut nonce_bytes).map_err(|e| format!("nonce gen failed: {e}"))?;

    let aad = format!("MILNET-SESSION-v1:{}", session_id);
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| "AES-256-GCM cipher initialization failed".to_string())?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: data,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|e| format!("session encryption failed: {e}"))?;

    let mut out = Vec::with_capacity(12 + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt session data.
pub fn decrypt_session_data(
    key: &[u8; 32],
    session_id: &Uuid,
    sealed: &[u8],
) -> Result<Vec<u8>, String> {
    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

    if sealed.len() < 28 {
        // 12 nonce + 16 tag minimum
        return Err("sealed data too short".to_string());
    }

    let aad = format!("MILNET-SESSION-v1:{}", session_id);
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| "AES-256-GCM cipher initialization failed".to_string())?;
    let nonce = Nonce::from_slice(&sealed[..12]);

    cipher
        .decrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: &sealed[12..],
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| "session decryption failed — tampered or wrong key".to_string())
}

fn now_us() -> i64 {
    crate::secure_time::secure_now_us_i64()
}

#[cfg(test)]
mod tests {
    // The legacy shared-HMAC InvalidationEventProcessor is #[deprecated] (F9).
    // These tests still exercise it as a test/dev helper and to pin its existing
    // behavior, so we allow deprecation here. Production paths use the per-node
    // ML-DSA-87 signer, which is covered by the F9 tests further below.
    #![allow(deprecated)]
    use super::*;

    fn make_store() -> DistributedSessionStore {
        let mut key = [0u8; 32];
        getrandom::getrandom(&mut key).unwrap();
        DistributedSessionStore::new(key, SessionStoreConfig::default())
    }

    fn make_store_with_config(config: SessionStoreConfig) -> DistributedSessionStore {
        let mut key = [0u8; 32];
        getrandom::getrandom(&mut key).unwrap();
        DistributedSessionStore::new(key, config)
    }

    #[test]
    fn create_session_returns_uuid() {
        let mut store = make_store();
        let user_id = Uuid::new_v4();
        let fingerprint = [0xABu8; 32];
        let chain_key = b"test-chain-key-data-32byteslong!";

        let session_id = store
            .create_session(user_id, 2, fingerprint, chain_key, 1)
            .unwrap();
        assert_ne!(session_id, Uuid::nil());
    }

    #[test]
    fn get_active_session() {
        let mut store = make_store();
        let user_id = Uuid::new_v4();
        let fingerprint = [0xCDu8; 32];
        let chain_key = b"chain-key-data";

        let session_id = store
            .create_session(user_id, 2, fingerprint, chain_key, 1)
            .unwrap();

        let session = store.get_session(&session_id).unwrap();
        assert_eq!(session.user_id, user_id);
        assert_eq!(session.tier, 2);
        assert_eq!(session.classification, 1);
        // The stored fingerprint is the HMAC blind index, not the raw value.
        assert_ne!(session.device_fingerprint, fingerprint, "raw fingerprint must not be stored");
        assert_eq!(session.device_fingerprint, blind_device_fingerprint(&fingerprint));
        assert!(!session.terminated);
        assert_eq!(session.ratchet_epoch, 1);
    }

    #[test]
    fn get_expired_session_returns_none() {
        let config = SessionStoreConfig {
            // All tiers expire in 0 microseconds (already expired)
            max_duration_by_tier: [0, 0, 0, 0],
            idle_timeout_us: 30 * 60 * 1_000_000,
            max_sessions_per_user: 5,
            cleanup_interval_secs: 60,
        };
        let mut store = make_store_with_config(config);
        let user_id = Uuid::new_v4();

        let session_id = store
            .create_session(user_id, 1, [0u8; 32], b"key", 0)
            .unwrap();

        // Session should be expired immediately
        assert!(store.get_session(&session_id).is_none());
    }

    #[test]
    fn touch_session_updates_activity() {
        let mut store = make_store();
        let user_id = Uuid::new_v4();

        let session_id = store
            .create_session(user_id, 2, [0u8; 32], b"key", 0)
            .unwrap();

        let before = store.get_session(&session_id).unwrap().last_activity;
        // Small delay to ensure time advances
        std::thread::sleep(std::time::Duration::from_millis(2));

        store.touch_session(&session_id, 5).unwrap();

        let session = store.get_session(&session_id).unwrap();
        assert!(session.last_activity >= before);
        assert_eq!(session.ratchet_epoch, 5);
    }

    #[test]
    fn terminate_session_marks_terminated() {
        let mut store = make_store();
        let user_id = Uuid::new_v4();

        let session_id = store
            .create_session(user_id, 2, [0u8; 32], b"key", 0)
            .unwrap();

        assert!(store.get_session(&session_id).is_some());
        assert!(store.terminate_session(&session_id));

        // Terminated session should not be returned
        assert!(store.get_session(&session_id).is_none());
    }

    #[test]
    fn terminate_nonexistent_session_returns_false() {
        let mut store = make_store();
        assert!(!store.terminate_session(&Uuid::new_v4()));
    }

    #[test]
    fn terminate_all_user_sessions() {
        let mut store = make_store();
        let user_id = Uuid::new_v4();

        let s1 = store
            .create_session(user_id, 1, [0u8; 32], b"k1", 0)
            .unwrap();
        let s2 = store
            .create_session(user_id, 2, [1u8; 32], b"k2", 0)
            .unwrap();
        let s3 = store
            .create_session(user_id, 3, [2u8; 32], b"k3", 0)
            .unwrap();

        assert_eq!(store.terminate_user_sessions(&user_id), 3);
        assert!(store.get_session(&s1).is_none());
        assert!(store.get_session(&s2).is_none());
        assert!(store.get_session(&s3).is_none());
    }

    #[test]
    fn concurrent_session_limit_enforcement() {
        let config = SessionStoreConfig {
            max_sessions_per_user: 2,
            ..SessionStoreConfig::default()
        };
        let mut store = make_store_with_config(config);
        let user_id = Uuid::new_v4();

        // First two should succeed
        store
            .create_session(user_id, 2, [0u8; 32], b"k1", 0)
            .unwrap();
        store
            .create_session(user_id, 2, [1u8; 32], b"k2", 0)
            .unwrap();

        // Third should fail
        let result = store.create_session(user_id, 2, [2u8; 32], b"k3", 0);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("concurrent session limit"));
    }

    #[test]
    fn concurrent_limit_allows_after_termination() {
        let config = SessionStoreConfig {
            max_sessions_per_user: 1,
            ..SessionStoreConfig::default()
        };
        let mut store = make_store_with_config(config);
        let user_id = Uuid::new_v4();

        let s1 = store
            .create_session(user_id, 2, [0u8; 32], b"k1", 0)
            .unwrap();

        // Second should fail
        assert!(store
            .create_session(user_id, 2, [1u8; 32], b"k2", 0)
            .is_err());

        // Terminate first, then second should succeed
        store.terminate_session(&s1);
        // Create triggers cleanup of terminated sessions
        assert!(store
            .create_session(user_id, 2, [1u8; 32], b"k2", 0)
            .is_ok());
    }

    #[test]
    fn cleanup_removes_expired_and_terminated_sessions() {
        let config = SessionStoreConfig {
            max_duration_by_tier: [0, 0, 0, 0], // Expire immediately
            idle_timeout_us: 30 * 60 * 1_000_000,
            max_sessions_per_user: 10,
            cleanup_interval_secs: 60,
        };
        let mut store = make_store_with_config(config);
        let user1 = Uuid::new_v4();
        let user2 = Uuid::new_v4();

        store
            .create_session(user1, 1, [0u8; 32], b"k1", 0)
            .unwrap();
        store
            .create_session(user1, 2, [1u8; 32], b"k2", 0)
            .unwrap();
        store
            .create_session(user2, 3, [2u8; 32], b"k3", 0)
            .unwrap();

        // All sessions are expired (max_duration_by_tier = 0)
        let cleaned = store.cleanup();
        assert_eq!(cleaned, 3);
        assert_eq!(store.active_count(), 0);
    }

    #[test]
    fn session_encryption_round_trip() {
        let mut key = [0u8; 32];
        getrandom::getrandom(&mut key).unwrap();
        let session_id = Uuid::new_v4();
        let plaintext = b"secret-chain-key-material-here!!";

        let sealed = encrypt_session_data(&key, &session_id, plaintext).unwrap();
        assert_ne!(&sealed, plaintext.as_slice());
        assert!(sealed.len() >= 12 + plaintext.len() + 16); // nonce + data + tag

        let decrypted = decrypt_session_data(&key, &session_id, &sealed).unwrap();
        assert_eq!(&decrypted, plaintext.as_slice());
    }

    #[test]
    fn wrong_key_fails_decryption() {
        let mut key1 = [0u8; 32];
        let mut key2 = [0u8; 32];
        getrandom::getrandom(&mut key1).unwrap();
        getrandom::getrandom(&mut key2).unwrap();
        let session_id = Uuid::new_v4();

        let sealed = encrypt_session_data(&key1, &session_id, b"secret data").unwrap();

        // Decrypting with wrong key should fail
        let result = decrypt_session_data(&key2, &session_id, &sealed);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("tampered or wrong key"));
    }

    #[test]
    fn wrong_session_id_fails_decryption() {
        let mut key = [0u8; 32];
        getrandom::getrandom(&mut key).unwrap();
        let session_id1 = Uuid::new_v4();
        let session_id2 = Uuid::new_v4();

        let sealed = encrypt_session_data(&key, &session_id1, b"secret").unwrap();

        // Decrypting with different session_id (different AAD) should fail
        let result = decrypt_session_data(&key, &session_id2, &sealed);
        assert!(result.is_err());
    }

    #[test]
    fn sealed_data_too_short_fails() {
        let mut key = [0u8; 32];
        getrandom::getrandom(&mut key).unwrap();
        let session_id = Uuid::new_v4();

        let result = decrypt_session_data(&key, &session_id, &[0u8; 10]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too short"));
    }

    #[test]
    fn idle_timeout_enforcement() {
        let config = SessionStoreConfig {
            max_duration_by_tier: [
                999_999_999_999, // very long
                999_999_999_999,
                999_999_999_999,
                999_999_999_999,
            ],
            idle_timeout_us: 1, // 1 microsecond idle timeout (will expire instantly)
            max_sessions_per_user: 5,
            cleanup_interval_secs: 60,
        };
        let mut store = make_store_with_config(config);
        let user_id = Uuid::new_v4();

        let session_id = store
            .create_session(user_id, 2, [0u8; 32], b"key", 0)
            .unwrap();

        // Even a tiny sleep should exceed the 1us idle timeout
        std::thread::sleep(std::time::Duration::from_millis(1));

        // Session should be considered idle
        assert!(store.get_session(&session_id).is_none());
    }

    #[test]
    fn tier_specific_duration_limits() {
        // Tier 4 (Emergency) has the shortest duration (15 minutes)
        let config = SessionStoreConfig::default();
        assert!(config.max_duration_by_tier[0] > config.max_duration_by_tier[1]); // T1 > T2
        assert!(config.max_duration_by_tier[1] > config.max_duration_by_tier[2]); // T2 > T3
        assert!(config.max_duration_by_tier[2] > config.max_duration_by_tier[3]); // T3 > T4

        // Verify specific values
        assert_eq!(config.max_duration_by_tier[0], 8 * 60 * 60 * 1_000_000); // 8h
        assert_eq!(config.max_duration_by_tier[1], 4 * 60 * 60 * 1_000_000); // 4h
        assert_eq!(config.max_duration_by_tier[2], 1 * 60 * 60 * 1_000_000); // 1h
        assert_eq!(config.max_duration_by_tier[3], 15 * 60 * 1_000_000);     // 15m
    }

    #[test]
    fn active_count_reflects_state() {
        let mut store = make_store();
        assert_eq!(store.active_count(), 0);

        let user_id = Uuid::new_v4();
        let s1 = store
            .create_session(user_id, 2, [0u8; 32], b"k1", 0)
            .unwrap();
        assert_eq!(store.active_count(), 1);

        store
            .create_session(user_id, 2, [1u8; 32], b"k2", 0)
            .unwrap();
        assert_eq!(store.active_count(), 2);

        store.terminate_session(&s1);
        assert_eq!(store.active_count(), 1);
    }

    #[test]
    fn user_active_sessions_returns_correct_set() {
        let mut store = make_store();
        let user1 = Uuid::new_v4();
        let user2 = Uuid::new_v4();

        store
            .create_session(user1, 1, [0u8; 32], b"k1", 0)
            .unwrap();
        store
            .create_session(user1, 2, [1u8; 32], b"k2", 0)
            .unwrap();
        store
            .create_session(user2, 3, [2u8; 32], b"k3", 0)
            .unwrap();

        assert_eq!(store.user_active_sessions(&user1).len(), 2);
        assert_eq!(store.user_active_sessions(&user2).len(), 1);
        assert_eq!(store.user_active_sessions(&Uuid::new_v4()).len(), 0);
    }

    #[test]
    fn default_session_store_config() {
        let config = SessionStoreConfig::default();
        assert_eq!(config.max_sessions_per_user, 5);
        assert_eq!(config.cleanup_interval_secs, 60);
        assert_eq!(config.idle_timeout_us, 30 * 60 * 1_000_000);
    }

    // ── Device fingerprint enforcement tests ────────────────────────────

    #[test]
    fn get_session_bound_rejects_wrong_device() {
        let mut store = make_store();
        let user_id = Uuid::new_v4();
        let device_fp = [0xAAu8; 32];
        let wrong_fp = [0xBBu8; 32];

        let session_id = store
            .create_session(user_id, 2, device_fp, b"chain-key", 1)
            .unwrap();

        // Correct device should work
        let s = store.get_session_bound(&session_id, Some(&device_fp));
        assert!(s.is_some(), "correct device fingerprint must be accepted");

        // Wrong device should be rejected
        let s = store.get_session_bound(&session_id, Some(&wrong_fp));
        assert!(s.is_none(), "wrong device fingerprint must be rejected");
    }

    #[test]
    fn get_session_bound_allows_none_fingerprint() {
        // When no fingerprint is provided, session should still work (backwards compat)
        let mut store = make_store();
        let user_id = Uuid::new_v4();

        let session_id = store
            .create_session(user_id, 2, [0xAAu8; 32], b"chain-key", 1)
            .unwrap();

        let s = store.get_session_bound(&session_id, None);
        assert!(s.is_some(), "None fingerprint must be accepted for backwards compatibility");
    }

    #[test]
    fn get_session_bound_rejects_subtle_fingerprint_difference() {
        // Even a single bit difference in the fingerprint must be rejected
        let mut store = make_store();
        let user_id = Uuid::new_v4();
        let device_fp = [0xAAu8; 32];
        let mut almost_right_fp = device_fp;
        almost_right_fp[31] ^= 0x01; // flip one bit

        let session_id = store
            .create_session(user_id, 2, device_fp, b"chain-key", 1)
            .unwrap();

        let s = store.get_session_bound(&session_id, Some(&almost_right_fp));
        assert!(
            s.is_none(),
            "fingerprint differing by a single bit must be rejected"
        );
    }

    #[test]
    fn terminated_session_rejected_even_with_correct_fingerprint() {
        let mut store = make_store();
        let user_id = Uuid::new_v4();
        let device_fp = [0xAAu8; 32];

        let session_id = store
            .create_session(user_id, 2, device_fp, b"chain-key", 1)
            .unwrap();

        store.terminate_session(&session_id);

        // Even correct fingerprint should not resurrect a terminated session
        let s = store.get_session_bound(&session_id, Some(&device_fp));
        assert!(s.is_none(), "terminated session must not be accessible");
    }

    // ── Zeroization tests ──────────────────────────────────────────────

    #[test]
    fn drop_zeroizes_distributed_session_runs_without_panic() {
        let session = DistributedSession {
            session_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            tier: 2,
            created_at: 1_000_000,
            expires_at: 2_000_000,
            last_activity: 1_000_000,
            ratchet_epoch: 1,
            encrypted_chain_key: vec![0xFFu8; 64],
            device_fingerprint: [0xAA; 32],
            classification: 1,
            terminated: false,
        };
        drop(session);
    }

    #[test]
    fn terminate_session_zeroizes_keys() {
        let mut store = make_store();
        let user_id = Uuid::new_v4();
        let fingerprint = [0xBBu8; 32];

        let session_id = store
            .create_session(user_id, 2, fingerprint, b"chain-key-material", 1)
            .unwrap();

        store.terminate_session(&session_id);

        let session = store.sessions.get(&session_id).unwrap();
        assert!(session.terminated);
        assert!(
            session.encrypted_chain_key.iter().all(|&b| b == 0),
            "encrypted_chain_key must be zeroized after terminate"
        );
        assert_eq!(
            session.device_fingerprint,
            [0u8; 32],
            "device_fingerprint must be zeroized after terminate"
        );
    }

    #[test]
    fn drop_zeroizes_empty_fields_without_panic() {
        let session = DistributedSession {
            session_id: Uuid::nil(),
            user_id: Uuid::nil(),
            tier: 0,
            created_at: 0,
            expires_at: 0,
            last_activity: 0,
            ratchet_epoch: 0,
            encrypted_chain_key: Vec::new(),
            device_fingerprint: [0u8; 32],
            classification: 0,
            terminated: false,
        };
        drop(session);
    }

    #[test]
    fn drop_zeroizes_large_chain_key_no_panic() {
        let session = DistributedSession {
            session_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            tier: 1,
            created_at: 0,
            expires_at: 0,
            last_activity: 0,
            ratchet_epoch: 0,
            encrypted_chain_key: vec![0xFFu8; 1_000_000],
            device_fingerprint: [0xCC; 32],
            classification: 0,
            terminated: false,
        };
        drop(session);
    }

    fn make_processor() -> InvalidationEventProcessor {
        let mut key = [0u8; 64];
        getrandom::getrandom(&mut key).unwrap();
        InvalidationEventProcessor::new(key)
    }

    #[test]
    fn create_and_verify_invalidation_event() {
        let mut proc = make_processor();
        let user_id = Uuid::new_v4();
        let event = proc.create_event(user_id, InvalidationReason::PasswordChanged, nid(1));
        let result = proc.verify_and_accept(&event);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), user_id);
    }

    #[test]
    fn reject_tampered_signature() {
        let mut proc = make_processor();
        let user_id = Uuid::new_v4();
        let mut event = proc.create_event(user_id, InvalidationReason::RoleChanged, nid(1));
        if let Some(byte) = event.signature.first_mut() {
            *byte ^= 0xFF;
        }
        let result = proc.verify_and_accept(&event);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("signature invalid"));
    }

    #[test]
    fn reject_replay_same_event() {
        let mut proc = make_processor();
        let user_id = Uuid::new_v4();
        let event = proc.create_event(user_id, InvalidationReason::SecurityIncident, nid(1));
        assert!(proc.verify_and_accept(&event).is_ok());
        let result = proc.verify_and_accept(&event);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("duplicate"));
    }

    #[test]
    fn reject_event_from_different_key() {
        let proc1 = make_processor();
        let mut proc2 = make_processor();
        let user_id = Uuid::new_v4();
        let event = proc1.create_event(user_id, InvalidationReason::AdminAction, nid(1));
        let result = proc2.verify_and_accept(&event);
        assert!(result.is_err());
    }

    #[test]
    fn apply_invalidation_event_terminates_sessions() {
        let mut store = make_store();
        let user_id = Uuid::new_v4();
        store.create_session(user_id, 2, [0u8; 32], b"k1", 0).unwrap();
        store.create_session(user_id, 2, [1u8; 32], b"k2", 0).unwrap();
        assert_eq!(store.active_count(), 2);

        let proc = make_processor();
        let event = proc.create_event(user_id, InvalidationReason::PasswordChanged, nid(2));
        let terminated = store.apply_invalidation_event(&event);
        assert_eq!(terminated, 2);
        assert_eq!(store.active_count(), 0);
    }

    #[test]
    fn invalidation_reason_as_str() {
        assert_eq!(InvalidationReason::PasswordChanged.as_str(), "password_changed");
        assert_eq!(InvalidationReason::RoleChanged.as_str(), "role_changed");
        assert_eq!(InvalidationReason::PermissionEscalation.as_str(), "permission_escalation");
        assert_eq!(InvalidationReason::SecurityIncident.as_str(), "security_incident");
        assert_eq!(InvalidationReason::AdminAction.as_str(), "admin_action");
    }

    // ── MD-34: FP blind key determinism tests ─────────────────────────

    #[test]
    fn fp_blind_key_returns_consistent_value() {
        // OnceLock ensures the same key is returned on every call.
        let key1 = fp_blind_key();
        let key2 = fp_blind_key();
        assert_eq!(key1, key2, "fp_blind_key must return the same value on repeated calls");
    }

    #[test]
    fn blind_device_fingerprint_deterministic() {
        let fp = [0xABu8; 32];
        let blind1 = blind_device_fingerprint(&fp);
        let blind2 = blind_device_fingerprint(&fp);
        assert_eq!(blind1, blind2, "same fingerprint must produce same blind index");
    }

    #[test]
    fn blind_device_fingerprint_different_inputs_differ() {
        let fp1 = [0xAAu8; 32];
        let fp2 = [0xBBu8; 32];
        let blind1 = blind_device_fingerprint(&fp1);
        let blind2 = blind_device_fingerprint(&fp2);
        assert_ne!(blind1, blind2, "different fingerprints must produce different blind indices");
    }

    // ── Debug redaction tests ─────────────────────────────────────────

    #[test]
    fn distributed_session_debug_redacts_sensitive_fields() {
        let session = DistributedSession {
            session_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            tier: 2,
            created_at: 1_000_000,
            expires_at: 2_000_000,
            last_activity: 1_000_000,
            ratchet_epoch: 1,
            encrypted_chain_key: vec![0xDE, 0xAD],
            device_fingerprint: [0xBE; 32],
            classification: 1,
            terminated: false,
        };
        let debug_str = format!("{:?}", session);
        assert!(debug_str.contains("[ENCRYPTED]"), "chain key must be redacted in Debug");
        assert!(debug_str.contains("[REDACTED]"), "fingerprint must be redacted in Debug");
        assert!(!debug_str.contains("DEAD"), "raw chain key bytes must not appear in Debug");
    }

    // ── F3: cross-node revocation watermark (read-path honoring) ──────────
    //
    // Audit F3 (zerotrust-gw): revocation did not propagate cross-node and the
    // read path read only the local cache. These tests pin the watermark gate.

    /// A revocation watermark denies a session that existed at/before it, even
    /// though the session's own `terminated` flag is false (it was never
    /// individually terminated on this node — the remote-revoke case).
    #[test]
    fn watermark_denies_preexisting_session() {
        let mut store = make_store();
        let user_id = Uuid::new_v4();
        let sid = store
            .create_session(user_id, 2, [0u8; 32], b"k", 0)
            .unwrap();
        assert!(store.get_session(&sid).is_some());

        // Simulate an invalidation that arrived from another node: watermark at
        // "now" (>= the session's created_at). The local cache entry is NOT
        // individually terminated — only the watermark is recorded.
        let watermark = now_us();
        store.record_user_invalidation(user_id, watermark);

        assert!(
            store.get_session(&sid).is_none(),
            "session must be denied by the cross-node revocation watermark"
        );
        assert!(
            store.user_active_sessions(&user_id).is_empty(),
            "user_active_sessions must also honor the watermark"
        );
    }

    /// A session created AFTER the watermark (a fresh re-authentication) is NOT
    /// denied — revocation is a not-before gate, not a permanent user ban.
    #[test]
    fn watermark_allows_session_created_after_revoke() {
        let mut store = make_store();
        let user_id = Uuid::new_v4();

        // Watermark in the past.
        let watermark = now_us() - 1_000_000; // 1s ago
        store.record_user_invalidation(user_id, watermark);

        // New session created now (after the watermark) must survive.
        let sid = store
            .create_session(user_id, 2, [0u8; 32], b"k", 0)
            .unwrap();
        assert!(
            store.get_session(&sid).is_some(),
            "post-revoke re-auth session must NOT be denied"
        );
        assert_eq!(store.user_active_sessions(&user_id).len(), 1);
    }

    /// `record_user_invalidation` is monotonic: an older watermark never moves
    /// the effective not-before backward.
    #[test]
    fn watermark_is_monotonic() {
        let mut store = make_store();
        let user_id = Uuid::new_v4();
        let newer = now_us();
        let older = newer - 5_000_000;
        store.record_user_invalidation(user_id, newer);
        store.record_user_invalidation(user_id, older); // must not regress
        // A session created between older and newer must still be denied.
        let created_between = newer - 1_000_000;
        assert!(store.is_user_invalidated(&user_id, created_between));
    }

    /// `apply_invalidation_event` records the watermark, so a subsequent read of
    /// even a freshly re-cached session for that user (created before the event)
    /// is denied.
    #[test]
    fn apply_invalidation_event_records_watermark() {
        let mut store = make_store();
        let user_id = Uuid::new_v4();
        let sid = store
            .create_session(user_id, 2, [0u8; 32], b"k", 0)
            .unwrap();

        let proc = make_processor();
        let event = proc.create_event(user_id, InvalidationReason::SecurityIncident, nid(2));
        store.apply_invalidation_event(&event);

        assert_eq!(store.invalidated_user_count(), 1);
        assert!(store.get_session(&sid).is_none());
        assert!(store.is_user_invalidated(&user_id, event.timestamp));
    }

    /// Watermark cleanup prunes entries older than the max session lifetime.
    #[test]
    fn cleanup_invalidations_prunes_old_watermarks() {
        let mut store = make_store();
        let user_id = Uuid::new_v4();
        // Watermark well beyond an 8h max lifetime ago.
        let stale = now_us() - 9 * 60 * 60 * 1_000_000;
        store.record_user_invalidation(user_id, stale);
        assert_eq!(store.invalidated_user_count(), 1);

        store.cleanup_invalidations(8 * 60 * 60 * 1_000_000);
        assert_eq!(store.invalidated_user_count(), 0, "stale watermark must be pruned");
    }

    // ── Step 3: fail-closed under partition for privileged tiers ──────────

    /// When partitioned from the revocation quorum, a Tier-1/Tier-2 session is
    /// DENIED (fail-closed), while Tier-3/Tier-4 sessions are still served
    /// (graceful degradation). Answers the audit's "fails OPEN" verdict.
    #[test]
    fn partition_fails_closed_for_high_tier_only() {
        let mut store = make_store();
        let user_id = Uuid::new_v4();
        let s_t1 = store.create_session(user_id, 1, [1u8; 32], b"k", 0).unwrap();
        let s_t2 = store.create_session(user_id, 2, [2u8; 32], b"k", 0).unwrap();
        let s_t3 = store.create_session(user_id, 3, [3u8; 32], b"k", 0).unwrap();
        let s_t4 = store.create_session(user_id, 4, [4u8; 32], b"k", 0).unwrap();

        // Connected: all served.
        assert!(store.get_session(&s_t1).is_some());
        assert!(store.get_session(&s_t3).is_some());

        // Partitioned: privileged tiers (1,2) denied, lower tiers (3,4) served.
        store.set_partitioned(true);
        assert!(store.is_partitioned());
        assert!(store.get_session(&s_t1).is_none(), "Tier 1 must fail closed under partition");
        assert!(store.get_session(&s_t2).is_none(), "Tier 2 must fail closed under partition");
        assert!(store.get_session(&s_t3).is_some(), "Tier 3 degrades gracefully (served)");
        assert!(store.get_session(&s_t4).is_some(), "Tier 4 degrades gracefully (served)");

        // Healed: privileged tiers served again.
        store.set_partitioned(false);
        assert!(store.get_session(&s_t1).is_some(), "Tier 1 served again after heal");
    }

    /// The fail-closed tier bound is configurable.
    #[test]
    fn partition_fail_closed_tier_bound_configurable() {
        let mut store = make_store();
        let user_id = Uuid::new_v4();
        let s_t3 = store.create_session(user_id, 3, [3u8; 32], b"k", 0).unwrap();

        store.set_fail_closed_max_tier(3); // now Tier 3 also fails closed
        store.set_partitioned(true);
        assert!(store.get_session(&s_t3).is_none(), "Tier 3 fails closed when bound raised to 3");
    }

    // ── F3 + F9: RevocationCoordinator end-to-end propagation ─────────────

    /// Test signer: per-node "signatures" that ONLY verify for the legitimately
    /// originating node, modeling raft-identity's pinned-VK registry. A signature
    /// minted by one node but claimed to originate from another MUST fail — this
    /// is the F9 anti-spoofing property under test.
    struct TestSigner {
        /// The node this signer signs AS.
        this_node: NodeId,
    }

    impl InvalidationSigner for TestSigner {
        fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, String> {
            // "Signature" = domain-separated hash of (this_node || payload),
            // standing in for an ML-DSA-87 signature under this node's key.
            Ok(test_node_sig(self.this_node, payload))
        }
        fn verify(&self, origin_node_id: NodeId, payload: &[u8], signature: &[u8]) -> bool {
            // Recompute the expected signature for the CLAIMED origin and compare.
            // A signature produced by a different node yields different bytes →
            // a non-originating node cannot mint a valid event for another.
            let expected = test_node_sig(origin_node_id, payload);
            use subtle::ConstantTimeEq;
            expected.as_slice().ct_eq(signature).unwrap_u8() == 1
        }
    }

    /// Map a small integer to a distinct, stable test [`NodeId`].
    fn nid(n: u128) -> NodeId {
        NodeId(Uuid::from_u128(n))
    }

    fn test_node_sig(node_id: NodeId, payload: &[u8]) -> Vec<u8> {
        use sha2::{Digest, Sha512};
        let mut h = Sha512::new();
        h.update(b"TEST-NODE-SIG-v1");
        h.update(node_id.0.as_bytes());
        h.update(payload);
        h.finalize().to_vec()
    }

    /// Broadcaster that captures dispatched events for assertions (models the
    /// SHARD/gossip fan-out).
    #[derive(Default)]
    struct CapturingBroadcaster {
        sent: std::sync::Mutex<Vec<SessionInvalidationEvent>>,
    }

    impl InvalidationBroadcaster for CapturingBroadcaster {
        fn broadcast(&self, event: &SessionInvalidationEvent) -> Result<usize, String> {
            self.sent.lock().unwrap().push(event.clone());
            Ok(1)
        }
    }

    /// End-to-end (F3): revoke on node A propagates and node B then DENIES the
    /// session. This is the core audit scenario.
    #[test]
    fn revoke_on_node_a_denies_on_node_b() {
        let user_id = Uuid::new_v4();

        // Node B holds a live session for the user.
        let mut store_b = make_store();
        let sid_b = store_b
            .create_session(user_id, 2, [0u8; 32], b"k", 0)
            .unwrap();
        assert!(store_b.get_session(&sid_b).is_some());

        // Node A issues the revoke: signs as node-a, broadcasts.
        let signer_a: std::sync::Arc<dyn InvalidationSigner> =
            std::sync::Arc::new(TestSigner { this_node: nid(0xA) });
        let bcast = std::sync::Arc::new(CapturingBroadcaster::default());
        let coord_a = RevocationCoordinator::new(nid(0xA), signer_a, bcast.clone());

        let mut store_a = make_store();
        store_a.create_session(user_id, 2, [9u8; 32], b"k", 0).unwrap();
        let event = coord_a
            .revoke_user(&mut store_a, user_id, InvalidationReason::PasswordChanged)
            .unwrap();
        // Node A is immediately consistent.
        assert_eq!(store_a.active_count(), 0);

        // The broadcast carried the signed event; node B receives + verifies it.
        let captured = bcast.sent.lock().unwrap().clone();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].node_id, nid(0xA));

        // Node B's coordinator verifies against the originating node's VK.
        let signer_b: std::sync::Arc<dyn InvalidationSigner> =
            std::sync::Arc::new(TestSigner { this_node: nid(0xB) });
        let coord_b = RevocationCoordinator::new(
            nid(0xB),
            signer_b,
            std::sync::Arc::new(CapturingBroadcaster::default()),
        );
        let accepted = coord_b.accept_event(&mut store_b, &event);
        assert!(accepted.is_ok(), "node B must accept node A's validly-signed event");

        // Node B now DENIES the session — propagation effective cluster-wide.
        assert!(
            store_b.get_session(&sid_b).is_none(),
            "node B must deny the revoked session after propagation"
        );
    }

    /// F9: a non-originating node CANNOT mint a valid invalidation attributed to
    /// another node. An event whose signature was produced by node-evil but that
    /// claims origin node-a is rejected on receipt.
    #[test]
    fn non_originating_node_cannot_mint_invalidation() {
        let user_id = Uuid::new_v4();
        let mut store_b = make_store();
        let sid_b = store_b
            .create_session(user_id, 2, [0u8; 32], b"k", 0)
            .unwrap();

        // Attacker (node-evil) forges an event but stamps node_id = "node-a".
        // It can only sign as itself, so the signature is node-evil's over a
        // payload that names node-a — verify() recomputes for node-a and fails.
        let timestamp = now_us();
        let payload =
            invalidation_signing_payload(&user_id, InvalidationReason::AdminAction, timestamp, nid(0xA));
        let forged_sig = test_node_sig(nid(0xE), &payload);
        let forged = SessionInvalidationEvent {
            user_id,
            reason: InvalidationReason::AdminAction,
            timestamp,
            node_id: nid(0xA), // claimed origin (spoofed)
            signature: forged_sig,
        };

        let signer_b: std::sync::Arc<dyn InvalidationSigner> =
            std::sync::Arc::new(TestSigner { this_node: nid(0xB) });
        let coord_b = RevocationCoordinator::new(
            nid(0xB),
            signer_b,
            std::sync::Arc::new(CapturingBroadcaster::default()),
        );

        let result = coord_b.accept_event(&mut store_b, &forged);
        assert!(result.is_err(), "spoofed-origin event must be rejected");
        assert!(result.unwrap_err().contains("signature invalid"));
        // The session must remain valid — the forged mass-revoke had no effect.
        assert!(
            store_b.get_session(&sid_b).is_some(),
            "forged invalidation must not revoke the victim's session"
        );
        assert_eq!(store_b.invalidated_user_count(), 0);
    }

    /// `accept_event` rejects a replayed event (same origin+timestamp twice).
    #[test]
    fn coordinator_rejects_replay() {
        let user_id = Uuid::new_v4();
        let mut store = make_store();
        store.create_session(user_id, 2, [0u8; 32], b"k", 0).unwrap();

        let signer: std::sync::Arc<dyn InvalidationSigner> =
            std::sync::Arc::new(TestSigner { this_node: nid(0xA) });
        let coord = RevocationCoordinator::new(
            nid(0xB),
            signer,
            std::sync::Arc::new(CapturingBroadcaster::default()),
        );

        // Build a validly-signed event as node-a.
        let timestamp = now_us();
        let payload = invalidation_signing_payload(
            &user_id,
            InvalidationReason::RoleChanged,
            timestamp,
            nid(0xA),
        );
        let event = SessionInvalidationEvent {
            user_id,
            reason: InvalidationReason::RoleChanged,
            timestamp,
            node_id: nid(0xA),
            signature: test_node_sig(nid(0xA),&payload),
        };

        assert!(coord.accept_event(&mut store, &event).is_ok());
        let replay = coord.accept_event(&mut store, &event);
        assert!(replay.is_err());
        assert!(replay.unwrap_err().contains("duplicate"));
    }

    /// `accept_event` rejects an event whose timestamp is outside the replay
    /// window (stale/future), before applying anything.
    #[test]
    fn coordinator_rejects_stale_timestamp() {
        let user_id = Uuid::new_v4();
        let mut store = make_store();
        store.create_session(user_id, 2, [0u8; 32], b"k", 0).unwrap();

        let signer: std::sync::Arc<dyn InvalidationSigner> =
            std::sync::Arc::new(TestSigner { this_node: nid(0xA) });
        let coord = RevocationCoordinator::new(
            nid(0xB),
            signer,
            std::sync::Arc::new(CapturingBroadcaster::default()),
        );

        // 10 minutes in the past — well outside the 60s window.
        let timestamp = now_us() - 600 * 1_000_000;
        let payload = invalidation_signing_payload(
            &user_id,
            InvalidationReason::AdminAction,
            timestamp,
            nid(0xA),
        );
        let event = SessionInvalidationEvent {
            user_id,
            reason: InvalidationReason::AdminAction,
            timestamp,
            node_id: nid(0xA),
            signature: test_node_sig(nid(0xA),&payload),
        };

        let result = coord.accept_event(&mut store, &event);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("replay window"));
        assert_eq!(store.invalidated_user_count(), 0);
    }

    /// `revoke_user` surfaces a broadcast failure but STILL applies locally
    /// (revocation never weaker than requested).
    #[test]
    fn revoke_user_applies_locally_even_if_broadcast_fails() {
        struct FailingBroadcaster;
        impl InvalidationBroadcaster for FailingBroadcaster {
            fn broadcast(&self, _e: &SessionInvalidationEvent) -> Result<usize, String> {
                Err("transport down".into())
            }
        }

        let user_id = Uuid::new_v4();
        let mut store = make_store();
        let sid = store.create_session(user_id, 2, [0u8; 32], b"k", 0).unwrap();

        let signer: std::sync::Arc<dyn InvalidationSigner> =
            std::sync::Arc::new(TestSigner { this_node: nid(0xA) });
        let coord =
            RevocationCoordinator::new(nid(0xA), signer, std::sync::Arc::new(FailingBroadcaster));

        // revoke_user returns Ok(event) (local revoke is authoritative) even
        // though the broadcast failed.
        let event = coord
            .revoke_user(&mut store, user_id, InvalidationReason::SecurityIncident)
            .unwrap();
        assert_eq!(event.node_id, nid(0xA));
        assert!(
            store.get_session(&sid).is_none(),
            "local session must be revoked even when broadcast fails"
        );
    }

    /// `NodeDsaSigner` correctly delegates to the injected sign/verify closures
    /// (the seam F9 wires raft-identity's node_sign/verify_node_sig into).
    #[test]
    fn node_dsa_signer_delegates_to_closures() {
        let signer = NodeDsaSigner::new(
            Box::new(|payload: &[u8]| Ok(test_node_sig(nid(0xA), payload))),
            Box::new(|origin: NodeId, payload: &[u8], sig: &[u8]| {
                use subtle::ConstantTimeEq;
                test_node_sig(origin, payload).as_slice().ct_eq(sig).unwrap_u8() == 1
            }),
        );
        let payload = b"hello-payload";
        let sig = signer.sign(payload).unwrap();
        assert!(signer.verify(nid(0xA),payload, &sig), "valid sig must verify for origin");
        assert!(!signer.verify(nid(0xB),payload, &sig), "sig must NOT verify for a different origin");
    }

    // ── F9: concrete per-node ML-DSA-87 signer (real post-quantum crypto) ──

    fn seed(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    /// Domain separation: the canonical payload is prefixed with
    /// `MILNET-SESSION-REVOKE-v1`, so a signature computed over the SAME logical
    /// fields WITHOUT the prefix (as another protocol sharing the node key, e.g.
    /// the Raft transport, would produce) does NOT verify as a revocation. This
    /// pins the cross-protocol replay resistance raft-identity flagged.
    #[test]
    fn signing_payload_is_domain_separated() {
        let user_id = Uuid::new_v4();
        let ts = now_us();
        let canonical =
            invalidation_signing_payload(&user_id, InvalidationReason::AdminAction, ts, nid(0xA));
        assert!(
            canonical.starts_with(b"MILNET-SESSION-REVOKE-v1"),
            "payload must carry the session-revoke domain prefix"
        );

        // Bytes WITHOUT the domain prefix (a different signing domain), same
        // field layout otherwise (node_id as its raw 16 UUID bytes).
        let mut undomained = Vec::new();
        undomained.extend_from_slice(user_id.as_bytes());
        undomained.extend_from_slice(InvalidationReason::AdminAction.as_str().as_bytes());
        undomained.extend_from_slice(&ts.to_be_bytes());
        undomained.extend_from_slice(nid(0xA).0.as_bytes());
        assert_ne!(canonical, undomained, "domain prefix must change the signed bytes");

        // A real ML-DSA-87 signature over the un-domained bytes must NOT verify
        // when checked against the canonical (domain-separated) payload.
        let node_a = MlDsaNodeSigner::new(nid(0xA), seed(0xA1));
        let foreign_sig = node_a.sign(&undomained).unwrap();
        assert!(
            !node_a.verify(nid(0xA), &canonical, &foreign_sig),
            "a signature from another signing domain must not verify as a revoke"
        );
    }

    /// A node's own ML-DSA-87 signature verifies under its own pinned key.
    #[test]
    fn mldsa_signer_self_sign_verifies() {
        let signer = MlDsaNodeSigner::new(nid(0xA), seed(0xA1));
        let payload = b"invalidation-payload";
        let sig = signer.sign(payload).unwrap();
        assert!(
            signer.verify(nid(0xA),payload, &sig),
            "self-originated ML-DSA-87 signature must verify"
        );
    }

    /// A peer's signature verifies on another node once its VK is pinned.
    #[test]
    fn mldsa_signer_cross_node_with_pin_verifies() {
        let node_a = MlDsaNodeSigner::new(nid(0xA), seed(0xA1));
        let mut node_b = MlDsaNodeSigner::new(nid(0xB), seed(0xB2));
        // node-b pins node-a's verifying key (as it would at startup).
        node_b.pin_node(nid(0xA),node_a.own_verifying_key());

        let payload = b"payload-from-a";
        let sig_a = node_a.sign(payload).unwrap();
        assert!(
            node_b.verify(nid(0xA),payload, &sig_a),
            "node-b must verify node-a's signature against the pinned VK"
        );
    }

    /// F9 CORE: a node CANNOT mint an invalidation attributed to another node.
    /// node-evil signs a payload that names node-a as origin; node-b has node-a's
    /// real pinned VK, so node-evil's signature fails verification for origin
    /// "node-a". (With the old shared HMAC key this forgery would have SUCCEEDED.)
    #[test]
    fn mldsa_signer_cannot_forge_other_node_origin() {
        let node_a = MlDsaNodeSigner::new(nid(0xA), seed(0xA1));
        let node_evil = MlDsaNodeSigner::new(nid(0xE), seed(0xEE));
        let mut node_b = MlDsaNodeSigner::new(nid(0xB), seed(0xB2));
        // node-b pins the REAL node-a key.
        node_b.pin_node(nid(0xA),node_a.own_verifying_key());

        let payload = b"forged-mass-revoke";
        // node-evil signs with its OWN key (it cannot access node-a's key).
        let forged_sig = node_evil.sign(payload).unwrap();
        assert!(
            !node_b.verify(nid(0xA),payload, &forged_sig),
            "node-evil must NOT be able to mint an event attributed to node-a"
        );
    }

    /// An invalidation from a node with no pinned VK is rejected (fail-closed).
    #[test]
    fn mldsa_signer_unknown_origin_rejected() {
        let node_x = MlDsaNodeSigner::new(nid(0x4), seed(0xCC));
        let node_b = MlDsaNodeSigner::new(nid(0xB), seed(0xB2)); // does NOT pin node-x
        let payload = b"payload";
        let sig = node_x.sign(payload).unwrap();
        assert!(
            !node_b.verify(nid(0x4),payload, &sig),
            "signature from an unpinned origin must be rejected"
        );
    }

    /// End-to-end through the coordinator with REAL ML-DSA-87: revoke on A is
    /// accepted and applied on B; a forged-origin event is rejected.
    #[test]
    fn mldsa_end_to_end_revoke_propagation() {
        let user_id = Uuid::new_v4();

        // Node A signer + coordinator.
        let signer_a = std::sync::Arc::new(MlDsaNodeSigner::new(nid(0xA), seed(0xA1)));
        let a_vk = signer_a.own_verifying_key();
        let bcast = std::sync::Arc::new(CapturingBroadcaster::default());
        let coord_a = RevocationCoordinator::new(
            nid(0xA),
            signer_a as std::sync::Arc<dyn InvalidationSigner>,
            bcast.clone(),
        );

        // Node A revokes.
        let mut store_a = make_store();
        store_a.create_session(user_id, 2, [9u8; 32], b"k", 0).unwrap();
        let event = coord_a
            .revoke_user(&mut store_a, user_id, InvalidationReason::PasswordChanged)
            .unwrap();
        assert_eq!(store_a.active_count(), 0);

        // Node B signer pins node-a's VK; coordinator verifies the event.
        let mut signer_b_inner = MlDsaNodeSigner::new(nid(0xB), seed(0xB2));
        signer_b_inner.pin_node(nid(0xA),a_vk);
        let signer_b = std::sync::Arc::new(signer_b_inner);
        let coord_b = RevocationCoordinator::new(
            nid(0xB),
            signer_b as std::sync::Arc<dyn InvalidationSigner>,
            std::sync::Arc::new(CapturingBroadcaster::default()),
        );

        let mut store_b = make_store();
        let sid_b = store_b.create_session(user_id, 2, [0u8; 32], b"k", 0).unwrap();
        assert!(store_b.get_session(&sid_b).is_some());

        // Valid event from node-a is accepted and the session is denied.
        assert!(coord_b.accept_event(&mut store_b, &event).is_ok());
        assert!(
            store_b.get_session(&sid_b).is_none(),
            "node-b must deny the revoked session after verifying node-a's ML-DSA event"
        );

        // A forged event (node-evil signing but claiming node-a) is rejected.
        let node_evil = MlDsaNodeSigner::new(nid(0xE), seed(0xEE));
        let ts = now_us();
        let payload =
            invalidation_signing_payload(&user_id, InvalidationReason::AdminAction, ts, nid(0xA));
        let forged = SessionInvalidationEvent {
            user_id,
            reason: InvalidationReason::AdminAction,
            timestamp: ts,
            node_id: nid(0xA),
            signature: node_evil.sign(&payload).unwrap(),
        };
        let mut store_b2 = make_store();
        let sid_b2 = store_b2.create_session(user_id, 2, [1u8; 32], b"k", 0).unwrap();
        assert!(coord_b.accept_event(&mut store_b2, &forged).is_err());
        assert!(
            store_b2.get_session(&sid_b2).is_some(),
            "forged-origin event must not revoke on node-b"
        );
    }
}
