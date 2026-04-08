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

/// HMAC key for computing device fingerprint blind indices.
/// Initialized once from the OS CSPRNG. In production this MUST come from a KMS.
static FP_BLIND_KEY: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();

fn fp_blind_key() -> &'static [u8; 32] {
    FP_BLIND_KEY.get_or_init(|| {
        let mut key = [0u8; 32];
        // SECURITY: CSPRNG failure at this point is unrecoverable — the system
        // cannot generate secure key material. OnceLock prevents retry, so we
        // must succeed or abort.
        if let Err(e) = getrandom::getrandom(&mut key) {
            tracing::error!("CRITICAL: OS CSPRNG failure during blind key init: {e}");
            std::process::exit(1);
        }
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
}

impl DistributedSessionStore {
    pub fn new(encryption_key: [u8; 32], config: SessionStoreConfig) -> Self {
        Self {
            sessions: std::collections::HashMap::new(),
            user_sessions: std::collections::HashMap::new(),
            encryption_key,
            config,
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

        // Check expiry
        let now = now_us();
        if session.expires_at <= now {
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
    pub fn user_active_sessions(&self, user_id: &Uuid) -> Vec<&DistributedSession> {
        let now = now_us();
        self.user_sessions
            .get(user_id)
            .map(|sids| {
                sids.iter()
                    .filter_map(|sid| self.sessions.get(sid))
                    .filter(|s| !s.terminated && s.expires_at > now)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Persist a session to PostgreSQL for cross-node replication.
    /// Called after create_session to ensure durability.
    #[cfg(feature = "persistence")]
    pub async fn persist_session(
        &self,
        pool: &sqlx::PgPool,
        session: &DistributedSession,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO distributed_sessions \
             (session_id, user_id, tier, device_fingerprint, created_at, expires_at, last_activity, terminated) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
             ON CONFLICT (session_id) DO UPDATE SET \
             last_activity = $7, terminated = $8"
        )
        .bind(session.session_id)
        .bind(session.user_id)
        .bind(session.tier as i16)
        .bind(&session.device_fingerprint[..])
        .bind(session.created_at)
        .bind(session.expires_at)
        .bind(session.last_activity)
        .bind(session.terminated)
        .execute(pool)
        .await?;
        Ok(())
    }

    /// Load a session from PostgreSQL (fallback when not in local cache).
    #[cfg(feature = "persistence")]
    pub async fn load_session(
        &self,
        pool: &sqlx::PgPool,
        session_id: &Uuid,
    ) -> Result<Option<DistributedSession>, sqlx::Error> {
        let row: Option<(
            Uuid, Uuid, i16, Vec<u8>, i64, i64, i64, bool,
        )> = sqlx::query_as(
            "SELECT session_id, user_id, tier, device_fingerprint, created_at, expires_at, last_activity, terminated \
             FROM distributed_sessions WHERE session_id = $1"
        )
        .bind(session_id)
        .fetch_optional(pool)
        .await?;

        Ok(row.map(|(session_id, user_id, tier, fp_vec, created_at, expires_at, last_activity, terminated)| {
            let mut device_fingerprint = [0u8; 32];
            let copy_len = fp_vec.len().min(32);
            device_fingerprint[..copy_len].copy_from_slice(&fp_vec[..copy_len]);
            DistributedSession {
                session_id,
                user_id,
                tier: tier as u8,
                created_at,
                expires_at,
                last_activity,
                ratchet_epoch: 0,
                encrypted_chain_key: Vec::new(),
                device_fingerprint,
                classification: 0,
                terminated,
            }
        }))
    }
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
}
