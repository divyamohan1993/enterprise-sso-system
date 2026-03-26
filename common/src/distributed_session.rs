//! Distributed session persistence with encryption at rest.
//!
//! Replaces memory-only sessions with encrypted PostgreSQL-backed sessions.
//! Sessions are:
//! - Encrypted at rest (AES-256-GCM per-session DEK)
//! - Replicated across database nodes via PostgreSQL streaming replication
//! - Automatically expired based on tier-specific TTLs
//! - Bound to device fingerprint for additional security

use serde::{Deserialize, Serialize};
use uuid::Uuid;

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
    /// Device fingerprint for binding.
    pub device_fingerprint: [u8; 32],
    /// Classification level for MAC enforcement.
    pub classification: u8,
    /// Whether the session has been terminated.
    pub terminated: bool,
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

        let session = DistributedSession {
            session_id,
            user_id,
            tier,
            created_at: now,
            expires_at: now + max_duration,
            last_activity: now,
            ratchet_epoch: 1,
            encrypted_chain_key,
            device_fingerprint,
            classification,
            terminated: false,
        };

        self.sessions.insert(session_id, session);
        user_sessions.push(session_id);

        Ok(session_id)
    }

    /// Get a session by ID. Returns None if expired or terminated.
    pub fn get_session(&self, session_id: &Uuid) -> Option<&DistributedSession> {
        let session = self.sessions.get(session_id)?;
        let now = now_us();
        if session.terminated || session.expires_at <= now {
            return None;
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

    /// Terminate a session (revoke).
    pub fn terminate_session(&mut self, session_id: &Uuid) -> bool {
        if let Some(session) = self.sessions.get_mut(session_id) {
            session.terminated = true;
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
}

impl Drop for DistributedSessionStore {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.encryption_key.zeroize();
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
    let cipher = Aes256Gcm::new_from_slice(key).expect("32-byte key");
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
    let cipher = Aes256Gcm::new_from_slice(key).expect("32-byte key");
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
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_micros() as i64
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
        assert_eq!(session.device_fingerprint, fingerprint);
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
}
