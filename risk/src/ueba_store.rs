//! UEBA (User and Entity Behavior Analytics) Persistent Storage.
//!
//! Provides PostgreSQL-backed persistence for `UserBaseline` from
//! `scoring.rs` with:
//! - Encrypted fields (AES-256-GCM) for sensitive behavioral data
//! - Load baselines on startup, periodic flush to DB (every 5 min)
//! - Baseline aging: reduce confidence for stale baselines (>30 days)
//! - Per-tenant baseline isolation
//! - Historical anomaly scores for trending
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use crate::scoring::UserBaseline;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Default flush interval (5 minutes).
const DEFAULT_FLUSH_INTERVAL_SECS: u64 = 300;

/// Baseline staleness threshold (30 days). Baselines older than this have
/// reduced confidence.
const BASELINE_STALENESS_DAYS: u64 = 30;
const BASELINE_STALENESS_SECS: i64 = (BASELINE_STALENESS_DAYS * 86400) as i64;

/// Maximum number of historical anomaly scores per user (ring buffer).
const MAX_ANOMALY_HISTORY: usize = 1000;

// ---------------------------------------------------------------------------
// Encrypted baseline record (DB row representation)
// ---------------------------------------------------------------------------

/// A serialized, encrypted baseline record suitable for DB storage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedBaselineRecord {
    /// User ID.
    pub user_id: Uuid,
    /// Tenant ID for isolation.
    pub tenant_id: Uuid,
    /// AES-256-GCM encrypted baseline payload (hex-encoded ciphertext).
    pub encrypted_payload: String,
    /// Nonce used for encryption (hex-encoded, 12 bytes).
    pub nonce: String,
    /// Unix timestamp of last update.
    pub last_updated: i64,
    /// Confidence score [0.0, 1.0] — decays with staleness.
    pub confidence: f64,
}

/// Plaintext baseline data (serialized before encryption).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselinePayload {
    pub typical_login_hours: (u8, u8),
    pub known_networks: Vec<String>,
    pub avg_session_duration_secs: f64,
    pub avg_login_hour: f64,
}

impl BaselinePayload {
    /// Convert from a `UserBaseline`.
    pub fn from_baseline(baseline: &UserBaseline) -> Self {
        Self {
            typical_login_hours: baseline.typical_login_hours,
            known_networks: baseline.known_networks.clone(),
            avg_session_duration_secs: baseline.avg_session_duration_secs,
            avg_login_hour: baseline.typical_login_hours.0 as f64 + 2.0, // center estimate
        }
    }
}

// ---------------------------------------------------------------------------
// Historical anomaly score
// ---------------------------------------------------------------------------

/// A single anomaly score observation for trending.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyScoreRecord {
    /// Unix timestamp of the observation.
    pub timestamp: i64,
    /// Anomaly score [0.0, 1.0].
    pub score: f64,
    /// Source of the score (e.g., "baseline", "correlation", "threat_intel").
    pub source: String,
}

// ---------------------------------------------------------------------------
// In-memory UEBA store (mirrors DB state)
// ---------------------------------------------------------------------------

/// Per-user UEBA state held in memory.
struct UserUebaState {
    /// The behavioral baseline.
    baseline: UserBaseline,
    /// Tenant isolation.
    tenant_id: Uuid,
    /// Current confidence (decays with age).
    confidence: f64,
    /// Whether the in-memory state is dirty (needs flush to DB).
    dirty: bool,
    /// Historical anomaly scores (ring buffer, O(1) pop_front).
    anomaly_history: VecDeque<AnomalyScoreRecord>,
}

/// Persistent UEBA store with in-memory cache and DB backing.
///
/// The store loads all baselines from the DB on startup, serves reads from
/// memory, and periodically flushes dirty entries back to the DB.
pub struct UebaStore {
    /// In-memory baseline cache, keyed by user_id.
    state: Mutex<HashMap<Uuid, UserUebaState>>,
    /// Flush interval.
    flush_interval: Duration,
    /// Unix timestamp of last flush.
    last_flush: Mutex<i64>,
    /// Encryption key for baseline payloads (32 bytes for AES-256).
    encryption_key: [u8; 32],
    /// Database connection string (for production use with sqlx).
    #[allow(dead_code)]
    db_url: String,
}

impl UebaStore {
    /// Create a new UEBA store.
    ///
    /// In production, `db_url` would be a PostgreSQL connection string and
    /// `encryption_key` would be derived from the HSM/KMS.
    pub fn new(db_url: &str, encryption_key: [u8; 32]) -> Self {
        Self {
            state: Mutex::new(HashMap::new()),
            flush_interval: Duration::from_secs(DEFAULT_FLUSH_INTERVAL_SECS),
            last_flush: Mutex::new(0),
            encryption_key,
            db_url: db_url.to_string(),
        }
    }

    /// Set a custom flush interval.
    pub fn with_flush_interval(mut self, interval: Duration) -> Self {
        self.flush_interval = interval;
        self
    }

    /// Load baselines from pre-existing records (simulates DB load on startup).
    ///
    /// In production this would execute:
    /// ```sql
    /// SELECT user_id, tenant_id, encrypted_payload, nonce, last_updated, confidence
    /// FROM ueba_baselines
    /// WHERE tenant_id = $1
    /// ```
    pub fn load_baselines(&self, records: Vec<EncryptedBaselineRecord>) -> usize {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let mut loaded = 0;

        for record in records {
            if let Some(payload) = self.decrypt_payload(&record.encrypted_payload, &record.nonce) {
                let baseline = UserBaseline {
                    typical_login_hours: payload.typical_login_hours,
                    known_networks: payload.known_networks,
                    avg_session_duration_secs: payload.avg_session_duration_secs,
                    last_updated: record.last_updated,
                    avg_login_hour: payload.avg_login_hour,
                };

                let confidence = compute_confidence(record.last_updated);

                state.insert(
                    record.user_id,
                    UserUebaState {
                        baseline,
                        tenant_id: record.tenant_id,
                        confidence,
                        dirty: false,
                        anomaly_history: VecDeque::new(),
                    },
                );
                loaded += 1;
            } else {
                tracing::warn!(
                    target: "ueba",
                    "Failed to decrypt baseline for user {}",
                    record.user_id
                );
            }
        }

        tracing::info!(target: "ueba", "Loaded {} baselines from DB", loaded);
        loaded
    }

    /// Get a baseline for a user (if it exists).
    pub fn get_baseline(&self, user_id: &Uuid) -> Option<UserBaseline> {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.get(user_id).map(|s| s.baseline.clone())
    }

    /// Get a baseline with its confidence score.
    pub fn get_baseline_with_confidence(&self, user_id: &Uuid) -> Option<(UserBaseline, f64)> {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state
            .get(user_id)
            .map(|s| (s.baseline.clone(), s.confidence))
    }

    /// Update (or create) a baseline for a user within a tenant.
    pub fn update_baseline(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        baseline: UserBaseline,
    ) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());

        let entry = state.entry(user_id).or_insert_with(|| UserUebaState {
            baseline: baseline.clone(),
            tenant_id,
            confidence: 1.0,
            dirty: true,
            anomaly_history: VecDeque::new(),
        });

        entry.baseline = baseline;
        entry.tenant_id = tenant_id;
        entry.confidence = 1.0; // Fresh update = full confidence
        entry.dirty = true;
    }

    /// Record an anomaly score for trending.
    pub fn record_anomaly_score(
        &self,
        user_id: &Uuid,
        score: f64,
        source: &str,
    ) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(user_state) = state.get_mut(user_id) {
            // Ring buffer: drop oldest when at capacity (O(1) with VecDeque)
            if user_state.anomaly_history.len() >= MAX_ANOMALY_HISTORY {
                user_state.anomaly_history.pop_front();
            }

            user_state.anomaly_history.push_back(AnomalyScoreRecord {
                timestamp: now,
                score,
                source: source.to_string(),
            });
            user_state.dirty = true;
        }
    }

    /// Get historical anomaly scores for a user.
    pub fn get_anomaly_history(&self, user_id: &Uuid) -> Vec<AnomalyScoreRecord> {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state
            .get(user_id)
            .map(|s| s.anomaly_history.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Get anomaly trend: average score over the last N records.
    pub fn anomaly_trend(&self, user_id: &Uuid, last_n: usize) -> Option<f64> {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let history = state.get(user_id).map(|s| &s.anomaly_history)?;

        if history.is_empty() {
            return None;
        }

        let recent: Vec<_> = history.iter().rev().take(last_n).collect();
        let sum: f64 = recent.iter().map(|r| r.score).sum();
        Some(sum / recent.len() as f64)
    }

    /// Age all baselines: reduce confidence for stale entries.
    ///
    /// Should be called periodically (e.g., daily). Baselines that have
    /// not been updated within `BASELINE_STALENESS_DAYS` have their
    /// confidence linearly decayed to a floor of 0.1.
    pub fn age_baselines(&self) -> usize {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let mut aged_count = 0;

        for user_state in state.values_mut() {
            let new_confidence = compute_confidence_at(user_state.baseline.last_updated, now);
            if (new_confidence - user_state.confidence).abs() > 0.001 {
                user_state.confidence = new_confidence;
                user_state.dirty = true;
                aged_count += 1;
            }
        }

        if aged_count > 0 {
            tracing::info!(
                target: "ueba",
                "Aged {} baselines (confidence reduced for stale entries)",
                aged_count
            );
        }

        aged_count
    }

    /// Get all baselines for a specific tenant.
    pub fn get_tenant_baselines(&self, tenant_id: &Uuid) -> Vec<(Uuid, UserBaseline, f64)> {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state
            .iter()
            .filter(|(_, v)| &v.tenant_id == tenant_id)
            .map(|(uid, v)| (*uid, v.baseline.clone(), v.confidence))
            .collect()
    }

    /// Count of baselines per tenant.
    pub fn tenant_baseline_count(&self, tenant_id: &Uuid) -> usize {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.values().filter(|v| &v.tenant_id == tenant_id).count()
    }

    /// Check if a flush to the database is needed (based on flush interval).
    pub fn needs_flush(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let last = *self.last_flush.lock().unwrap_or_else(|e| e.into_inner());
        (now - last).max(0) as u64 >= self.flush_interval.as_secs()
    }

    /// Flush all dirty baselines to encrypted records for DB persistence.
    ///
    /// Returns the encrypted records that should be upserted into the DB.
    /// In production, this would execute:
    /// ```sql
    /// INSERT INTO ueba_baselines (user_id, tenant_id, encrypted_payload, nonce, last_updated, confidence)
    /// VALUES ($1, $2, $3, $4, $5, $6)
    /// ON CONFLICT (user_id) DO UPDATE SET
    ///   encrypted_payload = EXCLUDED.encrypted_payload,
    ///   nonce = EXCLUDED.nonce,
    ///   last_updated = EXCLUDED.last_updated,
    ///   confidence = EXCLUDED.confidence
    /// ```
    pub fn flush(&self) -> Vec<EncryptedBaselineRecord> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let mut records = Vec::new();

        for (user_id, user_state) in state.iter_mut() {
            if !user_state.dirty {
                continue;
            }

            let payload = BaselinePayload::from_baseline(&user_state.baseline);
            if let Some((ciphertext, nonce)) = self.encrypt_payload(&payload) {
                records.push(EncryptedBaselineRecord {
                    user_id: *user_id,
                    tenant_id: user_state.tenant_id,
                    encrypted_payload: ciphertext,
                    nonce,
                    last_updated: user_state.baseline.last_updated,
                    confidence: user_state.confidence,
                });
                user_state.dirty = false;
            }
        }

        // Update last flush timestamp
        *self.last_flush.lock().unwrap_or_else(|e| e.into_inner()) = now;

        if !records.is_empty() {
            tracing::info!(
                target: "ueba",
                "Flushed {} dirty baselines to DB",
                records.len()
            );
        }

        records
    }

    /// Get the total number of baselines in memory.
    pub fn baseline_count(&self) -> usize {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Get the number of dirty (unflushed) baselines.
    pub fn dirty_count(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .filter(|s| s.dirty)
            .count()
    }

    // -----------------------------------------------------------------------
    // Encryption helpers
    // -----------------------------------------------------------------------

    /// Encrypt a baseline payload using AES-256-GCM.
    /// Returns (hex_ciphertext, hex_nonce).
    fn encrypt_payload(&self, payload: &BaselinePayload) -> Option<(String, String)> {
        use aes_gcm::aead::Aead;
        use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

        let plaintext = serde_json::to_vec(payload).ok()?;

        let cipher = Aes256Gcm::new_from_slice(&self.encryption_key).ok()?;

        // Generate a random 12-byte nonce
        let mut nonce_bytes = [0u8; 12];
        getrandom::getrandom(&mut nonce_bytes).ok()?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).ok()?;

        Some((hex::encode(&ciphertext), hex::encode(nonce_bytes)))
    }

    /// Decrypt a baseline payload from hex-encoded ciphertext and nonce.
    fn decrypt_payload(&self, ciphertext_hex: &str, nonce_hex: &str) -> Option<BaselinePayload> {
        use aes_gcm::aead::Aead;
        use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

        let ciphertext = hex::decode(ciphertext_hex).ok()?;
        let nonce_bytes = hex::decode(nonce_hex).ok()?;
        if nonce_bytes.len() != 12 {
            return None;
        }

        let cipher = Aes256Gcm::new_from_slice(&self.encryption_key).ok()?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let plaintext = cipher.decrypt(nonce, ciphertext.as_ref()).ok()?;
        serde_json::from_slice(&plaintext).ok()
    }
}

// ---------------------------------------------------------------------------
// Confidence computation
// ---------------------------------------------------------------------------

/// Compute confidence for a baseline based on its last_updated timestamp.
fn compute_confidence(last_updated: i64) -> f64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    compute_confidence_at(last_updated, now)
}

/// Compute confidence given a specific "now" timestamp.
///
/// - If updated within the staleness window: confidence = 1.0
/// - If older: linearly decays to a floor of 0.1 over another 30 days
fn compute_confidence_at(last_updated: i64, now: i64) -> f64 {
    let age = (now - last_updated).max(0);

    if age <= BASELINE_STALENESS_SECS {
        1.0
    } else {
        let excess = (age - BASELINE_STALENESS_SECS) as f64;
        let decay_window = BASELINE_STALENESS_SECS as f64; // 30 more days to reach floor
        let decayed = 1.0 - (excess / decay_window) * 0.9;
        decayed.max(0.1)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_encryption_key() -> [u8; 32] {
        // Deterministic key for testing
        let mut key = [0u8; 32];
        for (i, byte) in key.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(7).wrapping_add(42);
        }
        key
    }

    fn make_baseline() -> UserBaseline {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        UserBaseline {
            typical_login_hours: (8, 18),
            known_networks: vec!["AS1234".to_string(), "AS5678".to_string()],
            avg_session_duration_secs: 3600.0,
            last_updated: now,
            avg_login_hour: 13.0,
        }
    }

    #[test]
    fn test_store_update_and_get_baseline() {
        let store = UebaStore::new("postgres://test", test_encryption_key());
        let user_id = Uuid::new_v4();
        let tenant_id = Uuid::new_v4();
        let baseline = make_baseline();

        store.update_baseline(user_id, tenant_id, baseline.clone());

        let retrieved = store.get_baseline(&user_id);
        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.typical_login_hours, (8, 18));
        assert_eq!(retrieved.known_networks.len(), 2);
    }

    #[test]
    fn test_store_get_with_confidence() {
        let store = UebaStore::new("postgres://test", test_encryption_key());
        let user_id = Uuid::new_v4();
        let tenant_id = Uuid::new_v4();
        let baseline = make_baseline();

        store.update_baseline(user_id, tenant_id, baseline);

        let (_, confidence) = store.get_baseline_with_confidence(&user_id).unwrap();
        assert!((confidence - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_store_nonexistent_user() {
        let store = UebaStore::new("postgres://test", test_encryption_key());
        assert!(store.get_baseline(&Uuid::new_v4()).is_none());
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let store = UebaStore::new("postgres://test", test_encryption_key());
        let payload = BaselinePayload {
            typical_login_hours: (9, 17),
            known_networks: vec!["AS100".to_string()],
            avg_session_duration_secs: 1800.0,
            avg_login_hour: 13.0,
        };

        let (ciphertext, nonce) = store.encrypt_payload(&payload).unwrap();
        let decrypted = store.decrypt_payload(&ciphertext, &nonce).unwrap();

        assert_eq!(decrypted.typical_login_hours, (9, 17));
        assert_eq!(decrypted.known_networks, vec!["AS100".to_string()]);
        assert!((decrypted.avg_session_duration_secs - 1800.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_decrypt_with_wrong_key_fails() {
        let store1 = UebaStore::new("postgres://test", test_encryption_key());
        let payload = BaselinePayload {
            typical_login_hours: (9, 17),
            known_networks: vec![],
            avg_session_duration_secs: 600.0,
            avg_login_hour: 13.0,
        };

        let (ciphertext, nonce) = store1.encrypt_payload(&payload).unwrap();

        // Different key
        let store2 = UebaStore::new("postgres://test", [0xFFu8; 32]);
        assert!(store2.decrypt_payload(&ciphertext, &nonce).is_none());
    }

    #[test]
    fn test_flush_produces_encrypted_records() {
        let store = UebaStore::new("postgres://test", test_encryption_key());
        let user_id = Uuid::new_v4();
        let tenant_id = Uuid::new_v4();
        let baseline = make_baseline();

        store.update_baseline(user_id, tenant_id, baseline);
        assert_eq!(store.dirty_count(), 1);

        let records = store.flush();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].user_id, user_id);
        assert_eq!(records[0].tenant_id, tenant_id);
        assert!(!records[0].encrypted_payload.is_empty());
        assert!(!records[0].nonce.is_empty());

        // After flush, dirty count should be 0
        assert_eq!(store.dirty_count(), 0);
    }

    #[test]
    fn test_load_baselines_from_encrypted_records() {
        let store = UebaStore::new("postgres://test", test_encryption_key());
        let user_id = Uuid::new_v4();
        let tenant_id = Uuid::new_v4();
        let baseline = make_baseline();

        store.update_baseline(user_id, tenant_id, baseline);
        let records = store.flush();

        // Create a new store and load the records
        let store2 = UebaStore::new("postgres://test", test_encryption_key());
        let loaded = store2.load_baselines(records);
        assert_eq!(loaded, 1);
        assert_eq!(store2.baseline_count(), 1);

        let retrieved = store2.get_baseline(&user_id).unwrap();
        assert_eq!(retrieved.typical_login_hours, (8, 18));
    }

    #[test]
    fn test_anomaly_history() {
        let store = UebaStore::new("postgres://test", test_encryption_key());
        let user_id = Uuid::new_v4();
        let tenant_id = Uuid::new_v4();

        store.update_baseline(user_id, tenant_id, make_baseline());

        store.record_anomaly_score(&user_id, 0.2, "baseline");
        store.record_anomaly_score(&user_id, 0.5, "correlation");
        store.record_anomaly_score(&user_id, 0.8, "threat_intel");

        let history = store.get_anomaly_history(&user_id);
        assert_eq!(history.len(), 3);
        assert!((history[0].score - 0.2).abs() < f64::EPSILON);
        assert_eq!(history[1].source, "correlation");
    }

    #[test]
    fn test_anomaly_trend() {
        let store = UebaStore::new("postgres://test", test_encryption_key());
        let user_id = Uuid::new_v4();
        let tenant_id = Uuid::new_v4();

        store.update_baseline(user_id, tenant_id, make_baseline());

        store.record_anomaly_score(&user_id, 0.1, "test");
        store.record_anomaly_score(&user_id, 0.3, "test");
        store.record_anomaly_score(&user_id, 0.5, "test");

        let trend = store.anomaly_trend(&user_id, 2).unwrap();
        // Last 2: 0.3 and 0.5 => avg 0.4
        assert!((trend - 0.4).abs() < f64::EPSILON);

        // All 3 => avg 0.3
        let trend_all = store.anomaly_trend(&user_id, 10).unwrap();
        assert!((trend_all - 0.3).abs() < f64::EPSILON);
    }

    #[test]
    fn test_anomaly_history_ring_buffer() {
        let store = UebaStore::new("postgres://test", test_encryption_key());
        let user_id = Uuid::new_v4();
        let tenant_id = Uuid::new_v4();

        store.update_baseline(user_id, tenant_id, make_baseline());

        // Insert more than MAX_ANOMALY_HISTORY records
        for i in 0..(MAX_ANOMALY_HISTORY + 100) {
            store.record_anomaly_score(&user_id, i as f64 / 1000.0, "test");
        }

        let history = store.get_anomaly_history(&user_id);
        assert_eq!(history.len(), MAX_ANOMALY_HISTORY);
    }

    #[test]
    fn test_tenant_isolation() {
        let store = UebaStore::new("postgres://test", test_encryption_key());
        let tenant_a = Uuid::new_v4();
        let tenant_b = Uuid::new_v4();

        for _ in 0..3 {
            store.update_baseline(Uuid::new_v4(), tenant_a, make_baseline());
        }
        for _ in 0..5 {
            store.update_baseline(Uuid::new_v4(), tenant_b, make_baseline());
        }

        assert_eq!(store.tenant_baseline_count(&tenant_a), 3);
        assert_eq!(store.tenant_baseline_count(&tenant_b), 5);
        assert_eq!(store.baseline_count(), 8);

        let tenant_a_baselines = store.get_tenant_baselines(&tenant_a);
        assert_eq!(tenant_a_baselines.len(), 3);
    }

    #[test]
    fn test_confidence_fresh_baseline() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let confidence = compute_confidence_at(now, now);
        assert!((confidence - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_confidence_stale_baseline() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        // 31 days old
        let old = now - 31 * 86400;
        let confidence = compute_confidence_at(old, now);
        assert!(confidence < 1.0);
        assert!(confidence > 0.1);
    }

    #[test]
    fn test_confidence_very_stale_baseline() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        // 90 days old — should be at or near the floor
        let very_old = now - 90 * 86400;
        let confidence = compute_confidence_at(very_old, now);
        assert!(
            (confidence - 0.1).abs() < f64::EPSILON,
            "Very stale baseline confidence should be at floor: {}",
            confidence
        );
    }

    #[test]
    fn test_confidence_within_threshold_is_full() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        // 29 days old — still within threshold
        let recent = now - 29 * 86400;
        let confidence = compute_confidence_at(recent, now);
        assert!((confidence - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_age_baselines() {
        let store = UebaStore::new("postgres://test", test_encryption_key());
        let user_id = Uuid::new_v4();
        let tenant_id = Uuid::new_v4();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        // Create a baseline that is 60 days old
        let mut baseline = make_baseline();
        baseline.last_updated = now - 60 * 86400;

        store.update_baseline(user_id, tenant_id, baseline);

        let aged = store.age_baselines();
        assert!(aged > 0);

        let (_, confidence) = store.get_baseline_with_confidence(&user_id).unwrap();
        assert!(confidence < 1.0);
    }

    #[test]
    fn test_needs_flush() {
        let store = UebaStore::new("postgres://test", test_encryption_key())
            .with_flush_interval(Duration::from_secs(0));

        // With 0 flush interval and last_flush=0, should always need flush
        assert!(store.needs_flush());
    }

    #[test]
    fn test_baseline_count() {
        let store = UebaStore::new("postgres://test", test_encryption_key());
        assert_eq!(store.baseline_count(), 0);

        store.update_baseline(Uuid::new_v4(), Uuid::new_v4(), make_baseline());
        assert_eq!(store.baseline_count(), 1);
    }
}
