use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;
use uuid::Uuid;

/// Risk signal types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskSignals {
    pub device_attestation_age_secs: f64, // 0 = fresh, higher = stale
    pub geo_velocity_kmh: f64,            // impossible travel speed
    pub is_unusual_network: bool,         // unusual IP/VPN/Tor
    pub is_unusual_time: bool,            // outside normal hours
    pub unusual_access_score: f64,        // 0.0-1.0, API pattern anomaly
    pub recent_failed_attempts: u32,      // in last hour (client-supplied, ignored by server)
    /// Current login hour (0-23) for baseline comparison. Optional for
    /// backward compatibility; when absent, time-of-day baseline scoring
    /// falls back to the boolean `is_unusual_time` flag.
    #[serde(default)]
    pub login_hour: Option<u8>,
    /// Network identifier (e.g. AS number, subnet, VPN label) for baseline
    /// comparison. Optional for backward compatibility.
    #[serde(default)]
    pub network_id: Option<String>,
    /// Session duration in seconds (for completed sessions) used to update
    /// the baseline after successful auth.
    #[serde(default)]
    pub session_duration_secs: Option<f64>,
}

/// Risk score result
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskLevel {
    Normal,   // < 0.3
    Elevated, // 0.3 - 0.6
    High,     // 0.6 - 0.8
    Critical, // >= 0.8
}

/// Window duration for the server-side failed attempt counter (1 hour).
const FAILED_ATTEMPT_WINDOW_SECS: u64 = 3600;

/// Exponential moving average smoothing factor.
/// Lower values make the baseline adapt more slowly (more stable).
const EMA_ALPHA: f64 = 0.1;

// ---------------------------------------------------------------------------
// Per-user behavioral baseline
// ---------------------------------------------------------------------------

/// Tracks per-user behavioral norms used for anomaly detection.
///
/// Fields are updated via exponential moving average after each successful
/// authentication so the baseline gradually adapts to changing user behavior
/// without being easily poisoned by a single anomalous session.
#[derive(Debug, Clone)]
pub struct UserBaseline {
    /// Typical login hour range (start_hour, end_hour) in 24h format.
    /// For example `(8, 18)` means the user typically logs in between 08:00
    /// and 18:00. The range wraps around midnight if `start > end`.
    pub typical_login_hours: (u8, u8),
    /// Known network identifiers the user has authenticated from before
    /// (AS numbers, subnet labels, VPN identifiers, etc.).
    pub known_networks: Vec<String>,
    /// Exponential moving average of session duration in seconds.
    pub avg_session_duration_secs: f64,
    /// Unix timestamp (seconds) of the last baseline update.
    pub last_updated: i64,
    /// EMA of the login hour (used internally to track the center).
    pub avg_login_hour: f64,
}

impl UserBaseline {
    /// Create a new baseline seeded from an initial set of signals.
    fn new_from_signals(signals: &RiskSignals) -> Self {
        let hour = signals.login_hour.unwrap_or(12);
        let network = signals.network_id.clone().unwrap_or_default();
        let duration = signals.session_duration_secs.unwrap_or(300.0);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        Self {
            typical_login_hours: (hour.saturating_sub(2), (hour + 2).min(23)),
            known_networks: if network.is_empty() {
                Vec::new()
            } else {
                vec![network]
            },
            avg_session_duration_secs: duration,
            last_updated: now,
            avg_login_hour: hour as f64,
        }
    }
}

/// Thread-safe store for per-user behavioral baselines.
///
/// All access is serialized through a `Mutex`. In a production deployment
/// this would be backed by a persistent store; the in-memory version is
/// suitable for single-instance deployments and testing.
pub struct BaselineStore {
    inner: Mutex<HashMap<Uuid, UserBaseline>>,
}

impl BaselineStore {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Update (or create) the baseline for `user_id` after a successful auth.
    ///
    /// Numeric fields are updated via exponential moving average so the
    /// baseline drifts smoothly rather than snapping to the latest value.
    pub fn update_baseline(&self, user_id: Uuid, signals: &RiskSignals) {
        let mut store = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let baseline = store
            .entry(user_id)
            .or_insert_with(|| UserBaseline::new_from_signals(signals));

        // --- EMA update for login hour ---
        if let Some(hour) = signals.login_hour {
            let h = hour as f64;
            baseline.avg_login_hour =
                EMA_ALPHA * h + (1.0 - EMA_ALPHA) * baseline.avg_login_hour;
            // Re-derive the typical window: center +/- 2 hours
            let center = baseline.avg_login_hour.round() as u8;
            baseline.typical_login_hours =
                (center.saturating_sub(2), (center + 2).min(23));
        }

        // --- Accumulate known networks (cap at 50 to bound memory) ---
        if let Some(ref net) = signals.network_id {
            if !net.is_empty() && !baseline.known_networks.contains(net) {
                if baseline.known_networks.len() < 50 {
                    baseline.known_networks.push(net.clone());
                }
            }
        }

        // --- EMA update for session duration ---
        if let Some(dur) = signals.session_duration_secs {
            if dur > 0.0 {
                baseline.avg_session_duration_secs = EMA_ALPHA * dur
                    + (1.0 - EMA_ALPHA) * baseline.avg_session_duration_secs;
            }
        }

        baseline.last_updated = now;
    }

    /// Compute an anomaly score in `[0.0, 1.0]` by comparing the current
    /// signals against the stored baseline for `user_id`.
    ///
    /// Returns `0.0` if no baseline exists yet (benefit of the doubt for new
    /// users — other risk signals still apply).
    pub fn compute_anomaly_score(&self, user_id: &Uuid, signals: &RiskSignals) -> f64 {
        let store = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let baseline = match store.get(user_id) {
            Some(b) => b,
            None => return 0.0, // no baseline yet — no anomaly signal
        };

        let mut anomaly = 0.0;

        // --- Login hour anomaly (weight 0.4) ---
        if let Some(hour) = signals.login_hour {
            let (start, end) = baseline.typical_login_hours;
            let outside = if start <= end {
                hour < start || hour > end
            } else {
                // wraps midnight
                hour < start && hour > end
            };
            if outside {
                // Distance from the nearest boundary, normalized to max 12h
                let dist_start = ((hour as i16 - start as i16).abs() as f64).min(
                    24.0 - (hour as i16 - start as i16).abs() as f64,
                );
                let dist_end = ((hour as i16 - end as i16).abs() as f64).min(
                    24.0 - (hour as i16 - end as i16).abs() as f64,
                );
                let dist = dist_start.min(dist_end);
                anomaly += (dist / 12.0).min(1.0) * 0.4;
            }
        }

        // --- Network anomaly (weight 0.35) ---
        if let Some(ref net) = signals.network_id {
            if !net.is_empty() && !baseline.known_networks.contains(net) {
                anomaly += 0.35;
            }
        }

        // --- Session duration anomaly (weight 0.25) ---
        if let Some(dur) = signals.session_duration_secs {
            if baseline.avg_session_duration_secs > 0.0 && dur > 0.0 {
                let ratio = dur / baseline.avg_session_duration_secs;
                // Flag sessions that are >3x or <0.2x the average duration
                if ratio > 3.0 || ratio < 0.2 {
                    let deviation = if ratio > 3.0 {
                        ((ratio - 3.0) / 10.0).min(1.0)
                    } else {
                        ((0.2 - ratio) / 0.2).min(1.0)
                    };
                    anomaly += deviation * 0.25;
                }
            }
        }

        anomaly.min(1.0)
    }

    /// Get a snapshot of the baseline for a user (if it exists).
    pub fn get_baseline(&self, user_id: &Uuid) -> Option<UserBaseline> {
        let store = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        store.get(user_id).cloned()
    }
}

impl Default for BaselineStore {
    fn default() -> Self {
        Self::new()
    }
}

pub struct RiskEngine {
    /// Per-user behavioral baselines for anomaly detection.
    pub baseline_store: BaselineStore,

    /// Server-side failed attempt counter per user ID.
    /// Each entry stores (count, window_start). The counter resets when the
    /// window expires. This is authoritative and replaces the client-supplied
    /// `recent_failed_attempts` field.
    ///
    /// Wrapped in a Mutex so that `record_failed_attempt` can be called
    /// through a shared `&self` reference (the orchestrator holds the engine
    /// behind an immutable borrow in `process_auth`).
    failed_attempt_counter: Mutex<HashMap<Uuid, (u32, Instant)>>,
}

impl RiskEngine {
    pub fn new() -> Self {
        Self {
            baseline_store: BaselineStore::new(),
            failed_attempt_counter: Mutex::new(HashMap::new()),
        }
    }

    /// Record a failed authentication attempt for a user. Must be called by
    /// the orchestrator on each authentication failure.
    ///
    /// Takes `&self` (not `&mut self`) thanks to interior mutability via Mutex,
    /// so it can be called from the orchestrator's `&self` methods.
    pub fn record_failed_attempt(&self, user_id: &Uuid) {
        let now = Instant::now();
        let mut counter = self.failed_attempt_counter.lock().unwrap_or_else(|e| e.into_inner());
        let entry = counter.entry(*user_id).or_insert((0, now));

        // Reset counter if the window has expired
        if now.duration_since(entry.1).as_secs() > FAILED_ATTEMPT_WINDOW_SECS {
            *entry = (1, now);
        } else {
            entry.0 = entry.0.saturating_add(1);
        }
    }

    /// Get the server-side failed attempt count for a user.
    fn server_failed_attempts(&self, user_id: &Uuid) -> u32 {
        let counter = self.failed_attempt_counter.lock().unwrap_or_else(|e| e.into_inner());
        match counter.get(user_id) {
            Some((count, start)) => {
                let elapsed = Instant::now().duration_since(*start).as_secs();
                if elapsed > FAILED_ATTEMPT_WINDOW_SECS {
                    0 // window expired
                } else {
                    *count
                }
            }
            None => 0,
        }
    }

    /// Validate and sanitize client-supplied risk signals.
    /// Returns sanitized signals with bounds checks applied.
    fn validate_signals(&self, signals: &RiskSignals) -> RiskSignals {
        RiskSignals {
            // Negative device attestation age is impossible
            device_attestation_age_secs: signals.device_attestation_age_secs.max(0.0),
            // Negative geo velocity is impossible
            geo_velocity_kmh: signals.geo_velocity_kmh.max(0.0),
            is_unusual_network: signals.is_unusual_network,
            is_unusual_time: signals.is_unusual_time,
            unusual_access_score: signals.unusual_access_score.clamp(0.0, 1.0),
            // Client-supplied failed attempts field is preserved in the struct
            // but ignored in scoring; the server-side counter is used instead.
            recent_failed_attempts: signals.recent_failed_attempts,
            login_hour: signals.login_hour.map(|h| h.min(23)),
            network_id: signals.network_id.clone(),
            session_duration_secs: signals.session_duration_secs.map(|d| d.max(0.0)),
        }
    }

    /// Compute risk score from signals. Returns 0.0-1.0.
    pub fn compute_score(&self, user_id: &Uuid, signals: &RiskSignals) -> f64 {
        let signals = self.validate_signals(signals);

        // Impossibility detection: geo_velocity > 10,000 km/h is faster than
        // orbital velocity (~7.8 km/s = ~28,000 km/h). Anything above 10,000
        // is physically impossible for terrestrial travel and indicates either
        // a spoofed signal or a compromised session.
        if signals.geo_velocity_kmh > 10_000.0 {
            return 1.0;
        }

        let mut score = 0.0;

        // Device attestation freshness (weight ~0.25)
        if signals.device_attestation_age_secs > 3600.0 {
            score += 0.25;
        } else if signals.device_attestation_age_secs > 300.0 {
            score += 0.10;
        }

        // Geo-velocity (weight ~0.20)
        if signals.geo_velocity_kmh > 1000.0 {
            score += 0.20; // impossible travel
        } else if signals.geo_velocity_kmh > 500.0 {
            score += 0.10;
        }

        // Network context (weight ~0.15)
        if signals.is_unusual_network {
            score += 0.15;
        }

        // Time of day (weight ~0.10)
        if signals.is_unusual_time {
            score += 0.10;
        }

        // Access pattern anomaly (weight ~0.15)
        score += signals.unusual_access_score * 0.15;

        // Failed attempts — use the server-side counter, NOT the client-supplied value
        let server_fails = self.server_failed_attempts(user_id);
        let fail_score = (server_fails as f64 / 5.0).min(1.0);
        score += fail_score * 0.15;

        // Baseline anomaly detection (weight ~0.10) — compares current signals
        // against the user's historical behavioral baseline.
        let baseline_anomaly = self.baseline_store.compute_anomaly_score(user_id, &signals);
        score += baseline_anomaly * 0.10;

        // Mimicry detection: flag sessions where signals are suspiciously clean.
        // A legitimate user always has *some* attestation age, network jitter,
        // and minor anomalies. Nation-state attackers who craft perfect signals
        // to avoid detection are caught here.
        //
        // Use epsilon thresholds instead of exact == 0.0 to prevent trivial bypass
        // where an attacker sets values to 0.001 (above zero but below any penalty).
        const ATTESTATION_EPSILON: f64 = 1.0; // < 1 second = suspiciously fresh
        const GEO_EPSILON: f64 = 1.0;         // < 1 km/h = suspiciously static
        const ACCESS_EPSILON: f64 = 0.01;      // near-zero access anomaly
        let signals_too_clean = signals.device_attestation_age_secs < ATTESTATION_EPSILON
            && signals.geo_velocity_kmh < GEO_EPSILON
            && !signals.is_unusual_network
            && !signals.is_unusual_time
            && signals.unusual_access_score < ACCESS_EPSILON
            && server_fails == 0;
        if signals_too_clean {
            // Suspiciously clean signals get a penalty that scales with how
            // perfectly clean they are. Minimum +0.15, prevents adversaries
            // from staying below the 0.3 Elevated threshold.
            score += 0.15;
        }

        // Add small random noise to prevent attackers from computing exact
        // threshold-crossing signal combinations. Noise range: [0.0, 0.08)
        let noise_byte = {
            let mut buf = [0u8; 1];
            getrandom::getrandom(&mut buf).unwrap_or_default();
            (buf[0] as f64 / 255.0) * 0.08
        };
        score += noise_byte;

        score.min(1.0)
    }

    pub fn classify(&self, score: f64) -> RiskLevel {
        if score >= 0.8 {
            RiskLevel::Critical
        } else if score >= 0.6 {
            RiskLevel::High
        } else if score >= 0.3 {
            RiskLevel::Elevated
        } else {
            RiskLevel::Normal
        }
    }

    /// Check if step-up auth is required
    pub fn requires_step_up(&self, score: f64) -> bool {
        score >= 0.6
    }

    /// Check if session should be terminated
    pub fn requires_termination(&self, score: f64) -> bool {
        score >= 0.8
    }

    /// Check if a user is currently locked out due to too many failed attempts.
    /// Returns true if the user has exceeded `max_attempts` within the tracking window.
    pub fn is_locked_out(&self, user_id: &Uuid, max_attempts: u32) -> bool {
        let counter = self.failed_attempt_counter.lock().unwrap_or_else(|e| e.into_inner());
        match counter.get(user_id) {
            Some((count, first_attempt)) => {
                // Check if still within the lockout window
                if first_attempt.elapsed().as_secs() > FAILED_ATTEMPT_WINDOW_SECS {
                    false // Window expired, not locked out
                } else {
                    *count >= max_attempts
                }
            }
            None => false,
        }
    }
}

impl Default for RiskEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Wire request type for risk scoring via SHARD transport.
#[derive(Serialize, Deserialize)]
pub struct RiskRequest {
    pub user_id: uuid::Uuid,
    pub device_tier: u8,
    pub signals: RiskSignals,
}

/// Wire response type for risk scoring via SHARD transport.
#[derive(Serialize, Deserialize)]
pub struct RiskResponse {
    pub score: f64,
    pub classification: String,
    pub step_up_required: bool,
    pub session_terminate: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clean_signals() -> RiskSignals {
        RiskSignals {
            device_attestation_age_secs: 0.0,
            geo_velocity_kmh: 0.0,
            is_unusual_network: false,
            is_unusual_time: false,
            unusual_access_score: 0.0,
            recent_failed_attempts: 0,
            login_hour: None,
            network_id: None,
            session_duration_secs: None,
        }
    }

    // -- Risk level threshold tests --

    #[test]
    fn test_classify_normal_below_03() {
        let engine = RiskEngine::new();
        assert_eq!(engine.classify(0.0), RiskLevel::Normal);
        assert_eq!(engine.classify(0.1), RiskLevel::Normal);
        assert_eq!(engine.classify(0.29), RiskLevel::Normal);
    }

    #[test]
    fn test_classify_elevated_03_to_06() {
        let engine = RiskEngine::new();
        assert_eq!(engine.classify(0.3), RiskLevel::Elevated);
        assert_eq!(engine.classify(0.45), RiskLevel::Elevated);
        assert_eq!(engine.classify(0.59), RiskLevel::Elevated);
    }

    #[test]
    fn test_classify_high_06_to_08() {
        let engine = RiskEngine::new();
        assert_eq!(engine.classify(0.6), RiskLevel::High);
        assert_eq!(engine.classify(0.7), RiskLevel::High);
        assert_eq!(engine.classify(0.79), RiskLevel::High);
    }

    #[test]
    fn test_classify_critical_above_08() {
        let engine = RiskEngine::new();
        assert_eq!(engine.classify(0.8), RiskLevel::Critical);
        assert_eq!(engine.classify(0.9), RiskLevel::Critical);
        assert_eq!(engine.classify(1.0), RiskLevel::Critical);
    }

    // -- Risk score computation tests --

    #[test]
    fn test_clean_signals_mimicry_penalty() {
        let engine = RiskEngine::new();
        let user = Uuid::new_v4();
        let score = engine.compute_score(&user, &clean_signals());
        // All-zero signals trigger the mimicry detection penalty (+0.15)
        // plus random noise [0.0, 0.08), so score in [0.15, 0.23)
        assert!(
            score >= 0.15 && score < 0.23,
            "clean signals should trigger mimicry penalty: got {score}"
        );
    }

    #[test]
    fn test_impossible_geo_velocity_max_risk() {
        let engine = RiskEngine::new();
        let user = Uuid::new_v4();
        let mut signals = clean_signals();
        // > 10,000 km/h is physically impossible and returns 1.0 immediately
        signals.geo_velocity_kmh = 15_000.0;
        let score = engine.compute_score(&user, &signals);
        assert!(
            (score - 1.0).abs() < f64::EPSILON,
            "impossible velocity should return 1.0, got {score}"
        );
    }

    #[test]
    fn test_stale_device_attestation() {
        let engine = RiskEngine::new();
        let user = Uuid::new_v4();
        let mut signals = clean_signals();
        signals.device_attestation_age_secs = 7200.0; // > 3600
        let score = engine.compute_score(&user, &signals);
        // 0.25 (stale attestation) + noise
        assert!(score >= 0.25, "stale attestation should add at least 0.25, got {score}");
    }

    #[test]
    fn test_moderate_device_attestation() {
        let engine = RiskEngine::new();
        let user = Uuid::new_v4();
        let mut signals = clean_signals();
        signals.device_attestation_age_secs = 400.0; // > 300, < 3600
        let score = engine.compute_score(&user, &signals);
        assert!(score >= 0.10, "moderate attestation should add at least 0.10, got {score}");
    }

    #[test]
    fn test_server_side_failed_attempts() {
        let engine = RiskEngine::new();
        let user = Uuid::new_v4();

        // Record 5 server-side failures
        for _ in 0..5 {
            engine.record_failed_attempt(&user);
        }

        let mut signals = clean_signals();
        // Set a non-zero field to avoid mimicry penalty interfering
        signals.device_attestation_age_secs = 1.0;
        let score = engine.compute_score(&user, &signals);
        // 5/5 * 0.15 = 0.15 from failed attempts + noise
        assert!(score >= 0.15, "5 failed attempts should add at least 0.15, got {score}");
    }

    #[test]
    fn test_client_supplied_failed_attempts_ignored() {
        let engine = RiskEngine::new();
        let user = Uuid::new_v4();
        let mut signals = clean_signals();
        // Client claims 100 failed attempts, but no server-side failures recorded
        signals.recent_failed_attempts = 100;
        signals.device_attestation_age_secs = 1.0; // avoid mimicry
        let score = engine.compute_score(&user, &signals);
        // Should NOT include failed attempts contribution since server counter is 0
        assert!(score < 0.15, "client-supplied failures should be ignored, got {score}");
    }

    #[test]
    fn test_signal_validation_negative_values_clamped() {
        let engine = RiskEngine::new();
        let signals = RiskSignals {
            device_attestation_age_secs: -100.0,
            geo_velocity_kmh: -50.0,
            is_unusual_network: false,
            is_unusual_time: false,
            unusual_access_score: -0.5,
            recent_failed_attempts: 0,
            login_hour: None,
            network_id: None,
            session_duration_secs: Some(-10.0),
        };
        let validated = engine.validate_signals(&signals);
        assert_eq!(validated.device_attestation_age_secs, 0.0);
        assert_eq!(validated.geo_velocity_kmh, 0.0);
        assert_eq!(validated.unusual_access_score, 0.0);
        assert_eq!(validated.session_duration_secs, Some(0.0));
    }

    #[test]
    fn test_signal_validation_unusual_access_score_clamped() {
        let engine = RiskEngine::new();
        let mut signals = clean_signals();
        signals.unusual_access_score = 5.0; // above 1.0 max
        let validated = engine.validate_signals(&signals);
        assert_eq!(validated.unusual_access_score, 1.0);
    }

    #[test]
    fn test_login_hour_clamped_to_23() {
        let engine = RiskEngine::new();
        let mut signals = clean_signals();
        signals.login_hour = Some(99);
        let validated = engine.validate_signals(&signals);
        assert_eq!(validated.login_hour, Some(23));
    }

    // -- Fail-secure behavior tests --

    #[test]
    fn test_score_always_capped_at_1() {
        let engine = RiskEngine::new();
        let user = Uuid::new_v4();
        // Max out all signals
        for _ in 0..10 {
            engine.record_failed_attempt(&user);
        }
        let signals = RiskSignals {
            device_attestation_age_secs: 100000.0,
            geo_velocity_kmh: 5000.0,
            is_unusual_network: true,
            is_unusual_time: true,
            unusual_access_score: 1.0,
            recent_failed_attempts: 100,
            login_hour: None,
            network_id: None,
            session_duration_secs: None,
        };
        let score = engine.compute_score(&user, &signals);
        assert!(score <= 1.0, "score should never exceed 1.0, got {score}");
    }

    #[test]
    fn test_score_always_non_negative() {
        let engine = RiskEngine::new();
        let user = Uuid::new_v4();
        let score = engine.compute_score(&user, &clean_signals());
        assert!(score >= 0.0, "score should never be negative, got {score}");
    }

    // -- Lockout tests --

    #[test]
    fn test_lockout_after_max_attempts() {
        let engine = RiskEngine::new();
        let user = Uuid::new_v4();
        let max_attempts = 5u32;

        assert!(!engine.is_locked_out(&user, max_attempts));

        for _ in 0..max_attempts {
            engine.record_failed_attempt(&user);
        }

        assert!(engine.is_locked_out(&user, max_attempts));
    }

    #[test]
    fn test_not_locked_out_below_threshold() {
        let engine = RiskEngine::new();
        let user = Uuid::new_v4();

        for _ in 0..3 {
            engine.record_failed_attempt(&user);
        }

        assert!(!engine.is_locked_out(&user, 5));
    }

    #[test]
    fn test_lockout_different_users_independent() {
        let engine = RiskEngine::new();
        let user1 = Uuid::new_v4();
        let user2 = Uuid::new_v4();

        for _ in 0..5 {
            engine.record_failed_attempt(&user1);
        }

        assert!(engine.is_locked_out(&user1, 5));
        assert!(!engine.is_locked_out(&user2, 5));
    }

    // -- Step-up and termination tests --

    #[test]
    fn test_step_up_threshold() {
        let engine = RiskEngine::new();
        assert!(!engine.requires_step_up(0.59));
        assert!(engine.requires_step_up(0.6));
        assert!(engine.requires_step_up(1.0));
    }

    #[test]
    fn test_termination_threshold() {
        let engine = RiskEngine::new();
        assert!(!engine.requires_termination(0.79));
        assert!(engine.requires_termination(0.8));
        assert!(engine.requires_termination(1.0));
    }

    // -- Baseline store tests --

    #[test]
    fn test_baseline_store_no_baseline_zero_anomaly() {
        let store = BaselineStore::new();
        let user = Uuid::new_v4();
        let score = store.compute_anomaly_score(&user, &clean_signals());
        assert_eq!(score, 0.0, "no baseline should produce zero anomaly");
    }

    #[test]
    fn test_baseline_store_update_creates_baseline() {
        let store = BaselineStore::new();
        let user = Uuid::new_v4();
        let signals = RiskSignals {
            device_attestation_age_secs: 0.0,
            geo_velocity_kmh: 0.0,
            is_unusual_network: false,
            is_unusual_time: false,
            unusual_access_score: 0.0,
            recent_failed_attempts: 0,
            login_hour: Some(10),
            network_id: Some("AS1234".to_string()),
            session_duration_secs: Some(300.0),
        };
        store.update_baseline(user, &signals);
        let baseline = store.get_baseline(&user);
        assert!(baseline.is_some(), "baseline should exist after update");
    }

    #[test]
    fn test_baseline_unknown_network_adds_anomaly() {
        let store = BaselineStore::new();
        let user = Uuid::new_v4();

        // Establish baseline with known network
        let signals = RiskSignals {
            device_attestation_age_secs: 0.0,
            geo_velocity_kmh: 0.0,
            is_unusual_network: false,
            is_unusual_time: false,
            unusual_access_score: 0.0,
            recent_failed_attempts: 0,
            login_hour: Some(10),
            network_id: Some("AS1234".to_string()),
            session_duration_secs: Some(300.0),
        };
        store.update_baseline(user, &signals);

        // Compute anomaly from unknown network
        let new_signals = RiskSignals {
            network_id: Some("AS9999".to_string()),
            ..signals.clone()
        };
        let anomaly = store.compute_anomaly_score(&user, &new_signals);
        assert!(anomaly > 0.0, "unknown network should produce anomaly, got {anomaly}");
    }
}
