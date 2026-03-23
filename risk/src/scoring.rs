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

pub struct RiskEngine {
    // TODO: `baselines` is currently a stub. It needs to be populated with
    // actual per-user behavioral data (login hours, typical networks, access
    // patterns) from a persistent store or streaming pipeline. Until then,
    // baseline-aware scoring is not active.
    #[allow(dead_code)]
    baselines: HashMap<Uuid, UserBaseline>,

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

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct UserBaseline {
    avg_login_hour: f64,
    usual_networks: Vec<String>,
    typical_access_patterns: Vec<String>,
    last_updated: i64,
}

impl RiskEngine {
    pub fn new() -> Self {
        Self {
            baselines: HashMap::new(),
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

        // Mimicry detection: flag sessions where ALL signals are simultaneously
        // perfect (statistically improbable for real users). A legitimate user
        // will have at least some non-zero signal noise.
        let all_perfect = signals.device_attestation_age_secs == 0.0
            && signals.geo_velocity_kmh == 0.0
            && !signals.is_unusual_network
            && !signals.is_unusual_time
            && signals.unusual_access_score == 0.0
            && server_fails == 0;
        if all_perfect {
            // Suspiciously clean — add a small penalty.
            // Real users always have *some* attestation age and minor anomalies.
            score += 0.05;
        }

        // Add small random noise to prevent attackers from computing exact
        // threshold-crossing signal combinations. Noise range: [0.0, 0.03)
        let noise_byte = {
            let mut buf = [0u8; 1];
            getrandom::getrandom(&mut buf).unwrap_or_default();
            (buf[0] as f64 / 255.0) * 0.03
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
