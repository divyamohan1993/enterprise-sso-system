use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Risk signal types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskSignals {
    pub device_attestation_age_secs: f64, // 0 = fresh, higher = stale
    pub geo_velocity_kmh: f64,            // impossible travel speed
    pub is_unusual_network: bool,         // unusual IP/VPN/Tor
    pub is_unusual_time: bool,            // outside normal hours
    pub unusual_access_score: f64,        // 0.0-1.0, API pattern anomaly
    pub recent_failed_attempts: u32,      // in last hour
}

/// Risk score result
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskLevel {
    Normal,   // < 0.3
    Elevated, // 0.3 - 0.6
    High,     // 0.6 - 0.8
    Critical, // >= 0.8
}

pub struct RiskEngine {
    #[allow(dead_code)]
    baselines: HashMap<Uuid, UserBaseline>,
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
        }
    }

    /// Compute risk score from signals. Returns 0.0-1.0.
    pub fn compute_score(&self, _user_id: &Uuid, signals: &RiskSignals) -> f64 {
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

        // Failed attempts (weight ~0.15)
        let fail_score = (signals.recent_failed_attempts as f64 / 5.0).min(1.0);
        score += fail_score * 0.15;

        // Mimicry detection: flag sessions where ALL signals are simultaneously
        // perfect (statistically improbable for real users). A legitimate user
        // will have at least some non-zero signal noise.
        let all_perfect = signals.device_attestation_age_secs == 0.0
            && signals.geo_velocity_kmh == 0.0
            && !signals.is_unusual_network
            && !signals.is_unusual_time
            && signals.unusual_access_score == 0.0
            && signals.recent_failed_attempts == 0;
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
