//! Enhanced anomaly detection for the MILNET SSO risk engine.
//!
//! Extends the baseline behavioral analysis in `scoring.rs` with:
//! - Statistical anomaly detection (z-score based)
//! - Cross-user correlation (distributed attack detection)
//! - Impossible travel detection with actual distance/time calculation
//! - Session pattern analysis
//! - Adaptive thresholds that learn from historical data
//! - SIEM export of anomaly scores
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Geographic types for impossible travel
// ---------------------------------------------------------------------------

/// A geographic coordinate (latitude, longitude in degrees).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct GeoCoord {
    pub lat: f64,
    pub lon: f64,
}

impl GeoCoord {
    /// Haversine distance in kilometers between two coordinates.
    pub fn distance_km(&self, other: &GeoCoord) -> f64 {
        const R: f64 = 6371.0; // Earth radius in km
        let d_lat = (other.lat - self.lat).to_radians();
        let d_lon = (other.lon - self.lon).to_radians();
        let lat1 = self.lat.to_radians();
        let lat2 = other.lat.to_radians();

        let a = (d_lat / 2.0).sin().powi(2) + lat1.cos() * lat2.cos() * (d_lon / 2.0).sin().powi(2);
        let c = 2.0 * a.sqrt().atan2((1.0 - a).sqrt());
        R * c
    }
}

/// A login location event for impossible travel detection.
#[derive(Debug, Clone)]
pub struct LoginLocation {
    pub user_id: Uuid,
    pub coord: GeoCoord,
    pub timestamp: Instant,
    pub ip: String,
}

// ---------------------------------------------------------------------------
// Statistical anomaly detection (z-score)
// ---------------------------------------------------------------------------

/// Running statistics for z-score calculation using Welford's online algorithm.
#[derive(Debug, Clone)]
pub struct RunningStats {
    count: u64,
    mean: f64,
    m2: f64, // sum of squares of differences from the current mean
}

impl RunningStats {
    pub fn new() -> Self {
        Self {
            count: 0,
            mean: 0.0,
            m2: 0.0,
        }
    }

    /// Add a new observation.
    pub fn update(&mut self, value: f64) {
        self.count += 1;
        let delta = value - self.mean;
        self.mean += delta / self.count as f64;
        let delta2 = value - self.mean;
        self.m2 += delta * delta2;
    }

    /// Current mean.
    pub fn mean(&self) -> f64 {
        self.mean
    }

    /// Population variance.
    pub fn variance(&self) -> f64 {
        if self.count < 2 {
            return 0.0;
        }
        self.m2 / self.count as f64
    }

    /// Population standard deviation.
    pub fn std_dev(&self) -> f64 {
        self.variance().sqrt()
    }

    /// Compute the z-score for a value given the current distribution.
    /// Returns None if there is insufficient data (< 10 observations).
    pub fn z_score(&self, value: f64) -> Option<f64> {
        if self.count < 10 {
            return None; // Not enough data for statistical significance
        }
        let sd = self.std_dev();
        if sd < f64::EPSILON {
            return None; // No variance — all values identical
        }
        Some((value - self.mean) / sd)
    }

    /// Number of observations.
    pub fn count(&self) -> u64 {
        self.count
    }
}

impl Default for RunningStats {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Per-user anomaly profile
// ---------------------------------------------------------------------------

/// Per-user behavioral profile with statistical baselines.
#[derive(Debug, Clone)]
pub struct UserAnomalyProfile {
    /// Login time-of-day statistics (hour as f64).
    pub login_hour_stats: RunningStats,
    /// Session duration statistics (seconds).
    pub session_duration_stats: RunningStats,
    /// Request rate statistics (requests per minute during session).
    pub request_rate_stats: RunningStats,
    /// Known device fingerprints.
    pub known_devices: Vec<String>,
    /// Known IP addresses.
    pub known_ips: Vec<String>,
    /// Last login location (for impossible travel).
    pub last_location: Option<(GeoCoord, Instant)>,
    /// Resource access pattern (resource_name -> count).
    pub resource_access: HashMap<String, u32>,
    /// Total login count.
    pub login_count: u64,
}

impl UserAnomalyProfile {
    pub fn new() -> Self {
        Self {
            login_hour_stats: RunningStats::new(),
            session_duration_stats: RunningStats::new(),
            request_rate_stats: RunningStats::new(),
            known_devices: Vec::new(),
            known_ips: Vec::new(),
            last_location: None,
            resource_access: HashMap::new(),
            login_count: 0,
        }
    }
}

impl Default for UserAnomalyProfile {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Anomaly scores (composite result)
// ---------------------------------------------------------------------------

/// Detailed anomaly detection result with per-factor scores.
#[derive(Debug, Clone, Serialize)]
pub struct AnomalyResult {
    /// Overall composite anomaly score [0.0, 1.0].
    pub composite_score: f64,
    /// Login time z-score anomaly (0.0 = normal, 1.0 = extreme outlier).
    pub time_anomaly: f64,
    /// Session duration z-score anomaly.
    pub duration_anomaly: f64,
    /// Impossible travel score (based on distance/time).
    pub travel_anomaly: f64,
    /// New device score (1.0 if brand new device, 0.0 if known).
    pub device_anomaly: f64,
    /// New IP score.
    pub ip_anomaly: f64,
    /// Cross-user correlation score (same IP hitting multiple users).
    pub cross_user_anomaly: f64,
    /// Resource access pattern anomaly.
    pub access_pattern_anomaly: f64,
    /// Whether this triggered an alert.
    pub alert_triggered: bool,
    /// Explanation of the highest-contributing factor.
    pub explanation: String,
}

// ---------------------------------------------------------------------------
// Cross-user correlation tracker
// ---------------------------------------------------------------------------

/// Tracks IP -> user_id mappings for detecting distributed attacks where
/// a single IP targets multiple user accounts.
struct IpUserTracker {
    /// IP -> (set of user_ids, first_seen)
    ip_users: HashMap<String, (Vec<Uuid>, Instant)>,
    /// Cleanup interval
    window: std::time::Duration,
}

impl IpUserTracker {
    fn new() -> Self {
        Self {
            ip_users: HashMap::new(),
            window: std::time::Duration::from_secs(3600), // 1 hour window
        }
    }

    /// Record a login attempt from an IP for a user.
    fn record(&mut self, ip: &str, user_id: &Uuid) {
        let now = Instant::now();

        // Prune stale entries
        self.ip_users
            .retain(|_, (_, first)| now.duration_since(*first) < self.window);

        let entry = self
            .ip_users
            .entry(ip.to_string())
            .or_insert_with(|| (Vec::new(), now));

        if !entry.0.contains(user_id) && entry.0.len() < 1000 {
            entry.0.push(*user_id);
        }
    }

    /// Get the number of distinct users that have attempted login from this IP.
    fn distinct_users_for_ip(&self, ip: &str) -> usize {
        self.ip_users.get(ip).map(|(users, _)| users.len()).unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// Login velocity tracker (impossible travel)
// ---------------------------------------------------------------------------

/// Maximum physically possible speed in km/h.
/// Commercial aviation tops out around 900 km/h. We allow 1000 as a generous
/// upper bound before flagging impossible travel.
const MAX_TRAVEL_SPEED_KMH: f64 = 1000.0;

/// Check for impossible travel between two login locations.
/// Returns a score in [0.0, 1.0] where 1.0 means definitively impossible.
fn impossible_travel_score(prev: &(GeoCoord, Instant), current: &(GeoCoord, Instant)) -> f64 {
    let distance_km = prev.0.distance_km(&current.0);
    let time_hours = current.1.duration_since(prev.1).as_secs_f64() / 3600.0;

    if time_hours < 0.001 {
        // Less than ~3.6 seconds between logins at different locations
        if distance_km > 1.0 {
            return 1.0;
        }
        return 0.0;
    }

    let speed_kmh = distance_km / time_hours;

    if speed_kmh > 10_000.0 {
        // Faster than orbital velocity — definitely spoofed
        1.0
    } else if speed_kmh > MAX_TRAVEL_SPEED_KMH {
        // Impossible for commercial travel — scale score by excess speed
        let excess = (speed_kmh - MAX_TRAVEL_SPEED_KMH) / MAX_TRAVEL_SPEED_KMH;
        (0.6 + excess * 0.4).min(1.0)
    } else if speed_kmh > 500.0 {
        // Very fast but technically possible (air travel) — mild suspicion
        0.2
    } else {
        0.0
    }
}

// ---------------------------------------------------------------------------
// Anomaly Detection Engine
// ---------------------------------------------------------------------------

/// The main anomaly detection engine. Thread-safe.
pub struct AnomalyDetector {
    /// Per-user anomaly profiles.
    profiles: Mutex<HashMap<Uuid, UserAnomalyProfile>>,
    /// Cross-user IP correlation tracker.
    ip_tracker: Mutex<IpUserTracker>,
    /// Adaptive threshold: anomaly score above which we alert.
    /// Starts at 0.7, adapts based on false-positive feedback.
    alert_threshold: Mutex<f64>,
    /// Historical anomaly scores for adaptive threshold tuning.
    score_history: Mutex<RunningStats>,
}

impl AnomalyDetector {
    pub fn new() -> Self {
        Self {
            profiles: Mutex::new(HashMap::new()),
            ip_tracker: Mutex::new(IpUserTracker::new()),
            alert_threshold: Mutex::new(0.7),
            score_history: Mutex::new(RunningStats::new()),
        }
    }

    /// Analyze a login event and return a detailed anomaly result.
    pub fn analyze_login(
        &self,
        user_id: &Uuid,
        login_hour: f64,
        device_fingerprint: Option<&str>,
        source_ip: Option<&str>,
        location: Option<GeoCoord>,
    ) -> AnomalyResult {
        let now = Instant::now();
        let mut profiles = self.profiles.lock().unwrap_or_else(|e| e.into_inner());
        let profile = profiles
            .entry(*user_id)
            .or_insert_with(UserAnomalyProfile::new);

        // --- Time-of-day anomaly (z-score) ---
        let time_anomaly = profile
            .login_hour_stats
            .z_score(login_hour)
            .map(|z| z_score_to_anomaly(z.abs()))
            .unwrap_or(0.0);

        // --- Device anomaly ---
        let device_anomaly = if let Some(fp) = device_fingerprint {
            if profile.known_devices.contains(&fp.to_string()) {
                0.0
            } else {
                if profile.login_count > 5 {
                    0.8 // New device for established user = suspicious
                } else {
                    0.2 // New user, new device is normal
                }
            }
        } else {
            0.3 // No device info is mildly suspicious
        };

        // --- IP anomaly ---
        let ip_anomaly = if let Some(ip) = source_ip {
            if profile.known_ips.contains(&ip.to_string()) {
                0.0
            } else {
                if profile.login_count > 5 {
                    0.5
                } else {
                    0.1
                }
            }
        } else {
            0.2
        };

        // --- Impossible travel ---
        let travel_anomaly = if let (Some(loc), Some(ref prev)) = (location, &profile.last_location)
        {
            impossible_travel_score(prev, &(loc, now))
        } else {
            0.0
        };

        // --- Cross-user correlation ---
        let cross_user_anomaly = if let Some(ip) = source_ip {
            let mut tracker = self.ip_tracker.lock().unwrap_or_else(|e| e.into_inner());
            tracker.record(ip, user_id);
            let distinct = tracker.distinct_users_for_ip(ip);
            if distinct > 20 {
                1.0 // >20 distinct users from same IP in 1h = attack
            } else if distinct > 10 {
                0.7
            } else if distinct > 5 {
                0.4
            } else {
                0.0
            }
        } else {
            0.0
        };

        // --- Composite score with weights ---
        let composite = (time_anomaly * 0.15
            + device_anomaly * 0.20
            + ip_anomaly * 0.15
            + travel_anomaly * 0.25
            + cross_user_anomaly * 0.20
            + 0.0 * 0.05) // access_pattern placeholder weight
            .min(1.0);

        // Check against adaptive threshold
        let threshold = *self.alert_threshold.lock().unwrap_or_else(|e| e.into_inner());
        let alert_triggered = composite >= threshold;

        // Track score for adaptive threshold tuning
        {
            let mut history = self.score_history.lock().unwrap_or_else(|e| e.into_inner());
            history.update(composite);
        }

        // Determine explanation
        let factors = [
            (travel_anomaly, "impossible_travel"),
            (device_anomaly, "unknown_device"),
            (cross_user_anomaly, "distributed_attack_pattern"),
            (ip_anomaly, "unknown_ip"),
            (time_anomaly, "unusual_login_time"),
        ];
        let (max_score, max_factor) = factors
            .iter()
            .max_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal))
            .unwrap_or(&(0.0, "none"));

        let explanation = if *max_score > 0.3 {
            format!(
                "Highest anomaly factor: {} (score={:.2})",
                max_factor, max_score
            )
        } else {
            "No significant anomalies detected".to_string()
        };

        AnomalyResult {
            composite_score: composite,
            time_anomaly,
            duration_anomaly: 0.0, // Computed on session end
            travel_anomaly,
            device_anomaly,
            ip_anomaly,
            cross_user_anomaly,
            access_pattern_anomaly: 0.0,
            alert_triggered,
            explanation,
        }
    }

    /// Update the user's profile after a successful, legitimate login.
    /// Call this only after the login is confirmed authentic.
    pub fn record_successful_login(
        &self,
        user_id: &Uuid,
        login_hour: f64,
        device_fingerprint: Option<&str>,
        source_ip: Option<&str>,
        location: Option<GeoCoord>,
    ) {
        let now = Instant::now();
        let mut profiles = self.profiles.lock().unwrap_or_else(|e| e.into_inner());
        let profile = profiles
            .entry(*user_id)
            .or_insert_with(UserAnomalyProfile::new);

        profile.login_hour_stats.update(login_hour);
        profile.login_count += 1;

        if let Some(fp) = device_fingerprint {
            if !profile.known_devices.contains(&fp.to_string()) && profile.known_devices.len() < 50
            {
                profile.known_devices.push(fp.to_string());
            }
        }

        if let Some(ip) = source_ip {
            if !profile.known_ips.contains(&ip.to_string()) && profile.known_ips.len() < 100 {
                profile.known_ips.push(ip.to_string());
            }
        }

        if let Some(loc) = location {
            profile.last_location = Some((loc, now));
        }
    }

    /// Record a completed session's duration for the user's profile.
    pub fn record_session_duration(&self, user_id: &Uuid, duration_secs: f64) {
        let mut profiles = self.profiles.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(profile) = profiles.get_mut(user_id) {
            profile.session_duration_stats.update(duration_secs);
        }
    }

    /// Record resource access for session pattern analysis.
    pub fn record_resource_access(&self, user_id: &Uuid, resource: &str) {
        let mut profiles = self.profiles.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(profile) = profiles.get_mut(user_id) {
            let count = profile
                .resource_access
                .entry(resource.to_string())
                .or_insert(0);
            *count = count.saturating_add(1);
        }
    }

    /// Analyze session resource access patterns for anomalies.
    /// Compares the current session's accessed resources against the user's
    /// historical pattern.
    pub fn analyze_session_pattern(
        &self,
        user_id: &Uuid,
        session_resources: &[String],
    ) -> f64 {
        let profiles = self.profiles.lock().unwrap_or_else(|e| e.into_inner());
        let profile = match profiles.get(user_id) {
            Some(p) => p,
            None => return 0.0, // No history
        };

        if profile.resource_access.is_empty() || session_resources.is_empty() {
            return 0.0;
        }

        // Compute Jaccard similarity between session resources and historical pattern
        let historical: std::collections::HashSet<&str> = profile
            .resource_access
            .keys()
            .map(|s| s.as_str())
            .collect();
        let current: std::collections::HashSet<&str> =
            session_resources.iter().map(|s| s.as_str()).collect();

        let intersection = historical.intersection(&current).count();
        let union = historical.union(&current).count();

        if union == 0 {
            return 0.0;
        }

        let similarity = intersection as f64 / union as f64;
        // Low similarity = high anomaly
        (1.0 - similarity).max(0.0)
    }

    /// Adjust the adaptive alert threshold based on operator feedback.
    /// If `was_false_positive` is true, the threshold is raised (fewer alerts).
    /// If false, the threshold is lowered (more sensitive).
    pub fn feedback(&self, was_false_positive: bool) {
        let mut threshold = self.alert_threshold.lock().unwrap_or_else(|e| e.into_inner());
        if was_false_positive {
            *threshold = (*threshold + 0.02).min(0.95);
        } else {
            *threshold = (*threshold - 0.01).max(0.3);
        }
    }

    /// Get the current adaptive alert threshold.
    pub fn current_threshold(&self) -> f64 {
        *self.alert_threshold.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Export the anomaly result as a SIEM-compatible JSON value.
    pub fn export_to_siem(result: &AnomalyResult, user_id: &Uuid) -> serde_json::Value {
        serde_json::json!({
            "event_type": "anomaly_detection",
            "user_id": user_id.to_string(),
            "composite_score": result.composite_score,
            "factors": {
                "time_anomaly": result.time_anomaly,
                "duration_anomaly": result.duration_anomaly,
                "travel_anomaly": result.travel_anomaly,
                "device_anomaly": result.device_anomaly,
                "ip_anomaly": result.ip_anomaly,
                "cross_user_anomaly": result.cross_user_anomaly,
                "access_pattern_anomaly": result.access_pattern_anomaly,
            },
            "alert_triggered": result.alert_triggered,
            "explanation": result.explanation,
        })
    }
}

impl Default for AnomalyDetector {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Map an absolute z-score to an anomaly score in [0.0, 1.0].
/// z < 2:   normal (0.0)
/// z 2-3:   mild anomaly (0.0-0.5)
/// z 3-4:   significant anomaly (0.5-0.8)
/// z > 4:   extreme anomaly (0.8-1.0)
fn z_score_to_anomaly(abs_z: f64) -> f64 {
    if abs_z < 2.0 {
        0.0
    } else if abs_z < 3.0 {
        (abs_z - 2.0) * 0.5
    } else if abs_z < 4.0 {
        0.5 + (abs_z - 3.0) * 0.3
    } else {
        (0.8 + (abs_z - 4.0) * 0.1).min(1.0)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_haversine_distance() {
        // New York (40.7128, -74.0060) to London (51.5074, -0.1278)
        let ny = GeoCoord {
            lat: 40.7128,
            lon: -74.0060,
        };
        let london = GeoCoord {
            lat: 51.5074,
            lon: -0.1278,
        };
        let dist = ny.distance_km(&london);
        // Actual ~5570 km
        assert!(dist > 5500.0 && dist < 5650.0, "Distance was {}", dist);
    }

    #[test]
    fn test_impossible_travel() {
        let ny = GeoCoord {
            lat: 40.7128,
            lon: -74.0060,
        };
        let london = GeoCoord {
            lat: 51.5074,
            lon: -0.1278,
        };
        let now = Instant::now();

        // Login from NY, then London 30 minutes later => impossible
        let prev = (ny, now);
        let current = (london, now + std::time::Duration::from_secs(1800));
        let score = impossible_travel_score(&prev, &current);
        assert!(score > 0.6, "Should flag impossible travel: {}", score);

        // Login from NY, then London 8 hours later => possible (flight)
        let current_ok = (london, now + std::time::Duration::from_secs(28800));
        let score_ok = impossible_travel_score(&prev, &current_ok);
        assert!(score_ok < 0.3, "Should not flag 8h travel: {}", score_ok);
    }

    #[test]
    fn test_running_stats_z_score() {
        let mut stats = RunningStats::new();
        // Add 20 observations around mean=10
        for i in 0..20 {
            stats.update(10.0 + (i as f64 % 3.0) - 1.0);
        }

        let z = stats.z_score(10.0).unwrap();
        assert!(z.abs() < 1.0, "Mean should have low z-score: {}", z);

        let z_outlier = stats.z_score(20.0).unwrap();
        assert!(z_outlier > 2.0, "Outlier should have high z-score: {}", z_outlier);
    }

    #[test]
    fn test_anomaly_detector_new_user() {
        let detector = AnomalyDetector::new();
        let user_id = Uuid::new_v4();

        let result = detector.analyze_login(&user_id, 14.0, Some("device1"), Some("1.2.3.4"), None);
        // New user should have low anomaly (benefit of the doubt)
        assert!(
            result.composite_score < 0.5,
            "New user should have low anomaly: {}",
            result.composite_score
        );
    }

    #[test]
    fn test_anomaly_detector_known_device() {
        let detector = AnomalyDetector::new();
        let user_id = Uuid::new_v4();

        // Build up history
        for _ in 0..10 {
            detector.record_successful_login(&user_id, 14.0, Some("device1"), Some("1.2.3.4"), None);
        }

        // Login from known device
        let result = detector.analyze_login(&user_id, 14.0, Some("device1"), Some("1.2.3.4"), None);
        assert!(result.device_anomaly < 0.1, "Known device should be 0");
        assert!(result.ip_anomaly < 0.1, "Known IP should be 0");
    }

    #[test]
    fn test_anomaly_detector_unknown_device() {
        let detector = AnomalyDetector::new();
        let user_id = Uuid::new_v4();

        // Build up history
        for _ in 0..10 {
            detector.record_successful_login(&user_id, 14.0, Some("device1"), Some("1.2.3.4"), None);
        }

        // Login from unknown device
        let result = detector.analyze_login(
            &user_id,
            14.0,
            Some("unknown_device"),
            Some("9.9.9.9"),
            None,
        );
        assert!(result.device_anomaly > 0.5, "Unknown device should flag: {}", result.device_anomaly);
    }

    #[test]
    fn test_cross_user_correlation() {
        let detector = AnomalyDetector::new();
        let attack_ip = "203.0.113.1";

        // Simulate 25 different users from the same IP
        for i in 0..25 {
            let uid = Uuid::new_v4();
            let result = detector.analyze_login(&uid, 14.0, None, Some(attack_ip), None);
            if i >= 20 {
                assert!(
                    result.cross_user_anomaly > 0.5,
                    "Distributed attack pattern should be detected at user #{}: {}",
                    i,
                    result.cross_user_anomaly,
                );
            }
        }
    }

    #[test]
    fn test_adaptive_threshold() {
        let detector = AnomalyDetector::new();
        let initial = detector.current_threshold();
        assert!((initial - 0.7).abs() < f64::EPSILON);

        // False positive feedback should raise threshold
        detector.feedback(true);
        assert!(detector.current_threshold() > initial);

        // True positive feedback should lower threshold
        detector.feedback(false);
        detector.feedback(false);
        detector.feedback(false);
        assert!(detector.current_threshold() < initial + 0.02);
    }

    #[test]
    fn test_z_score_to_anomaly() {
        assert_eq!(z_score_to_anomaly(1.0), 0.0);
        assert!(z_score_to_anomaly(2.5) > 0.0 && z_score_to_anomaly(2.5) < 0.5);
        assert!(z_score_to_anomaly(3.5) > 0.5);
        assert!(z_score_to_anomaly(5.0) > 0.8);
    }

    #[test]
    fn test_siem_export() {
        let result = AnomalyResult {
            composite_score: 0.85,
            time_anomaly: 0.3,
            duration_anomaly: 0.0,
            travel_anomaly: 0.9,
            device_anomaly: 0.0,
            ip_anomaly: 0.1,
            cross_user_anomaly: 0.0,
            access_pattern_anomaly: 0.0,
            alert_triggered: true,
            explanation: "Highest anomaly factor: impossible_travel (score=0.90)".into(),
        };

        let uid = Uuid::new_v4();
        let json = AnomalyDetector::export_to_siem(&result, &uid);
        assert_eq!(json["event_type"], "anomaly_detection");
        assert_eq!(json["alert_triggered"], true);
    }
}
