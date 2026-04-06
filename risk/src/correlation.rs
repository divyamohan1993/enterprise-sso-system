//! SIEM Correlation Rules Engine for the SSO risk engine.
//!
//! Provides a pluggable correlation rules engine with:
//! - Trait-based rule definition for custom detection logic
//! - Built-in detection rules (brute force, credential stuffing, impossible
//!   travel, privilege escalation, account takeover, lateral movement,
//!   session anomaly, token replay, DDoS pattern)
//! - Sliding window event aggregation (in-memory with periodic flush)
//! - Alert severity scoring (Low/Medium/High/Critical)
//! - Automated response actions (block IP, lock account, revoke sessions)
//! - MITRE ATT&CK technique mapping per rule
//! - Rule chaining with escalation
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Alert severity and response actions
// ---------------------------------------------------------------------------

/// Alert severity levels for correlation rule hits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AlertSeverity {
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl std::fmt::Display for AlertSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AlertSeverity::Low => write!(f, "LOW"),
            AlertSeverity::Medium => write!(f, "MEDIUM"),
            AlertSeverity::High => write!(f, "HIGH"),
            AlertSeverity::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Automated response actions that can be triggered by correlation rules.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ResponseAction {
    /// Block the source IP address.
    BlockIp(String),
    /// Lock the user account.
    LockAccount(Uuid),
    /// Revoke all sessions for a user.
    RevokeSessions(Uuid),
    /// Send an alert webhook notification.
    AlertWebhook(String),
    /// Log for investigation (no automated action).
    LogOnly,
}

/// A correlation alert produced when a rule fires.
#[derive(Debug, Clone, Serialize)]
pub struct CorrelationAlert {
    /// Unique alert ID.
    pub alert_id: Uuid,
    /// Rule that triggered this alert.
    pub rule_id: String,
    /// Human-readable rule name.
    pub rule_name: String,
    /// Alert severity.
    pub severity: AlertSeverity,
    /// Description of what was detected.
    pub description: String,
    /// MITRE ATT&CK technique ID (e.g., "T1110.001").
    pub mitre_technique: String,
    /// Recommended response actions.
    pub response_actions: Vec<ResponseAction>,
    /// Unix timestamp when the alert was created.
    pub timestamp: i64,
    /// Associated user ID (if applicable).
    pub user_id: Option<Uuid>,
    /// Associated source IP (if applicable).
    pub source_ip: Option<String>,
    /// Additional context key-value pairs.
    pub context: HashMap<String, String>,
}

// ---------------------------------------------------------------------------
// Security events for correlation
// ---------------------------------------------------------------------------

/// A security event that flows into the correlation engine for analysis.
#[derive(Debug, Clone)]
pub struct SecurityEventRecord {
    pub event_type: EventType,
    pub timestamp: Instant,
    pub user_id: Option<Uuid>,
    pub source_ip: Option<String>,
    pub tenant_id: Option<Uuid>,
    pub session_id: Option<String>,
    pub jti: Option<String>,
    pub detail: HashMap<String, String>,
}

/// Event types recognized by the correlation engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EventType {
    LoginSuccess,
    LoginFailure,
    PasswordChange,
    MfaChange,
    MfaEnroll,
    PrivilegeActivation,
    ResourceAccess,
    SessionCreated,
    SessionRevoked,
    TokenIssued,
    TokenUsed,
    ApiRequest,
}

// ---------------------------------------------------------------------------
// Correlation Rule trait
// ---------------------------------------------------------------------------

/// Trait for defining a correlation detection rule.
///
/// Each rule evaluates a stream of security events within a sliding window
/// and produces alerts when suspicious patterns are detected.
pub trait CorrelationRule: Send + Sync {
    /// Unique identifier for this rule (e.g., "brute_force_login").
    fn rule_id(&self) -> &str;

    /// Human-readable name.
    fn rule_name(&self) -> &str;

    /// MITRE ATT&CK technique ID.
    fn mitre_technique(&self) -> &str;

    /// Default severity when this rule fires.
    fn default_severity(&self) -> AlertSeverity;

    /// Evaluate events within the window. Returns alerts if the rule fires.
    fn evaluate(&self, events: &[SecurityEventRecord]) -> Vec<CorrelationAlert>;

    /// The sliding window duration for this rule.
    fn window_duration(&self) -> Duration;
}

// ---------------------------------------------------------------------------
// Built-in rules
// ---------------------------------------------------------------------------

/// Brute force detection: >5 failed logins in 5 min from same IP.
pub struct BruteForceRule {
    pub threshold: u32,
    pub window: Duration,
}

impl Default for BruteForceRule {
    fn default() -> Self {
        Self {
            threshold: 5,
            window: Duration::from_secs(300),
        }
    }
}

impl CorrelationRule for BruteForceRule {
    fn rule_id(&self) -> &str {
        "brute_force_login"
    }

    fn rule_name(&self) -> &str {
        "Brute Force Login Attack"
    }

    fn mitre_technique(&self) -> &str {
        "T1110.001"
    }

    fn default_severity(&self) -> AlertSeverity {
        AlertSeverity::High
    }

    fn window_duration(&self) -> Duration {
        self.window
    }

    fn evaluate(&self, events: &[SecurityEventRecord]) -> Vec<CorrelationAlert> {
        let mut alerts = Vec::new();
        let now = Instant::now();

        // Group failed logins by source IP within window
        let mut ip_failures: HashMap<String, u32> = HashMap::new();
        for event in events {
            if event.event_type != EventType::LoginFailure {
                continue;
            }
            if now.duration_since(event.timestamp) > self.window {
                continue;
            }
            if let Some(ref ip) = event.source_ip {
                *ip_failures.entry(ip.clone()).or_insert(0) += 1;
            }
        }

        for (ip, count) in ip_failures {
            if count > self.threshold {
                alerts.push(CorrelationAlert {
                    alert_id: Uuid::new_v4(),
                    rule_id: self.rule_id().to_string(),
                    rule_name: self.rule_name().to_string(),
                    severity: self.default_severity(),
                    description: format!(
                        "Brute force detected: {} failed logins from {} in {:?}",
                        count, ip, self.window
                    ),
                    mitre_technique: self.mitre_technique().to_string(),
                    response_actions: vec![
                        ResponseAction::BlockIp(ip.clone()),
                        ResponseAction::AlertWebhook("brute_force_detected".to_string()),
                    ],
                    timestamp: unix_now(),
                    user_id: None,
                    source_ip: Some(ip.clone()),
                    context: {
                        let mut ctx = HashMap::new();
                        ctx.insert("failure_count".to_string(), count.to_string());
                        ctx
                    },
                });
            }
        }

        alerts
    }
}

/// Credential stuffing: >10 different usernames from same IP in 10 min.
pub struct CredentialStuffingRule {
    pub threshold: u32,
    pub window: Duration,
}

impl Default for CredentialStuffingRule {
    fn default() -> Self {
        Self {
            threshold: 10,
            window: Duration::from_secs(600),
        }
    }
}

impl CorrelationRule for CredentialStuffingRule {
    fn rule_id(&self) -> &str {
        "credential_stuffing"
    }

    fn rule_name(&self) -> &str {
        "Credential Stuffing Attack"
    }

    fn mitre_technique(&self) -> &str {
        "T1110.004"
    }

    fn default_severity(&self) -> AlertSeverity {
        AlertSeverity::Critical
    }

    fn window_duration(&self) -> Duration {
        self.window
    }

    fn evaluate(&self, events: &[SecurityEventRecord]) -> Vec<CorrelationAlert> {
        let mut alerts = Vec::new();
        let now = Instant::now();

        // Group distinct user_ids per source IP for login failures
        let mut ip_users: HashMap<String, Vec<Uuid>> = HashMap::new();
        for event in events {
            if event.event_type != EventType::LoginFailure {
                continue;
            }
            if now.duration_since(event.timestamp) > self.window {
                continue;
            }
            if let (Some(ref ip), Some(uid)) = (&event.source_ip, event.user_id) {
                let users = ip_users.entry(ip.clone()).or_default();
                if !users.contains(&uid) {
                    users.push(uid);
                }
            }
        }

        for (ip, users) in ip_users {
            if users.len() as u32 > self.threshold {
                alerts.push(CorrelationAlert {
                    alert_id: Uuid::new_v4(),
                    rule_id: self.rule_id().to_string(),
                    rule_name: self.rule_name().to_string(),
                    severity: self.default_severity(),
                    description: format!(
                        "Credential stuffing detected: {} distinct users from {} in {:?}",
                        users.len(),
                        ip,
                        self.window
                    ),
                    mitre_technique: self.mitre_technique().to_string(),
                    response_actions: vec![
                        ResponseAction::BlockIp(ip.clone()),
                        ResponseAction::AlertWebhook("credential_stuffing_detected".to_string()),
                    ],
                    timestamp: unix_now(),
                    user_id: None,
                    source_ip: Some(ip.clone()),
                    context: {
                        let mut ctx = HashMap::new();
                        ctx.insert("distinct_users".to_string(), users.len().to_string());
                        ctx
                    },
                });
            }
        }

        alerts
    }
}

/// Impossible travel: same user from >1000km apart within 30 min.
///
/// Requires `latitude` and `longitude` in event detail map.
pub struct ImpossibleTravelRule {
    pub max_speed_kmh: f64,
    pub window: Duration,
}

impl Default for ImpossibleTravelRule {
    fn default() -> Self {
        Self {
            max_speed_kmh: 1000.0,
            window: Duration::from_secs(1800),
        }
    }
}

impl CorrelationRule for ImpossibleTravelRule {
    fn rule_id(&self) -> &str {
        "impossible_travel"
    }

    fn rule_name(&self) -> &str {
        "Impossible Travel Detected"
    }

    fn mitre_technique(&self) -> &str {
        "T1078"
    }

    fn default_severity(&self) -> AlertSeverity {
        AlertSeverity::High
    }

    fn window_duration(&self) -> Duration {
        self.window
    }

    fn evaluate(&self, events: &[SecurityEventRecord]) -> Vec<CorrelationAlert> {
        let mut alerts = Vec::new();
        let now = Instant::now();

        // Group login successes by user
        let mut user_logins: HashMap<Uuid, Vec<&SecurityEventRecord>> = HashMap::new();
        for event in events {
            if event.event_type != EventType::LoginSuccess {
                continue;
            }
            if now.duration_since(event.timestamp) > self.window {
                continue;
            }
            if let Some(uid) = event.user_id {
                user_logins.entry(uid).or_default().push(event);
            }
        }

        for (uid, logins) in user_logins {
            // Compare consecutive logins
            for pair in logins.windows(2) {
                let prev = &pair[0];
                let curr = &pair[1];

                let prev_lat = prev.detail.get("latitude").and_then(|v| v.parse::<f64>().ok());
                let prev_lon = prev.detail.get("longitude").and_then(|v| v.parse::<f64>().ok());
                let curr_lat = curr.detail.get("latitude").and_then(|v| v.parse::<f64>().ok());
                let curr_lon = curr.detail.get("longitude").and_then(|v| v.parse::<f64>().ok());

                if let (Some(plat), Some(plon), Some(clat), Some(clon)) =
                    (prev_lat, prev_lon, curr_lat, curr_lon)
                {
                    let distance_km = haversine_km(plat, plon, clat, clon);
                    let time_hours =
                        curr.timestamp.duration_since(prev.timestamp).as_secs_f64() / 3600.0;

                    if time_hours > 0.001 {
                        let speed = distance_km / time_hours;
                        if speed > self.max_speed_kmh {
                            alerts.push(CorrelationAlert {
                                alert_id: Uuid::new_v4(),
                                rule_id: self.rule_id().to_string(),
                                rule_name: self.rule_name().to_string(),
                                severity: self.default_severity(),
                                description: format!(
                                    "Impossible travel for user {}: {:.0}km in {:.1}min ({:.0}km/h)",
                                    uid,
                                    distance_km,
                                    time_hours * 60.0,
                                    speed
                                ),
                                mitre_technique: self.mitre_technique().to_string(),
                                response_actions: vec![
                                    ResponseAction::RevokeSessions(uid),
                                    ResponseAction::LockAccount(uid),
                                ],
                                timestamp: unix_now(),
                                user_id: Some(uid),
                                source_ip: curr.source_ip.clone(),
                                context: {
                                    let mut ctx = HashMap::new();
                                    ctx.insert("distance_km".to_string(), format!("{:.0}", distance_km));
                                    ctx.insert("speed_kmh".to_string(), format!("{:.0}", speed));
                                    ctx
                                },
                            });
                        }
                    }
                }
            }
        }

        alerts
    }
}

/// Privilege escalation: PIM activation followed by unusual resource access.
pub struct PrivilegeEscalationRule {
    pub window: Duration,
}

impl Default for PrivilegeEscalationRule {
    fn default() -> Self {
        Self {
            window: Duration::from_secs(3600),
        }
    }
}

impl CorrelationRule for PrivilegeEscalationRule {
    fn rule_id(&self) -> &str {
        "privilege_escalation"
    }

    fn rule_name(&self) -> &str {
        "Privilege Escalation Followed by Unusual Access"
    }

    fn mitre_technique(&self) -> &str {
        "T1078.002"
    }

    fn default_severity(&self) -> AlertSeverity {
        AlertSeverity::Critical
    }

    fn window_duration(&self) -> Duration {
        self.window
    }

    fn evaluate(&self, events: &[SecurityEventRecord]) -> Vec<CorrelationAlert> {
        let mut alerts = Vec::new();
        let now = Instant::now();

        // Find users who activated privileges then accessed resources
        let mut user_priv_activations: HashMap<Uuid, Instant> = HashMap::new();
        let mut user_resource_accesses: HashMap<Uuid, Vec<&SecurityEventRecord>> = HashMap::new();

        for event in events {
            if now.duration_since(event.timestamp) > self.window {
                continue;
            }
            if let Some(uid) = event.user_id {
                match event.event_type {
                    EventType::PrivilegeActivation => {
                        user_priv_activations
                            .entry(uid)
                            .and_modify(|t| {
                                if event.timestamp > *t {
                                    *t = event.timestamp;
                                }
                            })
                            .or_insert(event.timestamp);
                    }
                    EventType::ResourceAccess => {
                        user_resource_accesses.entry(uid).or_default().push(event);
                    }
                    _ => {}
                }
            }
        }

        for (uid, activation_time) in &user_priv_activations {
            if let Some(accesses) = user_resource_accesses.get(uid) {
                let post_activation_accesses: Vec<_> = accesses
                    .iter()
                    .filter(|e| e.timestamp > *activation_time)
                    .collect();

                if post_activation_accesses.len() > 3 {
                    alerts.push(CorrelationAlert {
                        alert_id: Uuid::new_v4(),
                        rule_id: self.rule_id().to_string(),
                        rule_name: self.rule_name().to_string(),
                        severity: self.default_severity(),
                        description: format!(
                            "Privilege escalation: user {} activated PIM then accessed {} resources",
                            uid,
                            post_activation_accesses.len()
                        ),
                        mitre_technique: self.mitre_technique().to_string(),
                        response_actions: vec![
                            ResponseAction::RevokeSessions(*uid),
                            ResponseAction::AlertWebhook("priv_esc_detected".to_string()),
                        ],
                        timestamp: unix_now(),
                        user_id: Some(*uid),
                        source_ip: None,
                        context: {
                            let mut ctx = HashMap::new();
                            ctx.insert(
                                "resource_count".to_string(),
                                post_activation_accesses.len().to_string(),
                            );
                            ctx
                        },
                    });
                }
            }
        }

        alerts
    }
}

/// Account takeover: password change + MFA change within 1 hour.
pub struct AccountTakeoverRule {
    pub window: Duration,
}

impl Default for AccountTakeoverRule {
    fn default() -> Self {
        Self {
            window: Duration::from_secs(3600),
        }
    }
}

impl CorrelationRule for AccountTakeoverRule {
    fn rule_id(&self) -> &str {
        "account_takeover"
    }

    fn rule_name(&self) -> &str {
        "Account Takeover (Password + MFA Change)"
    }

    fn mitre_technique(&self) -> &str {
        "T1098"
    }

    fn default_severity(&self) -> AlertSeverity {
        AlertSeverity::Critical
    }

    fn window_duration(&self) -> Duration {
        self.window
    }

    fn evaluate(&self, events: &[SecurityEventRecord]) -> Vec<CorrelationAlert> {
        let mut alerts = Vec::new();
        let now = Instant::now();

        let mut pw_changes: HashMap<Uuid, bool> = HashMap::new();
        let mut mfa_changes: HashMap<Uuid, bool> = HashMap::new();

        for event in events {
            if now.duration_since(event.timestamp) > self.window {
                continue;
            }
            if let Some(uid) = event.user_id {
                match event.event_type {
                    EventType::PasswordChange => {
                        pw_changes.insert(uid, true);
                    }
                    EventType::MfaChange | EventType::MfaEnroll => {
                        mfa_changes.insert(uid, true);
                    }
                    _ => {}
                }
            }
        }

        // Users who changed both password and MFA within the window
        for uid in pw_changes.keys() {
            if mfa_changes.contains_key(uid) {
                alerts.push(CorrelationAlert {
                    alert_id: Uuid::new_v4(),
                    rule_id: self.rule_id().to_string(),
                    rule_name: self.rule_name().to_string(),
                    severity: self.default_severity(),
                    description: format!(
                        "Possible account takeover: user {} changed password and MFA within {:?}",
                        uid, self.window
                    ),
                    mitre_technique: self.mitre_technique().to_string(),
                    response_actions: vec![
                        ResponseAction::LockAccount(*uid),
                        ResponseAction::RevokeSessions(*uid),
                        ResponseAction::AlertWebhook("account_takeover_detected".to_string()),
                    ],
                    timestamp: unix_now(),
                    user_id: Some(*uid),
                    source_ip: None,
                    context: HashMap::new(),
                });
            }
        }

        alerts
    }
}

/// Lateral movement: single session accessing >5 different tenants.
pub struct LateralMovementRule {
    pub tenant_threshold: usize,
    pub window: Duration,
}

impl Default for LateralMovementRule {
    fn default() -> Self {
        Self {
            tenant_threshold: 5,
            window: Duration::from_secs(3600),
        }
    }
}

impl CorrelationRule for LateralMovementRule {
    fn rule_id(&self) -> &str {
        "lateral_movement"
    }

    fn rule_name(&self) -> &str {
        "Lateral Movement (Multi-Tenant Access)"
    }

    fn mitre_technique(&self) -> &str {
        "T1021"
    }

    fn default_severity(&self) -> AlertSeverity {
        AlertSeverity::High
    }

    fn window_duration(&self) -> Duration {
        self.window
    }

    fn evaluate(&self, events: &[SecurityEventRecord]) -> Vec<CorrelationAlert> {
        let mut alerts = Vec::new();
        let now = Instant::now();

        // Group tenants accessed by (session_id)
        let mut session_tenants: HashMap<String, Vec<Uuid>> = HashMap::new();
        let mut session_user: HashMap<String, Uuid> = HashMap::new();

        for event in events {
            if now.duration_since(event.timestamp) > self.window {
                continue;
            }
            if let (Some(ref sid), Some(tid)) = (&event.session_id, event.tenant_id) {
                let tenants = session_tenants.entry(sid.clone()).or_default();
                if !tenants.contains(&tid) {
                    tenants.push(tid);
                }
                if let Some(uid) = event.user_id {
                    session_user.entry(sid.clone()).or_insert(uid);
                }
            }
        }

        for (sid, tenants) in session_tenants {
            if tenants.len() > self.tenant_threshold {
                let uid = session_user.get(&sid).copied();
                alerts.push(CorrelationAlert {
                    alert_id: Uuid::new_v4(),
                    rule_id: self.rule_id().to_string(),
                    rule_name: self.rule_name().to_string(),
                    severity: self.default_severity(),
                    description: format!(
                        "Lateral movement: session {} accessed {} tenants",
                        sid,
                        tenants.len()
                    ),
                    mitre_technique: self.mitre_technique().to_string(),
                    response_actions: {
                        let mut actions = vec![ResponseAction::AlertWebhook(
                            "lateral_movement_detected".to_string(),
                        )];
                        if let Some(uid) = uid {
                            actions.push(ResponseAction::RevokeSessions(uid));
                        }
                        actions
                    },
                    timestamp: unix_now(),
                    user_id: uid,
                    source_ip: None,
                    context: {
                        let mut ctx = HashMap::new();
                        ctx.insert("session_id".to_string(), sid.clone());
                        ctx.insert("tenant_count".to_string(), tenants.len().to_string());
                        ctx
                    },
                });
            }
        }

        alerts
    }
}

/// Session anomaly: session activity at unusual hours (>3 sigma from baseline).
pub struct SessionAnomalyRule {
    pub sigma_threshold: f64,
    pub window: Duration,
}

impl Default for SessionAnomalyRule {
    fn default() -> Self {
        Self {
            sigma_threshold: 3.0,
            window: Duration::from_secs(3600),
        }
    }
}

impl CorrelationRule for SessionAnomalyRule {
    fn rule_id(&self) -> &str {
        "session_anomaly"
    }

    fn rule_name(&self) -> &str {
        "Session Activity at Unusual Hours"
    }

    fn mitre_technique(&self) -> &str {
        "T1078"
    }

    fn default_severity(&self) -> AlertSeverity {
        AlertSeverity::Medium
    }

    fn window_duration(&self) -> Duration {
        self.window
    }

    fn evaluate(&self, events: &[SecurityEventRecord]) -> Vec<CorrelationAlert> {
        let mut alerts = Vec::new();
        let now = Instant::now();

        for event in events {
            if now.duration_since(event.timestamp) > self.window {
                continue;
            }
            if event.event_type != EventType::LoginSuccess {
                continue;
            }
            // Check for z-score in the detail map (set by the anomaly detector)
            if let Some(z_str) = event.detail.get("login_hour_z_score") {
                if let Ok(z) = z_str.parse::<f64>() {
                    if z.abs() > self.sigma_threshold {
                        alerts.push(CorrelationAlert {
                            alert_id: Uuid::new_v4(),
                            rule_id: self.rule_id().to_string(),
                            rule_name: self.rule_name().to_string(),
                            severity: self.default_severity(),
                            description: format!(
                                "Session at unusual hour: z-score={:.2} (threshold={:.1})",
                                z, self.sigma_threshold
                            ),
                            mitre_technique: self.mitre_technique().to_string(),
                            response_actions: vec![ResponseAction::LogOnly],
                            timestamp: unix_now(),
                            user_id: event.user_id,
                            source_ip: event.source_ip.clone(),
                            context: {
                                let mut ctx = HashMap::new();
                                ctx.insert("z_score".to_string(), format!("{:.2}", z));
                                ctx
                            },
                        });
                    }
                }
            }
        }

        alerts
    }
}

/// Token replay: same JTI used from different IPs.
pub struct TokenReplayRule {
    pub window: Duration,
}

impl Default for TokenReplayRule {
    fn default() -> Self {
        Self {
            window: Duration::from_secs(3600),
        }
    }
}

impl CorrelationRule for TokenReplayRule {
    fn rule_id(&self) -> &str {
        "token_replay"
    }

    fn rule_name(&self) -> &str {
        "Token Replay (JTI Reuse from Different IP)"
    }

    fn mitre_technique(&self) -> &str {
        "T1550.001"
    }

    fn default_severity(&self) -> AlertSeverity {
        AlertSeverity::Critical
    }

    fn window_duration(&self) -> Duration {
        self.window
    }

    fn evaluate(&self, events: &[SecurityEventRecord]) -> Vec<CorrelationAlert> {
        let mut alerts = Vec::new();
        let now = Instant::now();

        // Group IPs per JTI
        let mut jti_ips: HashMap<String, Vec<String>> = HashMap::new();
        let mut jti_user: HashMap<String, Uuid> = HashMap::new();

        for event in events {
            if event.event_type != EventType::TokenUsed {
                continue;
            }
            if now.duration_since(event.timestamp) > self.window {
                continue;
            }
            if let (Some(ref jti), Some(ref ip)) = (&event.jti, &event.source_ip) {
                let ips = jti_ips.entry(jti.clone()).or_default();
                if !ips.contains(ip) {
                    ips.push(ip.clone());
                }
                if let Some(uid) = event.user_id {
                    jti_user.entry(jti.clone()).or_insert(uid);
                }
            }
        }

        for (jti, ips) in jti_ips {
            if ips.len() > 1 {
                let uid = jti_user.get(&jti).copied();
                alerts.push(CorrelationAlert {
                    alert_id: Uuid::new_v4(),
                    rule_id: self.rule_id().to_string(),
                    rule_name: self.rule_name().to_string(),
                    severity: self.default_severity(),
                    description: format!(
                        "Token replay: JTI {} used from {} different IPs",
                        jti,
                        ips.len()
                    ),
                    mitre_technique: self.mitre_technique().to_string(),
                    response_actions: {
                        let mut actions: Vec<ResponseAction> = ips
                            .iter()
                            .map(|ip| ResponseAction::BlockIp(ip.clone()))
                            .collect();
                        if let Some(uid) = uid {
                            actions.push(ResponseAction::RevokeSessions(uid));
                        }
                        actions
                    },
                    timestamp: unix_now(),
                    user_id: uid,
                    source_ip: None,
                    context: {
                        let mut ctx = HashMap::new();
                        ctx.insert("jti".to_string(), jti.clone());
                        ctx.insert("ip_count".to_string(), ips.len().to_string());
                        ctx
                    },
                });
            }
        }

        alerts
    }
}

/// DDoS pattern: >1000 requests/min from subnet.
pub struct DdosPatternRule {
    pub requests_per_min_threshold: u32,
    pub window: Duration,
}

impl Default for DdosPatternRule {
    fn default() -> Self {
        Self {
            requests_per_min_threshold: 1000,
            window: Duration::from_secs(60),
        }
    }
}

impl CorrelationRule for DdosPatternRule {
    fn rule_id(&self) -> &str {
        "ddos_pattern"
    }

    fn rule_name(&self) -> &str {
        "DDoS Pattern (High Request Rate from Subnet)"
    }

    fn mitre_technique(&self) -> &str {
        "T1498"
    }

    fn default_severity(&self) -> AlertSeverity {
        AlertSeverity::Critical
    }

    fn window_duration(&self) -> Duration {
        self.window
    }

    fn evaluate(&self, events: &[SecurityEventRecord]) -> Vec<CorrelationAlert> {
        let mut alerts = Vec::new();
        let now = Instant::now();

        // Count requests per /24 subnet
        let mut subnet_counts: HashMap<String, u32> = HashMap::new();

        for event in events {
            if now.duration_since(event.timestamp) > self.window {
                continue;
            }
            if let Some(ref ip) = event.source_ip {
                let subnet = ip_to_subnet_24(ip);
                *subnet_counts.entry(subnet).or_insert(0) += 1;
            }
        }

        for (subnet, count) in subnet_counts {
            if count > self.requests_per_min_threshold {
                alerts.push(CorrelationAlert {
                    alert_id: Uuid::new_v4(),
                    rule_id: self.rule_id().to_string(),
                    rule_name: self.rule_name().to_string(),
                    severity: self.default_severity(),
                    description: format!(
                        "DDoS pattern: {} requests from subnet {} in {:?}",
                        count, subnet, self.window
                    ),
                    mitre_technique: self.mitre_technique().to_string(),
                    response_actions: vec![
                        ResponseAction::BlockIp(subnet.clone()),
                        ResponseAction::AlertWebhook("ddos_pattern_detected".to_string()),
                    ],
                    timestamp: unix_now(),
                    user_id: None,
                    source_ip: Some(subnet.clone()),
                    context: {
                        let mut ctx = HashMap::new();
                        ctx.insert("request_count".to_string(), count.to_string());
                        ctx.insert("subnet".to_string(), subnet);
                        ctx
                    },
                });
            }
        }

        alerts
    }
}

// ---------------------------------------------------------------------------
// Rule chaining
// ---------------------------------------------------------------------------

/// Rule chaining configuration: if rule A AND rule B fire within a window,
/// escalate to a higher severity.
#[derive(Debug, Clone)]
pub struct RuleChain {
    /// Rule IDs that must all fire.
    pub required_rules: Vec<String>,
    /// Window within which all rules must fire.
    pub window: Duration,
    /// Escalated severity.
    pub escalated_severity: AlertSeverity,
    /// Description for the escalated alert.
    pub description: String,
}

// ---------------------------------------------------------------------------
// Correlation Engine
// ---------------------------------------------------------------------------

/// The main correlation engine. Thread-safe.
///
/// Maintains a sliding window of security events and evaluates registered
/// rules against them. Supports rule chaining for escalation.
pub struct CorrelationEngine {
    /// Registered correlation rules.
    rules: Vec<Box<dyn CorrelationRule>>,
    /// Event buffer (sliding window). Events older than the max rule window
    /// are pruned on each evaluation.
    events: Mutex<Vec<SecurityEventRecord>>,
    /// Maximum event buffer size (prevents unbounded memory growth).
    max_buffer_size: usize,
    /// Rule chains for escalation.
    chains: Vec<RuleChain>,
    /// Recent alert history for rule chaining (rule_id -> timestamp).
    alert_history: Mutex<HashMap<String, Vec<i64>>>,
}

impl CorrelationEngine {
    /// Create a new correlation engine.
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            events: Mutex::new(Vec::new()),
            max_buffer_size: 100_000,
            chains: Vec::new(),
            alert_history: Mutex::new(HashMap::new()),
        }
    }

    /// Create a new engine with all built-in rules registered.
    pub fn with_default_rules() -> Self {
        let mut engine = Self::new();
        engine.register_rule(Box::new(BruteForceRule::default()));
        engine.register_rule(Box::new(CredentialStuffingRule::default()));
        engine.register_rule(Box::new(ImpossibleTravelRule::default()));
        engine.register_rule(Box::new(PrivilegeEscalationRule::default()));
        engine.register_rule(Box::new(AccountTakeoverRule::default()));
        engine.register_rule(Box::new(LateralMovementRule::default()));
        engine.register_rule(Box::new(SessionAnomalyRule::default()));
        engine.register_rule(Box::new(TokenReplayRule::default()));
        engine.register_rule(Box::new(DdosPatternRule::default()));
        engine
    }

    /// Register a correlation rule.
    pub fn register_rule(&mut self, rule: Box<dyn CorrelationRule>) {
        self.rules.push(rule);
    }

    /// Add a rule chain for escalation.
    pub fn add_chain(&mut self, chain: RuleChain) {
        self.chains.push(chain);
    }

    /// Ingest a security event into the correlation engine.
    pub fn ingest_event(&self, event: SecurityEventRecord) {
        let mut events = self.events.lock().unwrap_or_else(|e| {
                    tracing::warn!(target: "siem", "SIEM:WARNING mutex poisoned in correlation - recovering: thread panicked while holding lock");
                    e.into_inner()
                });

        // Prune if buffer is at capacity
        if events.len() >= self.max_buffer_size {
            // Remove oldest 10%
            let drain_count = self.max_buffer_size / 10;
            events.drain(..drain_count);
        }

        events.push(event);
    }

    /// Evaluate all rules against the current event buffer.
    ///
    /// Returns all alerts that fired. Also checks rule chains for
    /// escalation opportunities and emits SIEM events for each alert.
    pub fn evaluate_all(&self) -> Vec<CorrelationAlert> {
        let events = self.events.lock().unwrap_or_else(|e| {
                    tracing::warn!(target: "siem", "SIEM:WARNING mutex poisoned in correlation - recovering: thread panicked while holding lock");
                    e.into_inner()
                });
        let mut all_alerts = Vec::new();

        for rule in &self.rules {
            let rule_alerts = rule.evaluate(&events);
            for alert in &rule_alerts {
                emit_correlation_siem_event(alert);
            }
            all_alerts.extend(rule_alerts);
        }

        // Record alerts for chain evaluation
        {
            let mut history = self.alert_history.lock().unwrap_or_else(|e| {
                    tracing::warn!(target: "siem", "SIEM:WARNING mutex poisoned in correlation - recovering: thread panicked while holding lock");
                    e.into_inner()
                });
            let now = unix_now();
            for alert in &all_alerts {
                history
                    .entry(alert.rule_id.clone())
                    .or_default()
                    .push(now);
            }

            // Prune old entries (older than 1 hour)
            let cutoff = now - 3600;
            for timestamps in history.values_mut() {
                timestamps.retain(|t| *t > cutoff);
            }
        }

        // Check rule chains
        let chain_alerts = self.evaluate_chains();
        all_alerts.extend(chain_alerts);

        all_alerts
    }

    /// Evaluate rule chains for escalation.
    fn evaluate_chains(&self) -> Vec<CorrelationAlert> {
        let history = self.alert_history.lock().unwrap_or_else(|e| {
                    tracing::warn!(target: "siem", "SIEM:WARNING mutex poisoned in correlation - recovering: thread panicked while holding lock");
                    e.into_inner()
                });
        let now = unix_now();
        let mut alerts = Vec::new();

        for chain in &self.chains {
            let window_secs = chain.window.as_secs() as i64;
            let all_fired = chain.required_rules.iter().all(|rule_id| {
                history.get(rule_id).map_or(false, |timestamps| {
                    timestamps.iter().any(|t| now - *t < window_secs)
                })
            });

            if all_fired {
                let alert = CorrelationAlert {
                    alert_id: Uuid::new_v4(),
                    rule_id: format!("chain_{}", chain.required_rules.join("+")),
                    rule_name: format!("Rule Chain: {}", chain.description),
                    severity: chain.escalated_severity,
                    description: chain.description.clone(),
                    mitre_technique: "TA0001".to_string(), // Initial Access tactic
                    response_actions: vec![ResponseAction::AlertWebhook(
                        "rule_chain_escalation".to_string(),
                    )],
                    timestamp: now,
                    user_id: None,
                    source_ip: None,
                    context: {
                        let mut ctx = HashMap::new();
                        ctx.insert(
                            "chained_rules".to_string(),
                            chain.required_rules.join(", "),
                        );
                        ctx
                    },
                };
                emit_correlation_siem_event(&alert);
                alerts.push(alert);
            }
        }

        alerts
    }

    /// Flush events older than the maximum rule window.
    pub fn flush_stale_events(&self) {
        let max_window = self
            .rules
            .iter()
            .map(|r| r.window_duration())
            .max()
            .unwrap_or(Duration::from_secs(3600));

        let now = Instant::now();
        let mut events = self.events.lock().unwrap_or_else(|e| {
                    tracing::warn!(target: "siem", "SIEM:WARNING mutex poisoned in correlation - recovering: thread panicked while holding lock");
                    e.into_inner()
                });
        events.retain(|e| now.duration_since(e.timestamp) <= max_window);
    }

    /// Get the current event buffer size.
    pub fn event_count(&self) -> usize {
        self.events.lock().unwrap_or_else(|e| {
                    tracing::warn!(target: "siem", "SIEM:WARNING mutex poisoned in correlation - recovering: thread panicked while holding lock");
                    e.into_inner()
                }).len()
    }

    /// Get the number of registered rules.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

impl Default for CorrelationEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Get current Unix timestamp in seconds.
fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Haversine distance in kilometers.
fn haversine_km(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    const R: f64 = 6371.0;
    let d_lat = (lat2 - lat1).to_radians();
    let d_lon = (lon2 - lon1).to_radians();
    let a = (d_lat / 2.0).sin().powi(2)
        + lat1.to_radians().cos() * lat2.to_radians().cos() * (d_lon / 2.0).sin().powi(2);
    let c = 2.0 * a.sqrt().atan2((1.0 - a).sqrt());
    R * c
}

/// Extract /24 subnet from an IPv4 address string.
fn ip_to_subnet_24(ip: &str) -> String {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() == 4 {
        format!("{}.{}.{}.0/24", parts[0], parts[1], parts[2])
    } else {
        ip.to_string() // IPv6 or unparseable: return as-is
    }
}

/// Emit a SIEM event for a correlation alert.
fn emit_correlation_siem_event(alert: &CorrelationAlert) {
    let json = serde_json::json!({
        "event_type": "correlation_alert",
        "timestamp": alert.timestamp,
        "severity": alert.severity.to_string(),
        "source_module": "correlation_engine",
        "details": {
            "alert_id": alert.alert_id.to_string(),
            "rule_id": alert.rule_id,
            "rule_name": alert.rule_name,
            "description": alert.description,
            "mitre_technique": alert.mitre_technique,
            "user_id": alert.user_id.map(|u| u.to_string()),
            "source_ip": alert.source_ip,
        }
    });
    tracing::info!(target: "siem", "{}", json);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_login_failure(ip: &str, user_id: Option<Uuid>) -> SecurityEventRecord {
        SecurityEventRecord {
            event_type: EventType::LoginFailure,
            timestamp: Instant::now(),
            user_id,
            source_ip: Some(ip.to_string()),
            tenant_id: None,
            session_id: None,
            jti: None,
            detail: HashMap::new(),
        }
    }

    fn make_login_success(
        user_id: Uuid,
        ip: &str,
        lat: f64,
        lon: f64,
    ) -> SecurityEventRecord {
        let mut detail = HashMap::new();
        detail.insert("latitude".to_string(), lat.to_string());
        detail.insert("longitude".to_string(), lon.to_string());
        SecurityEventRecord {
            event_type: EventType::LoginSuccess,
            timestamp: Instant::now(),
            user_id: Some(user_id),
            source_ip: Some(ip.to_string()),
            tenant_id: None,
            session_id: None,
            jti: None,
            detail,
        }
    }

    #[test]
    fn test_brute_force_rule() {
        let rule = BruteForceRule {
            threshold: 3,
            window: Duration::from_secs(300),
        };
        let mut events = Vec::new();

        // 5 failures from same IP
        for _ in 0..5 {
            events.push(make_login_failure("192.0.2.1", None));
        }

        let alerts = rule.evaluate(&events);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule_id, "brute_force_login");
        assert_eq!(alerts[0].severity, AlertSeverity::High);
        assert!(alerts[0].source_ip.as_deref() == Some("192.0.2.1"));
    }

    #[test]
    fn test_brute_force_below_threshold() {
        let rule = BruteForceRule {
            threshold: 5,
            window: Duration::from_secs(300),
        };
        let mut events = Vec::new();

        for _ in 0..3 {
            events.push(make_login_failure("192.0.2.1", None));
        }

        let alerts = rule.evaluate(&events);
        assert!(alerts.is_empty());
    }

    #[test]
    fn test_credential_stuffing_rule() {
        let rule = CredentialStuffingRule {
            threshold: 3,
            window: Duration::from_secs(600),
        };
        let mut events = Vec::new();

        // 5 different users from same IP
        for _ in 0..5 {
            events.push(make_login_failure("192.0.2.1", Some(Uuid::new_v4())));
        }

        let alerts = rule.evaluate(&events);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule_id, "credential_stuffing");
        assert_eq!(alerts[0].severity, AlertSeverity::Critical);
    }

    #[test]
    fn test_account_takeover_rule() {
        let rule = AccountTakeoverRule::default();
        let uid = Uuid::new_v4();

        let events = vec![
            SecurityEventRecord {
                event_type: EventType::PasswordChange,
                timestamp: Instant::now(),
                user_id: Some(uid),
                source_ip: None,
                tenant_id: None,
                session_id: None,
                jti: None,
                detail: HashMap::new(),
            },
            SecurityEventRecord {
                event_type: EventType::MfaChange,
                timestamp: Instant::now(),
                user_id: Some(uid),
                source_ip: None,
                tenant_id: None,
                session_id: None,
                jti: None,
                detail: HashMap::new(),
            },
        ];

        let alerts = rule.evaluate(&events);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule_id, "account_takeover");
        assert!(alerts[0].user_id == Some(uid));
    }

    #[test]
    fn test_token_replay_rule() {
        let rule = TokenReplayRule::default();

        let events = vec![
            SecurityEventRecord {
                event_type: EventType::TokenUsed,
                timestamp: Instant::now(),
                user_id: Some(Uuid::new_v4()),
                source_ip: Some("192.0.2.1".to_string()),
                tenant_id: None,
                session_id: None,
                jti: Some("jti-abc-123".to_string()),
                detail: HashMap::new(),
            },
            SecurityEventRecord {
                event_type: EventType::TokenUsed,
                timestamp: Instant::now(),
                user_id: Some(Uuid::new_v4()),
                source_ip: Some("198.51.100.1".to_string()),
                tenant_id: None,
                session_id: None,
                jti: Some("jti-abc-123".to_string()),
                detail: HashMap::new(),
            },
        ];

        let alerts = rule.evaluate(&events);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule_id, "token_replay");
    }

    #[test]
    fn test_ddos_pattern_rule() {
        let rule = DdosPatternRule {
            requests_per_min_threshold: 5,
            window: Duration::from_secs(60),
        };

        let mut events = Vec::new();
        for i in 0..10 {
            events.push(SecurityEventRecord {
                event_type: EventType::ApiRequest,
                timestamp: Instant::now(),
                user_id: None,
                source_ip: Some(format!("192.0.2.{}", i % 3 + 1)),
                tenant_id: None,
                session_id: None,
                jti: None,
                detail: HashMap::new(),
            });
        }

        let alerts = rule.evaluate(&events);
        // All IPs are in the 192.0.2.0/24 subnet, 10 > threshold of 5
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule_id, "ddos_pattern");
    }

    #[test]
    fn test_lateral_movement_rule() {
        let rule = LateralMovementRule {
            tenant_threshold: 2,
            window: Duration::from_secs(3600),
        };
        let uid = Uuid::new_v4();

        let events: Vec<SecurityEventRecord> = (0..4)
            .map(|_| SecurityEventRecord {
                event_type: EventType::ResourceAccess,
                timestamp: Instant::now(),
                user_id: Some(uid),
                source_ip: None,
                tenant_id: Some(Uuid::new_v4()), // different tenant each time
                session_id: Some("session-xyz".to_string()),
                jti: None,
                detail: HashMap::new(),
            })
            .collect();

        let alerts = rule.evaluate(&events);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule_id, "lateral_movement");
    }

    #[test]
    fn test_correlation_engine_ingest_and_evaluate() {
        let mut engine = CorrelationEngine::new();
        engine.register_rule(Box::new(BruteForceRule {
            threshold: 2,
            window: Duration::from_secs(300),
        }));

        // Ingest 5 login failures
        for _ in 0..5 {
            engine.ingest_event(make_login_failure("10.0.0.1", None));
        }

        let alerts = engine.evaluate_all();
        assert!(!alerts.is_empty());
        assert_eq!(engine.event_count(), 5);
    }

    #[test]
    fn test_correlation_engine_with_default_rules() {
        let engine = CorrelationEngine::with_default_rules();
        assert_eq!(engine.rule_count(), 9);
    }

    #[test]
    fn test_rule_chaining() {
        let mut engine = CorrelationEngine::new();
        engine.register_rule(Box::new(BruteForceRule {
            threshold: 2,
            window: Duration::from_secs(300),
        }));
        engine.register_rule(Box::new(CredentialStuffingRule {
            threshold: 2,
            window: Duration::from_secs(600),
        }));

        engine.add_chain(RuleChain {
            required_rules: vec![
                "brute_force_login".to_string(),
                "credential_stuffing".to_string(),
            ],
            window: Duration::from_secs(600),
            escalated_severity: AlertSeverity::Critical,
            description: "Combined brute force + credential stuffing attack".to_string(),
        });

        // Generate events that trigger both rules
        for _ in 0..5 {
            engine.ingest_event(make_login_failure("10.0.0.1", Some(Uuid::new_v4())));
        }

        let alerts = engine.evaluate_all();
        // Should have brute_force + credential_stuffing + chain escalation
        let chain_alerts: Vec<_> = alerts
            .iter()
            .filter(|a| a.rule_id.starts_with("chain_"))
            .collect();
        assert!(
            !chain_alerts.is_empty(),
            "Rule chain should fire when both constituent rules fire"
        );
        assert_eq!(chain_alerts[0].severity, AlertSeverity::Critical);
    }

    #[test]
    fn test_flush_stale_events() {
        let mut engine = CorrelationEngine::new();
        engine.register_rule(Box::new(BruteForceRule {
            threshold: 100,
            window: Duration::from_secs(1), // 1 second window
        }));

        engine.ingest_event(make_login_failure("10.0.0.1", None));
        assert_eq!(engine.event_count(), 1);

        // After sleeping 0ms, events are still fresh
        engine.flush_stale_events();
        // Events should still be present (they're within the 1s window)
        // The flush is based on Instant::now() comparison
    }

    #[test]
    fn test_ip_to_subnet_24() {
        assert_eq!(ip_to_subnet_24("192.168.1.100"), "192.168.1.0/24");
        assert_eq!(ip_to_subnet_24("10.0.0.1"), "10.0.0.0/24");
        // Non-IPv4 returned as-is
        assert_eq!(ip_to_subnet_24("::1"), "::1");
    }

    #[test]
    fn test_haversine_km_consistency() {
        // NY to London
        let dist = haversine_km(40.7128, -74.0060, 51.5074, -0.1278);
        assert!(dist > 5500.0 && dist < 5650.0, "Distance was {}", dist);
    }

    #[test]
    fn test_alert_severity_ordering() {
        assert!(AlertSeverity::Low < AlertSeverity::Medium);
        assert!(AlertSeverity::Medium < AlertSeverity::High);
        assert!(AlertSeverity::High < AlertSeverity::Critical);
    }
}
