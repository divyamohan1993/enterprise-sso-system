//! Continuous Access Evaluation (CAE) for the MILNET SSO system.
//!
//! Re-evaluates access policies mid-session based on real-time signal changes.
//! Triggers include: risk score change, device compliance change, user role
//! change, IP change, geo change, and time-based re-evaluation.
//!
//! Actions: force step-up auth, revoke session, reduce permissions, require
//! MFA re-verification.
//!
//! Sessions must send heartbeats at a configurable interval (default 60s).
//! Missed heartbeats mark the session as stale and require re-authentication.
//!
//! Per-tier evaluation frequency:
//! - Tier 1 (Sovereign): 30s
//! - Tier 2 (Operational): 60s
//! - Tier 3 (Sensor): 120s
//! - Tier 4 (Emergency): 30s
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use uuid::Uuid;

use crate::conditional_access::{AccessContext, PolicyAction, PolicyEngine};
use crate::siem::{SecurityEvent, Severity};
use crate::types::DeviceTier;

// ── CAE Configuration ────────────────────────────────────────────────

/// Configuration for the Continuous Access Evaluator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaeConfig {
    /// Heartbeat interval per tier in seconds: [Tier1, Tier2, Tier3, Tier4].
    pub heartbeat_interval_by_tier: [u64; 4],
    /// Evaluation frequency per tier in seconds: [Tier1, Tier2, Tier3, Tier4].
    pub eval_frequency_by_tier: [u64; 4],
    /// Grace period (seconds) after a missed heartbeat before marking stale.
    pub heartbeat_grace_secs: u64,
    /// Risk score delta that triggers immediate re-evaluation.
    pub risk_delta_threshold: f64,
    /// Maximum number of tracked sessions (memory cap).
    pub max_tracked_sessions: usize,
}

impl Default for CaeConfig {
    fn default() -> Self {
        Self {
            heartbeat_interval_by_tier: [30, 60, 120, 30],
            eval_frequency_by_tier: [30, 60, 120, 30],
            heartbeat_grace_secs: 10,
            risk_delta_threshold: 0.15,
            max_tracked_sessions: 100_000,
        }
    }
}

// ── CAE Trigger Types ────────────────────────────────────────────────

/// The type of change that triggered a CAE re-evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CaeTrigger {
    /// Risk score changed beyond the configured delta threshold.
    RiskScoreChange,
    /// Device compliance status changed (e.g. failed attestation).
    DeviceComplianceChange,
    /// User role or group membership changed.
    UserRoleChange,
    /// Client IP address changed mid-session.
    IpChange,
    /// Geolocation (country code) changed mid-session.
    GeoChange,
    /// Periodic time-based re-evaluation.
    TimeBased,
    /// Session heartbeat was missed (stale session).
    HeartbeatMissed,
    /// Manual re-evaluation requested by an administrator.
    AdminForced,
}

impl std::fmt::Display for CaeTrigger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RiskScoreChange => write!(f, "risk_score_change"),
            Self::DeviceComplianceChange => write!(f, "device_compliance_change"),
            Self::UserRoleChange => write!(f, "user_role_change"),
            Self::IpChange => write!(f, "ip_change"),
            Self::GeoChange => write!(f, "geo_change"),
            Self::TimeBased => write!(f, "time_based"),
            Self::HeartbeatMissed => write!(f, "heartbeat_missed"),
            Self::AdminForced => write!(f, "admin_forced"),
        }
    }
}

// ── CAE Action ───────────────────────────────────────────────────────

/// Action to enforce as a result of continuous access evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CaeAction {
    /// Continue — no change required.
    Continue,
    /// Force step-up authentication (e.g. CAC/PIV re-tap).
    ForceStepUp,
    /// Require MFA re-verification.
    RequireMfaReverification,
    /// Reduce session permissions to the given scope bitmask.
    ReducePermissions { new_scope: u32 },
    /// Revoke the session immediately.
    RevokeSession,
}

impl std::fmt::Display for CaeAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Continue => write!(f, "continue"),
            Self::ForceStepUp => write!(f, "force_step_up"),
            Self::RequireMfaReverification => write!(f, "require_mfa_reverification"),
            Self::ReducePermissions { new_scope } => {
                write!(f, "reduce_permissions(scope=0x{:08x})", new_scope)
            }
            Self::RevokeSession => write!(f, "revoke_session"),
        }
    }
}

// ── CAE Decision ─────────────────────────────────────────────────────

/// Result of a continuous access evaluation cycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaeDecision {
    /// Session that was evaluated.
    pub session_id: Uuid,
    /// User who owns the session.
    pub user_id: Uuid,
    /// What triggered this evaluation.
    pub trigger: CaeTrigger,
    /// The action to enforce.
    pub action: CaeAction,
    /// Human-readable reason for the decision.
    pub reason: String,
    /// Unix timestamp (seconds) of the evaluation.
    pub evaluated_at: i64,
}

// ── Session Signals ──────────────────────────────────────────────────

/// Snapshot of real-time signals for a tracked session.
///
/// Updated by heartbeats and external signal feeds (risk engine, GeoIP, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSignals {
    /// Current risk score (0.0 - 1.0).
    pub risk_score: f64,
    /// Previous risk score (for delta comparison).
    pub previous_risk_score: f64,
    /// Whether the device is currently compliant.
    pub device_compliant: bool,
    /// Current source IP.
    pub source_ip: Option<IpAddr>,
    /// Previous source IP (for change detection).
    pub previous_ip: Option<IpAddr>,
    /// Current country code (ISO 3166-1 alpha-2).
    pub country_code: Option<String>,
    /// Previous country code.
    pub previous_country_code: Option<String>,
    /// Current user groups/roles (for change detection).
    pub user_groups: Vec<String>,
    /// Previous user groups/roles.
    pub previous_user_groups: Vec<String>,
}

impl Default for SessionSignals {
    fn default() -> Self {
        Self {
            risk_score: 0.0,
            previous_risk_score: 0.0,
            device_compliant: true,
            source_ip: None,
            previous_ip: None,
            country_code: None,
            previous_country_code: None,
            user_groups: Vec::new(),
            previous_user_groups: Vec::new(),
        }
    }
}

// ── Tracked Session ──────────────────────────────────────────────────

/// Internal tracking state for a session under continuous evaluation.
#[derive(Debug, Clone)]
struct TrackedSession {
    /// Session identifier.
    session_id: Uuid,
    /// User identifier.
    user_id: Uuid,
    /// Device tier (determines eval frequency and heartbeat interval).
    tier: u8,
    /// Last heartbeat received (unix seconds).
    last_heartbeat: i64,
    /// Last full evaluation time (unix seconds).
    last_evaluation: i64,
    /// Current real-time signals.
    signals: SessionSignals,
    /// Whether the session has been marked stale (missed heartbeat).
    stale: bool,
    /// Whether the session has been revoked by CAE.
    revoked: bool,
}

// ── Continuous Access Evaluator ──────────────────────────────────────

/// The Continuous Access Evaluator.
///
/// Tracks active sessions, receives signal updates and heartbeats, and
/// re-evaluates access policies mid-session. Integrates with the
/// [`PolicyEngine`] from `conditional_access.rs` for policy decisions
/// and emits SIEM events for all CAE actions.
pub struct ContinuousAccessEvaluator {
    /// Configuration.
    config: CaeConfig,
    /// Tracked sessions indexed by session_id.
    sessions: HashMap<Uuid, TrackedSession>,
    /// Reference to the conditional access policy engine.
    policy_engine: PolicyEngine,
    /// Current unix timestamp provider (overridable for testing).
    pub now_fn: fn() -> i64,
}

/// Returns the current Unix timestamp in seconds.
fn system_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

impl ContinuousAccessEvaluator {
    /// Create a new evaluator with the given config and policy engine.
    pub fn new(config: CaeConfig, policy_engine: PolicyEngine) -> Self {
        Self {
            config,
            sessions: HashMap::new(),
            policy_engine,
            now_fn: system_now,
        }
    }

    /// Create an evaluator with a custom clock (for testing).
    pub fn with_clock(config: CaeConfig, policy_engine: PolicyEngine, now_fn: fn() -> i64) -> Self {
        Self {
            config,
            sessions: HashMap::new(),
            policy_engine,
            now_fn,
        }
    }

    /// Returns the current timestamp from the configured clock.
    fn now(&self) -> i64 {
        (self.now_fn)()
    }

    /// Start tracking a session for continuous access evaluation.
    ///
    /// Returns `Err` if the session capacity limit has been reached.
    pub fn track_session(
        &mut self,
        session_id: Uuid,
        user_id: Uuid,
        tier: u8,
        initial_signals: SessionSignals,
    ) -> Result<(), String> {
        if self.sessions.len() >= self.config.max_tracked_sessions {
            crate::siem::SecurityEvent::capacity_warning(
                "cae",
                self.sessions.len(),
                self.config.max_tracked_sessions,
            );
            return Err(format!(
                "CAE session tracking limit reached ({}/{})",
                self.sessions.len(),
                self.config.max_tracked_sessions
            ));
        }

        let now = self.now();
        self.sessions.insert(
            session_id,
            TrackedSession {
                session_id,
                user_id,
                tier,
                last_heartbeat: now,
                last_evaluation: now,
                signals: initial_signals,
                stale: false,
                revoked: false,
            },
        );

        emit_cae_siem_event(
            "cae_session_tracked",
            Severity::Info,
            "success",
            Some(user_id),
            Some(format!("session_id={} tier={}", session_id, tier)),
        );

        Ok(())
    }

    /// Stop tracking a session (e.g. on normal logout).
    pub fn untrack_session(&mut self, session_id: &Uuid) -> bool {
        self.sessions.remove(session_id).is_some()
    }

    /// Record a heartbeat from a session.
    ///
    /// Returns the current CAE decision (which may be `Continue` if all is well).
    pub fn heartbeat(
        &mut self,
        session_id: &Uuid,
        updated_signals: SessionSignals,
    ) -> Result<CaeDecision, String> {
        let now = self.now();
        let session = self
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| format!("session {} not tracked", session_id))?;

        if session.revoked {
            return Ok(CaeDecision {
                session_id: session.session_id,
                user_id: session.user_id,
                trigger: CaeTrigger::HeartbeatMissed,
                action: CaeAction::RevokeSession,
                reason: "session already revoked by CAE".to_string(),
                evaluated_at: now,
            });
        }

        // Update heartbeat timestamp
        session.last_heartbeat = now;
        session.stale = false;

        // Detect signal changes and determine triggers
        let triggers = detect_triggers(session, &updated_signals, &self.config);

        // Update signals (shift current → previous)
        session.signals.previous_risk_score = session.signals.risk_score;
        session.signals.previous_ip = session.signals.source_ip;
        session.signals.previous_country_code = session.signals.country_code.clone();
        session.signals.previous_user_groups = session.signals.user_groups.clone();

        session.signals.risk_score = updated_signals.risk_score;
        session.signals.device_compliant = updated_signals.device_compliant;
        session.signals.source_ip = updated_signals.source_ip;
        session.signals.country_code = updated_signals.country_code;
        session.signals.user_groups = updated_signals.user_groups;

        // If any trigger fired, re-evaluate
        if let Some(trigger) = triggers.into_iter().next() {
            let decision = self.evaluate_session_internal(session_id, trigger)?;
            return Ok(decision);
        }

        // Check if periodic re-evaluation is due
        let tier_idx = (session.tier.saturating_sub(1) as usize).min(3);
        let eval_freq = self.config.eval_frequency_by_tier[tier_idx] as i64;
        if now - session.last_evaluation >= eval_freq {
            let decision =
                self.evaluate_session_internal(session_id, CaeTrigger::TimeBased)?;
            return Ok(decision);
        }

        // No trigger, no periodic re-eval needed
        Ok(CaeDecision {
            session_id: *session_id,
            user_id: self.sessions[session_id].user_id,
            trigger: CaeTrigger::TimeBased,
            action: CaeAction::Continue,
            reason: "heartbeat received, no re-evaluation needed".to_string(),
            evaluated_at: now,
        })
    }

    /// Force a re-evaluation of a specific session (e.g. admin-triggered).
    pub fn force_evaluate(
        &mut self,
        session_id: &Uuid,
    ) -> Result<CaeDecision, String> {
        self.evaluate_session_internal(session_id, CaeTrigger::AdminForced)
    }

    /// Check all tracked sessions for missed heartbeats.
    ///
    /// Returns a list of CAE decisions for sessions that have gone stale.
    /// Call this periodically (e.g. every 10 seconds).
    pub fn check_heartbeats(&mut self) -> Vec<CaeDecision> {
        let now = self.now();
        let config = &self.config;
        let mut stale_sessions = Vec::new();

        for session in self.sessions.values_mut() {
            if session.revoked || session.stale {
                continue;
            }

            let tier_idx = (session.tier.saturating_sub(1) as usize).min(3);
            let heartbeat_interval = config.heartbeat_interval_by_tier[tier_idx] as i64;
            let grace = config.heartbeat_grace_secs as i64;
            let deadline = heartbeat_interval + grace;

            if now - session.last_heartbeat > deadline {
                session.stale = true;
                stale_sessions.push((session.session_id, session.user_id));
            }
        }

        let mut decisions = Vec::new();
        for (session_id, user_id) in stale_sessions {
            let decision = CaeDecision {
                session_id,
                user_id,
                trigger: CaeTrigger::HeartbeatMissed,
                action: CaeAction::RevokeSession,
                reason: "heartbeat missed — session marked stale, re-authentication required"
                    .to_string(),
                evaluated_at: now,
            };

            emit_cae_siem_event(
                "cae_heartbeat_missed",
                Severity::High,
                "failure",
                Some(user_id),
                Some(format!("session_id={}", session_id)),
            );

            decisions.push(decision);
        }

        decisions
    }

    /// Get the number of currently tracked sessions.
    pub fn tracked_count(&self) -> usize {
        self.sessions.len()
    }

    /// Get the number of active (non-stale, non-revoked) sessions.
    pub fn active_count(&self) -> usize {
        self.sessions
            .values()
            .filter(|s| !s.stale && !s.revoked)
            .count()
    }

    /// Check if a specific session is stale (missed heartbeat).
    pub fn is_stale(&self, session_id: &Uuid) -> Option<bool> {
        self.sessions.get(session_id).map(|s| s.stale)
    }

    /// Check if a specific session has been revoked by CAE.
    pub fn is_revoked(&self, session_id: &Uuid) -> Option<bool> {
        self.sessions.get(session_id).map(|s| s.revoked)
    }

    /// Update the policy engine (e.g. after a policy change).
    pub fn update_policy_engine(&mut self, engine: PolicyEngine) {
        self.policy_engine = engine;
    }

    /// Internal: evaluate a session against the policy engine and determine
    /// the appropriate CAE action.
    fn evaluate_session_internal(
        &mut self,
        session_id: &Uuid,
        trigger: CaeTrigger,
    ) -> Result<CaeDecision, String> {
        let now = self.now();
        let session = self
            .sessions
            .get(session_id)
            .ok_or_else(|| format!("session {} not tracked", session_id))?;

        let user_id = session.user_id;
        let signals = &session.signals;

        // Build an AccessContext from the current session signals
        let mut user_attributes = std::collections::HashMap::new();
        if !signals.user_groups.is_empty() {
            user_attributes.insert("group".to_string(), signals.user_groups.clone());
        }

        let ctx = AccessContext {
            source_ip: signals.source_ip,
            country_code: signals.country_code.clone(),
            current_hour: None, // will be filled by caller or use system time
            current_day: None,
            device_tier: Some(match session.tier {
                1 => DeviceTier::Sovereign,
                2 => DeviceTier::Operational,
                3 => DeviceTier::Sensor,
                _ => DeviceTier::Emergency,
            }),
            risk_score: Some(signals.risk_score),
            classification: None,
            user_attributes,
            auth_strength: None,
        };

        // Evaluate policy
        let policy_decision = self.policy_engine.evaluate(&ctx);

        // Map policy decision to CAE action
        let cae_action = match &trigger {
            CaeTrigger::HeartbeatMissed => CaeAction::RevokeSession,
            _ => match policy_decision.action {
                PolicyAction::Deny | PolicyAction::Block => CaeAction::RevokeSession,
                PolicyAction::RequireStepUp => CaeAction::ForceStepUp,
                PolicyAction::RequireMFA => CaeAction::RequireMfaReverification,
                PolicyAction::RequireApproval => CaeAction::ForceStepUp,
                PolicyAction::Allow => {
                    // Even with Allow, check for device compliance
                    if !signals.device_compliant {
                        CaeAction::ForceStepUp
                    } else if signals.risk_score >= 0.8 {
                        CaeAction::RevokeSession
                    } else if signals.risk_score >= 0.6 {
                        CaeAction::RequireMfaReverification
                    } else if signals.risk_score >= 0.3 {
                        CaeAction::ForceStepUp
                    } else {
                        CaeAction::Continue
                    }
                }
            },
        };

        let reason = format!(
            "trigger={} policy_rule={} policy_action={:?} risk={:.3} device_compliant={} cae_action={}",
            trigger, policy_decision.matched_rule, policy_decision.action,
            signals.risk_score, signals.device_compliant, cae_action
        );

        // Mark session as revoked if action is RevokeSession
        if cae_action == CaeAction::RevokeSession {
            if let Some(s) = self.sessions.get_mut(session_id) {
                s.revoked = true;
            }
        }

        // Update last evaluation time
        if let Some(s) = self.sessions.get_mut(session_id) {
            s.last_evaluation = now;
        }

        let severity = match &cae_action {
            CaeAction::Continue => Severity::Info,
            CaeAction::ForceStepUp => Severity::Notice,
            CaeAction::RequireMfaReverification => Severity::Warning,
            CaeAction::ReducePermissions { .. } => Severity::Warning,
            CaeAction::RevokeSession => Severity::High,
        };

        emit_cae_siem_event(
            "cae_evaluation",
            severity,
            match &cae_action {
                CaeAction::Continue => "success",
                _ => "action_required",
            },
            Some(user_id),
            Some(reason.clone()),
        );

        Ok(CaeDecision {
            session_id: *session_id,
            user_id,
            trigger,
            action: cae_action,
            reason,
            evaluated_at: now,
        })
    }
}

// ── Trigger Detection ────────────────────────────────────────────────

/// Detect which triggers have fired based on signal changes.
fn detect_triggers(
    session: &TrackedSession,
    new_signals: &SessionSignals,
    config: &CaeConfig,
) -> Vec<CaeTrigger> {
    let mut triggers = Vec::new();
    let old = &session.signals;

    // Risk score delta
    let delta = (new_signals.risk_score - old.risk_score).abs();
    if delta >= config.risk_delta_threshold {
        triggers.push(CaeTrigger::RiskScoreChange);
    }

    // Device compliance change
    if new_signals.device_compliant != old.device_compliant {
        triggers.push(CaeTrigger::DeviceComplianceChange);
    }

    // IP change
    if new_signals.source_ip.is_some()
        && old.source_ip.is_some()
        && new_signals.source_ip != old.source_ip
    {
        triggers.push(CaeTrigger::IpChange);
    }

    // Geo change
    if new_signals.country_code.is_some()
        && old.country_code.is_some()
        && new_signals.country_code != old.country_code
    {
        triggers.push(CaeTrigger::GeoChange);
    }

    // User role change
    if new_signals.user_groups != old.user_groups {
        triggers.push(CaeTrigger::UserRoleChange);
    }

    triggers
}

// ── SIEM Helper ──────────────────────────────────────────────────────

/// Emit a SIEM event for CAE decisions (mirrors the pattern from idm.rs).
fn emit_cae_siem_event(
    action: &'static str,
    severity: Severity,
    outcome: &'static str,
    user_id: Option<Uuid>,
    detail: Option<String>,
) {
    let event = SecurityEvent {
        timestamp: SecurityEvent::now_iso8601(),
        category: "continuous_access_evaluation",
        action,
        severity,
        outcome,
        user_id,
        source_ip: None,
        detail,
    };
    let json = event.to_json();
    tracing::info!(target: "siem", "{}", json);

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let siem_event = crate::siem::SiemEvent {
        timestamp,
        severity: severity as u8,
        event_type: action.to_string(),
        json,
    };
    crate::siem::broadcast_event(&siem_event);
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conditional_access::{
        Condition, PolicyRule, RiskThresholds,
    };

    fn test_now() -> i64 {
        1_000_000
    }

    fn make_evaluator() -> ContinuousAccessEvaluator {
        let engine = PolicyEngine::new(vec![
            PolicyRule {
                name: "allow-low-risk".to_string(),
                description: Some("Allow when risk is low".to_string()),
                condition: Condition::RiskScore(RiskThresholds {
                    allow_below: 0.3,
                    challenge_above: 0.6,
                    block_above: 0.8,
                }),
                action: PolicyAction::Allow,
                enabled: true,
            },
            PolicyRule {
                name: "challenge-medium-risk".to_string(),
                description: Some("Require MFA for medium risk".to_string()),
                condition: Condition::RiskScore(RiskThresholds {
                    allow_below: 0.6,
                    challenge_above: 0.3,
                    block_above: 0.8,
                }),
                action: PolicyAction::RequireMFA,
                enabled: true,
            },
        ]);
        ContinuousAccessEvaluator::with_clock(CaeConfig::default(), engine, test_now)
    }

    fn default_signals() -> SessionSignals {
        SessionSignals {
            risk_score: 0.1,
            previous_risk_score: 0.1,
            device_compliant: true,
            source_ip: Some("10.0.0.1".parse().unwrap()),
            previous_ip: Some("10.0.0.1".parse().unwrap()),
            country_code: Some("US".to_string()),
            previous_country_code: Some("US".to_string()),
            user_groups: vec!["ops-team".to_string()],
            previous_user_groups: vec!["ops-team".to_string()],
        }
    }

    #[test]
    fn track_and_heartbeat_low_risk() {
        let mut cae = make_evaluator();
        let sid = Uuid::new_v4();
        let uid = Uuid::new_v4();

        cae.track_session(sid, uid, 2, default_signals()).unwrap();
        assert_eq!(cae.tracked_count(), 1);
        assert_eq!(cae.active_count(), 1);

        let decision = cae.heartbeat(&sid, default_signals()).unwrap();
        assert_eq!(decision.action, CaeAction::Continue);
    }

    #[test]
    fn risk_score_spike_triggers_mfa() {
        let mut cae = make_evaluator();
        let sid = Uuid::new_v4();
        let uid = Uuid::new_v4();

        cae.track_session(sid, uid, 2, default_signals()).unwrap();

        // Spike risk to 0.5 (above delta threshold of 0.15)
        let mut new_signals = default_signals();
        new_signals.risk_score = 0.5;

        let decision = cae.heartbeat(&sid, new_signals).unwrap();
        // The policy engine will hit the "challenge-medium-risk" rule which
        // returns RequireMFA, which maps to RequireMfaReverification
        assert_eq!(decision.action, CaeAction::RequireMfaReverification);
        assert_eq!(decision.trigger, CaeTrigger::RiskScoreChange);
    }

    #[test]
    fn ip_change_triggers_reevaluation() {
        let mut cae = make_evaluator();
        let sid = Uuid::new_v4();
        let uid = Uuid::new_v4();

        cae.track_session(sid, uid, 1, default_signals()).unwrap();

        let mut new_signals = default_signals();
        new_signals.source_ip = Some("192.168.1.100".parse().unwrap());

        let decision = cae.heartbeat(&sid, new_signals).unwrap();
        assert_eq!(decision.trigger, CaeTrigger::IpChange);
    }

    #[test]
    fn device_compliance_change_triggers_reevaluation() {
        let mut cae = make_evaluator();
        let sid = Uuid::new_v4();
        let uid = Uuid::new_v4();

        cae.track_session(sid, uid, 2, default_signals()).unwrap();

        let mut new_signals = default_signals();
        new_signals.device_compliant = false;

        let decision = cae.heartbeat(&sid, new_signals).unwrap();
        assert_eq!(decision.trigger, CaeTrigger::DeviceComplianceChange);
        // Non-compliant device should force step-up even with low risk
        assert_eq!(decision.action, CaeAction::ForceStepUp);
    }

    #[test]
    fn geo_change_triggers_reevaluation() {
        let mut cae = make_evaluator();
        let sid = Uuid::new_v4();
        let uid = Uuid::new_v4();

        cae.track_session(sid, uid, 2, default_signals()).unwrap();

        let mut new_signals = default_signals();
        new_signals.country_code = Some("RU".to_string());

        let decision = cae.heartbeat(&sid, new_signals).unwrap();
        assert_eq!(decision.trigger, CaeTrigger::GeoChange);
    }

    #[test]
    fn user_role_change_triggers_reevaluation() {
        let mut cae = make_evaluator();
        let sid = Uuid::new_v4();
        let uid = Uuid::new_v4();

        cae.track_session(sid, uid, 2, default_signals()).unwrap();

        let mut new_signals = default_signals();
        new_signals.user_groups = vec!["admin".to_string()];

        let decision = cae.heartbeat(&sid, new_signals).unwrap();
        assert_eq!(decision.trigger, CaeTrigger::UserRoleChange);
    }

    #[test]
    fn missed_heartbeat_marks_stale() {
        let config = CaeConfig {
            heartbeat_interval_by_tier: [30, 60, 120, 30],
            heartbeat_grace_secs: 10,
            ..CaeConfig::default()
        };

        // Use a clock that returns a time well past the heartbeat deadline
        fn late_now() -> i64 {
            1_000_200 // 200 seconds after session was tracked at 1_000_000
        }

        let engine = PolicyEngine::empty();
        let mut cae = ContinuousAccessEvaluator::with_clock(config, engine, late_now);

        let sid = Uuid::new_v4();
        let uid = Uuid::new_v4();

        // Track at "early" time by temporarily using the base clock
        cae.now_fn = test_now;
        cae.track_session(sid, uid, 2, default_signals()).unwrap();
        cae.now_fn = late_now; // switch to late clock

        let stale_decisions = cae.check_heartbeats();
        assert_eq!(stale_decisions.len(), 1);
        assert_eq!(stale_decisions[0].action, CaeAction::RevokeSession);
        assert_eq!(stale_decisions[0].trigger, CaeTrigger::HeartbeatMissed);

        assert_eq!(cae.is_stale(&sid), Some(true));
    }

    #[test]
    fn capacity_limit_enforcement() {
        let config = CaeConfig {
            max_tracked_sessions: 2,
            ..CaeConfig::default()
        };
        let engine = PolicyEngine::empty();
        let mut cae = ContinuousAccessEvaluator::with_clock(config, engine, test_now);

        let uid = Uuid::new_v4();
        cae.track_session(Uuid::new_v4(), uid, 2, default_signals())
            .unwrap();
        cae.track_session(Uuid::new_v4(), uid, 2, default_signals())
            .unwrap();

        // Third should fail
        let result = cae.track_session(Uuid::new_v4(), uid, 2, default_signals());
        assert!(result.is_err());
    }

    #[test]
    fn untrack_session_removes_it() {
        let mut cae = make_evaluator();
        let sid = Uuid::new_v4();
        let uid = Uuid::new_v4();

        cae.track_session(sid, uid, 2, default_signals()).unwrap();
        assert_eq!(cae.tracked_count(), 1);

        assert!(cae.untrack_session(&sid));
        assert_eq!(cae.tracked_count(), 0);

        // Untracking a non-existent session returns false
        assert!(!cae.untrack_session(&Uuid::new_v4()));
    }

    #[test]
    fn force_evaluate_admin_trigger() {
        let mut cae = make_evaluator();
        let sid = Uuid::new_v4();
        let uid = Uuid::new_v4();

        cae.track_session(sid, uid, 2, default_signals()).unwrap();

        let decision = cae.force_evaluate(&sid).unwrap();
        assert_eq!(decision.trigger, CaeTrigger::AdminForced);
    }

    #[test]
    fn revoked_session_stays_revoked() {
        let mut cae = make_evaluator();
        let sid = Uuid::new_v4();
        let uid = Uuid::new_v4();

        cae.track_session(sid, uid, 2, default_signals()).unwrap();

        // Spike risk to critical to get revocation
        let mut high_risk = default_signals();
        high_risk.risk_score = 0.9;

        let decision = cae.heartbeat(&sid, high_risk).unwrap();
        assert_eq!(decision.action, CaeAction::RevokeSession);
        assert_eq!(cae.is_revoked(&sid), Some(true));

        // Subsequent heartbeat should still return revoked
        let decision2 = cae.heartbeat(&sid, default_signals()).unwrap();
        assert_eq!(decision2.action, CaeAction::RevokeSession);
    }

    #[test]
    fn tier_specific_heartbeat_intervals() {
        let config = CaeConfig::default();
        assert_eq!(config.heartbeat_interval_by_tier[0], 30); // Tier 1: Sovereign
        assert_eq!(config.heartbeat_interval_by_tier[1], 60); // Tier 2: Operational
        assert_eq!(config.heartbeat_interval_by_tier[2], 120); // Tier 3: Sensor
        assert_eq!(config.heartbeat_interval_by_tier[3], 30); // Tier 4: Emergency
    }

    #[test]
    fn tier_specific_eval_frequency() {
        let config = CaeConfig::default();
        assert_eq!(config.eval_frequency_by_tier[0], 30); // Tier 1
        assert_eq!(config.eval_frequency_by_tier[1], 60); // Tier 2
        assert_eq!(config.eval_frequency_by_tier[2], 120); // Tier 3
        assert_eq!(config.eval_frequency_by_tier[3], 30); // Tier 4
    }

    #[test]
    fn default_config_values() {
        let config = CaeConfig::default();
        assert_eq!(config.heartbeat_grace_secs, 10);
        assert!((config.risk_delta_threshold - 0.15).abs() < f64::EPSILON);
        assert_eq!(config.max_tracked_sessions, 100_000);
    }

    #[test]
    fn detect_triggers_empty_when_no_change() {
        let session = TrackedSession {
            session_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            tier: 2,
            last_heartbeat: 0,
            last_evaluation: 0,
            signals: default_signals(),
            stale: false,
            revoked: false,
        };
        let triggers = detect_triggers(&session, &default_signals(), &CaeConfig::default());
        assert!(triggers.is_empty());
    }

    #[test]
    fn update_policy_engine() {
        let mut cae = make_evaluator();
        let new_engine = PolicyEngine::empty();
        cae.update_policy_engine(new_engine);
        assert!(cae.policy_engine.rules.is_empty());
    }
}
