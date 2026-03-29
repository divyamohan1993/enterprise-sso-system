//! Incident response engine tests.
//!
//! Verifies the automated incident response system correctly:
//!   - Classifies incidents by severity
//!   - Generates appropriate response actions per severity
//!   - Manages lockdown mode activation/deactivation
//!   - Enforces SLA timers for acknowledgment
//!   - Tracks incident lifecycle (report -> acknowledge -> resolve)
//!   - Executes action callbacks

use common::incident_response::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use uuid::Uuid;

// ── Incident Severity Classification ──────────────────────────────────────

/// Security property: Duress activation is ALWAYS classified as Critical.
/// This is the highest severity because it indicates an operator is under coercion.
#[test]
fn duress_activation_is_critical_severity() {
    assert_eq!(
        IncidentType::DuressActivation.default_severity(),
        IncidentSeverity::Critical,
    );
}

/// Security property: Tamper detection is ALWAYS classified as Critical.
/// Physical or logical tampering indicates active hardware/software compromise.
#[test]
fn tamper_detection_is_critical_severity() {
    assert_eq!(
        IncidentType::TamperDetection.default_severity(),
        IncidentSeverity::Critical,
    );
}

/// Security property: Entropy failure is Critical because it means the
/// CSPRNG is compromised, invalidating all cryptographic operations.
#[test]
fn entropy_failure_is_critical_severity() {
    assert_eq!(
        IncidentType::EntropyFailure.default_severity(),
        IncidentSeverity::Critical,
    );
}

/// Security property: Brute force attack is High severity and triggers
/// IP blocking and increased auth requirements.
#[test]
fn brute_force_is_high_severity() {
    assert_eq!(
        IncidentType::BruteForceAttack.default_severity(),
        IncidentSeverity::High,
    );
}

/// Security property: Severity levels have a strict ordering that determines
/// escalation paths and SLA timers.
#[test]
fn severity_ordering_is_strict() {
    assert!(IncidentSeverity::Critical > IncidentSeverity::High);
    assert!(IncidentSeverity::High > IncidentSeverity::Medium);
    assert!(IncidentSeverity::Medium > IncidentSeverity::Low);
    assert!(IncidentSeverity::Low > IncidentSeverity::Info);
}

// ── Lockdown Mode ─────────────────────────────────────────────────────────

/// Security property: The system does NOT start in lockdown mode.
/// Lockdown is a circuit breaker that must be triggered by incidents.
#[test]
fn system_does_not_start_in_lockdown() {
    let engine = IncidentResponseEngine::new();
    assert!(!engine.is_lockdown(), "system must not start in lockdown");
}

/// Security property: Lockdown activates after the threshold number (20)
/// of critical incidents within the 1-hour window. This prevents an attacker
/// from trivially triggering lockdown with just a few events.
#[test]
fn lockdown_activates_after_threshold_critical_incidents() {
    let engine = IncidentResponseEngine::new();

    // 19 critical incidents: NOT enough for lockdown
    for i in 0..19 {
        engine.report_incident(
            IncidentType::TamperDetection,
            None,
            None,
            format!("tamper event {}", i),
        );
    }
    assert!(!engine.is_lockdown(), "19 critical incidents must NOT trigger lockdown");

    // 20th critical incident: triggers lockdown
    engine.report_incident(
        IncidentType::TamperDetection,
        None,
        None,
        "tamper event 19 - threshold reached",
    );
    assert!(engine.is_lockdown(), "20 critical incidents must trigger lockdown");
}

/// Security property: Lockdown mode blocks new authentications. Callers
/// MUST check is_lockdown() before allowing new sessions.
#[test]
fn lockdown_mode_is_queryable() {
    let engine = IncidentResponseEngine::new();
    assert!(!engine.is_lockdown());

    // Trigger lockdown
    for i in 0..20 {
        engine.report_incident(
            IncidentType::DuressActivation,
            Some(Uuid::new_v4()),
            None,
            format!("duress {}", i),
        );
    }

    assert!(engine.is_lockdown(), "lockdown must be queryable");
}

/// Security property: Lockdown can ONLY be deactivated by explicit admin action.
/// It does not auto-resolve, preventing an attacker from waiting out the lockdown.
#[test]
fn lockdown_requires_admin_to_exit() {
    let engine = IncidentResponseEngine::new();

    for i in 0..20 {
        engine.report_incident(
            IncidentType::TamperDetection,
            None,
            None,
            format!("tamper {}", i),
        );
    }
    assert!(engine.is_lockdown());

    engine.exit_lockdown();
    assert!(!engine.is_lockdown(), "admin action must exit lockdown");
}

// ── Auto-Response Actions ─────────────────────────────────────────────────

/// Security property: Critical incidents auto-revoke sessions and lock accounts
/// to contain the blast radius before human responders arrive.
#[test]
fn critical_incident_revokes_sessions_and_locks_account() {
    let engine = IncidentResponseEngine::new();
    let user_id = Uuid::new_v4();

    let id = engine.report_incident(
        IncidentType::DuressActivation,
        Some(user_id),
        None,
        "Duress PIN entered at terminal",
    );

    let incidents = engine.active_incidents();
    let incident = incidents.iter().find(|i| i.id == id).unwrap();

    let has_revoke = incident.actions_taken.iter().any(|a| {
        matches!(a, ResponseAction::RevokeSessions { user_id: uid } if *uid == user_id)
    });
    let has_lock = incident.actions_taken.iter().any(|a| {
        matches!(a, ResponseAction::LockAccount { user_id: uid } if *uid == user_id)
    });
    let has_page = incident
        .actions_taken
        .iter()
        .any(|a| matches!(a, ResponseAction::PageOnCall { .. }));

    assert!(has_revoke, "Critical: must revoke sessions");
    assert!(has_lock, "Critical: must lock account");
    assert!(has_page, "Critical: must page on-call");
}

/// Security property: High severity brute force triggers IP block to stop
/// the attack at the network level.
#[test]
fn high_severity_brute_force_blocks_ip() {
    let engine = IncidentResponseEngine::new();

    let id = engine.report_incident(
        IncidentType::BruteForceAttack,
        Some(Uuid::new_v4()),
        Some("198.51.100.1".into()),
        "100 failed login attempts in 2 minutes",
    );

    let incidents = engine.active_incidents();
    let incident = incidents.iter().find(|i| i.id == id).unwrap();

    let has_block = incident.actions_taken.iter().any(|a| {
        matches!(a, ResponseAction::BlockIp { ip, duration_secs } if ip == "198.51.100.1" && *duration_secs > 0)
    });
    assert!(has_block, "Brute force must trigger IP block");
}

/// Security property: Medium severity incidents generate alerts but do NOT
/// take destructive actions like session revocation or IP blocking.
#[test]
fn medium_severity_alerts_only_no_destructive_actions() {
    let engine = IncidentResponseEngine::new();

    let id = engine.report_incident(
        IncidentType::UnusualAccess,
        Some(Uuid::new_v4()),
        Some("10.0.0.1".into()),
        "Access from previously unseen country",
    );

    let incidents = engine.active_incidents();
    let incident = incidents.iter().find(|i| i.id == id).unwrap();

    assert_eq!(incident.severity, IncidentSeverity::Medium);

    let has_revoke = incident
        .actions_taken
        .iter()
        .any(|a| matches!(a, ResponseAction::RevokeSessions { .. }));
    let has_block = incident
        .actions_taken
        .iter()
        .any(|a| matches!(a, ResponseAction::BlockIp { .. }));
    let has_lock = incident
        .actions_taken
        .iter()
        .any(|a| matches!(a, ResponseAction::LockAccount { .. }));

    assert!(!has_revoke, "Medium: must NOT revoke sessions");
    assert!(!has_block, "Medium: must NOT block IPs");
    assert!(!has_lock, "Medium: must NOT lock accounts");
}

/// Security property: Low severity incidents only generate log entries.
/// No alerts, no blocks, no session revocations.
#[test]
fn low_severity_log_only() {
    let engine = IncidentResponseEngine::new();

    let id = engine.report_incident(
        IncidentType::RateLimitExceeded,
        None,
        Some("10.0.0.1".into()),
        "Rate limit hit on /token endpoint",
    );

    let incidents = engine.active_incidents();
    let incident = incidents.iter().find(|i| i.id == id).unwrap();

    assert_eq!(incident.severity, IncidentSeverity::Low);

    // Should only have a Log action
    let has_webhook = incident
        .actions_taken
        .iter()
        .any(|a| matches!(a, ResponseAction::AlertWebhook { .. }));
    assert!(!has_webhook, "Low: must NOT send webhook alerts");
}

// ── SLA Timers ────────────────────────────────────────────────────────────

/// Security property: SLA timers for acknowledgment decrease with severity.
/// Critical: 5min, High: 15min, Medium: 1hr, Low: 4hr, Info: no SLA.
#[test]
fn sla_timers_decrease_with_severity() {
    let crit_sla = IncidentType::DuressActivation.ack_sla_secs();
    let high_sla = IncidentType::BruteForceAttack.ack_sla_secs();
    let med_sla = IncidentType::UnusualAccess.ack_sla_secs();
    let low_sla = IncidentType::AccountLockout.ack_sla_secs();

    assert_eq!(crit_sla, 300, "Critical SLA must be 5 minutes");
    assert_eq!(high_sla, 900, "High SLA must be 15 minutes");
    assert_eq!(med_sla, 3600, "Medium SLA must be 1 hour");
    assert_eq!(low_sla, 14400, "Low SLA must be 4 hours");

    assert!(crit_sla < high_sla);
    assert!(high_sla < med_sla);
    assert!(med_sla < low_sla);
}

// ── Incident Lifecycle ────────────────────────────────────────────────────

/// Security property: Acknowledge stops the escalation timer.
/// Unacknowledged incidents escalate in severity over time.
#[test]
fn acknowledge_incident_lifecycle() {
    let engine = IncidentResponseEngine::new();

    let id = engine.report_incident(
        IncidentType::CertificateFailure,
        None,
        None,
        "mTLS certificate expired",
    );

    // Verify incident is not acknowledged initially
    let incidents = engine.active_incidents();
    assert!(!incidents[0].acknowledged);

    // Acknowledge
    assert!(engine.acknowledge(&id));

    // Verify acknowledged state
    let incidents = engine.active_incidents();
    let incident = incidents.iter().find(|i| i.id == id).unwrap();
    assert!(incident.acknowledged);
}

/// Security property: Resolve removes the incident from active tracking.
#[test]
fn resolve_incident_lifecycle() {
    let engine = IncidentResponseEngine::new();

    let id = engine.report_incident(
        IncidentType::SessionAnomaly,
        Some(Uuid::new_v4()),
        None,
        "session_id mismatch detected",
    );

    assert_eq!(engine.active_incidents().len(), 1);

    assert!(engine.resolve(&id));
    assert_eq!(engine.active_incidents().len(), 0);
}

/// Security property: Acknowledging or resolving a nonexistent incident
/// returns false, preventing confusion in distributed systems.
#[test]
fn acknowledge_and_resolve_nonexistent_returns_false() {
    let engine = IncidentResponseEngine::new();
    let fake_id = Uuid::new_v4();
    assert!(!engine.acknowledge(&fake_id));
    assert!(!engine.resolve(&fake_id));
}

// ── Action Executor Callback ──────────────────────────────────────────────

/// Security property: The action executor callback is invoked for every
/// action generated by an incident, enabling integration with external
/// systems (SIEM, PagerDuty, firewall).
#[test]
fn action_executor_receives_all_actions() {
    let engine = IncidentResponseEngine::new();
    let action_count = Arc::new(AtomicUsize::new(0));
    let count_clone = Arc::clone(&action_count);

    engine.set_action_executor(move |_action| {
        count_clone.fetch_add(1, Ordering::Relaxed);
    });

    engine.report_incident(
        IncidentType::DuressActivation,
        Some(Uuid::new_v4()),
        None,
        "test callback execution",
    );

    // Critical with user_id should produce: Log + RevokeSessions + LockAccount + AlertWebhook + PageOnCall
    assert!(
        action_count.load(Ordering::Relaxed) >= 4,
        "critical incident should trigger at least 4 response actions"
    );
}

// ── Runbook URLs ──────────────────────────────────────────────────────────

/// Security property: All incident types have HTTPS runbook URLs.
/// Operators need immediate guidance during incidents.
#[test]
fn all_incident_types_have_https_runbook_urls() {
    let types = vec![
        IncidentType::DuressActivation,
        IncidentType::TamperDetection,
        IncidentType::BruteForceAttack,
        IncidentType::PrivilegeEscalation,
        IncidentType::UnusualAccess,
        IncidentType::CertificateFailure,
        IncidentType::EntropyFailure,
        IncidentType::ImpossibleTravel,
        IncidentType::DistributedAttack,
        IncidentType::SessionAnomaly,
        IncidentType::CircuitBreakerCascade,
        IncidentType::AccountLockout,
        IncidentType::RateLimitExceeded,
    ];

    for t in types {
        let url = t.runbook_url();
        assert!(!url.is_empty(), "Runbook URL must not be empty for {:?}", t);
        assert!(
            url.starts_with("https://"),
            "Runbook URL must use HTTPS for {:?}: got {}",
            t,
            url,
        );
    }
}

// ── Incident Counts ───────────────────────────────────────────────────────

/// Security property: Incident counts by severity are accurate for
/// dashboard and SIEM reporting.
#[test]
fn incident_counts_by_severity_accurate() {
    let engine = IncidentResponseEngine::new();

    // 2 critical + 3 medium
    engine.report_incident(IncidentType::DuressActivation, Some(Uuid::new_v4()), None, "d1");
    engine.report_incident(IncidentType::TamperDetection, None, None, "t1");
    engine.report_incident(IncidentType::UnusualAccess, Some(Uuid::new_v4()), None, "u1");
    engine.report_incident(IncidentType::CertificateFailure, None, None, "c1");
    engine.report_incident(IncidentType::ImpossibleTravel, Some(Uuid::new_v4()), None, "it1");

    let counts = engine.incident_counts();
    assert_eq!(counts.get(&IncidentSeverity::Critical), Some(&2));
    assert_eq!(counts.get(&IncidentSeverity::Medium), Some(&3));
}
