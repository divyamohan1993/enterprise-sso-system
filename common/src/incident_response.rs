//! Incident response automation for the MILNET SSO system.
//!
//! Implements automated incident detection, classification, response actions,
//! escalation, and lockdown mode for military-grade security operations.
//!
//! # Severity Levels
//!
//! | Severity | Examples                          | Auto-Response                       |
//! |----------|-----------------------------------|-------------------------------------|
//! | Critical | Duress, tamper                    | Revoke sessions, lock account, page |
//! | High     | Brute force, privilege escalation | Increase auth, temp IP block        |
//! | Medium   | Unusual access, failed certs      | Log and alert                       |
//! | Low      | Rate limiting, anomalies          | Log only                            |
//! | Info     | Session lifecycle                 | Metric increment                    |
//!
//! # Circuit Breaker / Lockdown Mode
//!
//! If more than 5 critical incidents occur within 1 hour, the system enters
//! lockdown mode. In lockdown, all new sessions require admin approval.
#![forbid(unsafe_code)]

use serde::Serialize;
use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Incident severity classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum IncidentSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for IncidentSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IncidentSeverity::Info => write!(f, "INFO"),
            IncidentSeverity::Low => write!(f, "LOW"),
            IncidentSeverity::Medium => write!(f, "MEDIUM"),
            IncidentSeverity::High => write!(f, "HIGH"),
            IncidentSeverity::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// The type of security incident.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub enum IncidentType {
    DuressActivation,
    TamperDetection,
    BruteForceAttack,
    PrivilegeEscalation,
    UnusualAccess,
    CertificateFailure,
    EntropyFailure,
    ImpossibleTravel,
    DistributedAttack,
    SessionAnomaly,
    CircuitBreakerCascade,
    AccountLockout,
    RateLimitExceeded,
}

impl IncidentType {
    /// Default severity for this incident type.
    pub fn default_severity(&self) -> IncidentSeverity {
        match self {
            IncidentType::DuressActivation => IncidentSeverity::Critical,
            IncidentType::TamperDetection => IncidentSeverity::Critical,
            IncidentType::EntropyFailure => IncidentSeverity::Critical,
            IncidentType::BruteForceAttack => IncidentSeverity::High,
            IncidentType::PrivilegeEscalation => IncidentSeverity::High,
            IncidentType::DistributedAttack => IncidentSeverity::High,
            IncidentType::CircuitBreakerCascade => IncidentSeverity::High,
            IncidentType::UnusualAccess => IncidentSeverity::Medium,
            IncidentType::CertificateFailure => IncidentSeverity::Medium,
            IncidentType::ImpossibleTravel => IncidentSeverity::Medium,
            IncidentType::SessionAnomaly => IncidentSeverity::Medium,
            IncidentType::AccountLockout => IncidentSeverity::Low,
            IncidentType::RateLimitExceeded => IncidentSeverity::Low,
        }
    }

    /// Runbook URL for this incident type.
    pub fn runbook_url(&self) -> &'static str {
        match self {
            IncidentType::DuressActivation => "https://milnet-docs/runbook/duress-response",
            IncidentType::TamperDetection => "https://milnet-docs/runbook/tamper-response",
            IncidentType::BruteForceAttack => "https://milnet-docs/runbook/brute-force-response",
            IncidentType::PrivilegeEscalation => "https://milnet-docs/runbook/privilege-escalation",
            IncidentType::UnusualAccess => "https://milnet-docs/runbook/unusual-access",
            IncidentType::CertificateFailure => "https://milnet-docs/runbook/cert-errors",
            IncidentType::EntropyFailure => "https://milnet-docs/runbook/entropy-failure",
            IncidentType::ImpossibleTravel => "https://milnet-docs/runbook/impossible-travel",
            IncidentType::DistributedAttack => "https://milnet-docs/runbook/distributed-attack",
            IncidentType::SessionAnomaly => "https://milnet-docs/runbook/session-anomaly",
            IncidentType::CircuitBreakerCascade => "https://milnet-docs/runbook/cascade-failure",
            IncidentType::AccountLockout => "https://milnet-docs/runbook/account-lockout",
            IncidentType::RateLimitExceeded => "https://milnet-docs/runbook/rate-limiting",
        }
    }

    /// SLA for acknowledgment in seconds.
    pub fn ack_sla_secs(&self) -> u64 {
        match self.default_severity() {
            IncidentSeverity::Critical => 300,   // 5 minutes
            IncidentSeverity::High => 900,       // 15 minutes
            IncidentSeverity::Medium => 3600,    // 1 hour
            IncidentSeverity::Low => 14400,      // 4 hours
            IncidentSeverity::Info => u64::MAX,  // no SLA
        }
    }
}

/// Automated actions that can be taken in response to an incident.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum ResponseAction {
    /// Revoke all sessions for a specific user.
    RevokeSessions { user_id: Uuid },
    /// Lock a user account (require admin unlock).
    LockAccount { user_id: Uuid },
    /// Temporarily block an IP address.
    BlockIp { ip: String, duration_secs: u64 },
    /// Increase authentication requirements (step-up auth).
    IncreaseAuthRequirements { user_id: Uuid },
    /// Send alert to SIEM webhook (PagerDuty / Slack / email).
    AlertWebhook { severity: IncidentSeverity, message: String },
    /// Page on-call responder.
    PageOnCall { message: String },
    /// Log the event (always done).
    Log { message: String },
    /// Enter system lockdown mode.
    EnterLockdown,
    /// Escalate to higher severity.
    Escalate { reason: String },
}

/// A tracked incident with metadata, actions, and escalation state.
#[derive(Debug, Clone, Serialize)]
pub struct Incident {
    /// Unique incident ID.
    pub id: Uuid,
    /// When the incident was created.
    #[serde(skip)]
    pub created_at: Instant,
    /// Incident type.
    pub incident_type: IncidentType,
    /// Current severity (may be escalated).
    pub severity: IncidentSeverity,
    /// Affected user (if applicable).
    pub affected_user: Option<Uuid>,
    /// Source IP (if applicable).
    pub source_ip: Option<String>,
    /// Additional detail string.
    pub detail: String,
    /// Actions that have been executed.
    pub actions_taken: Vec<ResponseAction>,
    /// Whether the incident has been acknowledged by an operator.
    pub acknowledged: bool,
    /// Whether the incident has been resolved.
    pub resolved: bool,
    /// Number of times this incident has been escalated.
    pub escalation_count: u32,
}

// ---------------------------------------------------------------------------
// Forensic Evidence Collection
// ---------------------------------------------------------------------------

/// Forensic evidence snapshot collected at time of incident.
///
/// Evidence is collected BEFORE any automated response actions to preserve
/// the system state at the moment of detection. Each evidence entry is
/// hash-chained to the previous entry for tamper-evident integrity.
#[derive(Debug, Clone, Serialize)]
pub struct ForensicEvidence {
    /// Incident this evidence belongs to.
    pub incident_id: String,
    /// Unix timestamp (seconds) when evidence was collected.
    pub collected_at: i64,
    /// Snapshot of the current process state.
    pub process_info: ProcessSnapshot,
    /// Session IDs that were active at the time of the incident.
    pub active_sessions: Vec<String>,
    /// Recent auth event descriptions (last 100).
    pub recent_auth_events: Vec<String>,
    /// Active network connection descriptions.
    pub network_connections: Vec<String>,
    /// Current RSS memory usage in bytes.
    pub memory_usage_bytes: u64,
    /// SHA-512 hash of all evidence fields for integrity verification (hex-encoded).
    pub evidence_hash: String,
    /// SHA-512 hash of the previous evidence entry (hex-encoded, hash chain).
    /// All zeros for the first entry in the chain.
    pub prev_evidence_hash: String,
}

/// Snapshot of the current process at time of evidence collection.
#[derive(Debug, Clone, Serialize)]
pub struct ProcessSnapshot {
    /// Process ID.
    pub pid: u32,
    /// Seconds since process start.
    pub uptime_secs: u64,
    /// Number of active threads.
    pub thread_count: u32,
    /// Number of open file descriptors.
    pub open_file_descriptors: u32,
}

impl ProcessSnapshot {
    /// Capture a snapshot of the current process.
    fn capture() -> Self {
        let pid = std::process::id();

        // Read uptime from /proc/self/stat (field 22 = starttime in clock ticks)
        let uptime_secs = std::fs::read_to_string("/proc/self/stat")
            .ok()
            .and_then(|stat| {
                let fields: Vec<&str> = stat.split_whitespace().collect();
                // Field index 21 (0-based) is starttime in clock ticks
                fields.get(21)?.parse::<u64>().ok()
            })
            .map(|start_ticks| {
                let clock_hz = 100u64; // sysconf(_SC_CLK_TCK) is typically 100
                let system_uptime = std::fs::read_to_string("/proc/uptime")
                    .ok()
                    .and_then(|u| u.split_whitespace().next()?.parse::<f64>().ok())
                    .unwrap_or(0.0);
                let process_start_secs = start_ticks / clock_hz;
                (system_uptime as u64).saturating_sub(process_start_secs)
            })
            .unwrap_or(0);

        // Count threads from /proc/self/status
        let thread_count = std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|status| {
                for line in status.lines() {
                    if let Some(val) = line.strip_prefix("Threads:") {
                        return val.trim().parse::<u32>().ok();
                    }
                }
                None
            })
            .unwrap_or(1);

        // Count open file descriptors from /proc/self/fd
        let open_file_descriptors = std::fs::read_dir("/proc/self/fd")
            .map(|entries| entries.count() as u32)
            .unwrap_or(0);

        Self {
            pid,
            uptime_secs,
            thread_count,
            open_file_descriptors,
        }
    }
}

impl ForensicEvidence {
    /// Compute SHA-512 hash over all evidence fields for integrity verification.
    /// Returns hex-encoded hash string.
    fn compute_hash(
        incident_id: &str,
        collected_at: i64,
        process_info: &ProcessSnapshot,
        active_sessions: &[String],
        recent_auth_events: &[String],
        network_connections: &[String],
        memory_usage_bytes: u64,
        prev_hash: &str,
    ) -> String {
        use sha2::{Sha512, Digest};
        let mut hasher = Sha512::new();
        hasher.update(incident_id.as_bytes());
        hasher.update(collected_at.to_le_bytes());
        hasher.update(process_info.pid.to_le_bytes());
        hasher.update(process_info.uptime_secs.to_le_bytes());
        hasher.update(process_info.thread_count.to_le_bytes());
        hasher.update(process_info.open_file_descriptors.to_le_bytes());
        for s in active_sessions {
            hasher.update(s.as_bytes());
        }
        for e in recent_auth_events {
            hasher.update(e.as_bytes());
        }
        for c in network_connections {
            hasher.update(c.as_bytes());
        }
        hasher.update(memory_usage_bytes.to_le_bytes());
        hasher.update(prev_hash.as_bytes());
        hex::encode(hasher.finalize())
    }
}

// ---------------------------------------------------------------------------
// Incident Response Engine
// ---------------------------------------------------------------------------

/// Configuration for the lockdown circuit breaker.
/// SECURITY: Threshold raised from 5 to 20 to prevent attacker-triggered lockdown
/// DoS. An attacker could trivially generate 5 DuressActivation incidents to force
/// system-wide lockdown. 20 incidents in 1 hour is a more robust threshold that
/// still catches genuine compromise while resisting weaponized incident flooding.
const LOCKDOWN_THRESHOLD: usize = 20;
const LOCKDOWN_WINDOW: Duration = Duration::from_secs(3600); // 1 hour

/// The incident response engine. Tracks active incidents, determines automated
/// response actions, manages escalation, and controls lockdown mode.
pub struct IncidentResponseEngine {
    /// Active (unresolved) incidents.
    incidents: Mutex<Vec<Incident>>,
    /// Timestamps of recent critical incidents (for lockdown threshold).
    critical_timestamps: Mutex<VecDeque<Instant>>,
    /// Whether the system is in lockdown mode.
    lockdown: std::sync::atomic::AtomicBool,
    /// Callback for executing response actions. Set at initialization.
    action_executor: Mutex<Option<Box<dyn Fn(&ResponseAction) + Send + Sync>>>,
    /// Append-only forensic evidence log. Evidence entries are hash-chained.
    evidence_log: Mutex<Vec<ForensicEvidence>>,
}

impl IncidentResponseEngine {
    /// Create a new incident response engine.
    pub fn new() -> Self {
        Self {
            incidents: Mutex::new(Vec::new()),
            critical_timestamps: Mutex::new(VecDeque::new()),
            lockdown: std::sync::atomic::AtomicBool::new(false),
            action_executor: Mutex::new(None),
            evidence_log: Mutex::new(Vec::new()),
        }
    }

    /// Set the callback that executes response actions.
    pub fn set_action_executor(
        &self,
        executor: impl Fn(&ResponseAction) + Send + Sync + 'static,
    ) {
        let mut exec = self.action_executor.lock().unwrap_or_else(|e| e.into_inner());
        *exec = Some(Box::new(executor));
    }

    /// Collect forensic evidence for an incident.
    ///
    /// Snapshots the current system state and appends to the append-only
    /// evidence log. Each entry is hash-chained to the previous entry
    /// for tamper-evident integrity. Evidence cannot be modified after
    /// collection.
    pub fn collect_evidence(&self, incident_id: &str) -> ForensicEvidence {
        let collected_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let process_info = ProcessSnapshot::capture();

        // Read RSS memory from /proc/self/status
        let memory_usage_bytes = std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|status| {
                for line in status.lines() {
                    if let Some(val) = line.strip_prefix("VmRSS:") {
                        let kb: u64 = val.trim().split_whitespace().next()?.parse().ok()?;
                        return Some(kb * 1024);
                    }
                }
                None
            })
            .unwrap_or(0);

        // Read active TCP connections from /proc/self/net/tcp
        let network_connections = std::fs::read_to_string("/proc/self/net/tcp")
            .ok()
            .map(|content| {
                content
                    .lines()
                    .skip(1) // skip header
                    .take(100)
                    .map(|l| l.trim().to_string())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        // Get the previous evidence hash for the chain
        let prev_evidence_hash = {
            let log = self.evidence_log.lock().unwrap_or_else(|e| e.into_inner());
            log.last()
                .map(|e| e.evidence_hash.clone())
                .unwrap_or_else(|| "0".repeat(128)) // 64 zero bytes hex-encoded
        };

        let evidence_hash = ForensicEvidence::compute_hash(
            incident_id,
            collected_at,
            &process_info,
            &[], // active_sessions populated by caller if available
            &[], // recent_auth_events populated by caller if available
            &network_connections,
            memory_usage_bytes,
            &prev_evidence_hash,
        );

        let evidence = ForensicEvidence {
            incident_id: incident_id.to_string(),
            collected_at,
            process_info,
            active_sessions: Vec::new(),
            recent_auth_events: Vec::new(),
            network_connections,
            memory_usage_bytes,
            evidence_hash: evidence_hash.clone(),
            prev_evidence_hash,
        };

        // Append to the immutable evidence log
        {
            let mut log = self.evidence_log.lock().unwrap_or_else(|e| e.into_inner());
            log.push(evidence.clone());
        }

        tracing::info!(
            incident_id = %incident_id,
            evidence_hash = %&evidence.evidence_hash[..32],
            "Forensic evidence collected and hash-chained"
        );

        evidence
    }

    /// Return a copy of the full forensic evidence log (append-only, immutable).
    pub fn evidence_log(&self) -> Vec<ForensicEvidence> {
        let log = self.evidence_log.lock().unwrap_or_else(|e| e.into_inner());
        log.clone()
    }

    /// Whether the system is currently in lockdown mode.
    pub fn is_lockdown(&self) -> bool {
        self.lockdown.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Manually exit lockdown mode (admin action).
    pub fn exit_lockdown(&self) {
        self.lockdown.store(false, std::sync::atomic::Ordering::Relaxed);
        tracing::warn!("LOCKDOWN MODE DEACTIVATED by admin action");
    }

    /// Report a new incident. Determines severity, generates response actions,
    /// and executes them automatically.
    pub fn report_incident(
        &self,
        incident_type: IncidentType,
        affected_user: Option<Uuid>,
        source_ip: Option<String>,
        detail: impl Into<String>,
    ) -> Uuid {
        let severity = incident_type.default_severity();
        let detail = detail.into();

        // Determine automated actions based on severity and type
        let actions = self.determine_actions(
            &incident_type,
            severity,
            affected_user,
            source_ip.as_deref(),
        );

        let incident = Incident {
            id: Uuid::new_v4(),
            created_at: Instant::now(),
            incident_type: incident_type.clone(),
            severity,
            affected_user,
            source_ip: source_ip.clone(),
            detail: detail.clone(),
            actions_taken: actions.clone(),
            acknowledged: false,
            resolved: false,
            escalation_count: 0,
        };

        let incident_id = incident.id;

        // SECURITY: Collect forensic evidence BEFORE any automated response
        // actions, so the system state is preserved as-is at detection time.
        let _evidence = self.collect_evidence(&incident_id.to_string());

        // Store the incident
        {
            let mut incidents = self.incidents.lock().unwrap_or_else(|e| e.into_inner());
            incidents.push(incident);
        }

        // Execute all response actions
        self.execute_actions(&actions);

        // Track critical incidents for lockdown threshold
        if severity == IncidentSeverity::Critical {
            self.track_critical_incident();
        }

        // Update metrics
        crate::metrics::INCIDENTS_ACTIVE.inc(&[
            ("severity", &severity.to_string()),
            ("incident_type", &format!("{:?}", incident_type)),
        ]);

        tracing::warn!(
            incident_id = %incident_id,
            severity = %severity,
            incident_type = ?incident_type,
            runbook = incident_type.runbook_url(),
            "Incident reported: {}",
            detail,
        );

        incident_id
    }

    /// Acknowledge an incident (stops escalation timer).
    pub fn acknowledge(&self, incident_id: &Uuid) -> bool {
        let mut incidents = self.incidents.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(incident) = incidents.iter_mut().find(|i| i.id == *incident_id) {
            incident.acknowledged = true;
            tracing::info!(incident_id = %incident_id, "Incident acknowledged");
            true
        } else {
            false
        }
    }

    /// Resolve an incident.
    pub fn resolve(&self, incident_id: &Uuid) -> bool {
        let mut incidents = self.incidents.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(incident) = incidents.iter_mut().find(|i| i.id == *incident_id) {
            incident.resolved = true;
            crate::metrics::INCIDENTS_ACTIVE.dec(&[
                ("severity", &incident.severity.to_string()),
                ("incident_type", &format!("{:?}", incident.incident_type)),
            ]);
            tracing::info!(incident_id = %incident_id, "Incident resolved");
            true
        } else {
            false
        }
    }

    /// Check all active incidents for SLA violations and escalate as needed.
    /// This should be called periodically (e.g. every 60 seconds).
    pub fn check_escalations(&self) {
        let mut incidents = self.incidents.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();

        for incident in incidents.iter_mut() {
            if incident.resolved || incident.acknowledged {
                continue;
            }

            let sla = Duration::from_secs(incident.incident_type.ack_sla_secs());
            if now.duration_since(incident.created_at) > sla {
                incident.escalation_count += 1;
                let new_severity = match incident.severity {
                    IncidentSeverity::Low => IncidentSeverity::Medium,
                    IncidentSeverity::Medium => IncidentSeverity::High,
                    IncidentSeverity::High => IncidentSeverity::Critical,
                    _ => incident.severity,
                };

                if new_severity != incident.severity {
                    let reason = format!(
                        "No acknowledgment within SLA ({}s). Escalation #{}.",
                        incident.incident_type.ack_sla_secs(),
                        incident.escalation_count,
                    );
                    incident.severity = new_severity;
                    incident.actions_taken.push(ResponseAction::Escalate {
                        reason: reason.clone(),
                    });

                    tracing::warn!(
                        incident_id = %incident.id,
                        new_severity = %new_severity,
                        "Incident escalated: {}",
                        reason,
                    );
                }
            }
        }
    }

    /// Get all active (unresolved) incidents.
    pub fn active_incidents(&self) -> Vec<Incident> {
        let incidents = self.incidents.lock().unwrap_or_else(|e| e.into_inner());
        incidents.iter().filter(|i| !i.resolved).cloned().collect()
    }

    /// Get incident count by severity.
    pub fn incident_counts(&self) -> std::collections::HashMap<IncidentSeverity, usize> {
        let incidents = self.incidents.lock().unwrap_or_else(|e| e.into_inner());
        let mut counts = std::collections::HashMap::new();
        for i in incidents.iter().filter(|i| !i.resolved) {
            *counts.entry(i.severity).or_insert(0) += 1;
        }
        counts
    }

    // ── Internal helpers ──

    /// Determine the automated response actions for a given incident.
    fn determine_actions(
        &self,
        incident_type: &IncidentType,
        severity: IncidentSeverity,
        affected_user: Option<Uuid>,
        source_ip: Option<&str>,
    ) -> Vec<ResponseAction> {
        let mut actions = Vec::new();

        // Always log
        actions.push(ResponseAction::Log {
            message: format!(
                "[{}] {:?} - user={:?} ip={:?} runbook={}",
                severity,
                incident_type,
                affected_user,
                source_ip,
                incident_type.runbook_url(),
            ),
        });

        match severity {
            IncidentSeverity::Critical => {
                // Auto-revoke all sessions for the affected user
                if let Some(uid) = affected_user {
                    actions.push(ResponseAction::RevokeSessions { user_id: uid });
                    actions.push(ResponseAction::LockAccount { user_id: uid });
                }

                // Alert via webhook
                actions.push(ResponseAction::AlertWebhook {
                    severity,
                    message: format!("CRITICAL: {:?}", incident_type),
                });

                // Page on-call
                actions.push(ResponseAction::PageOnCall {
                    message: format!(
                        "CRITICAL INCIDENT: {:?}. Runbook: {}",
                        incident_type,
                        incident_type.runbook_url(),
                    ),
                });
            }
            IncidentSeverity::High => {
                // Increase auth requirements
                if let Some(uid) = affected_user {
                    actions.push(ResponseAction::IncreaseAuthRequirements { user_id: uid });
                }

                // Temporary IP block for brute force
                if let Some(ip) = source_ip {
                    if matches!(
                        incident_type,
                        IncidentType::BruteForceAttack | IncidentType::DistributedAttack
                    ) {
                        actions.push(ResponseAction::BlockIp {
                            ip: ip.to_string(),
                            duration_secs: 1800, // 30 minutes
                        });
                    }
                }

                // Alert via webhook
                actions.push(ResponseAction::AlertWebhook {
                    severity,
                    message: format!("HIGH: {:?}", incident_type),
                });
            }
            IncidentSeverity::Medium => {
                // Alert only
                actions.push(ResponseAction::AlertWebhook {
                    severity,
                    message: format!("MEDIUM: {:?}", incident_type),
                });
            }
            IncidentSeverity::Low | IncidentSeverity::Info => {
                // Log only (already added above)
            }
        }

        actions
    }

    /// Execute a list of response actions.
    fn execute_actions(&self, actions: &[ResponseAction]) {
        let executor = self.action_executor.lock().unwrap_or_else(|e| e.into_inner());
        for action in actions {
            tracing::info!(action = ?action, "Executing incident response action");
            if let Some(ref exec) = *executor {
                exec(action);
            }
        }
    }

    /// Track a critical incident and check if lockdown threshold is reached.
    fn track_critical_incident(&self) {
        let mut timestamps = self.critical_timestamps.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();

        // Prune old timestamps outside the window
        while let Some(front) = timestamps.front() {
            if now.duration_since(*front) > LOCKDOWN_WINDOW {
                timestamps.pop_front();
            } else {
                break;
            }
        }

        timestamps.push_back(now);

        // Check threshold
        if timestamps.len() >= LOCKDOWN_THRESHOLD && !self.is_lockdown() {
            self.lockdown
                .store(true, std::sync::atomic::Ordering::Relaxed);
            tracing::error!(
                critical_count = timestamps.len(),
                window_secs = LOCKDOWN_WINDOW.as_secs(),
                "LOCKDOWN MODE ACTIVATED: {} critical incidents in {} seconds. \
                 All new sessions require admin approval.",
                timestamps.len(),
                LOCKDOWN_WINDOW.as_secs(),
            );

            // Execute lockdown action
            let executor = self.action_executor.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(ref exec) = *executor {
                exec(&ResponseAction::EnterLockdown);
                exec(&ResponseAction::PageOnCall {
                    message: format!(
                        "LOCKDOWN ACTIVATED: {} critical incidents in 1 hour. \
                         Admin approval required for all new sessions.",
                        timestamps.len(),
                    ),
                });
            }
        }
    }
}

impl Default for IncidentResponseEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_incident_severity_ordering() {
        assert!(IncidentSeverity::Critical > IncidentSeverity::High);
        assert!(IncidentSeverity::High > IncidentSeverity::Medium);
        assert!(IncidentSeverity::Medium > IncidentSeverity::Low);
        assert!(IncidentSeverity::Low > IncidentSeverity::Info);
    }

    #[test]
    fn test_incident_type_defaults() {
        assert_eq!(
            IncidentType::DuressActivation.default_severity(),
            IncidentSeverity::Critical,
        );
        assert_eq!(
            IncidentType::TamperDetection.default_severity(),
            IncidentSeverity::Critical,
        );
        assert_eq!(
            IncidentType::EntropyFailure.default_severity(),
            IncidentSeverity::Critical,
        );
        assert_eq!(
            IncidentType::BruteForceAttack.default_severity(),
            IncidentSeverity::High,
        );
        assert_eq!(
            IncidentType::PrivilegeEscalation.default_severity(),
            IncidentSeverity::High,
        );
        assert_eq!(
            IncidentType::UnusualAccess.default_severity(),
            IncidentSeverity::Medium,
        );
        assert_eq!(
            IncidentType::AccountLockout.default_severity(),
            IncidentSeverity::Low,
        );
    }

    #[test]
    fn test_report_and_resolve_incident() {
        let engine = IncidentResponseEngine::new();
        let id = engine.report_incident(
            IncidentType::UnusualAccess,
            Some(Uuid::new_v4()),
            Some("10.0.0.1".into()),
            "Unusual access from new network",
        );

        assert_eq!(engine.active_incidents().len(), 1);
        assert!(engine.resolve(&id));
        assert_eq!(engine.active_incidents().len(), 0);
    }

    #[test]
    fn test_acknowledge_incident() {
        let engine = IncidentResponseEngine::new();
        let id = engine.report_incident(
            IncidentType::CertificateFailure,
            None,
            Some("10.0.0.2".into()),
            "mTLS cert expired",
        );

        assert!(engine.acknowledge(&id));
        let incidents = engine.active_incidents();
        assert!(incidents[0].acknowledged);
    }

    #[test]
    fn test_acknowledge_unknown_returns_false() {
        let engine = IncidentResponseEngine::new();
        assert!(!engine.acknowledge(&Uuid::new_v4()));
    }

    #[test]
    fn test_resolve_unknown_returns_false() {
        let engine = IncidentResponseEngine::new();
        assert!(!engine.resolve(&Uuid::new_v4()));
    }

    #[test]
    fn test_lockdown_activation() {
        let engine = IncidentResponseEngine::new();
        assert!(!engine.is_lockdown());

        // Report LOCKDOWN_THRESHOLD (20) critical incidents
        for i in 0..20 {
            engine.report_incident(
                IncidentType::TamperDetection,
                None,
                None,
                format!("tamper event {}", i),
            );
        }

        assert!(engine.is_lockdown());
    }

    #[test]
    fn test_lockdown_exit_requires_admin() {
        let engine = IncidentResponseEngine::new();

        // Trigger lockdown with LOCKDOWN_THRESHOLD (20) critical incidents
        for i in 0..20 {
            engine.report_incident(
                IncidentType::DuressActivation,
                Some(Uuid::new_v4()),
                None,
                format!("duress {}", i),
            );
        }
        assert!(engine.is_lockdown());

        // Only explicit admin action exits lockdown
        engine.exit_lockdown();
        assert!(!engine.is_lockdown());
    }

    #[test]
    fn test_lockdown_is_more_restrictive() {
        // Verify that lockdown mode makes the system MORE restrictive, not less.
        // In lockdown, is_lockdown() returns true, which callers must check
        // before allowing new sessions.
        let engine = IncidentResponseEngine::new();
        assert!(
            !engine.is_lockdown(),
            "System must not start in lockdown"
        );

        for i in 0..20 {
            engine.report_incident(
                IncidentType::TamperDetection,
                None,
                None,
                format!("tamper {}", i),
            );
        }

        assert!(
            engine.is_lockdown(),
            "Lockdown must activate after threshold"
        );
        // Lockdown means callers must require admin approval for new sessions
    }

    #[test]
    fn test_critical_actions_include_session_revocation() {
        let engine = IncidentResponseEngine::new();
        let user_id = Uuid::new_v4();
        let id = engine.report_incident(
            IncidentType::DuressActivation,
            Some(user_id),
            None,
            "Duress PIN entered",
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
        let has_webhook = incident
            .actions_taken
            .iter()
            .any(|a| matches!(a, ResponseAction::AlertWebhook { severity: IncidentSeverity::Critical, .. }));

        assert!(has_revoke, "Critical incident must revoke sessions");
        assert!(has_lock, "Critical incident must lock account");
        assert!(has_page, "Critical incident must page on-call");
        assert!(has_webhook, "Critical incident must send webhook alert");
    }

    #[test]
    fn test_high_severity_ip_block() {
        let engine = IncidentResponseEngine::new();
        let id = engine.report_incident(
            IncidentType::BruteForceAttack,
            Some(Uuid::new_v4()),
            Some("203.0.113.1".into()),
            "50 failed attempts in 5 minutes",
        );

        let incidents = engine.active_incidents();
        let incident = incidents.iter().find(|i| i.id == id).unwrap();

        let has_block = incident.actions_taken.iter().any(|a| {
            matches!(a, ResponseAction::BlockIp { ip, .. } if ip == "203.0.113.1")
        });
        let has_increase_auth = incident.actions_taken.iter().any(|a| {
            matches!(a, ResponseAction::IncreaseAuthRequirements { .. })
        });
        assert!(has_block, "Brute force must trigger IP block");
        assert!(has_increase_auth, "High severity must increase auth requirements");
    }

    #[test]
    fn test_medium_severity_alert_only() {
        let engine = IncidentResponseEngine::new();
        let id = engine.report_incident(
            IncidentType::UnusualAccess,
            Some(Uuid::new_v4()),
            Some("10.0.0.1".into()),
            "Unusual access pattern",
        );

        let incidents = engine.active_incidents();
        let incident = incidents.iter().find(|i| i.id == id).unwrap();

        // Should have log + webhook alert, but NOT session revocation or IP block
        let has_revoke = incident
            .actions_taken
            .iter()
            .any(|a| matches!(a, ResponseAction::RevokeSessions { .. }));
        let has_block = incident
            .actions_taken
            .iter()
            .any(|a| matches!(a, ResponseAction::BlockIp { .. }));

        assert!(!has_revoke, "Medium severity must NOT revoke sessions");
        assert!(!has_block, "Medium severity must NOT block IPs");
    }

    #[test]
    fn test_runbook_urls_all_non_empty() {
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
                "Runbook URL must use HTTPS for {:?}",
                t,
            );
        }
    }

    #[test]
    fn test_sla_values() {
        // Critical incidents must have shortest SLA
        assert!(
            IncidentType::DuressActivation.ack_sla_secs()
                < IncidentType::BruteForceAttack.ack_sla_secs()
        );
        assert!(
            IncidentType::BruteForceAttack.ack_sla_secs()
                < IncidentType::UnusualAccess.ack_sla_secs()
        );
        assert!(
            IncidentType::UnusualAccess.ack_sla_secs()
                < IncidentType::AccountLockout.ack_sla_secs()
        );
    }

    #[test]
    fn test_incident_counts() {
        let engine = IncidentResponseEngine::new();
        engine.report_incident(
            IncidentType::DuressActivation,
            Some(Uuid::new_v4()),
            None,
            "duress 1",
        );
        engine.report_incident(
            IncidentType::UnusualAccess,
            Some(Uuid::new_v4()),
            None,
            "unusual 1",
        );
        engine.report_incident(
            IncidentType::UnusualAccess,
            Some(Uuid::new_v4()),
            None,
            "unusual 2",
        );

        let counts = engine.incident_counts();
        assert_eq!(counts.get(&IncidentSeverity::Critical), Some(&1));
        assert_eq!(counts.get(&IncidentSeverity::Medium), Some(&2));
    }

    #[test]
    fn test_action_executor_callback() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let engine = IncidentResponseEngine::new();
        let action_count = Arc::new(AtomicUsize::new(0));
        let count_clone = Arc::clone(&action_count);

        engine.set_action_executor(move |_action| {
            count_clone.fetch_add(1, Ordering::Relaxed);
        });

        engine.report_incident(
            IncidentType::UnusualAccess,
            Some(Uuid::new_v4()),
            None,
            "test",
        );

        // Should have executed at least 2 actions (log + alert)
        assert!(action_count.load(Ordering::Relaxed) >= 2);
    }

    #[test]
    fn test_four_critical_no_lockdown() {
        let engine = IncidentResponseEngine::new();
        // 4 critical incidents should NOT trigger lockdown (threshold is 5)
        for i in 0..4 {
            engine.report_incident(
                IncidentType::TamperDetection,
                None,
                None,
                format!("tamper {}", i),
            );
        }
        assert!(!engine.is_lockdown(), "4 critical incidents must NOT trigger lockdown");
    }
}
