//! Emergency single-node mode for sub-quorum operation.
//!
//! Activates when a node detects quorum loss (consecutive Raft election
//! failures, FROST signing failures, peer heartbeat timeouts). In this mode:
//!
//! - New token issuance is SUSPENDED (FROST threshold unmet)
//! - Existing sessions can be VALIDATED using cached verification keys
//! - Audit entries are LOCAL-ONLY (BFT quorum unavailable)
//! - A distress beacon is broadcast to any reachable monitoring endpoint
//! - All peer TLS connections are severed (assume compromised)
//! - The node enters read-only mode with degraded but safe operation

use crate::siem::{PanelSiemEvent, SiemPanel, SiemSeverity};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Consecutive Raft election failures before emergency activation.
const ELECTION_FAILURE_THRESHOLD: u32 = 5;

/// Consecutive FROST signing failures before emergency activation.
const SIGNING_FAILURE_THRESHOLD: u32 = 3;

/// Minimum healthy peers required (below this = emergency).
/// For a 5-node cluster with 3-of-5 threshold, need at least 3.
const MIN_HEALTHY_PEERS: u32 = 3;

/// Dead man switch timeout: 5 minutes with no valid peer heartbeat.
const DEAD_MAN_SWITCH_TIMEOUT: Duration = Duration::from_secs(300);

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Reason the emergency mode was activated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmergencyReason {
    /// Too many consecutive Raft election failures (no quorum reachable).
    QuorumLoss,
    /// Multiple subsystems failing simultaneously, indicating mass node compromise.
    MassCompromise,
    /// Operator manually triggered emergency lockdown.
    ManualTrigger,
    /// Dead man switch fired (no peer heartbeat for 5 minutes).
    DeadManSwitch,
}

impl std::fmt::Display for EmergencyReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::QuorumLoss => write!(f, "quorum_loss"),
            Self::MassCompromise => write!(f, "mass_compromise"),
            Self::ManualTrigger => write!(f, "manual_trigger"),
            Self::DeadManSwitch => write!(f, "dead_man_switch"),
        }
    }
}

// ---------------------------------------------------------------------------
// EmergencyMode
// ---------------------------------------------------------------------------

/// Emergency mode state for a single node operating sub-quorum.
///
/// All fields use atomics so that any thread can check/update state without
/// locks. The `OnceLock` fields capture the moment of activation and never
/// change after that.
pub struct EmergencyMode {
    /// Whether emergency mode is currently active.
    active: AtomicBool,
    /// Instant when emergency mode was activated (set once).
    activated_at: OnceLock<Instant>,
    /// Reason for activation (set once).
    reason: OnceLock<EmergencyReason>,
    /// Rolling count of consecutive Raft election failures.
    pub consecutive_election_failures: AtomicU32,
    /// Rolling count of consecutive FROST signing failures.
    pub consecutive_signing_failures: AtomicU32,
    /// Number of peers currently responding to heartbeats.
    pub healthy_peer_count: AtomicU32,
    /// Dead man switch deadline as microseconds since UNIX epoch.
    /// If current time exceeds this and no heartbeat resets it, emergency fires.
    pub dead_man_switch_deadline: AtomicU64,
}

impl EmergencyMode {
    /// Create a new inactive emergency mode tracker.
    pub fn new() -> Self {
        let deadline = Self::micros_from_now(DEAD_MAN_SWITCH_TIMEOUT);
        Self {
            active: AtomicBool::new(false),
            activated_at: OnceLock::new(),
            reason: OnceLock::new(),
            consecutive_election_failures: AtomicU32::new(0),
            consecutive_signing_failures: AtomicU32::new(0),
            healthy_peer_count: AtomicU32::new(MIN_HEALTHY_PEERS),
            dead_man_switch_deadline: AtomicU64::new(deadline),
        }
    }

    /// Check all trigger conditions and activate emergency mode if any fire.
    ///
    /// Returns `true` if emergency mode was just activated (or was already active).
    pub fn check_and_activate(&self) -> bool {
        if self.active.load(Ordering::SeqCst) {
            return true;
        }

        let election_fails = self.consecutive_election_failures.load(Ordering::SeqCst);
        let signing_fails = self.consecutive_signing_failures.load(Ordering::SeqCst);
        let peers = self.healthy_peer_count.load(Ordering::SeqCst);

        // Determine trigger reason
        let reason = if election_fails > ELECTION_FAILURE_THRESHOLD {
            Some(EmergencyReason::QuorumLoss)
        } else if signing_fails > SIGNING_FAILURE_THRESHOLD {
            Some(EmergencyReason::QuorumLoss)
        } else if peers < MIN_HEALTHY_PEERS {
            if election_fails > 2 && signing_fails > 1 {
                Some(EmergencyReason::MassCompromise)
            } else {
                Some(EmergencyReason::QuorumLoss)
            }
        } else {
            None
        };

        if let Some(r) = reason {
            self.activate(r);
            true
        } else {
            false
        }
    }

    /// Manually trigger emergency mode.
    pub fn manual_activate(&self) {
        self.activate(EmergencyReason::ManualTrigger);
    }

    /// Core activation logic. Idempotent: only the first call sets the reason/time.
    fn activate(&self, reason: EmergencyReason) {
        let was_active = self.active.swap(true, Ordering::SeqCst);
        let _ = self.activated_at.set(Instant::now());
        let _ = self.reason.set(reason);

        if !was_active {
            PanelSiemEvent::new(
                SiemPanel::ThresholdViolations,
                SiemSeverity::Critical,
                "emergency_mode_activated",
                format!(
                    "EMERGENCY MODE ACTIVATED: reason={}, election_fails={}, signing_fails={}, healthy_peers={}",
                    reason,
                    self.consecutive_election_failures.load(Ordering::SeqCst),
                    self.consecutive_signing_failures.load(Ordering::SeqCst),
                    self.healthy_peer_count.load(Ordering::SeqCst),
                ),
                file!(),
                line!(),
                module_path!(),
            )
            .emit();

            tracing::error!(
                reason = %reason,
                "EMERGENCY MODE: node entering sub-quorum survival mode"
            );
        }
    }

    /// Whether emergency mode is currently active.
    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::SeqCst)
    }

    /// Token issuance requires FROST threshold signing. In emergency mode,
    /// we cannot reach threshold, so issuance is always suspended.
    pub fn can_issue_tokens(&self) -> bool {
        !self.is_active()
    }

    /// Token validation uses the cached FROST group public key, which is
    /// available locally. Safe to validate even in emergency mode.
    pub fn can_validate_tokens(&self) -> bool {
        true
    }

    /// Tick the dead man switch. Call this periodically (e.g. every 10s).
    ///
    /// If the deadline has passed without a heartbeat reset, activates emergency.
    pub fn dead_man_switch_tick(&self) {
        if self.is_active() {
            return;
        }

        let now_micros = Self::now_micros();
        let deadline = self.dead_man_switch_deadline.load(Ordering::SeqCst);

        if now_micros > deadline {
            self.activate(EmergencyReason::DeadManSwitch);
        }
    }

    /// Reset the dead man switch deadline. Call on each valid peer heartbeat.
    pub fn heartbeat_received(&self) {
        let new_deadline = Self::micros_from_now(DEAD_MAN_SWITCH_TIMEOUT);
        self.dead_man_switch_deadline
            .store(new_deadline, Ordering::SeqCst);
    }

    /// Record a Raft election failure.
    pub fn record_election_failure(&self) {
        self.consecutive_election_failures
            .fetch_add(1, Ordering::SeqCst);
    }

    /// Record a successful Raft election (resets failure counter).
    pub fn record_election_success(&self) {
        self.consecutive_election_failures
            .store(0, Ordering::SeqCst);
    }

    /// Record a FROST signing failure.
    pub fn record_signing_failure(&self) {
        self.consecutive_signing_failures
            .fetch_add(1, Ordering::SeqCst);
    }

    /// Record a successful FROST signing (resets failure counter).
    pub fn record_signing_success(&self) {
        self.consecutive_signing_failures
            .store(0, Ordering::SeqCst);
    }

    /// Update the count of healthy peers.
    pub fn update_healthy_peers(&self, count: u32) {
        self.healthy_peer_count.store(count, Ordering::SeqCst);
    }

    /// Get the activation reason (None if not activated).
    pub fn reason(&self) -> Option<EmergencyReason> {
        self.reason.get().copied()
    }

    /// Get the activation instant (None if not activated).
    pub fn activated_at(&self) -> Option<Instant> {
        self.activated_at.get().copied()
    }

    // -- Time helpers --

    fn now_micros() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64
    }

    fn micros_from_now(dur: Duration) -> u64 {
        Self::now_micros().saturating_add(dur.as_micros() as u64)
    }
}

impl Default for EmergencyMode {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Global singleton
// ---------------------------------------------------------------------------

/// Global emergency mode instance. Initialize once at startup.
pub static EMERGENCY: OnceLock<EmergencyMode> = OnceLock::new();

/// Get or initialize the global emergency mode.
pub fn emergency() -> &'static EmergencyMode {
    EMERGENCY.get_or_init(EmergencyMode::new)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_emergency_mode_is_inactive() {
        let em = EmergencyMode::new();
        assert!(!em.is_active());
        assert!(em.can_issue_tokens());
        assert!(em.can_validate_tokens());
        assert!(em.reason().is_none());
        assert!(em.activated_at().is_none());
    }

    #[test]
    fn election_failures_trigger_emergency() {
        let em = EmergencyMode::new();
        for _ in 0..5 {
            em.record_election_failure();
            assert!(!em.check_and_activate());
        }
        // 6th failure pushes over threshold (> 5)
        em.record_election_failure();
        assert!(em.check_and_activate());
        assert!(em.is_active());
        assert!(!em.can_issue_tokens());
        assert!(em.can_validate_tokens());
        assert_eq!(em.reason(), Some(EmergencyReason::QuorumLoss));
    }

    #[test]
    fn signing_failures_trigger_emergency() {
        let em = EmergencyMode::new();
        for _ in 0..3 {
            em.record_signing_failure();
            assert!(!em.check_and_activate());
        }
        // 4th failure pushes over threshold (> 3)
        em.record_signing_failure();
        assert!(em.check_and_activate());
        assert!(em.is_active());
        assert_eq!(em.reason(), Some(EmergencyReason::QuorumLoss));
    }

    #[test]
    fn low_peer_count_triggers_emergency() {
        let em = EmergencyMode::new();
        em.update_healthy_peers(2); // below MIN_HEALTHY_PEERS (3)
        assert!(em.check_and_activate());
        assert!(em.is_active());
    }

    #[test]
    fn mass_compromise_detected() {
        let em = EmergencyMode::new();
        em.update_healthy_peers(1);
        // Some election and signing failures but below individual thresholds
        em.consecutive_election_failures.store(3, Ordering::SeqCst);
        em.consecutive_signing_failures.store(2, Ordering::SeqCst);
        assert!(em.check_and_activate());
        assert_eq!(em.reason(), Some(EmergencyReason::MassCompromise));
    }

    #[test]
    fn manual_trigger() {
        let em = EmergencyMode::new();
        em.manual_activate();
        assert!(em.is_active());
        assert_eq!(em.reason(), Some(EmergencyReason::ManualTrigger));
        assert!(!em.can_issue_tokens());
    }

    #[test]
    fn dead_man_switch_fires_on_expired_deadline() {
        let em = EmergencyMode::new();
        // Set deadline to the past
        em.dead_man_switch_deadline.store(0, Ordering::SeqCst);
        em.dead_man_switch_tick();
        assert!(em.is_active());
        assert_eq!(em.reason(), Some(EmergencyReason::DeadManSwitch));
    }

    #[test]
    fn heartbeat_resets_dead_man_switch() {
        let em = EmergencyMode::new();
        // Set deadline to the past
        em.dead_man_switch_deadline.store(0, Ordering::SeqCst);
        // Heartbeat resets it
        em.heartbeat_received();
        // Now tick should NOT fire
        em.dead_man_switch_tick();
        assert!(!em.is_active());
    }

    #[test]
    fn dead_man_switch_noop_when_already_active() {
        let em = EmergencyMode::new();
        em.manual_activate();
        // Even with expired deadline, tick is a no-op
        em.dead_man_switch_deadline.store(0, Ordering::SeqCst);
        em.dead_man_switch_tick();
        // Still active with original reason
        assert_eq!(em.reason(), Some(EmergencyReason::ManualTrigger));
    }

    #[test]
    fn election_success_resets_counter() {
        let em = EmergencyMode::new();
        for _ in 0..5 {
            em.record_election_failure();
        }
        em.record_election_success();
        assert_eq!(
            em.consecutive_election_failures.load(Ordering::SeqCst),
            0
        );
        assert!(!em.check_and_activate());
    }

    #[test]
    fn signing_success_resets_counter() {
        let em = EmergencyMode::new();
        for _ in 0..3 {
            em.record_signing_failure();
        }
        em.record_signing_success();
        assert_eq!(
            em.consecutive_signing_failures.load(Ordering::SeqCst),
            0
        );
        assert!(!em.check_and_activate());
    }

    #[test]
    fn check_and_activate_idempotent() {
        let em = EmergencyMode::new();
        em.update_healthy_peers(0);
        assert!(em.check_and_activate());
        // Second call still returns true (already active)
        assert!(em.check_and_activate());
        assert!(em.is_active());
    }

    #[test]
    fn can_validate_tokens_always_true() {
        let em = EmergencyMode::new();
        assert!(em.can_validate_tokens());
        em.manual_activate();
        assert!(em.can_validate_tokens());
    }

    #[test]
    fn can_issue_tokens_false_when_active() {
        let em = EmergencyMode::new();
        assert!(em.can_issue_tokens());
        em.manual_activate();
        assert!(!em.can_issue_tokens());
    }

    #[test]
    fn emergency_reason_display() {
        assert_eq!(EmergencyReason::QuorumLoss.to_string(), "quorum_loss");
        assert_eq!(
            EmergencyReason::MassCompromise.to_string(),
            "mass_compromise"
        );
        assert_eq!(
            EmergencyReason::ManualTrigger.to_string(),
            "manual_trigger"
        );
        assert_eq!(
            EmergencyReason::DeadManSwitch.to_string(),
            "dead_man_switch"
        );
    }

    #[test]
    fn healthy_peers_above_threshold_no_emergency() {
        let em = EmergencyMode::new();
        em.update_healthy_peers(5);
        assert!(!em.check_and_activate());
        assert!(!em.is_active());
    }

    #[test]
    fn default_impl() {
        let em: EmergencyMode = Default::default();
        assert!(!em.is_active());
    }
}
