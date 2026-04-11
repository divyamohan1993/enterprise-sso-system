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
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

/// Default path for persisted emergency mode state.
const DEFAULT_EMERGENCY_STATE_PATH: &str = "/var/lib/milnet/emergency_mode.json";

/// Get the configured emergency state file path.
fn emergency_state_path() -> String {
    std::env::var("MILNET_EMERGENCY_STATE_PATH")
        .unwrap_or_else(|_| DEFAULT_EMERGENCY_STATE_PATH.to_string())
}

/// Persisted emergency mode state written to disk.
#[derive(serde::Serialize, serde::Deserialize)]
struct PersistedEmergencyState {
    active: bool,
    reason: u8,
    activated_at_micros: u64,
}

/// Persist emergency mode state to disk using atomic write (tmp+fsync+rename).
fn persist_emergency_state(active: bool, reason: u8, activated_at_micros: u64) {
    let state = PersistedEmergencyState { active, reason, activated_at_micros };
    let path = emergency_state_path();
    let tmp = format!("{path}.tmp");
    let json = match serde_json::to_string(&state) {
        Ok(j) => j,
        Err(e) => {
            tracing::error!("failed to serialize emergency state: {e}");
            return;
        }
    };
    // Ensure parent directory exists
    if let Some(parent) = std::path::Path::new(&path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(mut f) = std::fs::File::create(&tmp) {
        use std::io::Write;
        if f.write_all(json.as_bytes()).is_ok() && f.sync_all().is_ok() {
            let _ = std::fs::rename(&tmp, &path);
        }
    }
}

/// Load persisted emergency state from disk. Returns None if file doesn't exist.
fn load_emergency_state() -> Option<PersistedEmergencyState> {
    let path = emergency_state_path();
    let data = std::fs::read_to_string(&path).ok()?;
    serde_json::from_str(&data).ok()
}

/// Remove the persisted emergency state file.
fn clear_emergency_state() {
    let path = emergency_state_path();
    let _ = std::fs::remove_file(&path);
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Consecutive Raft election failures before emergency activation.
const ELECTION_FAILURE_THRESHOLD: u32 = 5;

/// Consecutive FROST signing failures before emergency activation.
const SIGNING_FAILURE_THRESHOLD: u32 = 3;

/// Default minimum healthy peers required (below this = emergency).
/// Configurable via `MILNET_MIN_HEALTHY_PEERS` environment variable.
const DEFAULT_MIN_HEALTHY_PEERS: u32 = 3;

/// Minimum healthy peers required (below this = emergency).
/// Configurable via `MILNET_MIN_HEALTHY_PEERS` environment variable at startup.
fn min_healthy_peers() -> u32 {
    static CACHED: OnceLock<u32> = OnceLock::new();
    *CACHED.get_or_init(|| {
        match std::env::var("MILNET_MIN_HEALTHY_PEERS") {
            Ok(val) => match val.parse::<u32>() {
                Ok(v) if v >= 1 => {
                    tracing::info!(
                        min_healthy_peers = v,
                        "MIN_HEALTHY_PEERS configured from environment"
                    );
                    v
                }
                Ok(0) => {
                    tracing::error!(
                        "MILNET_MIN_HEALTHY_PEERS=0 is invalid (must be >= 1), using default 3"
                    );
                    DEFAULT_MIN_HEALTHY_PEERS
                }
                _ => {
                    tracing::error!(
                        value = %val,
                        "MILNET_MIN_HEALTHY_PEERS invalid, using default 3"
                    );
                    DEFAULT_MIN_HEALTHY_PEERS
                }
            },
            Err(_) => DEFAULT_MIN_HEALTHY_PEERS,
        }
    })
}

/// Dead man switch timeout: 5 minutes with no valid peer heartbeat.
const DEAD_MAN_SWITCH_TIMEOUT: Duration = Duration::from_secs(300);

/// Minimum time emergency mode must be active before deactivation (prevent flip-flop).
const DEACTIVATION_COOLDOWN: Duration = Duration::from_secs(30);

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

impl EmergencyReason {
    fn to_u8(self) -> u8 {
        match self {
            Self::QuorumLoss => 1,
            Self::MassCompromise => 2,
            Self::ManualTrigger => 3,
            Self::DeadManSwitch => 4,
        }
    }

    fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::QuorumLoss),
            2 => Some(Self::MassCompromise),
            3 => Some(Self::ManualTrigger),
            4 => Some(Self::DeadManSwitch),
            _ => None,
        }
    }
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
/// locks. Activation time and reason are stored as atomics to support
/// deactivation and re-activation without requiring process restart.
pub struct EmergencyMode {
    /// Whether emergency mode is currently active.
    active: AtomicBool,
    /// Microseconds since UNIX_EPOCH when emergency mode was activated (0 = not activated).
    activated_at_micros: AtomicU64,
    /// Reason for activation as u8 (0 = None, 1-4 = reason variants).
    reason: AtomicU8,
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
    /// Create a new emergency mode tracker.
    /// Restores persisted state from disk if available: if emergency mode was
    /// active when the process last exited, it will be re-entered on startup.
    pub fn new() -> Self {
        let deadline = Self::micros_from_now(DEAD_MAN_SWITCH_TIMEOUT);
        let em = Self {
            active: AtomicBool::new(false),
            activated_at_micros: AtomicU64::new(0),
            reason: AtomicU8::new(0),
            consecutive_election_failures: AtomicU32::new(0),
            consecutive_signing_failures: AtomicU32::new(0),
            healthy_peer_count: AtomicU32::new(min_healthy_peers()),
            dead_man_switch_deadline: AtomicU64::new(deadline),
        };

        // Restore persisted state from disk
        if let Some(state) = load_emergency_state() {
            if state.active {
                em.active.store(true, Ordering::SeqCst);
                em.activated_at_micros.store(state.activated_at_micros, Ordering::SeqCst);
                em.reason.store(state.reason, Ordering::SeqCst);
                let reason_name = EmergencyReason::from_u8(state.reason)
                    .map(|r| r.to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                tracing::warn!(
                    reason = %reason_name,
                    "EMERGENCY MODE RESTORED from persisted state on startup"
                );
            }
        }

        em
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
        } else if peers < min_healthy_peers() {
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

    /// Core activation logic. Idempotent if already active: does not overwrite reason/time.
    fn activate(&self, reason: EmergencyReason) {
        let was_active = self.active.swap(true, Ordering::SeqCst);
        if !was_active {
            let now = Self::now_micros();
            self.activated_at_micros.store(now, Ordering::SeqCst);
            self.reason.store(reason.to_u8(), Ordering::SeqCst);
            // Persist to disk so state survives restarts
            persist_emergency_state(true, reason.to_u8(), now);
        }

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
        EmergencyReason::from_u8(self.reason.load(Ordering::SeqCst))
    }

    /// Get the activation time as microseconds since UNIX_EPOCH (0 = not activated).
    pub fn activated_at_micros(&self) -> u64 {
        self.activated_at_micros.load(Ordering::SeqCst)
    }

    /// Try to deactivate emergency mode.
    ///
    /// Succeeds only when ALL of the following hold:
    /// - Emergency mode is currently active
    /// - Reason is NOT `ManualTrigger` (use `manual_deactivate` for that)
    /// - All conditions are resolved: election_failures == 0, signing_failures == 0,
    ///   healthy_peers >= min_healthy_peers()
    /// - Emergency has been active for at least 30 seconds (cooldown)
    ///
    /// Returns `true` if deactivation succeeded.
    pub fn try_deactivate(&self) -> bool {
        if !self.active.load(Ordering::SeqCst) {
            return false;
        }

        // ManualTrigger requires explicit manual_deactivate
        let reason_val = self.reason.load(Ordering::SeqCst);
        if reason_val == EmergencyReason::ManualTrigger.to_u8() {
            return false;
        }

        // Check all conditions resolved
        let election_fails = self.consecutive_election_failures.load(Ordering::SeqCst);
        let signing_fails = self.consecutive_signing_failures.load(Ordering::SeqCst);
        let peers = self.healthy_peer_count.load(Ordering::SeqCst);

        if election_fails != 0 || signing_fails != 0 || peers < min_healthy_peers() {
            return false;
        }

        // Cooldown: must be active for at least DEACTIVATION_COOLDOWN
        let activated = self.activated_at_micros.load(Ordering::SeqCst);
        let now = Self::now_micros();
        let cooldown_micros = DEACTIVATION_COOLDOWN.as_micros() as u64;
        if now.saturating_sub(activated) < cooldown_micros {
            return false;
        }

        self.do_deactivate();
        true
    }

    /// Explicitly deactivate a `ManualTrigger` emergency (or any reason).
    /// Bypasses condition checks but still enforces the 30s cooldown.
    pub fn manual_deactivate(&self) -> bool {
        if !self.active.load(Ordering::SeqCst) {
            return false;
        }

        let activated = self.activated_at_micros.load(Ordering::SeqCst);
        let now = Self::now_micros();
        let cooldown_micros = DEACTIVATION_COOLDOWN.as_micros() as u64;
        if now.saturating_sub(activated) < cooldown_micros {
            return false;
        }

        self.do_deactivate();
        true
    }

    /// Check conditions and deactivate if possible.
    /// Returns `true` if emergency mode was deactivated.
    pub fn check_and_maybe_deactivate(&self) -> bool {
        if !self.active.load(Ordering::SeqCst) {
            return false;
        }
        self.try_deactivate()
    }

    /// Internal deactivation: reset all state, clear persisted state, and emit SIEM event.
    fn do_deactivate(&self) {
        let reason_val = self.reason.load(Ordering::SeqCst);
        let reason_name = EmergencyReason::from_u8(reason_val)
            .map(|r| r.to_string())
            .unwrap_or_else(|| "unknown".to_string());

        self.active.store(false, Ordering::SeqCst);
        self.activated_at_micros.store(0, Ordering::SeqCst);
        self.reason.store(0, Ordering::SeqCst);

        // Clear persisted state from disk
        clear_emergency_state();

        // Reset dead man switch deadline
        let new_deadline = Self::micros_from_now(DEAD_MAN_SWITCH_TIMEOUT);
        self.dead_man_switch_deadline.store(new_deadline, Ordering::SeqCst);

        PanelSiemEvent::new(
            SiemPanel::ThresholdViolations,
            SiemSeverity::Critical,
            "emergency_mode_deactivated",
            format!(
                "EMERGENCY MODE DEACTIVATED: previous_reason={}, election_fails={}, signing_fails={}, healthy_peers={}",
                reason_name,
                self.consecutive_election_failures.load(Ordering::SeqCst),
                self.consecutive_signing_failures.load(Ordering::SeqCst),
                self.healthy_peer_count.load(Ordering::SeqCst),
            ),
            file!(),
            line!(),
            module_path!(),
        )
        .emit();

        tracing::info!(
            previous_reason = %reason_name,
            "EMERGENCY MODE DEACTIVATED: node resuming normal operation"
        );
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
        assert_eq!(em.activated_at_micros(), 0);
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
        em.update_healthy_peers(2); // below DEFAULT_MIN_HEALTHY_PEERS (3)
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

    // -- Deactivation tests --

    #[test]
    fn deactivation_succeeds_when_conditions_resolved() {
        let em = EmergencyMode::new();
        // Activate via low peers
        em.update_healthy_peers(1);
        assert!(em.check_and_activate());
        assert!(em.is_active());

        // Resolve all conditions
        em.consecutive_election_failures.store(0, Ordering::SeqCst);
        em.consecutive_signing_failures.store(0, Ordering::SeqCst);
        em.update_healthy_peers(DEFAULT_MIN_HEALTHY_PEERS);

        // Simulate cooldown elapsed: set activated_at to 31 seconds ago
        let past = EmergencyMode::now_micros()
            .saturating_sub(Duration::from_secs(31).as_micros() as u64);
        em.activated_at_micros.store(past, Ordering::SeqCst);

        assert!(em.try_deactivate());
        assert!(!em.is_active());
        assert!(em.can_issue_tokens());
        assert!(em.reason().is_none());
        assert_eq!(em.activated_at_micros(), 0);
    }

    #[test]
    fn deactivation_fails_when_conditions_not_resolved() {
        let em = EmergencyMode::new();
        em.update_healthy_peers(1);
        assert!(em.check_and_activate());

        // Conditions NOT resolved: still low peers
        let past = EmergencyMode::now_micros()
            .saturating_sub(Duration::from_secs(31).as_micros() as u64);
        em.activated_at_micros.store(past, Ordering::SeqCst);

        assert!(!em.try_deactivate());
        assert!(em.is_active());

        // Fix peers but leave election failures
        em.update_healthy_peers(DEFAULT_MIN_HEALTHY_PEERS);
        em.consecutive_election_failures.store(1, Ordering::SeqCst);
        assert!(!em.try_deactivate());
        assert!(em.is_active());

        // Fix election failures but leave signing failures
        em.consecutive_election_failures.store(0, Ordering::SeqCst);
        em.consecutive_signing_failures.store(1, Ordering::SeqCst);
        assert!(!em.try_deactivate());
        assert!(em.is_active());
    }

    #[test]
    fn deactivation_fails_within_cooldown() {
        let em = EmergencyMode::new();
        em.update_healthy_peers(1);
        assert!(em.check_and_activate());

        // Resolve conditions but do NOT bypass cooldown
        em.consecutive_election_failures.store(0, Ordering::SeqCst);
        em.consecutive_signing_failures.store(0, Ordering::SeqCst);
        em.update_healthy_peers(DEFAULT_MIN_HEALTHY_PEERS);

        // activated_at is "now", so cooldown has not elapsed
        assert!(!em.try_deactivate());
        assert!(em.is_active());
    }

    #[test]
    fn reactivation_after_deactivation() {
        let em = EmergencyMode::new();
        // First activation
        em.update_healthy_peers(1);
        assert!(em.check_and_activate());
        assert_eq!(em.reason(), Some(EmergencyReason::QuorumLoss));

        // Resolve and deactivate
        em.consecutive_election_failures.store(0, Ordering::SeqCst);
        em.consecutive_signing_failures.store(0, Ordering::SeqCst);
        em.update_healthy_peers(DEFAULT_MIN_HEALTHY_PEERS);
        let past = EmergencyMode::now_micros()
            .saturating_sub(Duration::from_secs(31).as_micros() as u64);
        em.activated_at_micros.store(past, Ordering::SeqCst);
        assert!(em.try_deactivate());
        assert!(!em.is_active());

        // Re-activate with a different trigger
        em.consecutive_signing_failures.store(4, Ordering::SeqCst);
        assert!(em.check_and_activate());
        assert!(em.is_active());
        assert_eq!(em.reason(), Some(EmergencyReason::QuorumLoss));
        assert_ne!(em.activated_at_micros(), 0);
    }

    #[test]
    fn cannot_deactivate_manual_trigger() {
        let em = EmergencyMode::new();
        em.manual_activate();
        assert!(em.is_active());
        assert_eq!(em.reason(), Some(EmergencyReason::ManualTrigger));

        // Resolve all conditions and bypass cooldown
        em.consecutive_election_failures.store(0, Ordering::SeqCst);
        em.consecutive_signing_failures.store(0, Ordering::SeqCst);
        em.update_healthy_peers(DEFAULT_MIN_HEALTHY_PEERS);
        let past = EmergencyMode::now_micros()
            .saturating_sub(Duration::from_secs(31).as_micros() as u64);
        em.activated_at_micros.store(past, Ordering::SeqCst);

        // try_deactivate must refuse ManualTrigger
        assert!(!em.try_deactivate());
        assert!(em.is_active());

        // check_and_maybe_deactivate also refuses
        assert!(!em.check_and_maybe_deactivate());
        assert!(em.is_active());
    }

    #[test]
    fn manual_deactivate_works() {
        let em = EmergencyMode::new();
        em.manual_activate();
        assert!(em.is_active());

        // Bypass cooldown
        let past = EmergencyMode::now_micros()
            .saturating_sub(Duration::from_secs(31).as_micros() as u64);
        em.activated_at_micros.store(past, Ordering::SeqCst);

        assert!(em.manual_deactivate());
        assert!(!em.is_active());
        assert!(em.can_issue_tokens());
        assert!(em.reason().is_none());
    }

    #[test]
    fn manual_deactivate_respects_cooldown() {
        let em = EmergencyMode::new();
        em.manual_activate();
        // No cooldown bypass - should fail
        assert!(!em.manual_deactivate());
        assert!(em.is_active());
    }

    #[test]
    fn check_and_maybe_deactivate_when_inactive() {
        let em = EmergencyMode::new();
        assert!(!em.check_and_maybe_deactivate());
    }

    #[test]
    fn deactivation_resets_dead_man_switch() {
        let em = EmergencyMode::new();
        em.update_healthy_peers(1);
        assert!(em.check_and_activate());

        // Set dead man switch to past
        em.dead_man_switch_deadline.store(0, Ordering::SeqCst);

        // Resolve and deactivate
        em.consecutive_election_failures.store(0, Ordering::SeqCst);
        em.consecutive_signing_failures.store(0, Ordering::SeqCst);
        em.update_healthy_peers(DEFAULT_MIN_HEALTHY_PEERS);
        let past = EmergencyMode::now_micros()
            .saturating_sub(Duration::from_secs(31).as_micros() as u64);
        em.activated_at_micros.store(past, Ordering::SeqCst);
        assert!(em.try_deactivate());

        // Dead man switch should be reset to future, so tick should NOT fire
        em.dead_man_switch_tick();
        assert!(!em.is_active());
    }

    #[test]
    fn persistence_survives_restart() {
        // Use a temp file for this test
        let dir = std::env::temp_dir().join("milnet_emergency_test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("emergency_mode.json");
        std::env::set_var("MILNET_EMERGENCY_STATE_PATH", path.to_str().unwrap());

        // Clean up any prior state
        let _ = std::fs::remove_file(&path);

        // Activate emergency mode
        {
            let em = EmergencyMode::new();
            assert!(!em.is_active());
            em.manual_activate();
            assert!(em.is_active());
            assert_eq!(em.reason(), Some(EmergencyReason::ManualTrigger));
        }

        // "Restart" by creating a new instance -- should restore state
        {
            let em = EmergencyMode::new();
            assert!(em.is_active(), "emergency mode should be restored from disk");
            assert_eq!(em.reason(), Some(EmergencyReason::ManualTrigger));

            // Deactivate
            let past = EmergencyMode::now_micros()
                .saturating_sub(Duration::from_secs(31).as_micros() as u64);
            em.activated_at_micros.store(past, Ordering::SeqCst);
            assert!(em.manual_deactivate());
            assert!(!em.is_active());
        }

        // After deactivation, restart should not re-enter emergency mode
        {
            let em = EmergencyMode::new();
            assert!(!em.is_active(), "emergency mode should not restore after deactivation");
        }

        // Clean up
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
        std::env::remove_var("MILNET_EMERGENCY_STATE_PATH");
    }

    #[test]
    fn min_healthy_peers_default_is_three() {
        assert_eq!(DEFAULT_MIN_HEALTHY_PEERS, 3);
    }

    #[test]
    fn emergency_mode_respects_default_min_peers() {
        let em = EmergencyMode::new();
        em.update_healthy_peers(DEFAULT_MIN_HEALTHY_PEERS);
        assert!(!em.check_and_activate());

        em.update_healthy_peers(DEFAULT_MIN_HEALTHY_PEERS - 1);
        assert!(em.check_and_activate());
    }
}
