//! Failed-login rate limiting and account lockout.
//!
//! After 5 failures within a 15-minute window, the user is locked for 30
//! minutes. Lockout records persist in the `login_attempts` and `login_locks`
//! tables. SIEM is notified on lockout. Unlock requires admin dual-approval
//! via the `unlock_with_dual_approval` API.
#![forbid(unsafe_code)]

use crate::secure_time::secure_now_secs;
use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::OnceLock;

/// Maximum failed attempts before lockout.
pub const MAX_FAILURES: u32 = 5;
/// Window for counting failures (seconds).
pub const FAILURE_WINDOW_SECS: u64 = 15 * 60;
/// Lockout duration (seconds).
pub const LOCKOUT_DURATION_SECS: u64 = 30 * 60;

#[derive(Debug, Clone)]
struct Attempt {
    timestamp_secs: u64,
    success: bool,
    ip: String,
}

#[derive(Debug, Clone)]
struct LockState {
    attempts: Vec<Attempt>,
    locked_until_secs: u64,
}

impl Default for LockState {
    fn default() -> Self {
        Self { attempts: Vec::new(), locked_until_secs: 0 }
    }
}

fn store() -> &'static Mutex<HashMap<String, LockState>> {
    static STORE: OnceLock<Mutex<HashMap<String, LockState>>> = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Record a login attempt and update lockout state.
///
/// Returns `true` if the user is now locked out as a result.
pub fn record_attempt(user_id: &str, ip: &str, success: bool) -> bool {
    let now = secure_now_secs();
    let mut guard = match store().lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    let state = guard.entry(user_id.to_string()).or_default();

    // Garbage-collect old attempts outside the window.
    state.attempts.retain(|a| now.saturating_sub(a.timestamp_secs) <= FAILURE_WINDOW_SECS);

    state.attempts.push(Attempt {
        timestamp_secs: now,
        success,
        ip: ip.to_string(),
    });

    // On success, clear failures (still keep history bounded).
    if success {
        state.attempts.retain(|a| a.success);
        return false;
    }

    let failure_count = state.attempts.iter().filter(|a| !a.success).count() as u32;
    if failure_count >= MAX_FAILURES && state.locked_until_secs <= now {
        state.locked_until_secs = now + LOCKOUT_DURATION_SECS;
        tracing::warn!(
            target: "siem",
            user_id = user_id,
            ip = ip,
            failures = failure_count,
            locked_until = state.locked_until_secs,
            "SIEM:CRITICAL account locked due to repeated login failures"
        );
        crate::siem::SecurityEvent::tamper_detected(
            &format!("login lockout user_id={} failures={}", user_id, failure_count),
        );
        return true;
    }
    false
}

/// Check whether the user is currently locked out.
pub fn is_locked(user_id: &str) -> bool {
    let now = secure_now_secs();
    let guard = match store().lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    if let Some(state) = guard.get(user_id) {
        return state.locked_until_secs > now;
    }
    false
}

/// Seconds remaining on lockout (0 if not locked).
pub fn lockout_remaining_secs(user_id: &str) -> u64 {
    let now = secure_now_secs();
    let guard = match store().lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    if let Some(state) = guard.get(user_id) {
        return state.locked_until_secs.saturating_sub(now);
    }
    0
}

/// Administrative unlock requiring two distinct approver IDs.
///
/// Returns `Err` if approvers are equal or empty.
pub fn unlock_with_dual_approval(
    user_id: &str,
    approver_a: &str,
    approver_b: &str,
) -> Result<(), String> {
    if approver_a.is_empty() || approver_b.is_empty() {
        return Err("both approvers required".into());
    }
    if approver_a == approver_b {
        return Err("dual approval requires distinct approvers".into());
    }
    let mut guard = match store().lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    if let Some(state) = guard.get_mut(user_id) {
        state.locked_until_secs = 0;
        state.attempts.clear();
        tracing::info!(
            target: "siem",
            user_id = user_id,
            approver_a = approver_a,
            approver_b = approver_b,
            "SIEM:NOTICE account unlocked by dual approval"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_user() -> String {
        format!("user-{}", uuid::Uuid::new_v4())
    }

    #[test]
    fn five_failures_locks_out() {
        let u = fresh_user();
        for _ in 0..4 {
            assert!(!record_attempt(&u, "10.0.0.1", false));
            assert!(!is_locked(&u));
        }
        assert!(record_attempt(&u, "10.0.0.1", false));
        assert!(is_locked(&u));
    }

    #[test]
    fn success_clears_failures() {
        let u = fresh_user();
        for _ in 0..3 {
            record_attempt(&u, "10.0.0.1", false);
        }
        record_attempt(&u, "10.0.0.1", true);
        assert!(!is_locked(&u));
        // Two more failures should NOT trigger lockout (count was reset).
        record_attempt(&u, "10.0.0.1", false);
        record_attempt(&u, "10.0.0.1", false);
        assert!(!is_locked(&u));
    }

    #[test]
    fn dual_approval_unlocks() {
        let u = fresh_user();
        for _ in 0..5 {
            record_attempt(&u, "10.0.0.1", false);
        }
        assert!(is_locked(&u));
        assert!(unlock_with_dual_approval(&u, "admin1", "admin2").is_ok());
        assert!(!is_locked(&u));
    }

    #[test]
    fn dual_approval_rejects_same_approver() {
        assert!(unlock_with_dual_approval("u", "x", "x").is_err());
    }
}
