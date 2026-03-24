//! Concurrent session tracking — enforces max_concurrent_sessions_per_user.
#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::sync::Mutex;
use uuid::Uuid;

/// Tracks active sessions per user to enforce concurrency limits.
pub struct SessionTracker {
    /// Maps user_id -> set of active session IDs with their creation timestamps.
    active: Mutex<HashMap<Uuid, Vec<(Uuid, i64)>>>,
    /// Maximum concurrent sessions per user.
    max_per_user: u32,
}

impl SessionTracker {
    /// Create a new session tracker with the given per-user limit.
    pub fn new(max_per_user: u32) -> Self {
        Self {
            active: Mutex::new(HashMap::new()),
            max_per_user,
        }
    }

    /// Try to register a new session. Returns Ok(()) if within limits,
    /// Err with message if the user has too many active sessions.
    pub fn register_session(&self, user_id: Uuid, session_id: Uuid, now: i64) -> Result<(), String> {
        let mut active = self.active.lock().unwrap_or_else(|e| e.into_inner());
        let sessions = active.entry(user_id).or_default();

        // Evict sessions older than 8 hours (max session lifetime)
        const MAX_SESSION_AGE_SECS: i64 = 28800;
        let len_before = sessions.len();
        sessions.retain(|(_sid, created)| now - created < MAX_SESSION_AGE_SECS);
        let evicted_age = len_before - sessions.len();
        for _ in 0..evicted_age {
            crate::siem::SecurityEvent::session_expired(&user_id.to_string());
        }

        if sessions.len() >= self.max_per_user as usize {
            crate::siem::SecurityEvent::session_revoked(
                &user_id.to_string(),
                "concurrent session limit exceeded",
            );
            return Err(format!(
                "session limit exceeded: max {} concurrent sessions per user",
                self.max_per_user
            ));
        }

        sessions.push((session_id, now));
        crate::siem::SecurityEvent::session_created(
            &user_id.to_string(),
            "internal",
        );
        Ok(())
    }

    /// Remove a session (on logout or expiry).
    pub fn remove_session(&self, user_id: &Uuid, session_id: &Uuid) {
        let mut active = self.active.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(sessions) = active.get_mut(user_id) {
            sessions.retain(|(sid, _)| sid != session_id);
            if sessions.is_empty() {
                active.remove(user_id);
            }
        }
    }

    /// Get number of active sessions for a user.
    pub fn active_count(&self, user_id: &Uuid) -> usize {
        let active = self.active.lock().unwrap_or_else(|e| e.into_inner());
        active.get(user_id).map_or(0, |s| s.len())
    }

    /// Update the last-activity timestamp for a session.
    /// Returns true if the session was found and updated, false otherwise.
    pub fn touch_session(&self, user_id: &Uuid, session_id: &Uuid, now: i64) -> bool {
        let mut active = self.active.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(sessions) = active.get_mut(user_id) {
            for (sid, ts) in sessions.iter_mut() {
                if sid == session_id {
                    *ts = now;
                    return true;
                }
            }
        }
        false
    }

    /// Remove sessions that have been inactive for longer than `timeout_secs`.
    /// Returns the number of sessions removed.
    pub fn cleanup_inactive(&self, now: i64, timeout_secs: i64) -> usize {
        let mut active = self.active.lock().unwrap_or_else(|e| e.into_inner());
        let mut removed = 0usize;
        active.retain(|_user_id, sessions| {
            let before = sessions.len();
            sessions.retain(|(_sid, ts)| now - *ts < timeout_secs);
            removed += before - sessions.len();
            !sessions.is_empty()
        });
        removed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_touch_session_updates_timestamp() {
        let tracker = SessionTracker::new(5);
        let user = Uuid::new_v4();
        let session = Uuid::new_v4();
        tracker.register_session(user, session, 1000).unwrap();

        assert!(tracker.touch_session(&user, &session, 2000));
        // Session should not be cleaned up if touched recently
        let removed = tracker.cleanup_inactive(2500, 1000);
        assert_eq!(removed, 0);
        assert_eq!(tracker.active_count(&user), 1);
    }

    #[test]
    fn test_touch_session_returns_false_for_unknown() {
        let tracker = SessionTracker::new(5);
        let user = Uuid::new_v4();
        let session = Uuid::new_v4();
        assert!(!tracker.touch_session(&user, &session, 1000));
    }

    #[test]
    fn test_cleanup_inactive_removes_old_sessions() {
        let tracker = SessionTracker::new(5);
        let user = Uuid::new_v4();
        let s1 = Uuid::new_v4();
        let s2 = Uuid::new_v4();
        tracker.register_session(user, s1, 1000).unwrap();
        tracker.register_session(user, s2, 2000).unwrap();

        // At time 2500, with timeout 1000: s1 (age 1500) should be removed, s2 (age 500) stays
        let removed = tracker.cleanup_inactive(2500, 1000);
        assert_eq!(removed, 1);
        assert_eq!(tracker.active_count(&user), 1);
    }

    #[test]
    fn test_cleanup_inactive_removes_all_expired() {
        let tracker = SessionTracker::new(5);
        let user = Uuid::new_v4();
        let s1 = Uuid::new_v4();
        tracker.register_session(user, s1, 1000).unwrap();

        let removed = tracker.cleanup_inactive(5000, 1000);
        assert_eq!(removed, 1);
        assert_eq!(tracker.active_count(&user), 0);
    }

    #[test]
    fn test_cleanup_inactive_returns_zero_when_none_expired() {
        let tracker = SessionTracker::new(5);
        let user = Uuid::new_v4();
        let s1 = Uuid::new_v4();
        tracker.register_session(user, s1, 1000).unwrap();

        let removed = tracker.cleanup_inactive(1500, 1000);
        assert_eq!(removed, 0);
        assert_eq!(tracker.active_count(&user), 1);
    }
}
