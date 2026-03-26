//! Concurrent session tracking — enforces max_concurrent_sessions_per_user.
#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::sync::Mutex;
use uuid::Uuid;

/// Session metadata with timestamps for both creation and last activity.
struct SessionEntry {
    session_id: Uuid,
    created_at: i64,
    last_activity: i64,
}

/// Tracks active sessions per user to enforce concurrency limits.
pub struct SessionTracker {
    /// Maps user_id -> set of active session IDs with their creation timestamps.
    active: Mutex<HashMap<Uuid, Vec<SessionEntry>>>,
    /// Maximum concurrent sessions per user.
    max_per_user: u32,
}

impl SessionTracker {
    /// Maximum idle time before session eviction (30 minutes).
    const IDLE_TIMEOUT_SECS: i64 = 1800;

    /// Create a new session tracker with the given per-user limit.
    pub fn new(max_per_user: u32) -> Self {
        Self {
            active: Mutex::new(HashMap::new()),
            max_per_user,
        }
    }

    /// Try to register a new session. Returns Ok(()) if within limits,
    /// Err with message if the user has too many active sessions.
    // SECURITY: The mutex MUST be held continuously from the length check through
    // the push to prevent TOCTOU race conditions on session limits.
    pub fn register_session(&self, user_id: Uuid, session_id: Uuid, now: i64) -> Result<(), String> {
        let mut active = self.active.lock().unwrap_or_else(|e| {
            tracing::error!(
                target: "siem",
                category = "security",
                action = "mutex_poisoning_recovered",
                "SessionTracker mutex poisoned — recovering with inner data. \
                 A thread panicked while holding this lock."
            );
            e.into_inner()
        });
        let sessions = active.entry(user_id).or_default();

        // Evict sessions older than 8 hours (max session lifetime)
        const MAX_SESSION_AGE_SECS: i64 = 28800;
        let len_before = sessions.len();
        sessions.retain(|entry| {
            now - entry.created_at < MAX_SESSION_AGE_SECS && now - entry.last_activity < Self::IDLE_TIMEOUT_SECS
        });
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

        sessions.push(SessionEntry { session_id, created_at: now, last_activity: now });
        // Defense-in-depth: verify limit was not violated despite mutex protection
        assert!(
            sessions.len() <= self.max_per_user as usize + 1,
            "session limit invariant violated: {} sessions for user {}",
            sessions.len(), user_id
        );
        crate::siem::SecurityEvent::session_created(
            &user_id.to_string(),
            "internal",
        );
        Ok(())
    }

    /// Remove a session (on logout or expiry).
    pub fn remove_session(&self, user_id: &Uuid, session_id: &Uuid) {
        let mut active = self.active.lock().unwrap_or_else(|e| {
            tracing::error!(
                target: "siem",
                category = "security",
                action = "mutex_poisoning_recovered",
                "SessionTracker mutex poisoned — recovering with inner data. \
                 A thread panicked while holding this lock."
            );
            e.into_inner()
        });
        if let Some(sessions) = active.get_mut(user_id) {
            sessions.retain(|entry| &entry.session_id != session_id);
            if sessions.is_empty() {
                active.remove(user_id);
            }
        }
    }

    /// Get number of active sessions for a user.
    pub fn active_count(&self, user_id: &Uuid) -> usize {
        let active = self.active.lock().unwrap_or_else(|e| {
            tracing::error!(
                target: "siem",
                category = "security",
                action = "mutex_poisoning_recovered",
                "SessionTracker mutex poisoned — recovering with inner data. \
                 A thread panicked while holding this lock."
            );
            e.into_inner()
        });
        active.get(user_id).map_or(0, |s| s.len())
    }

    /// Check if a session has exceeded the idle timeout without being touched.
    /// Returns true if the session is idle (last activity > 30 minutes ago) or unknown.
    pub fn is_session_idle(&self, user_id: &Uuid, session_id: &Uuid, now: i64) -> bool {
        let active = self.active.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(sessions) = active.get(user_id) {
            for entry in sessions {
                if &entry.session_id == session_id {
                    return (now - entry.last_activity) > Self::IDLE_TIMEOUT_SECS;
                }
            }
        }
        true // Unknown session = expired
    }

    /// Update the last-activity timestamp for a session (call on each API request).
    pub fn touch_session(&self, user_id: &Uuid, session_id: &Uuid, now: i64) {
        let mut active = self.active.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(sessions) = active.get_mut(user_id) {
            for entry in sessions.iter_mut() {
                if &entry.session_id == session_id {
                    entry.last_activity = now;
                    return;
                }
            }
        }
    }

    /// Returns the total number of active sessions across all users.
    pub fn total_active_count(&self) -> usize {
        let active = self.active.lock().unwrap_or_else(|e| e.into_inner());
        active.values().map(|v| v.len()).sum()
    }

    /// Remove all sessions for a user. Used for account deletion (GDPR Article 17).
    pub fn remove_all_sessions(&self, user_id: &Uuid) {
        let mut active = self.active.lock().unwrap_or_else(|e| e.into_inner());
        active.remove(user_id);
    }

    /// Persist all active sessions to a JSONL file for crash recovery.
    /// Called periodically or on graceful shutdown.
    pub fn persist_to_file(&self, path: &std::path::Path) -> Result<(), String> {
        let active = self.active.lock().unwrap_or_else(|e| e.into_inner());
        let file = std::fs::File::create(path)
            .map_err(|e| format!("failed to create session file: {e}"))?;
        let mut writer = std::io::BufWriter::new(file);

        for (user_id, sessions) in active.iter() {
            for entry in sessions {
                let record = serde_json::json!({
                    "user_id": user_id.to_string(),
                    "session_id": entry.session_id.to_string(),
                    "created_at": entry.created_at,
                    "last_activity": entry.last_activity,
                });
                if let Err(e) = serde_json::to_writer(&mut writer, &record) {
                    tracing::warn!("Failed to persist session entry: {e}");
                }
                use std::io::Write;
                let _ = writer.write_all(b"\n");
            }
        }
        Ok(())
    }

    /// Load sessions from a persistence file on startup.
    pub fn load_from_file(&self, path: &std::path::Path, now: i64) -> usize {
        let file = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(_) => return 0,
        };
        let reader = std::io::BufReader::new(file);
        let mut loaded = 0usize;

        use std::io::BufRead;
        for line in reader.lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => continue,
            };
            if let Ok(record) = serde_json::from_str::<serde_json::Value>(&line) {
                let user_id = record["user_id"].as_str()
                    .and_then(|s| uuid::Uuid::parse_str(s).ok());
                let session_id = record["session_id"].as_str()
                    .and_then(|s| uuid::Uuid::parse_str(s).ok());
                let created_at = record["created_at"].as_i64().unwrap_or(0);
                let last_activity = record["last_activity"].as_i64().unwrap_or(0);

                if let (Some(uid), Some(sid)) = (user_id, session_id) {
                    // Only load sessions that haven't expired
                    if now - created_at < 28800 && now - last_activity < 1800 {
                        let _ = self.register_session(uid, sid, created_at);
                        loaded += 1;
                    }
                }
            }
        }
        loaded
    }

    /// Remove sessions that have been inactive for longer than `timeout_secs`.
    /// Returns the number of sessions removed.
    pub fn cleanup_inactive(&self, now: i64, timeout_secs: i64) -> usize {
        let mut active = self.active.lock().unwrap_or_else(|e| {
            tracing::error!(
                target: "siem",
                category = "security",
                action = "mutex_poisoning_recovered",
                "SessionTracker mutex poisoned — recovering with inner data. \
                 A thread panicked while holding this lock."
            );
            e.into_inner()
        });
        let mut removed = 0usize;
        active.retain(|_user_id, sessions| {
            let before = sessions.len();
            sessions.retain(|entry| now - entry.last_activity < timeout_secs);
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

        tracker.touch_session(&user, &session, 2000);
        // Session should not be cleaned up if touched recently
        let removed = tracker.cleanup_inactive(2500, 1000);
        assert_eq!(removed, 0);
        assert_eq!(tracker.active_count(&user), 1);
    }

    #[test]
    fn test_touch_session_noop_for_unknown() {
        let tracker = SessionTracker::new(5);
        let user = Uuid::new_v4();
        let session = Uuid::new_v4();
        tracker.touch_session(&user, &session, 1000);
        // No panic, no-op for unknown session
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
