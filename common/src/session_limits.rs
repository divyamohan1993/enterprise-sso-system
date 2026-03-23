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
        sessions.retain(|(_sid, created)| now - created < MAX_SESSION_AGE_SECS);

        if sessions.len() >= self.max_per_user as usize {
            return Err(format!(
                "session limit exceeded: max {} concurrent sessions per user",
                self.max_per_user
            ));
        }

        sessions.push((session_id, now));
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
}
