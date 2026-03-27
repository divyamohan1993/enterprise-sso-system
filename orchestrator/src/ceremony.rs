//! Ceremony state machine for auth orchestration.

use std::collections::HashMap;
use crypto::receipts::ReceiptChain;
use uuid::Uuid;

/// The possible states of a ceremony session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CeremonyState {
    PendingOpaque,
    PendingTss,
    Complete,
    Failed(String),
}

/// A ceremony session tracks the progress of one authentication attempt.
pub struct CeremonySession {
    pub session_id: [u8; 32],
    pub state: CeremonyState,
    pub user_id: Option<Uuid>,
    pub receipt_chain: ReceiptChain,
    pub created_at: i64,
}

/// Timeout for ceremony sessions in seconds.
pub const CEREMONY_TIMEOUT_SECS: i64 = 30;

/// Maximum total pending ceremonies system-wide (prevents memory exhaustion).
pub const MAX_PENDING_CEREMONIES: usize = 10_000;

/// Maximum pending ceremonies per user (prevents ceremony flooding).
pub const MAX_CEREMONIES_PER_USER: usize = 1;

/// Tracks active ceremony sessions with per-user limits and system-wide caps.
pub struct CeremonyTracker {
    /// All active ceremony sessions, keyed by session ID hex.
    sessions: HashMap<String, CeremonySession>,
    /// Per-user count of active (non-terminal) ceremonies.
    user_ceremony_count: HashMap<Uuid, usize>,
}

impl CeremonyTracker {
    /// Create a new empty ceremony tracker.
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            user_ceremony_count: HashMap::new(),
        }
    }

    /// Total number of active ceremonies.
    pub fn active_count(&self) -> usize {
        self.sessions.len()
    }

    /// Number of active ceremonies for a specific user.
    pub fn user_active_count(&self, user_id: &Uuid) -> usize {
        self.user_ceremony_count.get(user_id).copied().unwrap_or(0)
    }

    /// Try to register a new ceremony session for a user.
    ///
    /// Returns `Err` if:
    /// - The user already has `MAX_CEREMONIES_PER_USER` active ceremonies
    /// - The system-wide `MAX_PENDING_CEREMONIES` limit is reached
    ///
    /// The old ceremony is cancelled if the user already has one and we allow
    /// replacement (cancel-and-replace strategy).
    pub fn create_ceremony(
        &mut self,
        session: CeremonySession,
        user_id: Option<Uuid>,
    ) -> Result<(), String> {
        // System-wide cap
        if self.sessions.len() >= MAX_PENDING_CEREMONIES {
            tracing::error!(
                total = self.sessions.len(),
                limit = MAX_PENDING_CEREMONIES,
                "SIEM:WARN ceremony creation rejected: system-wide limit reached"
            );
            return Err("system-wide ceremony limit reached".into());
        }

        // Per-user cap: cancel existing ceremony if the user already has one
        if let Some(uid) = user_id {
            let count = self.user_active_count(&uid);
            if count >= MAX_CEREMONIES_PER_USER {
                // Cancel the user's existing ceremonies to allow the new one
                let to_remove: Vec<String> = self.sessions.iter()
                    .filter(|(_, s)| s.user_id == Some(uid) && !is_terminal(&s.state))
                    .map(|(k, _)| k.clone())
                    .collect();
                for key in &to_remove {
                    tracing::warn!(
                        session_id = %key,
                        user_id = %uid,
                        "cancelling stale ceremony for user (replaced by new ceremony)"
                    );
                    self.sessions.remove(key);
                }
                if let Some(c) = self.user_ceremony_count.get_mut(&uid) {
                    *c = c.saturating_sub(to_remove.len());
                }
            }
        }

        let session_hex = short_session_hex(&session.session_id);
        if let Some(uid) = user_id {
            *self.user_ceremony_count.entry(uid).or_insert(0) += 1;
        }
        self.sessions.insert(session_hex, session);
        Ok(())
    }

    /// Mark a ceremony as complete or failed and update user counts.
    pub fn finish_ceremony(&mut self, session_hex: &str) {
        if let Some(session) = self.sessions.remove(session_hex) {
            if let Some(uid) = session.user_id {
                if let Some(c) = self.user_ceremony_count.get_mut(&uid) {
                    *c = c.saturating_sub(1);
                    if *c == 0 {
                        self.user_ceremony_count.remove(&uid);
                    }
                }
            }
        }
    }

    /// Get a mutable reference to a session by hex ID.
    pub fn get_mut(&mut self, session_hex: &str) -> Option<&mut CeremonySession> {
        self.sessions.get_mut(session_hex)
    }

    /// Get an immutable reference to a session by hex ID.
    pub fn get(&self, session_hex: &str) -> Option<&CeremonySession> {
        self.sessions.get(session_hex)
    }

    /// Remove all expired and timed-out ceremonies.
    /// Returns the number of ceremonies cleaned up.
    pub fn cleanup_expired(&mut self) -> usize {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let to_remove: Vec<String> = self.sessions.iter()
            .filter(|(_, s)| (now - s.created_at) > CEREMONY_TIMEOUT_SECS)
            .map(|(k, _)| k.clone())
            .collect();

        let count = to_remove.len();
        for key in to_remove {
            if let Some(session) = self.sessions.remove(&key) {
                tracing::warn!(
                    session_id = %key,
                    age_secs = now - session.created_at,
                    "ceremony cleanup: removing timed-out session"
                );
                if let Some(uid) = session.user_id {
                    if let Some(c) = self.user_ceremony_count.get_mut(&uid) {
                        *c = c.saturating_sub(1);
                        if *c == 0 {
                            self.user_ceremony_count.remove(&uid);
                        }
                    }
                }
            }
        }

        if count > 0 {
            tracing::info!(
                removed = count,
                remaining = self.sessions.len(),
                "ceremony cleanup completed"
            );
        }
        count
    }

    /// Spawn a background task that periodically cleans up timed-out ceremonies.
    pub fn spawn_cleanup_task(tracker: std::sync::Arc<tokio::sync::Mutex<Self>>) {
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                let mut t = tracker.lock().await;
                t.cleanup_expired();
            }
        });
    }
}

/// Check whether a ceremony state is terminal (Complete or Failed).
fn is_terminal(state: &CeremonyState) -> bool {
    matches!(state, CeremonyState::Complete | CeremonyState::Failed(_))
}

/// Format the first 8 bytes of a session ID as a hex string for logging.
fn short_session_hex(session_id: &[u8; 32]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        session_id[0], session_id[1], session_id[2], session_id[3],
        session_id[4], session_id[5], session_id[6], session_id[7],
    )
}

impl CeremonySession {
    /// Create a new ceremony session in the `PendingOpaque` state.
    pub fn new(session_id: [u8; 32]) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        tracing::info!(
            session_id = %short_session_hex(&session_id),
            "Ceremony started: state=PendingOpaque"
        );

        Self {
            receipt_chain: ReceiptChain::new(session_id),
            session_id,
            state: CeremonyState::PendingOpaque,
            user_id: None,
            created_at: now,
        }
    }

    /// Check whether this session has expired.
    pub fn is_expired(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let expired = (now - self.created_at) > CEREMONY_TIMEOUT_SECS;
        if expired {
            tracing::warn!(
                session_id = %short_session_hex(&self.session_id),
                age_secs = now - self.created_at,
                timeout_secs = CEREMONY_TIMEOUT_SECS,
                "Ceremony timeout: session exceeded maximum lifetime"
            );
        }
        expired
    }

    /// Transition from `PendingOpaque` to `PendingTss` after receiving an
    /// OPAQUE receipt.
    pub fn opaque_complete(&mut self) -> Result<(), String> {
        match &self.state {
            CeremonyState::PendingOpaque => {
                tracing::info!(
                    session_id = %short_session_hex(&self.session_id),
                    "Ceremony transition: PendingOpaque -> PendingTss"
                );
                self.state = CeremonyState::PendingTss;
                Ok(())
            }
            other => {
                tracing::warn!(
                    session_id = %short_session_hex(&self.session_id),
                    current_state = ?other,
                    "Ceremony invalid transition: cannot move to PendingTss from current state"
                );
                Err(format!(
                    "invalid transition: cannot move from {:?} to PendingTss",
                    other
                ))
            }
        }
    }

    /// Transition from `PendingTss` to `Complete` after receiving a signed
    /// token from the TSS.
    pub fn tss_complete(&mut self) -> Result<(), String> {
        match &self.state {
            CeremonyState::PendingTss => {
                tracing::info!(
                    session_id = %short_session_hex(&self.session_id),
                    user_id = ?self.user_id,
                    "Ceremony complete: PendingTss -> Complete"
                );
                self.state = CeremonyState::Complete;
                Ok(())
            }
            other => {
                tracing::warn!(
                    session_id = %short_session_hex(&self.session_id),
                    current_state = ?other,
                    "Ceremony invalid transition: cannot move to Complete from current state"
                );
                Err(format!(
                    "invalid transition: cannot move from {:?} to Complete",
                    other
                ))
            }
        }
    }

    /// Transition to the `Failed` state from any non-terminal state.
    pub fn fail(&mut self, reason: String) -> Result<(), String> {
        match &self.state {
            CeremonyState::Complete => {
                tracing::warn!(
                    session_id = %short_session_hex(&self.session_id),
                    reason = %reason,
                    "Ceremony fail rejected: cannot fail an already-completed ceremony"
                );
                Err("cannot fail an already-completed ceremony".into())
            }
            CeremonyState::Failed(_) => {
                tracing::warn!(
                    session_id = %short_session_hex(&self.session_id),
                    reason = %reason,
                    "Ceremony fail rejected: ceremony has already failed"
                );
                Err("ceremony has already failed".into())
            }
            other => {
                tracing::warn!(
                    session_id = %short_session_hex(&self.session_id),
                    previous_state = ?other,
                    reason = %reason,
                    "Ceremony failed"
                );
                self.state = CeremonyState::Failed(reason);
                Ok(())
            }
        }
    }
}
