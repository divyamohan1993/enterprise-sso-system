//! Ceremony state machine for auth orchestration.

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
