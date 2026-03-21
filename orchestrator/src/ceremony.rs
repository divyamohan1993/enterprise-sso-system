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

impl CeremonySession {
    /// Create a new ceremony session in the `PendingOpaque` state.
    pub fn new(session_id: [u8; 32]) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
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
        (now - self.created_at) > CEREMONY_TIMEOUT_SECS
    }

    /// Transition from `PendingOpaque` to `PendingTss` after receiving an
    /// OPAQUE receipt.
    pub fn opaque_complete(&mut self) -> Result<(), String> {
        match &self.state {
            CeremonyState::PendingOpaque => {
                self.state = CeremonyState::PendingTss;
                Ok(())
            }
            other => Err(format!(
                "invalid transition: cannot move from {:?} to PendingTss",
                other
            )),
        }
    }

    /// Transition from `PendingTss` to `Complete` after receiving a signed
    /// token from the TSS.
    pub fn tss_complete(&mut self) -> Result<(), String> {
        match &self.state {
            CeremonyState::PendingTss => {
                self.state = CeremonyState::Complete;
                Ok(())
            }
            other => Err(format!(
                "invalid transition: cannot move from {:?} to Complete",
                other
            )),
        }
    }

    /// Transition to the `Failed` state from any non-terminal state.
    pub fn fail(&mut self, reason: String) -> Result<(), String> {
        match &self.state {
            CeremonyState::Complete => Err("cannot fail an already-completed ceremony".into()),
            CeremonyState::Failed(_) => Err("ceremony has already failed".into()),
            _ => {
                self.state = CeremonyState::Failed(reason);
                Ok(())
            }
        }
    }
}
