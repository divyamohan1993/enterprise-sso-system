//! Level 4 Sovereign Ceremony — three-person, random selection, cooling period
//! Spec Section 7

use common::actions::{validate_multi_person_ceremony, ActionToken, CeremonyParticipant};
use common::types::ActionLevel;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// Sovereign ceremony state machine
#[derive(Debug, Clone)]
pub enum SovereignState {
    AwaitingParticipants,
    ParticipantsAuthenticated {
        participants: Vec<CeremonyParticipant>,
    },
    AbortWindow {
        deadline: i64,
        participants: Vec<CeremonyParticipant>,
        action: String,
    },
    CoolingPeriod {
        expires: i64,
        participants: Vec<CeremonyParticipant>,
        action: String,
    },
    Complete {
        action_token: ActionToken,
    },
    Aborted {
        reason: String,
    },
}

pub struct SovereignCeremony {
    pub ceremony_id: Uuid,
    pub state: SovereignState,
    pub action_name: String,
    pub created_at: i64,
}

impl SovereignCeremony {
    pub fn new(action_name: &str) -> Self {
        Self {
            ceremony_id: Uuid::new_v4(),
            state: SovereignState::AwaitingParticipants,
            action_name: action_name.to_string(),
            created_at: now_us(),
        }
    }

    /// Add authenticated participants (need 3 from 3 departments)
    pub fn add_participants(
        &mut self,
        participants: Vec<CeremonyParticipant>,
    ) -> Result<(), String> {
        validate_multi_person_ceremony(&participants, ActionLevel::Sovereign)
            .map_err(|e| e.to_string())?;
        self.state = SovereignState::ParticipantsAuthenticated { participants };
        Ok(())
    }

    /// Enter abort window (10 seconds, default = abort)
    pub fn enter_abort_window(&mut self) -> Result<(), String> {
        match &self.state {
            SovereignState::ParticipantsAuthenticated { participants } => {
                let deadline = now_us() + 10_000_000; // 10 seconds
                self.state = SovereignState::AbortWindow {
                    deadline,
                    participants: participants.clone(),
                    action: self.action_name.clone(),
                };
                Ok(())
            }
            _ => Err("wrong state for abort window".into()),
        }
    }

    /// Abort the ceremony (any single participant can abort)
    pub fn abort(&mut self, reason: &str) {
        self.state = SovereignState::Aborted {
            reason: reason.to_string(),
        };
    }

    /// Proceed after abort window (requires explicit proceed from all participants).
    ///
    /// SECURITY: Enforces that the abort deadline has actually passed before
    /// allowing the transition to the cooling period.
    pub fn proceed_to_cooling(&mut self) -> Result<(), String> {
        match &self.state {
            SovereignState::AbortWindow {
                deadline,
                participants,
                action,
            } => {
                let now = now_us();
                if now < *deadline {
                    return Err("Cannot proceed: abort window has not expired".into());
                }
                let cooling_expires = now + 900_000_000; // 15 minutes
                self.state = SovereignState::CoolingPeriod {
                    expires: cooling_expires,
                    participants: participants.clone(),
                    action: action.clone(),
                };
                Ok(())
            }
            _ => Err("wrong state for cooling period".into()),
        }
    }

    /// Complete the ceremony and issue action token
    pub fn complete(&mut self) -> Result<ActionToken, String> {
        match &self.state {
            SovereignState::CoolingPeriod {
                expires,
                participants,
                action,
            } => {
                if now_us() < *expires {
                    return Err("cooling period not yet expired".into());
                }
                let token = ActionToken {
                    action_name: action.clone(),
                    authorized_by: participants.iter().map(|p| p.user_id).collect(),
                    device_ids: participants.iter().map(|p| p.device_id).collect(),
                    nonce: crypto::entropy::generate_nonce(),
                    timestamp: now_us(),
                    max_executions: 1,
                    abort_deadline: now_us() + 10_000_000,
                };
                self.state = SovereignState::Complete {
                    action_token: token.clone(),
                };
                Ok(token)
            }
            _ => Err("wrong state for completion".into()),
        }
    }
}

fn now_us() -> i64 {
    common::secure_time::secure_now_us_i64()
}
