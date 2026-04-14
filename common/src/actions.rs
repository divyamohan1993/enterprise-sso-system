use crate::error::MilnetError;
use crate::types::ActionLevel;

/// Action classification with required auth level per spec Section 7
#[derive(Debug, Clone)]
pub struct ActionPolicy {
    pub action_name: String,
    pub level: ActionLevel,
    pub min_tier: u8,
    pub description: String,
}

/// Action authorization check result
#[derive(Debug, Clone)]
pub struct ActionAuthorization {
    pub permitted: bool,
    pub requires_step_up: bool,
    pub requires_two_person: bool,
    pub requires_sovereign: bool,
    pub reason: Option<String>,
}

/// Check if a session can perform an action
pub fn check_action_authorization(
    session_tier: u8,
    action_level: ActionLevel,
    has_fresh_dpop: bool,
    step_up_completed: bool,
) -> ActionAuthorization {
    match action_level {
        ActionLevel::Read => ActionAuthorization {
            permitted: true,
            requires_step_up: false,
            requires_two_person: false,
            requires_sovereign: false,
            reason: None,
        },
        ActionLevel::Modify => ActionAuthorization {
            permitted: has_fresh_dpop,
            requires_step_up: false,
            requires_two_person: false,
            requires_sovereign: false,
            reason: if !has_fresh_dpop {
                Some("fresh DPoP proof required for Modify actions".into())
            } else {
                None
            },
        },
        ActionLevel::Privileged => ActionAuthorization {
            permitted: step_up_completed && session_tier <= 2,
            requires_step_up: !step_up_completed,
            requires_two_person: false,
            requires_sovereign: false,
            reason: if !step_up_completed {
                Some("step-up re-authentication required".into())
            } else if session_tier > 2 {
                Some("insufficient tier for privileged actions".into())
            } else {
                None
            },
        },
        ActionLevel::Critical => ActionAuthorization {
            permitted: false,
            requires_step_up: true,
            requires_two_person: true,
            requires_sovereign: false,
            reason: Some("two-person ceremony required for critical actions".into()),
        },
        ActionLevel::Sovereign => ActionAuthorization {
            permitted: false,
            requires_step_up: true,
            requires_two_person: true,
            requires_sovereign: true,
            reason: Some("sovereign ceremony required (three-person, random selection)".into()),
        },
    }
}

/// Multi-person ceremony participant tracking
#[derive(Debug, Clone)]
pub struct CeremonyParticipant {
    pub user_id: uuid::Uuid,
    pub department: String,
    pub authenticated_at: i64,
    pub device_id: uuid::Uuid,
}

/// Validate multi-person ceremony requirements
pub fn validate_multi_person_ceremony(
    participants: &[CeremonyParticipant],
    action_level: ActionLevel,
) -> Result<(), MilnetError> {
    let required_count = match action_level {
        ActionLevel::Critical => 2,
        ActionLevel::Sovereign => 3,
        _ => return Ok(()),
    };

    if participants.len() < required_count {
        return Err(MilnetError::QuorumNotMet);
    }

    // Check all participants are different users
    let unique_users: std::collections::HashSet<_> =
        participants.iter().map(|p| p.user_id).collect();
    if unique_users.len() < required_count {
        return Err(MilnetError::CryptoVerification(
            "duplicate participants".into(),
        ));
    }

    // Check participants are from different departments (for Sovereign)
    if action_level == ActionLevel::Sovereign {
        let unique_depts: std::collections::HashSet<_> =
            participants.iter().map(|p| &p.department).collect();
        if unique_depts.len() < required_count {
            return Err(MilnetError::CryptoVerification(
                "sovereign ceremony requires participants from different departments".into(),
            ));
        }
    }

    // Check all different devices
    let unique_devices: std::collections::HashSet<_> =
        participants.iter().map(|p| p.device_id).collect();
    if unique_devices.len() < required_count {
        return Err(MilnetError::CryptoVerification(
            "participants must use different devices".into(),
        ));
    }

    Ok(())
}

/// Action token for single-use critical operations per spec Section 7
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionToken {
    pub action_name: String,
    pub authorized_by: Vec<uuid::Uuid>,
    pub device_ids: Vec<uuid::Uuid>,
    pub nonce: [u8; 32],
    pub timestamp: i64,
    pub max_executions: u32,
    pub abort_deadline: i64,
}

impl ActionToken {
    /// Check if this action token has been used up
    pub fn is_exhausted(&self, execution_count: u32) -> bool {
        execution_count >= self.max_executions
    }

    /// Check if the abort deadline has passed
    pub fn past_abort_deadline(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros() as i64;
        now > self.abort_deadline
    }
}
