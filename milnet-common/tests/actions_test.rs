use milnet_common::actions::*;
use milnet_common::error::MilnetError;
use milnet_common::types::ActionLevel;
use uuid::Uuid;

#[test]
fn read_action_always_permitted() {
    let auth = check_action_authorization(4, ActionLevel::Read, false, false);
    assert!(auth.permitted);
    assert!(!auth.requires_step_up);
    assert!(!auth.requires_two_person);
    assert!(!auth.requires_sovereign);
    assert!(auth.reason.is_none());
}

#[test]
fn modify_requires_fresh_dpop() {
    let without = check_action_authorization(1, ActionLevel::Modify, false, false);
    assert!(!without.permitted);
    assert!(without.reason.unwrap().contains("DPoP"));

    let with = check_action_authorization(1, ActionLevel::Modify, true, false);
    assert!(with.permitted);
    assert!(with.reason.is_none());
}

#[test]
fn privileged_requires_step_up() {
    let no_step_up = check_action_authorization(1, ActionLevel::Privileged, true, false);
    assert!(!no_step_up.permitted);
    assert!(no_step_up.requires_step_up);
    assert!(no_step_up.reason.unwrap().contains("step-up"));

    let with_step_up = check_action_authorization(1, ActionLevel::Privileged, true, true);
    assert!(with_step_up.permitted);
    assert!(with_step_up.reason.is_none());
}

#[test]
fn critical_requires_two_person() {
    let auth = check_action_authorization(1, ActionLevel::Critical, true, true);
    assert!(!auth.permitted);
    assert!(auth.requires_two_person);
    assert!(!auth.requires_sovereign);
    assert!(auth.reason.unwrap().contains("two-person"));
}

#[test]
fn sovereign_requires_three_person_different_departments() {
    let auth = check_action_authorization(1, ActionLevel::Sovereign, true, true);
    assert!(!auth.permitted);
    assert!(auth.requires_two_person);
    assert!(auth.requires_sovereign);
    assert!(auth.reason.unwrap().contains("sovereign"));

    // Valid sovereign ceremony: 3 participants, different departments, different devices
    let participants = vec![
        CeremonyParticipant {
            user_id: Uuid::new_v4(),
            department: "Engineering".into(),
            authenticated_at: 1_700_000_000,
            device_id: Uuid::new_v4(),
        },
        CeremonyParticipant {
            user_id: Uuid::new_v4(),
            department: "Operations".into(),
            authenticated_at: 1_700_000_001,
            device_id: Uuid::new_v4(),
        },
        CeremonyParticipant {
            user_id: Uuid::new_v4(),
            department: "Security".into(),
            authenticated_at: 1_700_000_002,
            device_id: Uuid::new_v4(),
        },
    ];
    assert!(validate_multi_person_ceremony(&participants, ActionLevel::Sovereign).is_ok());
}

#[test]
fn duplicate_participants_rejected() {
    let shared_user = Uuid::new_v4();
    let participants = vec![
        CeremonyParticipant {
            user_id: shared_user,
            department: "Engineering".into(),
            authenticated_at: 1_700_000_000,
            device_id: Uuid::new_v4(),
        },
        CeremonyParticipant {
            user_id: shared_user,
            department: "Operations".into(),
            authenticated_at: 1_700_000_001,
            device_id: Uuid::new_v4(),
        },
    ];
    let err = validate_multi_person_ceremony(&participants, ActionLevel::Critical).unwrap_err();
    match err {
        MilnetError::CryptoVerification(msg) => assert!(msg.contains("duplicate")),
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn same_device_rejected() {
    let shared_device = Uuid::new_v4();
    let participants = vec![
        CeremonyParticipant {
            user_id: Uuid::new_v4(),
            department: "Engineering".into(),
            authenticated_at: 1_700_000_000,
            device_id: shared_device,
        },
        CeremonyParticipant {
            user_id: Uuid::new_v4(),
            department: "Operations".into(),
            authenticated_at: 1_700_000_001,
            device_id: shared_device,
        },
    ];
    let err = validate_multi_person_ceremony(&participants, ActionLevel::Critical).unwrap_err();
    match err {
        MilnetError::CryptoVerification(msg) => assert!(msg.contains("different devices")),
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn action_token_exhaustion() {
    let token = ActionToken {
        action_name: "deploy".into(),
        authorized_by: vec![Uuid::new_v4()],
        device_ids: vec![Uuid::new_v4()],
        nonce: [0u8; 32],
        timestamp: 1_700_000_000,
        max_executions: 1,
        abort_deadline: i64::MAX,
    };
    assert!(!token.is_exhausted(0));
    assert!(token.is_exhausted(1));
    assert!(token.is_exhausted(2));
}

#[test]
fn action_token_abort_deadline() {
    // Deadline far in the past
    let expired = ActionToken {
        action_name: "deploy".into(),
        authorized_by: vec![Uuid::new_v4()],
        device_ids: vec![Uuid::new_v4()],
        nonce: [0u8; 32],
        timestamp: 1_700_000_000,
        max_executions: 1,
        abort_deadline: 0,
    };
    assert!(expired.past_abort_deadline());

    // Deadline far in the future
    let active = ActionToken {
        action_name: "deploy".into(),
        authorized_by: vec![Uuid::new_v4()],
        device_ids: vec![Uuid::new_v4()],
        nonce: [0u8; 32],
        timestamp: 1_700_000_000,
        max_executions: 1,
        abort_deadline: i64::MAX,
    };
    assert!(!active.past_abort_deadline());
}

#[test]
fn insufficient_tier_rejected_for_privileged() {
    // Tier 3 (Sensor) should be rejected for privileged actions even with step-up
    let auth = check_action_authorization(3, ActionLevel::Privileged, true, true);
    assert!(!auth.permitted);
    assert!(auth.reason.unwrap().contains("insufficient tier"));

    // Tier 4 (Emergency) also rejected
    let auth = check_action_authorization(4, ActionLevel::Privileged, true, true);
    assert!(!auth.permitted);

    // Tier 2 (Operational) should be allowed
    let auth = check_action_authorization(2, ActionLevel::Privileged, true, true);
    assert!(auth.permitted);
}
