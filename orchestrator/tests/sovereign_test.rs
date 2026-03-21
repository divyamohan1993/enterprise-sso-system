use common::actions::CeremonyParticipant;
use orchestrator::sovereign::{SovereignCeremony, SovereignState};
use uuid::Uuid;

fn make_participants() -> Vec<CeremonyParticipant> {
    vec![
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
    ]
}

#[test]
fn test_sovereign_ceremony_full_flow() {
    let mut ceremony = SovereignCeremony::new("rotate_root_key");
    assert!(matches!(ceremony.state, SovereignState::AwaitingParticipants));

    // Add participants
    let participants = make_participants();
    ceremony.add_participants(participants).unwrap();
    assert!(matches!(
        ceremony.state,
        SovereignState::ParticipantsAuthenticated { .. }
    ));

    // Enter abort window
    ceremony.enter_abort_window().unwrap();
    assert!(matches!(ceremony.state, SovereignState::AbortWindow { .. }));

    // Proceed to cooling period
    ceremony.proceed_to_cooling().unwrap();
    assert!(matches!(
        ceremony.state,
        SovereignState::CoolingPeriod { .. }
    ));

    // Cannot complete yet — cooling period not expired
    let err = ceremony.complete();
    assert!(err.is_err());
    assert!(err.unwrap_err().contains("cooling period"));
}

#[test]
fn test_sovereign_ceremony_abort() {
    let mut ceremony = SovereignCeremony::new("delete_all_keys");
    let participants = make_participants();
    ceremony.add_participants(participants).unwrap();
    ceremony.enter_abort_window().unwrap();

    // Any participant can abort
    ceremony.abort("participant 2 objected");
    assert!(matches!(ceremony.state, SovereignState::Aborted { .. }));
    if let SovereignState::Aborted { reason } = &ceremony.state {
        assert!(reason.contains("objected"));
    }
}

#[test]
fn test_sovereign_wrong_state_transitions() {
    let mut ceremony = SovereignCeremony::new("test_action");

    // Cannot enter abort window from AwaitingParticipants
    assert!(ceremony.enter_abort_window().is_err());

    // Cannot proceed to cooling from AwaitingParticipants
    assert!(ceremony.proceed_to_cooling().is_err());

    // Cannot complete from AwaitingParticipants
    assert!(ceremony.complete().is_err());

    // Add participants, then try invalid transitions
    let participants = make_participants();
    ceremony.add_participants(participants).unwrap();

    // Cannot proceed to cooling from ParticipantsAuthenticated (must go through abort window)
    assert!(ceremony.proceed_to_cooling().is_err());

    // Cannot complete from ParticipantsAuthenticated
    assert!(ceremony.complete().is_err());
}
