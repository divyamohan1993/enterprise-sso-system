//! Tests for distributed Pedersen DKG.

use crypto::pedersen_dkg::{DkgParticipant, DkgRound1, DkgRound2};

#[test]
fn test_pedersen_dkg_3_of_5_succeeds() {
    let threshold = 3u16;
    let total = 5u16;

    // Round 1: Each participant generates commitments
    let mut participants: Vec<DkgParticipant> = (1..=total)
        .map(|id| DkgParticipant::new(id, threshold, total))
        .collect();

    let round1_packages: Vec<DkgRound1> = participants
        .iter_mut()
        .map(|p| p.round1())
        .collect();

    // Round 2: Each participant processes others' round1 packages
    let round2_packages: Vec<Vec<DkgRound2>> = participants
        .iter_mut()
        .enumerate()
        .map(|(i, p)| {
            let others: Vec<&DkgRound1> = round1_packages.iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, pkg)| pkg)
                .collect();
            p.round2(&others).unwrap_or_else(|e| panic!(
                "round2 failed for participant {}: {e}", i + 1
            ))
        })
        .collect();

    // Finalize: Each participant combines received shares
    for (i, participant) in participants.iter_mut().enumerate() {
        let my_id = (i + 1) as u16;
        let others_r2: Vec<&DkgRound2> = round2_packages.iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .flat_map(|(_, pkgs)| pkgs.iter().filter(|p| p.receiver_id == my_id))
            .collect();
        participant.finalize(&others_r2).unwrap_or_else(|e| panic!(
            "finalize failed for participant {}: {e}", i + 1
        ));
    }

    // All participants must agree on the group public key
    let group_keys: Vec<_> = participants.iter()
        .map(|p| p.group_public_key().expect("must have group key after finalize"))
        .collect();
    for (i, key) in group_keys.iter().enumerate().skip(1) {
        assert_eq!(
            group_keys[0].verifying_key(), key.verifying_key(),
            "participant {} disagrees on group verifying key with participant 1",
            i + 1
        );
    }
}

#[test]
fn test_no_single_process_holds_full_secret() {
    let threshold = 3u16;
    let total = 5u16;

    let participants: Vec<DkgParticipant> = (1..=total)
        .map(|id| DkgParticipant::new(id, threshold, total))
        .collect();

    for (i, p) in participants.iter().enumerate() {
        assert!(
            p.full_secret().is_none(),
            "participant {} should NOT hold the full secret",
            i + 1
        );
    }
}

#[test]
fn test_dkg_produces_valid_key_packages() {
    let threshold = 2u16;
    let total = 3u16;

    let mut participants: Vec<DkgParticipant> = (1..=total)
        .map(|id| DkgParticipant::new(id, threshold, total))
        .collect();

    let round1_packages: Vec<DkgRound1> = participants
        .iter_mut()
        .map(|p| p.round1())
        .collect();

    let round2_packages: Vec<Vec<DkgRound2>> = participants
        .iter_mut()
        .enumerate()
        .map(|(i, p)| {
            let others: Vec<&DkgRound1> = round1_packages.iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, pkg)| pkg)
                .collect();
            p.round2(&others).expect("round2 should succeed")
        })
        .collect();

    for (i, participant) in participants.iter_mut().enumerate() {
        let my_id = (i + 1) as u16;
        let others_r2: Vec<&DkgRound2> = round2_packages.iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .flat_map(|(_, pkgs)| pkgs.iter().filter(|p| p.receiver_id == my_id))
            .collect();
        participant.finalize(&others_r2).expect("finalize should succeed");
    }

    // Every participant should have a key package
    for (i, p) in participants.iter().enumerate() {
        assert!(
            p.key_package().is_some(),
            "participant {} must have key_package after finalize",
            i + 1
        );
    }
}
