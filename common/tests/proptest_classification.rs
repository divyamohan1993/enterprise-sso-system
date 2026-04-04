use proptest::prelude::*;
use common::classification::{
    ClassificationLevel, ClassificationDecision,
    enforce_classification, enforce_no_downgrade, check_compartment_access,
};

/// Strategy that generates a valid ClassificationLevel.
fn arb_classification() -> impl Strategy<Value = ClassificationLevel> {
    (0u8..=4).prop_map(|v| ClassificationLevel::from_u8(v).unwrap())
}

/// Strategy that generates a vector of compartment tag strings.
fn arb_compartments() -> impl Strategy<Value = Vec<String>> {
    prop::collection::vec(
        prop::sample::select(vec![
            "TK".to_string(), "SI".to_string(), "HCS".to_string(),
            "GAMMA".to_string(), "ORCON".to_string(), "NOFORN".to_string(),
        ]),
        0..=4,
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    // ---- Dominance is transitive ----
    // If a >= b and b >= c, then a >= c.
    #[test]
    fn dominance_is_transitive(
        a in arb_classification(),
        b in arb_classification(),
        c in arb_classification(),
    ) {
        if a >= b && b >= c {
            prop_assert!(a >= c, "transitivity violated: {:?} >= {:?} >= {:?} but not {:?} >= {:?}", a, b, c, a, c);
        }
    }

    // ---- Dominance is reflexive ----
    #[test]
    fn dominance_is_reflexive(a in arb_classification()) {
        prop_assert!(a >= a);
        prop_assert!(enforce_classification(a, a).is_granted());
    }

    // ---- Dominance is antisymmetric ----
    // If a >= b and b >= a, then a == b.
    #[test]
    fn dominance_is_antisymmetric(
        a in arb_classification(),
        b in arb_classification(),
    ) {
        if a >= b && b >= a {
            prop_assert_eq!(a, b, "antisymmetry violated");
        }
    }

    // ---- Join (max) is commutative ----
    // max(a, b) == max(b, a)
    #[test]
    fn join_is_commutative(
        a in arb_classification(),
        b in arb_classification(),
    ) {
        prop_assert_eq!(std::cmp::max(a, b), std::cmp::max(b, a));
    }

    // ---- Join is associative ----
    // max(max(a, b), c) == max(a, max(b, c))
    #[test]
    fn join_is_associative(
        a in arb_classification(),
        b in arb_classification(),
        c in arb_classification(),
    ) {
        let left = std::cmp::max(std::cmp::max(a, b), c);
        let right = std::cmp::max(a, std::cmp::max(b, c));
        prop_assert_eq!(left, right);
    }

    // ---- Meet (min) is commutative ----
    #[test]
    fn meet_is_commutative(
        a in arb_classification(),
        b in arb_classification(),
    ) {
        prop_assert_eq!(std::cmp::min(a, b), std::cmp::min(b, a));
    }

    // ---- Simple security property: no read up ----
    // A subject at level S can read resources at level R only if S >= R.
    #[test]
    fn no_read_up(
        subject in arb_classification(),
        resource in arb_classification(),
    ) {
        let decision = enforce_classification(subject, resource);
        if subject >= resource {
            prop_assert!(decision.is_granted(), "should grant: subject {:?} >= resource {:?}", subject, resource);
        } else {
            prop_assert!(!decision.is_granted(), "should deny: subject {:?} < resource {:?}", subject, resource);
            match decision {
                ClassificationDecision::Denied { subject_level, resource_level } => {
                    prop_assert_eq!(subject_level, subject);
                    prop_assert_eq!(resource_level, resource);
                }
                _ => prop_assert!(false, "expected Denied variant"),
            }
        }
    }

    // ---- Star property: no write down ----
    // Data at source level may only flow to target at same or higher level.
    #[test]
    fn no_write_down(
        source in arb_classification(),
        target in arb_classification(),
    ) {
        let decision = enforce_no_downgrade(source, target);
        if target >= source {
            prop_assert!(decision.is_granted(), "should allow: target {:?} >= source {:?}", target, source);
        } else {
            prop_assert!(!decision.is_granted(), "should prevent downgrade: target {:?} < source {:?}", target, source);
            match decision {
                ClassificationDecision::DowngradePrevented { source_level, target_level } => {
                    prop_assert_eq!(source_level, source);
                    prop_assert_eq!(target_level, target);
                }
                _ => prop_assert!(false, "expected DowngradePrevented variant"),
            }
        }
    }

    // ---- Compartment access: superset grants, subset denies ----
    #[test]
    fn compartment_superset_grants(
        user_comps in arb_compartments(),
        extra in arb_compartments(),
    ) {
        // User has user_comps. Resource requires a subset of user_comps.
        // Subset of user's compartments should always be accessible.
        let resource_comps: Vec<String> = user_comps.iter()
            .take(user_comps.len() / 2)
            .cloned()
            .collect();
        prop_assert!(check_compartment_access(&user_comps, &resource_comps),
            "user should have access to subset of their compartments");

        // Empty resource compartments always accessible
        prop_assert!(check_compartment_access(&user_comps, &[]),
            "empty compartments should always be accessible");

        // If resource requires compartments the user does not have, deny
        let _ = extra; // used to ensure proptest generates the parameter
        let impossible = vec!["NONEXISTENT_COMPARTMENT_ZZZZZ".to_string()];
        if !user_comps.contains(&impossible[0]) {
            prop_assert!(!check_compartment_access(&user_comps, &impossible),
                "user should not access compartment they do not hold");
        }
    }

    // ---- Round-trip from_u8 / as_u8 ----
    #[test]
    fn from_u8_roundtrip(v in 0u8..=4) {
        let level = ClassificationLevel::from_u8(v).unwrap();
        prop_assert_eq!(level.as_u8(), v);
    }

    // ---- Invalid u8 values rejected ----
    #[test]
    fn invalid_u8_rejected(v in 5u8..=255) {
        prop_assert!(ClassificationLevel::from_u8(v).is_none());
    }
}
