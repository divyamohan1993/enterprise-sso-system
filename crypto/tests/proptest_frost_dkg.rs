use proptest::prelude::*;
use crypto::threshold::{dkg_distributed, threshold_sign_with_indices, verify_group_signature};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(8))]

    /// Any t-subset of n shares can produce a valid signature.
    #[test]
    fn any_t_subset_produces_valid_signature(
        msg in prop::collection::vec(any::<u8>(), 1..128),
        subset_offset in 0u16..3,
    ) {
        let t = 3u16;
        let n = 5u16;
        let result = dkg_distributed(n, t);
        let mut shares = result.shares;

        // Pick a t-sized subset starting at subset_offset (wrapping)
        let indices: Vec<usize> = (0..t as usize)
            .map(|i| ((subset_offset as usize) + i) % (n as usize))
            .collect();

        let sig = threshold_sign_with_indices(
            &mut shares,
            &result.group,
            &msg,
            t as usize,
            &indices,
        )
        .expect("t-subset signing must succeed");

        prop_assert!(
            verify_group_signature(&result.group, &msg, &sig),
            "signature from t-subset {:?} must verify", indices
        );
    }

    /// t-1 shares cannot produce a valid signature.
    #[test]
    fn t_minus_1_shares_cannot_sign(
        msg in prop::collection::vec(any::<u8>(), 1..64),
    ) {
        let t = 3u16;
        let n = 5u16;
        let result = dkg_distributed(n, t);
        let mut shares = result.shares;

        let indices: Vec<usize> = (0..(t as usize - 1)).collect();
        let err = threshold_sign_with_indices(
            &mut shares,
            &result.group,
            &msg,
            t as usize,
            &indices,
        );
        prop_assert!(err.is_err(), "t-1 shares must fail to sign");
    }

    /// DKG produces consistent key packages across all participants.
    #[test]
    fn dkg_consistent_group_key(
        _seed in any::<u64>(),
    ) {
        let t = 3u16;
        let n = 5u16;
        let result = dkg_distributed(n, t);

        // group key is deterministic for a single ceremony
        prop_assert_eq!(result.group.threshold, t as usize);
        prop_assert_eq!(result.group.total, n as usize);
        prop_assert_eq!(result.shares.len(), n as usize);

        // Sign with two different subsets, both should verify against the same group key
        let msg = b"consistency check";
        let mut shares1 = {
            let r = dkg_distributed(n, t);
            // Verify group key exists and shares match
            assert_eq!(r.shares.len(), n as usize);
            r
        };

        let sig1 = threshold_sign_with_indices(
            &mut shares1.shares,
            &shares1.group,
            msg,
            t as usize,
            &[0, 1, 2],
        ).expect("subset 1 sign");

        let sig2 = threshold_sign_with_indices(
            &mut shares1.shares,
            &shares1.group,
            msg,
            t as usize,
            &[2, 3, 4],
        ).expect("subset 2 sign");

        prop_assert!(verify_group_signature(&shares1.group, msg, &sig1));
        prop_assert!(verify_group_signature(&shares1.group, msg, &sig2));
    }

    /// Different subsets produce signatures that verify against the same group public key.
    #[test]
    fn different_subsets_verify_same_group_key(
        msg in prop::collection::vec(any::<u8>(), 1..64),
    ) {
        let t = 3u16;
        let n = 5u16;
        let result = dkg_distributed(n, t);
        let mut shares = result.shares;

        let sig_a = threshold_sign_with_indices(
            &mut shares, &result.group, &msg, t as usize, &[0, 1, 2],
        ).expect("subset A");

        let sig_b = threshold_sign_with_indices(
            &mut shares, &result.group, &msg, t as usize, &[2, 3, 4],
        ).expect("subset B");

        prop_assert!(verify_group_signature(&result.group, &msg, &sig_a));
        prop_assert!(verify_group_signature(&result.group, &msg, &sig_b));
    }
}
