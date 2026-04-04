use proptest::prelude::*;
use common::threshold_kek::{split_secret, reconstruct_secret};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    /// Any k-of-n subset of shares reconstructs the same secret.
    /// Generate a random secret, split into shares, pick different k-sized
    /// subsets, and verify all reconstruct identically.
    #[test]
    fn any_k_subset_reconstructs_same_secret(
        secret in prop::array::uniform32(any::<u8>()),
        // threshold 2..5, total = threshold..threshold+3 (capped at 5)
        t in 2u8..=5,
        extra in 0u8..=3,
    ) {
        let n = std::cmp::min(t.saturating_add(extra), 255).max(t);
        let shares = split_secret(&secret, t, n).unwrap();

        // Reconstruct with first k shares
        let first_k: Vec<_> = shares.iter().take(t as usize).cloned().collect();
        let reconstructed = reconstruct_secret(&first_k).unwrap();
        prop_assert_eq!(reconstructed, secret, "first k shares failed to reconstruct");

        // Reconstruct with last k shares (if n > t, this is a different subset)
        if n > t {
            let last_k: Vec<_> = shares.iter().rev().take(t as usize).cloned().collect();
            let reconstructed2 = reconstruct_secret(&last_k).unwrap();
            prop_assert_eq!(reconstructed2, secret, "last k shares failed to reconstruct");
        }

        // Reconstruct with all n shares
        let reconstructed_all = reconstruct_secret(&shares).unwrap();
        prop_assert_eq!(reconstructed_all, secret, "all shares failed to reconstruct");
    }

    /// k-1 shares must NOT reveal the secret.
    /// With threshold t, any subset of t-1 shares fed to reconstruct must
    /// produce a value different from the original secret (with overwhelming
    /// probability for a random secret).
    #[test]
    fn k_minus_1_shares_reveal_nothing(
        secret in prop::array::uniform32(any::<u8>()),
        t in 3u8..=5,
        extra in 0u8..=2,
    ) {
        let n = std::cmp::min(t.saturating_add(extra), 255).max(t);
        let shares = split_secret(&secret, t, n).unwrap();

        // Take only t-1 shares
        let insufficient: Vec<_> = shares.iter().take((t - 1) as usize).cloned().collect();

        // Reconstruction with t-1 shares will "succeed" mathematically
        // (Lagrange interpolation works on any # of points) but the
        // reconstructed value must differ from the real secret.
        // For a random 256-bit secret, the probability of collision is 2^{-256}.
        let wrong = reconstruct_secret(&insufficient).unwrap();
        prop_assert_ne!(wrong, secret,
            "t-1 shares reconstructed to the real secret (should be astronomically unlikely)");
    }

    /// Duplicate share indices produce an error, not a wrong answer.
    #[test]
    fn duplicate_indices_rejected(
        secret in prop::array::uniform32(any::<u8>()),
    ) {
        let shares = split_secret(&secret, 3, 5).unwrap();
        let duped = vec![shares[0].clone(), shares[0].clone(), shares[1].clone()];
        let result = reconstruct_secret(&duped);
        prop_assert!(result.is_err(), "duplicate indices should be rejected");
    }

    /// Single share is always rejected.
    #[test]
    fn single_share_rejected(
        secret in prop::array::uniform32(any::<u8>()),
    ) {
        let shares = split_secret(&secret, 2, 3).unwrap();
        let single = vec![shares[0].clone()];
        let result = reconstruct_secret(&single);
        prop_assert!(result.is_err(), "single share should be rejected");
    }
}
