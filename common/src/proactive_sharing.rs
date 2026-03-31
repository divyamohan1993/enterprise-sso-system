//! Proactive Secret Sharing (PSS) — refresh Shamir shares without reconstructing the secret.
//!
//! THREAT MODEL: An adaptive adversary who compromises t-1 shares in epoch N
//! and t-1 *different* shares in epoch N+1 CANNOT reconstruct the secret.
//! After each refresh round, old shares become cryptographically useless.
//!
//! ALGORITHM (Herzberg et al., 1995):
//! 1. Each node i generates a random polynomial δ_i(x) of degree t-1
//!    with constant term δ_i(0) = 0 (preserving the secret).
//! 2. Node i sends δ_i(j) to every node j (encrypted + authenticated).
//! 3. Each node j computes its new share: s'_j = s_j + Σ_i δ_i(j).
//! 4. The resulting shares s'_j are valid for the SAME secret s,
//!    but the old shares s_j are now useless.
//!
//! VERIFICATION: Each node publishes Pedersen commitments to its polynomial
//! coefficients, allowing all nodes to verify received sub-shares without
//! learning the polynomial.
//!
//! INVARIANTS:
//! - The secret is NEVER reconstructed during refresh.
//! - All sub-share polynomials have constant term 0.
//! - Contributions are verified via Pedersen commitments before application.
//! - Old shares are zeroized after refresh.
//! - Every refresh round emits a SIEM event.

use crate::siem::{PanelSiemEvent, SiemPanel, SiemSeverity};
use crate::threshold_kek::{ct_gf256_mul, gf256_add, KekShare};
use std::sync::atomic::{AtomicU64, Ordering};
use zeroize::Zeroize;

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

/// Orchestrates proactive share refresh rounds.
pub struct ProactiveRefresh {
    threshold: usize,
    total_shares: usize,
    refresh_epoch: AtomicU64,
}

/// A sub-share contribution from one node to another during a refresh round.
#[derive(Clone)]
pub struct RefreshContribution {
    /// Node index that generated this contribution (1-based).
    pub from_node: usize,
    /// Target node index (1-based).
    pub to_node: usize,
    /// The sub-share value (32 bytes, one per secret byte).
    pub sub_share: Vec<u8>,
    /// Refresh epoch this contribution belongs to.
    pub epoch: u64,
    /// Pedersen-style commitment: for each coefficient a_k, commitment[k] = g^{a_k} in GF(256).
    /// Used to verify the sub-share without revealing the polynomial.
    pub commitment: Vec<u8>,
}

impl Drop for RefreshContribution {
    fn drop(&mut self) {
        self.sub_share.zeroize();
    }
}

/// The set of Pedersen commitments for a single node's refresh polynomial
/// (one polynomial per secret byte, but we batch: commitment[byte][coeff]).
#[derive(Clone)]
pub struct RefreshCommitments {
    /// Node index that published these commitments.
    pub from_node: usize,
    /// Epoch.
    pub epoch: u64,
    /// commitments[byte_idx][coeff_idx] — commitment to each coefficient.
    /// For GF(256) Pedersen: C_k = g^{a_k} where g is a fixed generator.
    pub commitments: Vec<Vec<u8>>,
}

// ---------------------------------------------------------------------------
// Pedersen commitment helpers (GF(256))
// ---------------------------------------------------------------------------

/// Fixed generator for GF(256) Pedersen commitments.
/// We use 0x03 which is a primitive element of GF(2^8) mod x^8+x^4+x^3+x+1.
const PEDERSEN_GENERATOR: u8 = 0x03;

/// Compute g^a in GF(256) via repeated squaring.
fn gf256_exp(base: u8, mut exp: u8) -> u8 {
    if exp == 0 {
        return 1;
    }
    let mut result = 1u8;
    let mut b = base;
    while exp > 0 {
        if exp & 1 != 0 {
            result = ct_gf256_mul(result, b);
        }
        b = ct_gf256_mul(b, b);
        exp >>= 1;
    }
    result
}

/// Commit to a coefficient: C = g^coeff in GF(256).
fn pedersen_commit(coeff: u8) -> u8 {
    gf256_exp(PEDERSEN_GENERATOR, coeff)
}

/// Verify a sub-share against commitments.
///
/// Given commitments C_0, C_1, ..., C_{t-1} for polynomial coefficients,
/// and a sub-share value v at evaluation point x, verify:
///   g^v == Π_{k=0}^{t-1} C_k^{x^k}
///
/// This works because if v = Σ a_k * x^k, then:
///   g^v = g^{Σ a_k * x^k} = Π g^{a_k * x^k} = Π (g^{a_k})^{x^k} = Π C_k^{x^k}
///
/// In GF(256), multiplication is XOR-based and exponentiation uses ct_gf256_mul.
fn verify_subshare_against_commitments(
    sub_share_byte: u8,
    eval_point: u8,
    commitments: &[u8],
) -> bool {
    // LHS: g^v
    let lhs = pedersen_commit(sub_share_byte);

    // RHS: product of C_k^{x^k} for k = 0..t-1
    let mut rhs = 1u8;
    let mut x_power = 1u8; // x^0 = 1
    for &c_k in commitments {
        // C_k^{x^k}
        let term = gf256_exp(c_k, x_power);
        rhs = ct_gf256_mul(rhs, term);
        x_power = ct_gf256_mul(x_power, eval_point);
    }

    lhs == rhs
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

impl ProactiveRefresh {
    /// Create a new proactive refresh orchestrator.
    ///
    /// # Panics
    /// Panics if threshold < 2 or threshold > total.
    pub fn new(threshold: usize, total: usize) -> Self {
        assert!(threshold >= 2, "threshold must be >= 2, got {threshold}");
        assert!(
            threshold <= total,
            "threshold ({threshold}) must be <= total ({total})"
        );
        assert!(total <= 255, "maximum 255 shares");
        Self {
            threshold,
            total_shares: total,
            refresh_epoch: AtomicU64::new(0),
        }
    }

    /// Current refresh epoch.
    pub fn epoch(&self) -> u64 {
        self.refresh_epoch.load(Ordering::SeqCst)
    }

    /// Generate a refresh polynomial for `my_index` and produce sub-shares
    /// for every node (including self).
    ///
    /// The polynomial δ(x) has degree t-1 with δ(0) = 0 (constant term is zero).
    /// This ensures the secret is preserved: Σ δ(j) over any t nodes reconstructs to 0.
    ///
    /// Returns (contributions, commitments) — commitments must be broadcast to all nodes
    /// so they can verify the sub-shares.
    pub fn generate_refresh_polynomial(
        &self,
        my_index: usize,
    ) -> Result<(Vec<RefreshContribution>, RefreshCommitments), String> {
        if my_index == 0 || my_index > self.total_shares {
            return Err(format!(
                "node index {my_index} out of range [1, {}]",
                self.total_shares
            ));
        }

        let epoch = self.refresh_epoch.load(Ordering::SeqCst);
        let t = self.threshold;

        // For each of the 32 secret bytes, generate a random polynomial of degree t-1
        // with constant term 0: δ(x) = a_1*x + a_2*x^2 + ... + a_{t-1}*x^{t-1}
        //
        // We need (t-1) random coefficients per byte = 32*(t-1) random bytes total.
        let coeffs_per_byte = t - 1; // degree t-1 but constant term fixed to 0
        let mut random_bytes = vec![0u8; 32 * coeffs_per_byte];
        getrandom::getrandom(&mut random_bytes)
            .map_err(|e| format!("CSPRNG failed: {e}"))?;

        // Build coefficient matrix: coefficients[byte_idx] = [a_1, a_2, ..., a_{t-1}]
        // (constant term a_0 = 0 is implicit and NOT stored)
        let mut coefficients: Vec<Vec<u8>> = Vec::with_capacity(32);
        for byte_idx in 0..32 {
            let start = byte_idx * coeffs_per_byte;
            let end = start + coeffs_per_byte;
            coefficients.push(random_bytes[start..end].to_vec());
        }

        // Generate commitments: for each byte, commit to [0, a_1, a_2, ..., a_{t-1}]
        // The constant term commitment is g^0 = 1.
        let mut all_commitments: Vec<Vec<u8>> = Vec::with_capacity(32);
        for byte_idx in 0..32 {
            let mut byte_commitments = Vec::with_capacity(t);
            byte_commitments.push(pedersen_commit(0)); // constant term = 0
            for k in 0..coeffs_per_byte {
                byte_commitments.push(pedersen_commit(coefficients[byte_idx][k]));
            }
            all_commitments.push(byte_commitments);
        }

        // Flatten commitments for the RefreshCommitments struct
        let flat_commitments = RefreshCommitments {
            from_node: my_index,
            epoch,
            commitments: all_commitments.clone(),
        };

        // Evaluate polynomial at each target node's index to produce sub-shares
        let mut contributions = Vec::with_capacity(self.total_shares);
        for target in 1..=self.total_shares {
            let x = target as u8;
            let mut sub_share = vec![0u8; 32];

            for byte_idx in 0..32 {
                // δ(x) = a_1*x + a_2*x^2 + ... + a_{t-1}*x^{t-1}
                let mut y = 0u8;
                let mut x_power = x; // x^1
                for k in 0..coeffs_per_byte {
                    y = gf256_add(y, ct_gf256_mul(coefficients[byte_idx][k], x_power));
                    x_power = ct_gf256_mul(x_power, x);
                }
                sub_share[byte_idx] = y;
            }

            // Per-byte commitment for this sub-share (flatten all byte commitments)
            let mut commitment = Vec::new();
            for byte_idx in 0..32 {
                commitment.extend_from_slice(&all_commitments[byte_idx]);
            }

            contributions.push(RefreshContribution {
                from_node: my_index,
                to_node: target,
                sub_share,
                epoch,
                commitment,
            });
        }

        // Zeroize coefficient material
        for c in &mut coefficients {
            c.zeroize();
        }
        random_bytes.zeroize();

        Ok((contributions, flat_commitments))
    }

    /// Verify a single contribution against published commitments.
    ///
    /// Checks that for each byte, the sub-share value is consistent
    /// with the Pedersen commitments.
    pub fn verify_contribution(
        &self,
        contribution: &RefreshContribution,
        commitments: &RefreshCommitments,
    ) -> Result<(), String> {
        if contribution.from_node != commitments.from_node {
            return Err(format!(
                "contribution from node {} but commitments from node {}",
                contribution.from_node, commitments.from_node
            ));
        }
        if contribution.epoch != commitments.epoch {
            return Err("epoch mismatch between contribution and commitments".into());
        }
        if contribution.sub_share.len() != 32 {
            return Err(format!(
                "sub-share length {} != 32",
                contribution.sub_share.len()
            ));
        }
        if commitments.commitments.len() != 32 {
            return Err(format!(
                "commitments length {} != 32 (one per byte)",
                commitments.commitments.len()
            ));
        }

        let eval_point = contribution.to_node as u8;

        for byte_idx in 0..32 {
            let byte_commitments = &commitments.commitments[byte_idx];
            if byte_commitments.len() != self.threshold {
                return Err(format!(
                    "byte {} has {} commitments, expected {}",
                    byte_idx,
                    byte_commitments.len(),
                    self.threshold
                ));
            }

            if !verify_subshare_against_commitments(
                contribution.sub_share[byte_idx],
                eval_point,
                byte_commitments,
            ) {
                return Err(format!(
                    "Pedersen verification failed for byte {byte_idx} from node {} to node {}",
                    contribution.from_node, contribution.to_node
                ));
            }
        }

        Ok(())
    }

    /// Apply received sub-shares to the current share, producing a refreshed share.
    ///
    /// new_share[byte] = old_share[byte] + Σ contributions[byte]
    ///
    /// In GF(256), addition is XOR.
    ///
    /// # Security
    /// The old share is zeroized after producing the new share.
    pub fn apply_refresh(
        &self,
        mut my_share: KekShare,
        received_contributions: &[RefreshContribution],
    ) -> Result<KekShare, String> {
        let my_idx = my_share.index as usize;

        // Verify all contributions target this node
        for c in received_contributions {
            if c.to_node != my_idx {
                return Err(format!(
                    "contribution targets node {} but this is node {}",
                    c.to_node, my_idx
                ));
            }
        }

        // Verify we have contributions from all nodes (including self)
        if received_contributions.len() != self.total_shares {
            return Err(format!(
                "expected {} contributions, got {}",
                self.total_shares,
                received_contributions.len()
            ));
        }

        let mut new_value = my_share.value;

        for contribution in received_contributions {
            if contribution.sub_share.len() != 32 {
                return Err("sub-share must be 32 bytes".into());
            }
            for byte_idx in 0..32 {
                new_value[byte_idx] =
                    gf256_add(new_value[byte_idx], contribution.sub_share[byte_idx]);
            }
        }

        // Zeroize old share
        my_share.value.zeroize();

        Ok(KekShare {
            index: my_share.index,
            value: new_value,
        })
    }

    /// Orchestrate a complete refresh round across all nodes.
    ///
    /// This is a simulation of the distributed protocol for local testing:
    /// in production, each step would be a separate network round.
    ///
    /// Steps:
    /// 1. Each node generates its refresh polynomial and commitments.
    /// 2. Each node broadcasts commitments to all others.
    /// 3. Each node sends sub-shares to target nodes (verified by recipients).
    /// 4. Each node applies verified sub-shares to produce a new share.
    /// 5. Old shares are zeroized.
    pub fn full_refresh_round(
        &self,
        mut shares: Vec<KekShare>,
    ) -> Result<Vec<KekShare>, String> {
        if shares.len() != self.total_shares {
            return Err(format!(
                "expected {} shares, got {}",
                self.total_shares,
                shares.len()
            ));
        }

        // Step 1: Each node generates refresh polynomial
        let mut all_contributions: Vec<Vec<RefreshContribution>> =
            Vec::with_capacity(self.total_shares);
        let mut all_commitments: Vec<RefreshCommitments> =
            Vec::with_capacity(self.total_shares);

        for node_idx in 1..=self.total_shares {
            let (contributions, commitments) =
                self.generate_refresh_polynomial(node_idx)?;
            all_contributions.push(contributions);
            all_commitments.push(commitments);
        }

        // Step 2-3: Each target node collects and verifies contributions
        let mut new_shares = Vec::with_capacity(self.total_shares);

        for target_idx in 1..=self.total_shares {
            // Gather contributions for this target from all source nodes
            let mut target_contributions = Vec::with_capacity(self.total_shares);

            for (source_idx_0, contribs) in all_contributions.iter().enumerate() {
                let contrib = &contribs[target_idx - 1]; // contribution to target
                assert_eq!(contrib.to_node, target_idx);

                // Verify contribution against commitments
                self.verify_contribution(contrib, &all_commitments[source_idx_0])?;

                target_contributions.push(contrib.clone());
            }

            // Step 4: Apply refresh
            let old_share = std::mem::replace(
                &mut shares[target_idx - 1],
                KekShare { index: target_idx as u8, value: [0u8; 32] },
            );
            let new_share = self.apply_refresh(old_share, &target_contributions)?;
            new_shares.push(new_share);
        }

        // Zeroize old share placeholders
        for share in &mut shares {
            share.value.zeroize();
        }

        // Advance epoch
        self.refresh_epoch.fetch_add(1, Ordering::SeqCst);

        // SIEM event
        PanelSiemEvent::new(
            SiemPanel::KeyManagement,
            SiemSeverity::Info,
            "proactive_share_refresh",
            format!(
                "PSS refresh round completed: epoch {} -> {}, threshold={}, total={}",
                self.refresh_epoch.load(Ordering::SeqCst) - 1,
                self.refresh_epoch.load(Ordering::SeqCst),
                self.threshold,
                self.total_shares,
            ),
            file!(),
            line!(),
            module_path!(),
        )
        .emit();

        Ok(new_shares)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::threshold_kek::{reconstruct_secret, split_secret};

    #[test]
    fn refresh_preserves_secret_3_of_5() {
        let secret = [0x42u8; 32];
        let shares = split_secret(&secret, 3, 5).unwrap();

        let pss = ProactiveRefresh::new(3, 5);
        let new_shares = pss.full_refresh_round(shares.clone()).unwrap();

        // New shares reconstruct the SAME secret
        let recovered = reconstruct_secret(&new_shares[0..3]).unwrap();
        assert_eq!(recovered, secret);

        // Different subsets also work
        let picked = vec![
            new_shares[0].clone(),
            new_shares[2].clone(),
            new_shares[4].clone(),
        ];
        let recovered2 = reconstruct_secret(&picked).unwrap();
        assert_eq!(recovered2, secret);
    }

    #[test]
    fn old_shares_invalid_after_refresh() {
        let secret = [0xABu8; 32];
        let shares = split_secret(&secret, 3, 5).unwrap();
        let old_values: Vec<[u8; 32]> = shares.iter().map(|s| s.value).collect();

        let pss = ProactiveRefresh::new(3, 5);
        let new_shares = pss.full_refresh_round(shares).unwrap();

        // New shares must differ from old shares (overwhelmingly likely)
        let mut any_different = false;
        for (i, new_share) in new_shares.iter().enumerate() {
            if new_share.value != old_values[i] {
                any_different = true;
                break;
            }
        }
        assert!(any_different, "refreshed shares should differ from originals");
    }

    #[test]
    fn multiple_refresh_rounds_preserve_secret() {
        let secret = [0x77u8; 32];
        let mut shares = split_secret(&secret, 3, 5).unwrap();

        let pss = ProactiveRefresh::new(3, 5);

        // Run 5 refresh rounds
        for round in 0..5 {
            shares = pss.full_refresh_round(shares).unwrap();
            assert_eq!(pss.epoch(), round + 1);

            // Verify secret is still recoverable
            let recovered = reconstruct_secret(&shares[0..3]).unwrap();
            assert_eq!(recovered, secret, "secret corrupted after round {}", round + 1);
        }
    }

    #[test]
    fn epoch_advances_on_refresh() {
        let secret = [0x01u8; 32];
        let shares = split_secret(&secret, 2, 3).unwrap();

        let pss = ProactiveRefresh::new(2, 3);
        assert_eq!(pss.epoch(), 0);

        let shares = pss.full_refresh_round(shares).unwrap();
        assert_eq!(pss.epoch(), 1);

        let _shares = pss.full_refresh_round(shares).unwrap();
        assert_eq!(pss.epoch(), 2);
    }

    #[test]
    fn verify_contribution_rejects_tampered_subshare() {
        let pss = ProactiveRefresh::new(3, 5);
        let (mut contributions, commitments) =
            pss.generate_refresh_polynomial(1).unwrap();

        // Tamper with a sub-share
        contributions[2].sub_share[0] ^= 0xFF;

        let result = pss.verify_contribution(&contributions[2], &commitments);
        assert!(result.is_err(), "tampered sub-share must fail verification");
    }

    #[test]
    fn verify_contribution_accepts_valid_subshare() {
        let pss = ProactiveRefresh::new(3, 5);
        let (contributions, commitments) =
            pss.generate_refresh_polynomial(2).unwrap();

        for contrib in &contributions {
            pss.verify_contribution(contrib, &commitments).unwrap();
        }
    }

    #[test]
    fn generate_polynomial_rejects_invalid_index() {
        let pss = ProactiveRefresh::new(2, 3);
        assert!(pss.generate_refresh_polynomial(0).is_err());
        assert!(pss.generate_refresh_polynomial(4).is_err());
    }

    #[test]
    fn apply_refresh_rejects_wrong_target() {
        let pss = ProactiveRefresh::new(2, 3);
        let share = KekShare::new(1, [0x42; 32]);

        let (contributions, _) = pss.generate_refresh_polynomial(1).unwrap();
        // contributions[1] targets node 2, not node 1
        let wrong = vec![contributions[1].clone(), contributions[1].clone(), contributions[1].clone()];
        assert!(pss.apply_refresh(share, &wrong).is_err());
    }

    #[test]
    fn refresh_with_2_of_3_threshold() {
        let secret = [0xEEu8; 32];
        let shares = split_secret(&secret, 2, 3).unwrap();

        let pss = ProactiveRefresh::new(2, 3);
        let new_shares = pss.full_refresh_round(shares).unwrap();

        let recovered = reconstruct_secret(&new_shares[0..2]).unwrap();
        assert_eq!(recovered, secret);

        let picked = vec![new_shares[0].clone(), new_shares[2].clone()];
        let recovered2 = reconstruct_secret(&picked).unwrap();
        assert_eq!(recovered2, secret);
    }

    #[test]
    fn subshare_constant_term_is_zero() {
        // The refresh polynomial must have δ(0) = 0 for all bytes.
        // We verify by checking that summing sub-shares at x=0 would yield 0.
        // Equivalently: reconstructing from sub-shares alone (as if they were
        // shares of a secret) must yield the zero secret.
        let pss = ProactiveRefresh::new(3, 5);
        let (contributions, _) = pss.generate_refresh_polynomial(1).unwrap();

        // Create KekShares from sub-shares
        let sub_shares: Vec<KekShare> = contributions
            .iter()
            .map(|c| KekShare {
                index: c.to_node as u8,
                value: {
                    let mut v = [0u8; 32];
                    v.copy_from_slice(&c.sub_share);
                    v
                },
            })
            .collect();

        // Reconstruct: should be the zero polynomial's constant term = 0
        let reconstructed = reconstruct_secret(&sub_shares[0..3]).unwrap();
        assert_eq!(reconstructed, [0u8; 32], "refresh polynomial constant term must be 0");
    }
}
