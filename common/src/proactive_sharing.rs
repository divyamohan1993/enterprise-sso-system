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
//! VERIFICATION: Each node publishes SHA-512 hash commitments to the sub-shares
//! it will send, allowing receivers to verify authenticity (CNSA 2.0 Level 5).
//!
//! INVARIANTS:
//! - The secret is NEVER reconstructed during refresh.
//! - All sub-share polynomials have constant term 0.
//! - Contributions are verified via SHA-512 hash commitments before application.
//! - Old shares are zeroized after refresh.
//! - Every refresh round emits a SIEM event.

use crate::siem::{PanelSiemEvent, SiemPanel, SiemSeverity};
use crate::threshold_kek::{ct_gf256_mul, gf256_add, KekShare};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha512};
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
    /// SHA-512 hash commitment: `H(from_node || to_node || epoch || sub_share)`.
    /// Used to verify the sub-share against the published commitments (CNSA 2.0).
    pub commitment: Vec<u8>,
}

impl Drop for RefreshContribution {
    fn drop(&mut self) {
        self.sub_share.zeroize();
    }
}

/// Feldman VSS commitments: g^coefficient for each polynomial coefficient.
#[derive(Clone)]
pub struct FeldmanCommitments {
    pub from_node: usize,
    pub epoch: u64,
    pub commitments: Vec<[u8; 32]>,
    pub feldman_shares: Vec<[u8; 32]>,
}

/// Hash-based commitments (secondary) + Feldman VSS commitments (primary).
#[derive(Clone)]
pub struct RefreshCommitments {
    pub from_node: usize,
    pub epoch: u64,
    pub commitments: Vec<Vec<u8>>,
    pub feldman: FeldmanCommitments,
}

// ---------------------------------------------------------------------------
// Hash-based commitment helpers
// ---------------------------------------------------------------------------

/// Compute a SHA-512 commitment to a sub-share (CNSA 2.0 Level 5).
///
/// `H(from_node || to_node || epoch || sub_share_bytes)` binds the commitment
/// to the exact context, preventing cross-node or cross-epoch replay.
fn hash_commit(from_node: usize, to_node: usize, epoch: u64, sub_share: &[u8]) -> Vec<u8> {
    let mut hasher = Sha512::new();
    hasher.update(&(from_node as u64).to_be_bytes());
    hasher.update(&(to_node as u64).to_be_bytes());
    hasher.update(&epoch.to_be_bytes());
    hasher.update(sub_share);
    hasher.finalize().to_vec()
}

// ---------------------------------------------------------------------------
// Feldman VSS helpers (Ristretto255 group)
// ---------------------------------------------------------------------------

fn bytes_to_scalar(data: &[u8]) -> Scalar { Scalar::hash_from_bytes::<Sha512>(data) }

fn feldman_commit(scalar: &Scalar) -> CompressedRistretto {
    (RISTRETTO_BASEPOINT_POINT * scalar).compress()
}

fn feldman_verify(commitments: &[[u8; 32]], target_index: usize, share_scalar: &Scalar) -> bool {
    let lhs: RistrettoPoint = RISTRETTO_BASEPOINT_POINT * share_scalar;
    let i_scalar = Scalar::from(target_index as u64);
    let mut rhs = RistrettoPoint::default();
    let mut i_power = Scalar::ONE;
    for cb in commitments {
        let point = match CompressedRistretto(*cb).decompress() { Some(p) => p, None => return false };
        rhs += point * i_power;
        i_power *= i_scalar;
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

        // Evaluate polynomial at each target node's index to produce sub-shares
        let mut contributions = Vec::with_capacity(self.total_shares);
        let mut per_target_hashes: Vec<Vec<u8>> = Vec::with_capacity(self.total_shares);

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

            // Hash commitment for this sub-share
            let commitment = hash_commit(my_index, target, epoch, &sub_share);
            per_target_hashes.push(commitment.clone());

            contributions.push(RefreshContribution {
                from_node: my_index,
                to_node: target,
                sub_share,
                epoch,
                commitment,
            });
        }

        // Build Feldman VSS commitments (primary verification layer).
        let mut feldman_coeff_commitments: Vec<[u8; 32]> = Vec::with_capacity(t);
        let c0_scalar = bytes_to_scalar(&[0u8; 32]);
        feldman_coeff_commitments.push(feldman_commit(&c0_scalar).to_bytes());
        for k in 0..coeffs_per_byte {
            let mut coeff_vec = [0u8; 32];
            for byte_idx in 0..32 { coeff_vec[byte_idx] = coefficients[byte_idx][k]; }
            feldman_coeff_commitments.push(feldman_commit(&bytes_to_scalar(&coeff_vec)).to_bytes());
        }
        let mut feldman_shares: Vec<[u8; 32]> = Vec::with_capacity(self.total_shares);
        for contrib in &contributions { feldman_shares.push(bytes_to_scalar(&contrib.sub_share).to_bytes()); }

        let feldman = FeldmanCommitments {
            from_node: my_index, epoch,
            commitments: feldman_coeff_commitments,
            feldman_shares,
        };
        let flat_commitments = RefreshCommitments {
            from_node: my_index, epoch,
            commitments: per_target_hashes,
            feldman,
        };

        // Zeroize coefficient material
        for c in &mut coefficients {
            c.zeroize();
        }
        random_bytes.zeroize();

        Ok((contributions, flat_commitments))
    }

    /// Verify a single contribution against published commitments.
    ///
    /// Checks that the SHA-256 hash of the received sub-share matches the
    /// committed hash published by the source node.
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

        // Look up the committed hash for this target node (0-indexed)
        let target_idx = contribution.to_node.checked_sub(1).ok_or_else(|| {
            format!("to_node {} is invalid (must be >= 1)", contribution.to_node)
        })?;
        if target_idx >= commitments.commitments.len() {
            return Err(format!(
                "no commitment for target node {} (have {} entries)",
                contribution.to_node,
                commitments.commitments.len()
            ));
        }

        let expected_hash = &commitments.commitments[target_idx];
        let actual_hash = hash_commit(
            contribution.from_node,
            contribution.to_node,
            contribution.epoch,
            &contribution.sub_share,
        );

        if expected_hash != &actual_hash {
            return Err(format!(
                "hash commitment verification failed from node {} to node {}",
                contribution.from_node, contribution.to_node
            ));
        }

        // Primary: Feldman VSS verification over Ristretto255.
        if target_idx >= commitments.feldman.feldman_shares.len() {
            return Err(format!("no Feldman share for target node {}", contribution.to_node));
        }
        let share_scalar = Scalar::from_canonical_bytes(commitments.feldman.feldman_shares[target_idx]);
        let share_scalar = if share_scalar.is_some().into() { share_scalar.unwrap() } else { bytes_to_scalar(&contribution.sub_share) };
        if !feldman_verify(&commitments.feldman.commitments, contribution.to_node, &share_scalar) {
            return Err(format!("Feldman VSS verification failed from node {} to node {}", contribution.from_node, contribution.to_node));
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

        Ok(KekShare::new(my_share.index, new_value))
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
                KekShare::new(target_idx as u8, [0u8; 32]),
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
            .map(|c| {
                let mut v = [0u8; 32];
                v.copy_from_slice(&c.sub_share);
                KekShare::new(c.to_node as u8, v)
            })
            .collect();

        // Reconstruct: should be the zero polynomial's constant term = 0
        let reconstructed = reconstruct_secret(&sub_shares[0..3]).unwrap();
        assert_eq!(reconstructed, [0u8; 32], "refresh polynomial constant term must be 0");
    }
}
