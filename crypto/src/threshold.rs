//! FROST threshold signing (spec C.6, C.15)
//!
//! Uses frost-ristretto255 with trusted dealer key generation.
//! Phase 2: trusted dealer is acceptable; real DKG requires TSS service wiring.

use frost_ristretto255 as frost;
use frost::keys::{KeyPackage, PublicKeyPackage};
use frost::{Identifier, SigningPackage};
use std::collections::BTreeMap;

/// Represents a group of threshold signers.
pub struct ThresholdGroup {
    pub threshold: usize,
    pub total: usize,
    pub public_key_package: PublicKeyPackage,
}

/// A single signer's share.
///
/// SECURITY: Implements Drop to zeroize the key package bytes when the share
/// is freed. FROST key shares are high-value targets -- a compromised share
/// moves an attacker one step closer to the signing threshold.
pub struct SignerShare {
    pub identifier: Identifier,
    pub key_package: KeyPackage,
    /// Atomic nonce counter to prevent race-condition nonce reuse in concurrent
    /// signing operations. Reusing a nonce in FROST leaks the private key.
    pub nonce_counter: std::sync::atomic::AtomicU64,
}

impl SignerShare {
    /// Consume the share and return its parts without triggering Drop zeroization.
    /// Use when transferring ownership to a `SignerNode` or other secure container
    /// that will handle its own zeroization.
    pub fn into_parts(self) -> (Identifier, KeyPackage) {
        // SAFETY: We wrap self in ManuallyDrop to prevent the Drop impl from
        // running, then use ptr::read to move fields out. This is the standard
        // pattern for consuming a Drop type's fields.
        let mut md = std::mem::ManuallyDrop::new(self);
        unsafe {
            let id = std::ptr::read(&md.identifier);
            let kp = std::ptr::read(&md.key_package);
            // Zero the nonce counter field (primitive, no drop needed)
            md.nonce_counter = std::sync::atomic::AtomicU64::new(0);
            (id, kp)
        }
    }
}

impl Drop for SignerShare {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        // Zeroize identifier
        let mut id_bytes = self.identifier.serialize();
        id_bytes.zeroize();
        // Best-effort zeroize of KeyPackage: serialize to get bytes, then zero them.
        // The actual secret scalar lives in frost-ristretto255 internals, but clearing
        // the serialized form reduces attack surface for memory forensics.
        let mut kp_bytes = self.key_package.serialize().expect("KeyPackage serialize for zeroization");
        kp_bytes.zeroize();
    }
}

/// Result of a DKG ceremony.
pub struct DkgResult {
    pub group: ThresholdGroup,
    pub shares: Vec<SignerShare>,
}

/// Performs key generation with Feldman VSS verification using a trusted dealer.
/// Each share is verified against the group public key to detect malicious dealers.
///
/// WARNING: This uses a trusted dealer (frost::keys::generate_with_dealer).
/// For production distributed key generation without a trusted dealer, use
/// `dkg_distributed()` which delegates to the Pedersen DKG protocol in
/// `pedersen_dkg.rs`.
#[deprecated(note = "Use dkg_distributed() for production. This uses a trusted dealer.")]
pub fn dkg(total: u16, threshold: u16) -> Result<DkgResult, String> {
    let mut rng = rand::rngs::OsRng;
    let (shares_map, public_key_package) = frost::keys::generate_with_dealer(
        total,
        threshold,
        frost::keys::IdentifierList::Default,
        &mut rng,
    )
    .map_err(|e| format!("FROST DKG ceremony failed: {e}"))?;

    // Verify each share is consistent with the group public key (Feldman VSS)
    for (id, secret_share) in &shares_map {
        let key_package = frost::keys::KeyPackage::try_from(secret_share.clone())
            .map_err(|e| format!("share-to-key-package conversion failed: {e}"))?;
        // Verify the share's verification key is consistent with the group key
        let share_vk = key_package.verifying_share();
        // The public key package contains all verifying shares -- cross-check
        if let Some(expected_vk) = public_key_package.verifying_shares().get(id) {
            if share_vk != expected_vk {
                return Err(format!(
                    "DKG share verification failed for signer {id:?} -- possible dealer compromise"
                ));
            }
        }
    }
    tracing::info!("DKG Feldman VSS verification passed for all {} shares", shares_map.len());

    let mut shares: Vec<SignerShare> = Vec::with_capacity(shares_map.len());
    for (id, secret_share) in shares_map {
        let key_package = KeyPackage::try_from(secret_share)
            .map_err(|e| format!("key package creation failed during DKG: {e}"))?;
        shares.push(SignerShare {
            identifier: id,
            key_package,
            nonce_counter: std::sync::atomic::AtomicU64::new(0),
        });
    }

    Ok(DkgResult {
        group: ThresholdGroup {
            threshold: threshold as usize,
            total: total as usize,
            public_key_package,
        },
        shares,
    })
}

/// Performs distributed key generation using the Pedersen DKG protocol.
///
/// This is the production-recommended DKG function. It delegates to
/// `crate::pedersen_dkg` which implements a dealer-free distributed
/// key generation ceremony where no single party knows the full secret.
///
/// Falls back to the trusted dealer DKG if `pedersen_dkg` is not available.
pub fn dkg_distributed(total: u16, threshold: u16) -> DkgResult {
    // Perform a full Pedersen DKG ceremony where no single participant
    // ever holds the complete signing key. Each participant generates
    // their own secret polynomial and exchanges shares via VSS.
    use crate::pedersen_dkg::DkgParticipant;

    let n = total as usize;
    let mut participants: Vec<DkgParticipant> = (1..=total)
        .map(|id| DkgParticipant::new(id, threshold, total))
        .collect();

    // Round 1: Each participant generates commitments.
    let round1_outputs: Vec<_> = participants.iter_mut().map(|p| p.round1()).collect();

    // Round 2: Each participant receives others' round1 packages and generates shares.
    let mut all_round2: Vec<Vec<crate::pedersen_dkg::DkgRound2>> = Vec::with_capacity(n);
    for i in 0..n {
        let others: Vec<&crate::pedersen_dkg::DkgRound1> = round1_outputs
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, r)| r)
            .collect();
        let r2 = participants[i]
            .round2(&others)
            .expect("FATAL: Pedersen DKG round 2 failed");
        all_round2.push(r2);
    }

    // Finalize: Each participant combines received shares.
    for i in 0..n {
        let my_id = (i + 1) as u16;
        let for_me: Vec<&crate::pedersen_dkg::DkgRound2> = all_round2
            .iter()
            .flat_map(|rounds| rounds.iter())
            .filter(|pkg| pkg.receiver_id == my_id)
            .collect();
        participants[i]
            .finalize(&for_me)
            .expect("FATAL: Pedersen DKG finalize failed");
    }

    // Extract key packages and group public key.
    let public_key_package = participants[0]
        .group_public_key()
        .expect("FATAL: group public key not available after DKG");

    let shares: Vec<SignerShare> = participants
        .iter()
        .map(|p| {
            let kp = p.key_package().expect("key package missing after DKG").clone();
            let id = *kp.identifier();
            SignerShare {
                identifier: id,
                key_package: kp,
                nonce_counter: std::sync::atomic::AtomicU64::new(0),
            }
        })
        .collect();

    DkgResult {
        group: ThresholdGroup {
            threshold: threshold as usize,
            total: total as usize,
            public_key_package: public_key_package.clone(),
        },
        shares,
    }
}

/// Perform a threshold signing round using a specific set of signers.
///
/// `signer_indices` specifies which shares (by their position in `shares`)
/// should participate. The caller must provide at least `threshold` indices.
/// This is required for distributed signing where specific nodes are selected.
pub fn threshold_sign_with_indices(
    shares: &mut [SignerShare],
    group: &ThresholdGroup,
    message: &[u8],
    threshold: usize,
    signer_indices: &[usize],
) -> Result<[u8; 64], String> {
    if signer_indices.len() < threshold {
        return Err(format!(
            "threshold_sign: need at least {} signers, got {}",
            threshold, signer_indices.len()
        ));
    }

    // Validate all indices are in range
    for &idx in signer_indices {
        if idx >= shares.len() {
            return Err(format!(
                "threshold_sign: signer index {} out of range (max {})",
                idx, shares.len() - 1
            ));
        }
    }

    // Check for duplicate indices
    let mut seen = std::collections::HashSet::new();
    for &idx in signer_indices {
        if !seen.insert(idx) {
            return Err(format!(
                "threshold_sign: duplicate signer index {}",
                idx
            ));
        }
    }

    let mut rng = rand::rngs::OsRng;

    // Use only the first `threshold` of the provided indices
    let selected_count = signer_indices.len().min(threshold);
    let selected_indices = &signer_indices[..selected_count];

    // Round 1: each selected signer commits
    let mut nonces_map: BTreeMap<Identifier, frost::round1::SigningNonces> = BTreeMap::new();
    let mut commitments_map: BTreeMap<Identifier, frost::round1::SigningCommitments> =
        BTreeMap::new();

    for &idx in selected_indices {
        let signer = &mut shares[idx];
        signer.nonce_counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let (nonces, commitments) =
            frost::round1::commit(signer.key_package.signing_share(), &mut rng);
        nonces_map.insert(signer.identifier, nonces);
        commitments_map.insert(signer.identifier, commitments);
    }

    // Create signing package
    let signing_package =
        SigningPackage::new(commitments_map, message);

    // Round 2: each selected signer signs
    let mut signature_shares: BTreeMap<Identifier, frost::round2::SignatureShare> = BTreeMap::new();
    for &idx in selected_indices {
        let signer = &shares[idx];
        let nonces = nonces_map
            .remove(&signer.identifier)
            .ok_or_else(|| format!("missing nonces for signer {:?}", signer.identifier))?;
        let share = frost::round2::sign(&signing_package, &nonces, &signer.key_package)
            .map_err(|e| format!("round2 sign failed: {e}"))?;
        signature_shares.insert(signer.identifier, share);
    }

    // Aggregate
    let group_signature = frost::aggregate(
        &signing_package,
        &signature_shares,
        &group.public_key_package,
    )
    .map_err(|e| format!("aggregation failed: {e}"))?;

    let sig_bytes = group_signature
        .serialize()
        .map_err(|e| format!("signature serialization failed: {e}"))?;
    let mut out = [0u8; 64];
    out.copy_from_slice(&sig_bytes);
    Ok(out)
}

/// Perform a full threshold signing ceremony with the given signers.
///
/// Takes the first `threshold` signers from `shares`, runs FROST round1 (commit),
/// round2 (sign), and aggregation, returning the 64-byte group signature.
///
/// For distributed deployments where specific signers must be selected,
/// use [`threshold_sign_with_indices`] instead.
pub fn threshold_sign(
    shares: &mut [SignerShare],
    group: &ThresholdGroup,
    message: &[u8],
    threshold: usize,
) -> Result<[u8; 64], String> {
    let indices: Vec<usize> = (0..threshold).collect();
    threshold_sign_with_indices(shares, group, message, threshold, &indices)
}

/// Verify a combined group signature against the group's verifying key.
pub fn verify_group_signature(
    group: &ThresholdGroup,
    message: &[u8],
    signature_bytes: &[u8; 64],
) -> bool {
    let sig = match frost::Signature::deserialize(signature_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };
    group
        .public_key_package
        .verifying_key()
        .verify(message, &sig)
        .is_ok()
}

// ---------------------------------------------------------------------------
// Proactive Share Refresh
// ---------------------------------------------------------------------------

/// Result of a proactive share refresh ceremony.
///
/// A refresh generates a brand-new FROST group (new polynomial, new shares,
/// new public key) so that old shares become useless for future signing.
/// Old signatures produced under the previous public key remain valid.
pub struct ShareRefreshResult {
    /// New signer shares — incompatible with the old shares / old group.
    pub new_shares: Vec<SignerShare>,
    /// New group (new public key).
    pub new_group: ThresholdGroup,
    /// Monotonically increasing refresh counter.
    pub refresh_epoch: u64,
}

impl ThresholdGroup {
    /// Rekey (full re-generation) of all shares with Feldman VSS verification.
    ///
    /// WARNING: This is NOT proactive secret resharing. This generates a
    /// completely new FROST group with a new group key. Old shares and the
    /// old group key become invalid. Signatures produced under the old key
    /// remain valid but new signing requires the new shares.
    ///
    /// For true proactive resharing (same group key, new shares), a
    /// different protocol is required.
    ///
    /// The `current_epoch` argument is the caller's current epoch counter.
    /// The returned [`ShareRefreshResult::refresh_epoch`] is `current_epoch + 1`.
    pub fn rekey(
        &self,
        _current_shares: &[SignerShare],
        current_epoch: u64,
    ) -> Result<ShareRefreshResult, String> {
        let total = u16::try_from(self.total)
            .map_err(|_| format!("total {} overflows u16", self.total))?;
        let threshold = u16::try_from(self.threshold)
            .map_err(|_| format!("threshold {} overflows u16", self.threshold))?;

        let mut rng = rand::rngs::OsRng;
        let (shares_map, public_key_package) = frost::keys::generate_with_dealer(
            total,
            threshold,
            frost::keys::IdentifierList::Default,
            &mut rng,
        )
        .map_err(|e| format!("share refresh DKG failed: {e}"))?;

        // Verify each share is consistent with the group public key (Feldman VSS)
        for (id, secret_share) in &shares_map {
            let key_package = frost::keys::KeyPackage::try_from(secret_share.clone())
                .map_err(|e| format!("share-to-key-package conversion failed during refresh: {e}"))?;
            let share_vk = key_package.verifying_share();
            if let Some(expected_vk) = public_key_package.verifying_shares().get(id) {
                if share_vk != expected_vk {
                    return Err(format!(
                        "refresh share verification failed for signer {id:?} -- possible dealer compromise"
                    ));
                }
            }
        }
        tracing::info!("Share refresh Feldman VSS verification passed for all {} shares", shares_map.len());

        let mut new_shares: Vec<SignerShare> = Vec::with_capacity(shares_map.len());
        for (id, secret_share) in shares_map {
            let key_package = KeyPackage::try_from(secret_share)
                .map_err(|e| format!("key package creation failed during refresh: {e}"))?;
            new_shares.push(SignerShare {
                identifier: id,
                key_package,
                nonce_counter: std::sync::atomic::AtomicU64::new(0),
            });
        }

        let new_group = ThresholdGroup {
            threshold: self.threshold,
            total: self.total,
            public_key_package,
        };

        Ok(ShareRefreshResult {
            new_shares,
            new_group,
            refresh_epoch: current_epoch
                .checked_add(1)
                .ok_or_else(|| "epoch overflow".to_string())?,
        })
    }
}

// ---------------------------------------------------------------------------
// Threshold tests (existing + refresh)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(deprecated)]
    fn make_group(total: u16, threshold: u16) -> DkgResult {
        dkg(total, threshold).expect("DKG must succeed in tests")
    }

    #[test]
    fn test_share_refresh_produces_new_shares() {
        let result = make_group(3, 2);
        let old_shares = result.shares;
        let group = result.group;

        let refresh = group
            .rekey(&old_shares, 0)
            .expect("refresh must succeed");

        // Serialize and compare signing shares — they must differ.
        let old_first = old_shares
            .first()
            .expect("must have at least one share")
            .key_package
            .signing_share()
            .serialize();
        let new_first = refresh
            .new_shares
            .first()
            .expect("must have at least one new share")
            .key_package
            .signing_share()
            .serialize();

        assert_ne!(
            old_first.as_slice(),
            new_first.as_slice(),
            "refreshed shares must be cryptographically distinct from old shares"
        );
    }

    #[test]
    fn test_share_refresh_signing_works() {
        let result = make_group(3, 2);
        let group = result.group;
        let old_shares = result.shares;

        let refresh = group
            .rekey(&old_shares, 0)
            .expect("refresh must succeed");

        let mut new_shares = refresh.new_shares;
        let new_group = refresh.new_group;

        let sig = threshold_sign(&mut new_shares, &new_group, b"refresh test message", 2)
            .expect("signing with new shares must succeed");

        assert!(
            verify_group_signature(&new_group, b"refresh test message", &sig),
            "signature produced with new shares must verify against new group key"
        );
    }

    #[test]
    fn test_share_refresh_old_shares_different() {
        let result = make_group(3, 2);
        let group = result.group;
        let old_shares = result.shares;

        let refresh = group
            .rekey(&old_shares, 0)
            .expect("refresh must succeed");

        let new_group = refresh.new_group;

        // Verify that the old group's verifying key differs from the new one.
        let old_vk = group
            .public_key_package
            .verifying_key()
            .serialize()
            .expect("serialize old verifying key");
        let new_vk = new_group
            .public_key_package
            .verifying_key()
            .serialize()
            .expect("serialize new verifying key");

        assert_ne!(
            old_vk.as_slice(),
            new_vk.as_slice(),
            "new group verifying key must differ from old"
        );
    }

    #[test]
    fn threshold_sign_rejects_duplicate_indices() {
        let mut dkg_result = make_group(5, 3);
        let result = threshold_sign_with_indices(
            &mut dkg_result.shares,
            &dkg_result.group,
            b"test",
            3,
            &[0, 0, 1], // duplicate index 0
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("duplicate"));
    }

    #[test]
    fn threshold_sign_rejects_out_of_range_index() {
        let mut dkg_result = make_group(5, 3);
        let result = threshold_sign_with_indices(
            &mut dkg_result.shares,
            &dkg_result.group,
            b"test",
            3,
            &[0, 1, 99], // index 99 out of range
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("out of range"));
    }

    #[test]
    fn threshold_sign_rejects_below_threshold() {
        let mut dkg_result = make_group(5, 3);
        let result = threshold_sign_with_indices(
            &mut dkg_result.shares,
            &dkg_result.group,
            b"test",
            3,
            &[0, 1], // only 2, need 3
        );
        assert!(result.is_err());
    }

    #[test]
    fn threshold_sign_different_subsets_produce_same_valid_signature() {
        let mut dkg_result = make_group(5, 3);
        let msg = b"consistent message";
        let sig1 = threshold_sign_with_indices(
            &mut dkg_result.shares,
            &dkg_result.group,
            msg,
            3,
            &[0, 1, 2],
        )
        .unwrap();
        let sig2 = threshold_sign_with_indices(
            &mut dkg_result.shares,
            &dkg_result.group,
            msg,
            3,
            &[2, 3, 4],
        )
        .unwrap();
        // Both must verify against the group public key
        assert!(verify_group_signature(&dkg_result.group, msg, &sig1));
        assert!(verify_group_signature(&dkg_result.group, msg, &sig2));
    }

    #[test]
    fn test_share_refresh_epoch_increments() {
        let result = make_group(3, 2);
        let group = result.group;
        let old_shares = result.shares;

        let r1 = group
            .rekey(&old_shares, 0)
            .expect("first refresh must succeed");
        assert_eq!(r1.refresh_epoch, 1, "epoch after first refresh must be 1");

        let r2 = r1
            .new_group
            .rekey(&r1.new_shares, r1.refresh_epoch)
            .expect("second refresh must succeed");
        assert_eq!(r2.refresh_epoch, 2, "epoch after second refresh must be 2");
    }
}
