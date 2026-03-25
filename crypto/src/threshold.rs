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
pub struct SignerShare {
    pub identifier: Identifier,
    pub key_package: KeyPackage,
    pub nonce_counter: u64,
}

/// Result of a DKG ceremony.
pub struct DkgResult {
    pub group: ThresholdGroup,
    pub shares: Vec<SignerShare>,
}

/// Run a DKG ceremony to generate a threshold group.
/// Uses trusted dealer (frost::keys::generate_with_dealer).
pub fn dkg(total: u16, threshold: u16) -> DkgResult {
    let mut rng = rand::rngs::OsRng;
    let (shares_map, public_key_package) = frost::keys::generate_with_dealer(
        total,
        threshold,
        frost::keys::IdentifierList::Default,
        &mut rng,
    )
    .expect("DKG failed");

    let shares: Vec<SignerShare> = shares_map
        .into_iter()
        .map(|(id, secret_share)| SignerShare {
            identifier: id,
            key_package: KeyPackage::try_from(secret_share).unwrap(),
            nonce_counter: 0,
        })
        .collect();

    DkgResult {
        group: ThresholdGroup {
            threshold: threshold as usize,
            total: total as usize,
            public_key_package,
        },
        shares,
    }
}

/// Perform a full threshold signing ceremony with the given signers.
///
/// Takes the first `threshold` signers from `shares`, runs FROST round1 (commit),
/// round2 (sign), and aggregation, returning the 64-byte group signature.
pub fn threshold_sign(
    shares: &mut [SignerShare],
    group: &ThresholdGroup,
    message: &[u8],
    threshold: usize,
) -> Result<[u8; 64], String> {
    if shares.len() < threshold {
        return Err(format!(
            "need {} signers, got {}",
            threshold,
            shares.len()
        ));
    }

    let mut rng = rand::rngs::OsRng;

    // Round 1: each signer commits
    let mut nonces_map: BTreeMap<Identifier, frost::round1::SigningNonces> = BTreeMap::new();
    let mut commitments_map: BTreeMap<Identifier, frost::round1::SigningCommitments> =
        BTreeMap::new();

    for signer in shares.iter_mut().take(threshold) {
        signer.nonce_counter += 1;
        let (nonces, commitments) =
            frost::round1::commit(signer.key_package.signing_share(), &mut rng);
        nonces_map.insert(signer.identifier, nonces);
        commitments_map.insert(signer.identifier, commitments);
    }

    // Create signing package
    let signing_package =
        SigningPackage::new(commitments_map, message);

    // Round 2: each signer signs
    let mut signature_shares: BTreeMap<Identifier, frost::round2::SignatureShare> = BTreeMap::new();
    for signer in shares.iter().take(threshold) {
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
    /// Refresh all shares.
    ///
    /// Generates a completely fresh FROST group with the same threshold and
    /// total-signer parameters. The new group has a new verifying key; old
    /// shares cannot be combined with new shares for signing.
    ///
    /// The `current_epoch` argument is the caller's current epoch counter.
    /// The returned [`ShareRefreshResult::refresh_epoch`] is `current_epoch + 1`.
    pub fn refresh_shares(
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

        let new_shares: Vec<SignerShare> = shares_map
            .into_iter()
            .map(|(id, secret_share)| {
                let key_package = KeyPackage::try_from(secret_share)
                    .expect("key package creation must succeed during refresh");
                SignerShare {
                    identifier: id,
                    key_package,
                    nonce_counter: 0,
                }
            })
            .collect();

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

    fn make_group(total: u16, threshold: u16) -> DkgResult {
        dkg(total, threshold)
    }

    #[test]
    fn test_share_refresh_produces_new_shares() {
        let result = make_group(3, 2);
        let old_shares = result.shares;
        let group = result.group;

        let refresh = group
            .refresh_shares(&old_shares, 0)
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
            .refresh_shares(&old_shares, 0)
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
            .refresh_shares(&old_shares, 0)
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
    fn test_share_refresh_epoch_increments() {
        let result = make_group(3, 2);
        let group = result.group;
        let old_shares = result.shares;

        let r1 = group
            .refresh_shares(&old_shares, 0)
            .expect("first refresh must succeed");
        assert_eq!(r1.refresh_epoch, 1, "epoch after first refresh must be 1");

        let r2 = r1
            .new_group
            .refresh_shares(&r1.new_shares, r1.refresh_epoch)
            .expect("second refresh must succeed");
        assert_eq!(r2.refresh_epoch, 2, "epoch after second refresh must be 2");
    }
}
