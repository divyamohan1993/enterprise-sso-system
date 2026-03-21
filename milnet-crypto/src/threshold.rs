//! FROST threshold signing (spec C.6, C.15)
//!
//! Uses frost-ristretto255 with trusted dealer key generation.
//! Phase 2: trusted dealer is acceptable; real DKG requires TSS service wiring.

use frost_ristretto255 as frost;
use frost::keys::{KeyPackage, PublicKeyPackage};
use frost::{Identifier, SigningPackage};
use rand::thread_rng;
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
    let mut rng = thread_rng();
    let (shares_map, public_key_package) = frost::keys::generate_with_dealer(
        total.into(),
        threshold.into(),
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

    let mut rng = thread_rng();

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
