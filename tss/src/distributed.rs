//! Distributed FROST signing across separate signer processes.
//! Each signer holds exactly ONE share. The coordinator aggregates.

use frost_ristretto255 as frost;
use frost::keys::{KeyPackage, PublicKeyPackage};
use frost::round1::{SigningCommitments, SigningNonces};
use frost::round2::SignatureShare;
use frost::{Identifier, SigningPackage};
use std::collections::BTreeMap;

/// A single signer node -- holds exactly ONE key share.
///
/// In production each `SignerNode` runs in a separate OS process (or
/// container). The coordinator communicates with it over IPC / SHARD.
pub struct SignerNode {
    pub identifier: Identifier,
    pub key_package: KeyPackage,
    nonce_counter: u64,
}

impl SignerNode {
    pub fn new(identifier: Identifier, key_package: KeyPackage) -> Self {
        Self {
            identifier,
            key_package,
            nonce_counter: 0,
        }
    }

    /// Round 1: Generate commitments (called on each signer independently).
    pub fn commit(&mut self) -> (SigningNonces, SigningCommitments) {
        self.nonce_counter += 1;
        let mut rng = rand::thread_rng();
        frost::round1::commit(self.key_package.signing_share(), &mut rng)
    }

    /// Round 2: Produce a signature share (called on each signer independently).
    pub fn sign(
        &self,
        signing_package: &SigningPackage,
        nonces: &SigningNonces,
    ) -> Result<SignatureShare, frost::Error> {
        frost::round2::sign(signing_package, nonces, &self.key_package)
    }

    /// Return this node's FROST identifier.
    pub fn identifier(&self) -> Identifier {
        self.identifier
    }

    /// Return how many nonce-commit rounds this node has participated in.
    pub fn nonce_counter(&self) -> u64 {
        self.nonce_counter
    }
}

/// Coordinator -- holds NO shares, only the public key package.
///
/// The coordinator orchestrates the two-round FROST protocol by collecting
/// commitments from signers, building the `SigningPackage`, distributing it
/// back, collecting signature shares, and finally aggregating them into a
/// group signature.
pub struct SigningCoordinator {
    pub public_key_package: PublicKeyPackage,
    pub threshold: usize,
}

impl SigningCoordinator {
    pub fn new(public_key_package: PublicKeyPackage, threshold: usize) -> Self {
        Self {
            public_key_package,
            threshold,
        }
    }

    /// Coordinate a distributed signing ceremony.
    ///
    /// Takes separate signer nodes (each holding 1 share) and a message,
    /// runs FROST round-1 and round-2, and aggregates into a group signature.
    pub fn coordinate_signing(
        &self,
        signers: &mut [&mut SignerNode],
        message: &[u8],
    ) -> Result<[u8; 64], String> {
        if signers.len() < self.threshold {
            return Err(format!(
                "need {} signers, got {}",
                self.threshold,
                signers.len()
            ));
        }

        // Round 1: Collect commitments from each signer
        let mut nonces_map: BTreeMap<Identifier, SigningNonces> = BTreeMap::new();
        let mut commitments_map: BTreeMap<Identifier, SigningCommitments> = BTreeMap::new();

        for signer in signers.iter_mut() {
            let (nonces, commitments) = signer.commit();
            nonces_map.insert(signer.identifier(), nonces);
            commitments_map.insert(signer.identifier(), commitments);
        }

        // Create signing package
        let signing_package = SigningPackage::new(commitments_map, message);

        // Round 2: Collect signature shares from each signer
        let mut signature_shares: BTreeMap<Identifier, SignatureShare> = BTreeMap::new();

        for signer in signers.iter() {
            let nonces = nonces_map
                .remove(&signer.identifier())
                .ok_or("missing nonces")?;
            let share = signer
                .sign(&signing_package, &nonces)
                .map_err(|e| format!("signer {:?} failed: {e}", signer.identifier()))?;
            signature_shares.insert(signer.identifier(), share);
        }

        // Aggregate
        let group_signature = frost::aggregate(
            &signing_package,
            &signature_shares,
            &self.public_key_package,
        )
        .map_err(|e| format!("aggregation failed: {e}"))?;

        let sig_bytes = group_signature
            .serialize()
            .map_err(|e| format!("signature serialization failed: {e}"))?;
        let mut out = [0u8; 64];
        out.copy_from_slice(&sig_bytes);
        Ok(out)
    }
}

/// Distribute DKG result into separate signer nodes (one share each).
///
/// Returns the coordinator (which holds NO signing keys, only the group
/// public key) and a `Vec` of `SignerNode`s, each holding exactly one
/// `KeyPackage`.
pub fn distribute_shares(
    dkg_result: &mut crypto::threshold::DkgResult,
) -> (SigningCoordinator, Vec<SignerNode>) {
    let coordinator = SigningCoordinator::new(
        dkg_result.group.public_key_package.clone(),
        dkg_result.group.threshold,
    );

    let nodes: Vec<SignerNode> = dkg_result
        .shares
        .drain(..)
        .map(|share| SignerNode::new(share.identifier, share.key_package))
        .collect();

    (coordinator, nodes)
}
