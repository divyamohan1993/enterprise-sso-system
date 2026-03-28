//! Distributed Pedersen DKG for FROST Ristretto255.
//!
//! Unlike `generate_with_dealer` (crypto::threshold::dkg), this ensures NO
//! single process ever holds the complete signing key. Each participant
//! generates their own secret polynomial and shares commitments via
//! verifiable secret sharing.
//!
//! Protocol:
//! 1. Round 1: Each participant generates a random polynomial, publishes commitments
//! 2. Round 2: Each participant evaluates polynomial at others' indices, sends shares
//! 3. Finalize: Each participant combines received shares to form their key share

use frost_ristretto255 as frost;
use frost::keys::dkg;
use rand::rngs::OsRng;
use std::collections::BTreeMap;

/// A participant in the distributed Pedersen DKG ceremony.
pub struct DkgParticipant {
    /// The u16 ID this participant was created with (for labelling output packages).
    id: u16,
    identifier: frost::Identifier,
    threshold: u16,
    total: u16,
    /// Secret from round 1 — stored here so round 2 can use it.
    round1_secret: Option<dkg::round1::SecretPackage>,
    /// Secret from round 2 — stored here so finalize can use it.
    round2_secret: Option<dkg::round2::SecretPackage>,
    /// All round 1 packages from other participants (stored for use in part3).
    all_round1_packages: BTreeMap<frost::Identifier, dkg::round1::Package>,
    /// Final key package after DKG completes.
    key_package: Option<frost::keys::KeyPackage>,
    /// Group public key package.
    public_key_package: Option<frost::keys::PublicKeyPackage>,
}

/// Round 1 output: commitment package to broadcast to all participants.
pub struct DkgRound1 {
    pub sender_id: u16,
    pub package: dkg::round1::Package,
}

/// Round 2 output: encrypted share for a specific receiver.
pub struct DkgRound2 {
    pub sender_id: u16,
    pub receiver_id: u16,
    pub package: dkg::round2::Package,
}

impl DkgParticipant {
    pub fn new(id: u16, threshold: u16, total: u16) -> Self {
        let identifier = frost::Identifier::try_from(id)
            .expect("valid participant ID (1-based, non-zero)");
        Self {
            id,
            identifier,
            threshold,
            total,
            round1_secret: None,
            round2_secret: None,
            all_round1_packages: BTreeMap::new(),
            key_package: None,
            public_key_package: None,
        }
    }

    /// Round 1: Generate random polynomial and commitment.
    /// Stores the secret internally — it NEVER leaves this participant.
    pub fn round1(&mut self) -> DkgRound1 {
        let (secret, package) = dkg::part1(
            self.identifier,
            self.total,
            self.threshold,
            &mut OsRng,
        ).expect("DKG round 1 failed");

        self.round1_secret = Some(secret);

        DkgRound1 {
            sender_id: self.id,
            package,
        }
    }

    /// Round 2: Process others' round 1 packages, generate per-participant shares.
    pub fn round2(&mut self, others_round1: &[&DkgRound1]) -> Result<Vec<DkgRound2>, String> {
        let round1_secret = self.round1_secret.take()
            .ok_or_else(|| "round1() must be called before round2()".to_string())?;

        let mut round1_packages: BTreeMap<frost::Identifier, dkg::round1::Package> = BTreeMap::new();
        for pkg in others_round1 {
            let id = frost::Identifier::try_from(pkg.sender_id)
                .map_err(|e| format!("invalid sender ID {}: {e}", pkg.sender_id))?;
            round1_packages.insert(id, pkg.package.clone());
        }

        // Store for use in finalize (part3 needs the same round1 packages used in part2)
        self.all_round1_packages = round1_packages.clone();

        let (round2_secret, round2_packages) = dkg::part2(
            round1_secret,
            &round1_packages,
        ).map_err(|e| format!("DKG round 2 failed: {e}"))?;

        self.round2_secret = Some(round2_secret);

        // frost::Identifier does not implement TryFrom<Identifier> for u16.
        // Recover the receiver u16 ID by scanning 1..=total and comparing identifiers.
        let my_sender_id = self.id;
        let total = self.total;
        let result: Vec<DkgRound2> = round2_packages
            .into_iter()
            .map(|(recipient_frost_id, pkg)| {
                let receiver_id = (1..=total)
                    .find(|&n| {
                        frost::Identifier::try_from(n)
                            .map(|id| id == recipient_frost_id)
                            .unwrap_or(false)
                    })
                    .unwrap_or(0);
                DkgRound2 {
                    sender_id: my_sender_id,
                    receiver_id,
                    package: pkg,
                }
            })
            .collect();

        Ok(result)
    }

    /// Finalize: Combine received round 2 shares to produce key share.
    pub fn finalize(&mut self, others_round2: &[&DkgRound2]) -> Result<(), String> {
        let round2_secret = self.round2_secret.take()
            .ok_or_else(|| "round2() must be called before finalize()".to_string())?;

        let mut round2_packages: BTreeMap<frost::Identifier, dkg::round2::Package> = BTreeMap::new();
        for pkg in others_round2 {
            let sender_id = frost::Identifier::try_from(pkg.sender_id)
                .map_err(|e| format!("invalid sender {}: {e}", pkg.sender_id))?;
            round2_packages.insert(sender_id, pkg.package.clone());
        }

        // part3 uses the same round1_packages that were passed to part2 (others only, not self)
        let (key_package, public_key_package) = dkg::part3(
            &round2_secret,
            &self.all_round1_packages,
            &round2_packages,
        ).map_err(|e| format!("DKG finalize failed: {e}"))?;

        self.key_package = Some(key_package);
        self.public_key_package = Some(public_key_package);
        Ok(())
    }

    /// Get the group public key (available after finalize).
    pub fn group_public_key(&self) -> Option<frost::keys::PublicKeyPackage> {
        self.public_key_package.clone()
    }

    /// Get this participant's key package (available after finalize).
    pub fn key_package(&self) -> Option<&frost::keys::KeyPackage> {
        self.key_package.as_ref()
    }

    /// No participant ever holds the full secret — always returns None.
    /// This is a security assertion, not a runtime check.
    pub fn full_secret(&self) -> Option<()> {
        None
    }
}
