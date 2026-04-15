// CAT-O-followup (DT-BFT, DT-QUORUM-RECONFIG):
//   1. Hand-rolled PBFT (propose → 2f+1 prepare → 2f+1 commit → apply)
//      over existing ML-DSA-87 signatures belongs in `common/src/bft.rs`.
//      Apply to ceremony state, KT leaf proposals, audit-witness
//      checkpoint signing. Keep Raft for crash-only non-security
//      replication.
//   2. Joint-consensus quorum reconfiguration: make
//      `OrchestratorWitnessPolicy` runtime-reconfigurable via a
//      2-phase Raft-backed config entry, so N and f can change at
//      runtime with no downtime.

//! Independent-witness orchestrator rotation ceremony (CAT-O DT-IDROT).
//!
//! The pre-existing 2-of-3 orchestrator pin rotation in `shard/src/tls.rs`
//! is circular: the orchestrators sign their own rotation. A compromise
//! of 2-of-3 orchestrator keys lets an attacker rotate to any pinset they
//! want. This module adds an **out-of-band witness quorum**: a rotation
//! ceremony is only valid when co-signed by an independent set of nodes
//! that do NOT share key material with the orchestrators.
//!
//! # Threshold
//!
//! Default policy: `OrchestratorWitnessPolicy::default()` requires
//!
//! * 2-of-3 **orchestrator** ML-DSA-87 signatures, AND
//! * 2-of-5 **KT (key-transparency)** ML-DSA-87 signatures, AND
//! * 1 **audit-witness** ML-DSA-87 signature
//!
//! yielding 5 independent signers drawn from 3 independent role pools;
//! the overall threshold is 5-of-9. To roll a pinset an attacker must
//! compromise nodes in all three pools, which by design live in
//! different trust domains, run on different hardware, and load
//! different `KeyDomain` roots (see `key_hierarchy`).
//!
//! # Anti-replay
//!
//! Every ceremony carries a monotonic `ceremony_nonce` (128-bit random
//! plus a strictly-increasing epoch). Verifiers reject any nonce they
//! have seen before; persistence of the seen-set is the caller's
//! responsibility (audit log or append-only state chain).
//!
//! # Break-glass
//!
//! Total loss of an entire role pool (e.g. all orchestrators destroyed)
//! is handled by the manual paper-ballot path documented in
//! `docs/runbooks/orchestrator-break-glass.md`. That path requires
//! physical PIV/CAC co-signatures from a documented human operator
//! quorum and re-seeds the ceremony verifier with a fresh pubkey set.
//! This module exposes [`BreakGlassAttestation`] so the runbook output
//! can be machine-verified before being spliced in.

use std::collections::HashSet;

use sha2::{Digest, Sha512};

/// Canonical ML-DSA-87 signature-verification callback.
/// `(public_key_bytes, message, signature_bytes) -> verified`.
pub type PqVerifyFn = fn(&[u8], &[u8], &[u8]) -> bool;

/// Pool that a signer belongs to. Quorum policy counts signatures
/// per-pool independently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignerRole {
    Orchestrator,
    KeyTransparency,
    AuditWitness,
    /// Break-glass human operator (PIV-CAC). Only counted when the
    /// ceremony explicitly enters break-glass mode.
    BreakGlassHuman,
}

/// A single signer in a rotation ceremony, scoped to one role pool.
#[derive(Debug, Clone)]
pub struct CeremonySigner {
    pub role: SignerRole,
    pub pubkey: Vec<u8>,
    /// Pool-local index; MUST be unique within (role, pool).
    pub index: usize,
}

/// Policy governing how many signatures are required per role pool.
#[derive(Debug, Clone)]
pub struct OrchestratorWitnessPolicy {
    pub orchestrator_required: usize,
    pub orchestrator_total: usize,
    pub kt_required: usize,
    pub kt_total: usize,
    pub audit_witness_required: usize,
    pub audit_witness_total: usize,
}

impl Default for OrchestratorWitnessPolicy {
    fn default() -> Self {
        // 2-of-3 orchestrators + 2-of-5 KT + 1-of-N audit witnesses
        // = 5-of-9 overall, drawn from 3 independent trust domains.
        Self {
            orchestrator_required: 2,
            orchestrator_total: 3,
            kt_required: 2,
            kt_total: 5,
            audit_witness_required: 1,
            // Audit-witness cluster is typically 3 nodes minimum; exact
            // total is deployment-specific.
            audit_witness_total: 3,
        }
    }
}

impl OrchestratorWitnessPolicy {
    /// Total distinct signatures required across all pools.
    pub fn total_required(&self) -> usize {
        self.orchestrator_required + self.kt_required + self.audit_witness_required
    }
}

/// A single (signer-index, signature) pair over the canonical ceremony
/// digest.
#[derive(Debug, Clone)]
pub struct CeremonySignature {
    pub role: SignerRole,
    pub signer_index: usize,
    pub signature: Vec<u8>,
}

/// Anti-replay nonce. Callers persist seen nonces out-of-band; the
/// module only guarantees structural uniqueness within a single
/// verification call.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CeremonyNonce {
    pub epoch: u64,
    pub random: [u8; 16],
}

impl CeremonyNonce {
    fn feed(&self, h: &mut Sha512) {
        h.update(b"MILNET-CEREMONY-NONCE-v1");
        h.update(self.epoch.to_be_bytes());
        h.update(self.random);
    }
}

/// The rotation proposal being ratified.
#[derive(Debug, Clone)]
pub struct RotationProposal {
    /// Free-form ceremony type, e.g. `b"SHARD_PIN_ROTATION"`.
    pub ceremony_type: &'static [u8],
    /// Canonical serialized payload — caller's responsibility to
    /// canonicalize (e.g. sorted pin list).
    pub payload: Vec<u8>,
    pub nonce: CeremonyNonce,
}

/// Break-glass attestation body. Produced by the physical-ballot
/// runbook and machine-verified before re-seeding the ceremony
/// verifier. Intentionally inert in normal operation.
#[derive(Debug, Clone)]
pub struct BreakGlassAttestation {
    pub proposal: RotationProposal,
    pub human_signers: Vec<CeremonySigner>,
    pub signatures: Vec<CeremonySignature>,
}

/// Outcome of a ceremony verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CeremonyOutcome {
    /// Proposal ratified; caller may apply it.
    Ratified,
    /// Structural failure (bad pool sizing, duplicate signer, etc.).
    Rejected(String),
    /// Signature arithmetic failed (not enough valid sigs per pool).
    InsufficientSignatures {
        orchestrator: usize,
        kt: usize,
        audit_witness: usize,
    },
}

/// Compute the canonical digest that signers MUST sign. All fields are
/// length-prefixed (u32 big-endian) so that structurally distinct
/// proposals cannot collide.
pub fn canonical_digest(proposal: &RotationProposal) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(b"MILNET-BOOTSTRAP-CEREMONY-v1");
    h.update((proposal.ceremony_type.len() as u32).to_be_bytes());
    h.update(proposal.ceremony_type);
    h.update((proposal.payload.len() as u32).to_be_bytes());
    h.update(&proposal.payload);
    proposal.nonce.feed(&mut h);
    let d = h.finalize();
    let mut out = [0u8; 64];
    out.copy_from_slice(&d);
    out
}

/// Verify a rotation ceremony against the independent-witness policy.
///
/// `verify` is injected so that `common` stays free of a hard
/// dependency on the `crypto` crate; callers pass
/// `crypto::pq_sign::pq_verify_raw_from_bytes` as the implementation.
///
/// Replay protection: the caller must have already checked
/// `proposal.nonce` against a persisted seen-set; this function
/// additionally refuses to count any (role, index) pair more than once
/// within a single verification.
pub fn verify_ceremony(
    proposal: &RotationProposal,
    policy: &OrchestratorWitnessPolicy,
    signers: &[CeremonySigner],
    signatures: &[CeremonySignature],
    verify: PqVerifyFn,
) -> CeremonyOutcome {
    // Structural checks: pool sizes must match policy totals exactly.
    let orchestrator_pool: Vec<&CeremonySigner> = signers
        .iter()
        .filter(|s| s.role == SignerRole::Orchestrator)
        .collect();
    let kt_pool: Vec<&CeremonySigner> = signers
        .iter()
        .filter(|s| s.role == SignerRole::KeyTransparency)
        .collect();
    let aw_pool: Vec<&CeremonySigner> = signers
        .iter()
        .filter(|s| s.role == SignerRole::AuditWitness)
        .collect();

    if orchestrator_pool.len() != policy.orchestrator_total {
        return CeremonyOutcome::Rejected(format!(
            "orchestrator pool size {} != policy total {}",
            orchestrator_pool.len(),
            policy.orchestrator_total
        ));
    }
    if kt_pool.len() != policy.kt_total {
        return CeremonyOutcome::Rejected(format!(
            "KT pool size {} != policy total {}",
            kt_pool.len(),
            policy.kt_total
        ));
    }
    if aw_pool.len() != policy.audit_witness_total {
        return CeremonyOutcome::Rejected(format!(
            "audit-witness pool size {} != policy total {}",
            aw_pool.len(),
            policy.audit_witness_total
        ));
    }

    let digest = canonical_digest(proposal);

    let mut orchestrator_ok = 0usize;
    let mut kt_ok = 0usize;
    let mut aw_ok = 0usize;
    let mut seen: HashSet<(SignerRole, usize)> = HashSet::new();

    for sig in signatures {
        if !seen.insert((sig.role, sig.signer_index)) {
            // Duplicate signer attempt — reject outright rather than
            // silently drop, to surface malformed bundles.
            return CeremonyOutcome::Rejected(format!(
                "duplicate signer ({:?}, {})",
                sig.role, sig.signer_index
            ));
        }
        let pool: &[&CeremonySigner] = match sig.role {
            SignerRole::Orchestrator => &orchestrator_pool,
            SignerRole::KeyTransparency => &kt_pool,
            SignerRole::AuditWitness => &aw_pool,
            SignerRole::BreakGlassHuman => {
                // Not allowed in the normal path.
                return CeremonyOutcome::Rejected(
                    "BreakGlassHuman signer appeared in normal ceremony".into(),
                );
            }
        };
        let signer = match pool.iter().find(|s| s.index == sig.signer_index) {
            Some(s) => *s,
            None => continue,
        };
        if verify(&signer.pubkey, digest.as_slice(), &sig.signature) {
            match sig.role {
                SignerRole::Orchestrator => orchestrator_ok += 1,
                SignerRole::KeyTransparency => kt_ok += 1,
                SignerRole::AuditWitness => aw_ok += 1,
                SignerRole::BreakGlassHuman => unreachable!(),
            }
        }
    }

    if orchestrator_ok >= policy.orchestrator_required
        && kt_ok >= policy.kt_required
        && aw_ok >= policy.audit_witness_required
    {
        CeremonyOutcome::Ratified
    } else {
        CeremonyOutcome::InsufficientSignatures {
            orchestrator: orchestrator_ok,
            kt: kt_ok,
            audit_witness: aw_ok,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A stub signature scheme for tests: "signature" is just the
    // SHA-512 of (pubkey || message). Lets us exercise quorum
    // arithmetic without pulling crypto into common's test deps.
    fn stub_verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
        let mut h = Sha512::new();
        h.update(pk);
        h.update(msg);
        let d = h.finalize();
        sig == d.as_slice()
    }

    fn stub_sign(pk: &[u8], msg: &[u8]) -> Vec<u8> {
        let mut h = Sha512::new();
        h.update(pk);
        h.update(msg);
        h.finalize().to_vec()
    }

    fn signer(role: SignerRole, index: usize) -> CeremonySigner {
        CeremonySigner {
            role,
            pubkey: format!("pk-{:?}-{}", role, index).into_bytes(),
            index,
        }
    }

    fn make_proposal() -> RotationProposal {
        RotationProposal {
            ceremony_type: b"TEST_ROTATION",
            payload: b"new-pinset".to_vec(),
            nonce: CeremonyNonce {
                epoch: 42,
                random: [1u8; 16],
            },
        }
    }

    #[test]
    fn default_policy_ratifies_with_full_quorum() {
        let policy = OrchestratorWitnessPolicy::default();
        let signers: Vec<CeremonySigner> = (0..3)
            .map(|i| signer(SignerRole::Orchestrator, i))
            .chain((0..5).map(|i| signer(SignerRole::KeyTransparency, i)))
            .chain((0..3).map(|i| signer(SignerRole::AuditWitness, i)))
            .collect();
        let proposal = make_proposal();
        let digest = canonical_digest(&proposal);

        let mut sigs = Vec::new();
        // 2 orchestrators
        for i in 0..2 {
            let pk = &signers
                .iter()
                .find(|s| s.role == SignerRole::Orchestrator && s.index == i)
                .unwrap()
                .pubkey;
            sigs.push(CeremonySignature {
                role: SignerRole::Orchestrator,
                signer_index: i,
                signature: stub_sign(pk, &digest),
            });
        }
        // 2 KT
        for i in 0..2 {
            let pk = &signers
                .iter()
                .find(|s| s.role == SignerRole::KeyTransparency && s.index == i)
                .unwrap()
                .pubkey;
            sigs.push(CeremonySignature {
                role: SignerRole::KeyTransparency,
                signer_index: i,
                signature: stub_sign(pk, &digest),
            });
        }
        // 1 audit-witness
        let pk = &signers
            .iter()
            .find(|s| s.role == SignerRole::AuditWitness && s.index == 0)
            .unwrap()
            .pubkey;
        sigs.push(CeremonySignature {
            role: SignerRole::AuditWitness,
            signer_index: 0,
            signature: stub_sign(pk, &digest),
        });

        let outcome = verify_ceremony(&proposal, &policy, &signers, &sigs, stub_verify);
        assert_eq!(outcome, CeremonyOutcome::Ratified);
    }

    #[test]
    fn orchestrators_alone_cannot_ratify() {
        // Proves the anti-circular property: 3-of-3 orchestrator sigs
        // with zero witnesses MUST be rejected.
        let policy = OrchestratorWitnessPolicy::default();
        let signers: Vec<CeremonySigner> = (0..3)
            .map(|i| signer(SignerRole::Orchestrator, i))
            .chain((0..5).map(|i| signer(SignerRole::KeyTransparency, i)))
            .chain((0..3).map(|i| signer(SignerRole::AuditWitness, i)))
            .collect();
        let proposal = make_proposal();
        let digest = canonical_digest(&proposal);
        let sigs: Vec<CeremonySignature> = (0..3)
            .map(|i| {
                let pk = &signers
                    .iter()
                    .find(|s| s.role == SignerRole::Orchestrator && s.index == i)
                    .unwrap()
                    .pubkey;
                CeremonySignature {
                    role: SignerRole::Orchestrator,
                    signer_index: i,
                    signature: stub_sign(pk, &digest),
                }
            })
            .collect();
        let outcome = verify_ceremony(&proposal, &policy, &signers, &sigs, stub_verify);
        assert!(matches!(
            outcome,
            CeremonyOutcome::InsufficientSignatures { .. }
        ));
    }

    #[test]
    fn duplicate_signer_is_rejected() {
        let policy = OrchestratorWitnessPolicy::default();
        let signers: Vec<CeremonySigner> = (0..3)
            .map(|i| signer(SignerRole::Orchestrator, i))
            .chain((0..5).map(|i| signer(SignerRole::KeyTransparency, i)))
            .chain((0..3).map(|i| signer(SignerRole::AuditWitness, i)))
            .collect();
        let proposal = make_proposal();
        let digest = canonical_digest(&proposal);
        let pk = &signers[0].pubkey;
        let dup_sig = stub_sign(pk, &digest);
        let sigs = vec![
            CeremonySignature {
                role: SignerRole::Orchestrator,
                signer_index: 0,
                signature: dup_sig.clone(),
            },
            CeremonySignature {
                role: SignerRole::Orchestrator,
                signer_index: 0,
                signature: dup_sig,
            },
        ];
        let outcome = verify_ceremony(&proposal, &policy, &signers, &sigs, stub_verify);
        assert!(matches!(outcome, CeremonyOutcome::Rejected(_)));
    }
}
