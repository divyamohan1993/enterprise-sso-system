//! Distributed signing witness protocol.
//!
//! Every signing operation must be observed and certified by at least 2
//! independent witness nodes that are NOT the signer. This ensures no
//! single VM can sign anything alone.
//!
//! Flow:
//! 1. Signer announces intent to sign (data hash + ceremony_id)
//! 2. Witness nodes independently verify the data hash
//! 3. Each witness signs a `WitnessAttestation` (node_id + data_hash + timestamp + ML-DSA-87 sig)
//! 4. Signer collects 2+ attestations before proceeding
//! 5. Attestations are bundled with the signature for audit trail
//!
//! Fail-closed: if insufficient witnesses respond within the timeout,
//! the signing operation is denied.

use ml_dsa::{
    signature::{Signer, Verifier},
    KeyGen, MlDsa87, SigningKey, VerifyingKey,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// ML-DSA-87 signing key type alias.
pub type PqSigningKey = SigningKey<MlDsa87>;
/// ML-DSA-87 verifying key type alias.
pub type PqVerifyingKey = VerifyingKey<MlDsa87>;

/// Sign raw bytes with ML-DSA-87.
fn sign_raw(signing_key: &PqSigningKey, data: &[u8]) -> Vec<u8> {
    let sig: ml_dsa::Signature<MlDsa87> = signing_key.sign(data);
    sig.encode().to_vec()
}

/// Verify a raw ML-DSA-87 signature over data.
fn verify_raw(verifying_key: &PqVerifyingKey, data: &[u8], sig_bytes: &[u8]) -> bool {
    let sig = match ml_dsa::Signature::<MlDsa87>::try_from(sig_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };
    verifying_key.verify(data, &sig).is_ok()
}

/// Generate an ML-DSA-87 keypair from OS randomness.
/// Returns error instead of panicking on CSPRNG failure (DoS prevention).
pub fn generate_pq_keypair() -> Result<(PqSigningKey, PqVerifyingKey), String> {
    let mut seed = [0u8; 32];
    if getrandom::getrandom(&mut seed).is_err() {
        crate::siem::SecurityEvent::crypto_failure(
            "OS CSPRNG unavailable during PQ keypair generation",
        );
        return Err("FATAL: OS CSPRNG unavailable -- cannot generate PQ keypair safely".into());
    }
    let kp = MlDsa87::from_seed(&seed.into());
    seed.iter_mut().for_each(|b| *b = 0); // zeroize seed
    Ok((kp.signing_key().clone(), kp.verifying_key().clone()))
}

/// Default minimum witnesses required.
const DEFAULT_MIN_WITNESSES: usize = 2;

/// Default attestation timeout in seconds.
const DEFAULT_ATTESTATION_TIMEOUT_SECS: i64 = 5;

/// Serde helper for `[u8; 64]`.
mod byte_array_64 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(data: &[u8; 64], ser: S) -> Result<S::Ok, S::Error> {
        data.as_slice().serialize(ser)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<[u8; 64], D::Error> {
        let v: Vec<u8> = Vec::deserialize(de)?;
        v.try_into().map_err(|v: Vec<u8>| {
            serde::de::Error::custom(format!("expected 64 bytes, got {}", v.len()))
        })
    }
}

/// A witness attestation: proof that an independent node observed a signing request.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessAttestation {
    /// Node ID of the witness (must differ from the signer).
    pub witness_node_id: String,
    /// Ceremony ID binding this attestation to a specific signing ceremony.
    pub ceremony_id: String,
    /// SHA-512 hash of the data being signed (never the data itself).
    #[serde(with = "byte_array_64")]
    pub data_hash: [u8; 64],
    /// Microsecond-precision Unix timestamp when the attestation was created.
    pub timestamp: i64,
    /// ML-DSA-87 signature over the attestation payload by the witness.
    pub signature: Vec<u8>,
}

impl std::fmt::Debug for WitnessAttestation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WitnessAttestation")
            .field("witness_node_id", &self.witness_node_id)
            .field("ceremony_id", &self.ceremony_id)
            .field("data_hash", &"[REDACTED]")
            .field("timestamp", &self.timestamp)
            .field("signature", &"[REDACTED]")
            .finish()
    }
}

/// A signature bundled with its witness attestations for audit trail.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessedSignature {
    /// The actual cryptographic signature produced by the signer.
    pub signature: Vec<u8>,
    /// At least 2 witness attestations from independent nodes.
    pub attestations: Vec<WitnessAttestation>,
    /// Node ID of the signer.
    pub signer_node_id: String,
}

impl std::fmt::Debug for WitnessedSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WitnessedSignature")
            .field("signature", &"[REDACTED]")
            .field("attestation_count", &self.attestations.len())
            .field("signer_node_id", &self.signer_node_id)
            .finish()
    }
}

/// A registered witness node with its ML-DSA-87 verifying key.
struct WitnessNode {
    node_id: String,
    verifying_key: PqVerifyingKey,
}

/// Distributed signing witness protocol.
///
/// Manages a set of witness nodes and enforces that every signing operation
/// is observed by the required minimum number of independent witnesses.
pub struct SigningWitnessProtocol {
    /// Registered witness nodes, keyed by node_id.
    witnesses: HashMap<String, WitnessNode>,
    /// Minimum number of witnesses required (default: 2, configurable via MILNET_MIN_WITNESSES).
    min_witnesses: usize,
    /// Attestation timeout in seconds (default: 5).
    attestation_timeout_secs: i64,
}

impl SigningWitnessProtocol {
    /// Create a new protocol instance.
    ///
    /// Reads `MILNET_MIN_WITNESSES` env var for the minimum witness count (default: 2).
    /// Reads `MILNET_ATTESTATION_TIMEOUT_SECS` env var for timeout (default: 5).
    pub fn new() -> Self {
        let min_witnesses = std::env::var("MILNET_MIN_WITNESSES")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(DEFAULT_MIN_WITNESSES);

        let attestation_timeout_secs = std::env::var("MILNET_ATTESTATION_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(DEFAULT_ATTESTATION_TIMEOUT_SECS);

        Self {
            witnesses: HashMap::new(),
            min_witnesses,
            attestation_timeout_secs,
        }
    }

    /// Create a protocol instance with explicit parameters (for testing).
    pub fn with_params(min_witnesses: usize, attestation_timeout_secs: i64) -> Self {
        Self {
            witnesses: HashMap::new(),
            min_witnesses,
            attestation_timeout_secs,
        }
    }

    /// Register a witness node with its ML-DSA-87 verifying key.
    pub fn register_witness(&mut self, node_id: String, verifying_key: PqVerifyingKey) {
        self.witnesses.insert(
            node_id.clone(),
            WitnessNode {
                node_id,
                verifying_key,
            },
        );
    }

    /// Compute the SHA-512 hash of the data being signed.
    pub fn hash_data(data: &[u8]) -> [u8; 64] {
        let mut hasher = Sha512::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut out = [0u8; 64];
        out.copy_from_slice(&result);
        out
    }

    /// Build the canonical payload that a witness signs over.
    ///
    /// Format: `ceremony_id || witness_node_id || data_hash || timestamp_bytes`
    fn attestation_payload(
        ceremony_id: &str,
        witness_node_id: &str,
        data_hash: &[u8; 64],
        timestamp: i64,
    ) -> Vec<u8> {
        let mut payload =
            Vec::with_capacity(ceremony_id.len() + witness_node_id.len() + 64 + 8);
        payload.extend_from_slice(ceremony_id.as_bytes());
        payload.extend_from_slice(witness_node_id.as_bytes());
        payload.extend_from_slice(data_hash);
        payload.extend_from_slice(&timestamp.to_le_bytes());
        payload
    }

    /// Create a witness attestation (called by a witness node).
    ///
    /// The witness signs over `(ceremony_id || node_id || data_hash || timestamp)`
    /// using ML-DSA-87.
    pub fn create_attestation(
        ceremony_id: &str,
        witness_node_id: &str,
        data_hash: &[u8; 64],
        signing_key: &PqSigningKey,
    ) -> WitnessAttestation {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as i64;

        let payload =
            Self::attestation_payload(ceremony_id, witness_node_id, data_hash, timestamp);
        let signature = sign_raw(signing_key, &payload);

        WitnessAttestation {
            witness_node_id: witness_node_id.to_string(),
            ceremony_id: ceremony_id.to_string(),
            data_hash: *data_hash,
            timestamp,
            signature,
        }
    }

    /// Create an attestation with an explicit timestamp (for testing expiry).
    pub fn create_attestation_with_timestamp(
        ceremony_id: &str,
        witness_node_id: &str,
        data_hash: &[u8; 64],
        signing_key: &PqSigningKey,
        timestamp: i64,
    ) -> WitnessAttestation {
        let payload =
            Self::attestation_payload(ceremony_id, witness_node_id, data_hash, timestamp);
        let signature = sign_raw(signing_key, &payload);

        WitnessAttestation {
            witness_node_id: witness_node_id.to_string(),
            ceremony_id: ceremony_id.to_string(),
            data_hash: *data_hash,
            timestamp,
            signature,
        }
    }

    /// Validate a single attestation.
    ///
    /// Checks:
    /// 1. Witness node is registered
    /// 2. Witness node is NOT the signer
    /// 3. Ceremony ID matches
    /// 4. Data hash matches
    /// 5. Attestation is not expired (within timeout window)
    /// 6. ML-DSA-87 signature is valid
    fn validate_attestation(
        &self,
        attestation: &WitnessAttestation,
        signer_node_id: &str,
        ceremony_id: &str,
        data_hash: &[u8; 64],
        now_micros: i64,
    ) -> Result<(), String> {
        // 1. Witness must be registered
        let witness = self
            .witnesses
            .get(&attestation.witness_node_id)
            .ok_or_else(|| {
                format!(
                    "unknown witness node: {}",
                    attestation.witness_node_id
                )
            })?;

        // 2. Witness must NOT be the signer
        if attestation.witness_node_id == signer_node_id {
            return Err(format!(
                "witness {} is the same node as signer — self-witnessing rejected",
                attestation.witness_node_id
            ));
        }

        // 3. Ceremony ID must match
        if attestation.ceremony_id != ceremony_id {
            return Err(format!(
                "ceremony_id mismatch: attestation has '{}', expected '{}'",
                attestation.ceremony_id, ceremony_id
            ));
        }

        // 4. Data hash must match
        if attestation.data_hash != *data_hash {
            return Err("data_hash mismatch in attestation".to_string());
        }

        // 5. Check timestamp is within timeout window
        let timeout_micros = self.attestation_timeout_secs * 1_000_000;
        let age_micros = now_micros.saturating_sub(attestation.timestamp);
        if age_micros > timeout_micros {
            return Err(format!(
                "attestation expired: age {}us exceeds timeout {}us",
                age_micros, timeout_micros
            ));
        }
        // Reject attestations from the future (clock skew tolerance: 1 second)
        if attestation.timestamp > now_micros + 1_000_000 {
            return Err("attestation timestamp is in the future".to_string());
        }

        // 6. Verify ML-DSA-87 signature
        let payload = Self::attestation_payload(
            ceremony_id,
            &attestation.witness_node_id,
            data_hash,
            attestation.timestamp,
        );
        if !verify_raw(&witness.verifying_key, &payload, &attestation.signature) {
            return Err(format!(
                "ML-DSA-87 signature verification failed for witness {}",
                attestation.witness_node_id
            ));
        }

        Ok(())
    }

    /// Validate attestations and produce a witnessed signature.
    ///
    /// Fail-closed: returns an error if fewer than `min_witnesses` valid
    /// attestations from distinct, non-signer nodes are provided.
    pub fn finalize_witnessed_signature(
        &self,
        signature: Vec<u8>,
        attestations: Vec<WitnessAttestation>,
        signer_node_id: &str,
        ceremony_id: &str,
        data_hash: &[u8; 64],
    ) -> Result<WitnessedSignature, String> {
        let now_micros = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as i64;

        self.finalize_witnessed_signature_at(
            signature,
            attestations,
            signer_node_id,
            ceremony_id,
            data_hash,
            now_micros,
        )
    }

    /// Validate attestations at a specific timestamp (for testing).
    pub fn finalize_witnessed_signature_at(
        &self,
        signature: Vec<u8>,
        attestations: Vec<WitnessAttestation>,
        signer_node_id: &str,
        ceremony_id: &str,
        data_hash: &[u8; 64],
        now_micros: i64,
    ) -> Result<WitnessedSignature, String> {
        let mut valid_witnesses: Vec<WitnessAttestation> = Vec::new();
        let mut seen_nodes = std::collections::HashSet::new();

        for attestation in attestations {
            match self.validate_attestation(
                &attestation,
                signer_node_id,
                ceremony_id,
                data_hash,
                now_micros,
            ) {
                Ok(()) => {
                    // Deduplicate: only count one attestation per witness node
                    if seen_nodes.insert(attestation.witness_node_id.clone()) {
                        valid_witnesses.push(attestation);
                    } else {
                        tracing::warn!(
                            "duplicate attestation from witness {} — ignoring",
                            attestation.witness_node_id
                        );
                    }
                }
                Err(reason) => {
                    tracing::warn!(
                        "rejecting attestation from {}: {}",
                        attestation.witness_node_id,
                        reason
                    );
                    // Emit SIEM event for rejected attestation
                    emit_siem_event(
                        "attestation_rejected",
                        &format!(
                            "witness={}, ceremony={}, reason={}",
                            attestation.witness_node_id, ceremony_id, reason
                        ),
                    );
                }
            }
        }

        // Fail-closed: require minimum witnesses
        if valid_witnesses.len() < self.min_witnesses {
            let msg = format!(
                "insufficient witnesses: {} valid out of minimum {} required for ceremony {}",
                valid_witnesses.len(),
                self.min_witnesses,
                ceremony_id
            );
            tracing::error!("{}", msg);
            emit_siem_event("signing_denied_insufficient_witnesses", &msg);
            return Err(msg);
        }

        // Emit success SIEM event
        emit_siem_event(
            "signing_witnessed",
            &format!(
                "ceremony={}, signer={}, witnesses={}",
                ceremony_id,
                signer_node_id,
                valid_witnesses.len()
            ),
        );

        Ok(WitnessedSignature {
            signature,
            attestations: valid_witnesses,
            signer_node_id: signer_node_id.to_string(),
        })
    }
}

/// Emit a SIEM event for signing witness operations.
fn emit_siem_event(action: &str, detail: &str) {
    use crate::siem::{SecurityEvent, Severity};

    let event = SecurityEvent {
        timestamp: SecurityEvent::now_iso8601(),
        category: "SIGNING_WITNESS",
        action: "signing_witness",
        severity: if action.contains("denied") || action.contains("rejected") {
            Severity::High
        } else {
            Severity::Medium
        },
        outcome: if action.contains("denied") || action.contains("rejected") {
            "failure"
        } else {
            "success"
        },
        user_id: None,
        source_ip: None,
        detail: Some(format!("{}: {}", action, detail)),
    };
    event.emit();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: generate an ML-DSA-87 keypair for a witness node.
    /// Runs in a thread with large stack since ML-DSA-87 keys are ~4KB.
    fn generate_keypair() -> (PqSigningKey, PqVerifyingKey) {
        std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .name("pq-keygen".into())
            .spawn(|| generate_pq_keypair().expect("CSPRNG must be available in tests"))
            .expect("failed to spawn keygen thread")
            .join()
            .expect("keygen thread panicked")
    }

    /// Helper: set up a protocol with N witness nodes, returning their signing keys.
    fn setup_protocol(
        num_witnesses: usize,
        min_witnesses: usize,
    ) -> (SigningWitnessProtocol, Vec<(String, PqSigningKey)>) {
        let mut protocol = SigningWitnessProtocol::with_params(min_witnesses, 5);
        let mut witness_keys = Vec::with_capacity(num_witnesses);

        for i in 0..num_witnesses {
            let node_id = format!("witness-{}", i);
            let (sk, vk) = generate_keypair();
            protocol.register_witness(node_id.clone(), vk);
            witness_keys.push((node_id, sk));
        }

        (protocol, witness_keys)
    }

    /// Helper: create attestations from a set of witnesses for given data.
    fn create_attestations(
        witness_keys: &[(String, PqSigningKey)],
        ceremony_id: &str,
        data_hash: &[u8; 64],
        indices: &[usize],
    ) -> Vec<WitnessAttestation> {
        indices
            .iter()
            .map(|&i| {
                let (ref node_id, ref sk) = witness_keys[i];
                SigningWitnessProtocol::create_attestation(ceremony_id, node_id, data_hash, sk)
            })
            .collect()
    }

    #[test]
    fn test_signing_with_zero_witnesses_fails() {
        let (protocol, _witness_keys) = setup_protocol(3, 2);
        let data = b"classified payload";
        let data_hash = SigningWitnessProtocol::hash_data(data);
        let ceremony_id = "ceremony-001";
        let signature = vec![0xAA; 64];

        let result = protocol.finalize_witnessed_signature(
            signature,
            vec![], // no attestations
            "signer-node",
            ceremony_id,
            &data_hash,
        );

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("insufficient witnesses"),
            "expected insufficient witnesses error, got: {}",
            err
        );
    }

    #[test]
    fn test_signing_with_one_witness_fails() {
        let (protocol, witness_keys) = setup_protocol(3, 2);
        let data = b"classified payload";
        let data_hash = SigningWitnessProtocol::hash_data(data);
        let ceremony_id = "ceremony-002";
        let signature = vec![0xBB; 64];

        let attestations = create_attestations(&witness_keys, ceremony_id, &data_hash, &[0]);

        let result = protocol.finalize_witnessed_signature(
            signature,
            attestations,
            "signer-node",
            ceremony_id,
            &data_hash,
        );

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("insufficient witnesses"),
            "expected insufficient witnesses error with 1 witness, got: {}",
            err
        );
    }

    #[test]
    fn test_signing_with_two_witnesses_succeeds() {
        let (protocol, witness_keys) = setup_protocol(3, 2);
        let data = b"classified payload";
        let data_hash = SigningWitnessProtocol::hash_data(data);
        let ceremony_id = "ceremony-003";
        let signature = vec![0xCC; 64];

        let attestations =
            create_attestations(&witness_keys, ceremony_id, &data_hash, &[0, 1]);

        let result = protocol.finalize_witnessed_signature(
            signature.clone(),
            attestations,
            "signer-node",
            ceremony_id,
            &data_hash,
        );

        assert!(result.is_ok(), "signing with 2 witnesses must succeed");
        let witnessed = result.unwrap();
        assert_eq!(witnessed.attestations.len(), 2);
        assert_eq!(witnessed.signature, signature);
        assert_eq!(witnessed.signer_node_id, "signer-node");
    }

    #[test]
    fn test_witness_from_same_node_as_signer_rejected() {
        let (mut protocol, _witness_keys) = setup_protocol(0, 2);

        // Register a witness with the same node_id as the signer
        let signer_node_id = "signer-node";
        let (sk_self, vk_self) = generate_keypair();
        protocol.register_witness(signer_node_id.to_string(), vk_self);

        // Also register a legitimate witness
        let (sk_legit, vk_legit) = generate_keypair();
        protocol.register_witness("witness-legit".to_string(), vk_legit);

        let data = b"classified payload";
        let data_hash = SigningWitnessProtocol::hash_data(data);
        let ceremony_id = "ceremony-004";
        let signature = vec![0xDD; 64];

        // Create attestation from the signer's own node
        let self_attestation = SigningWitnessProtocol::create_attestation(
            ceremony_id,
            signer_node_id,
            &data_hash,
            &sk_self,
        );
        // Create attestation from the legitimate witness
        let legit_attestation = SigningWitnessProtocol::create_attestation(
            ceremony_id,
            "witness-legit",
            &data_hash,
            &sk_legit,
        );

        let result = protocol.finalize_witnessed_signature(
            signature,
            vec![self_attestation, legit_attestation],
            signer_node_id,
            ceremony_id,
            &data_hash,
        );

        // Should fail: only 1 valid witness (the self-attestation is rejected)
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("insufficient witnesses"),
            "self-witnessing should be rejected, got: {}",
            err
        );
    }

    #[test]
    fn test_expired_attestation_rejected() {
        let (protocol, witness_keys) = setup_protocol(3, 2);
        let data = b"classified payload";
        let data_hash = SigningWitnessProtocol::hash_data(data);
        let ceremony_id = "ceremony-005";
        let signature = vec![0xEE; 64];

        // Create one fresh attestation
        let fresh = SigningWitnessProtocol::create_attestation(
            ceremony_id,
            &witness_keys[0].0,
            &data_hash,
            &witness_keys[0].1,
        );

        // Create one expired attestation (10 seconds ago, timeout is 5s)
        let now_micros = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros() as i64;
        let expired_timestamp = now_micros - 10_000_000; // 10 seconds ago

        let expired = SigningWitnessProtocol::create_attestation_with_timestamp(
            ceremony_id,
            &witness_keys[1].0,
            &data_hash,
            &witness_keys[1].1,
            expired_timestamp,
        );

        let result = protocol.finalize_witnessed_signature(
            signature,
            vec![fresh, expired],
            "signer-node",
            ceremony_id,
            &data_hash,
        );

        // Should fail: only 1 valid (the expired one is rejected)
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("insufficient witnesses"),
            "expired attestation should be rejected, got: {}",
            err
        );
    }

    #[test]
    fn test_tampered_attestation_signature_rejected() {
        let (protocol, witness_keys) = setup_protocol(3, 2);
        let data = b"classified payload";
        let data_hash = SigningWitnessProtocol::hash_data(data);
        let ceremony_id = "ceremony-006";
        let signature = vec![0xFF; 64];

        // Create a valid attestation then tamper with its signature
        let mut tampered = SigningWitnessProtocol::create_attestation(
            ceremony_id,
            &witness_keys[0].0,
            &data_hash,
            &witness_keys[0].1,
        );
        // Flip a byte in the signature
        if !tampered.signature.is_empty() {
            tampered.signature[0] ^= 0xFF;
        }

        // Create one valid attestation
        let valid = SigningWitnessProtocol::create_attestation(
            ceremony_id,
            &witness_keys[1].0,
            &data_hash,
            &witness_keys[1].1,
        );

        let result = protocol.finalize_witnessed_signature(
            signature,
            vec![tampered, valid],
            "signer-node",
            ceremony_id,
            &data_hash,
        );

        // Should fail: only 1 valid (the tampered one is rejected)
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("insufficient witnesses"),
            "tampered attestation should be rejected, got: {}",
            err
        );
    }
}
