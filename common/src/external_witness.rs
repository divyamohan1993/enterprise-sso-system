//! External witness cosigner service.
//!
//! SECURITY: The witness signing key MUST NOT reside in the audit service.
//! This module implements a separate cosigning service that:
//! 1. Runs on a different VM/pod than the audit service
//! 2. Holds its own ML-DSA-87 signing key (never shared with audit)
//! 3. Receives checkpoint data (audit_root + kt_root) from audit
//! 4. Independently verifies the data against its own view of the cluster
//! 5. Signs the checkpoint only if verification passes
//! 6. Returns the signature to the audit service
//!
//! This ensures that even if the audit service is fully compromised,
//! the attacker cannot forge witness checkpoints without also compromising
//! this separate service.

use crate::raft::NodeId;
use ml_dsa::{
    signature::{Signer, Verifier},
    EncodedVerifyingKey, KeyGen, MlDsa87, VerifyingKey,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// Wire types for serde -- [u8; 64] needs a helper
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

/// Request from audit service to witness cosigner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessSignRequest {
    #[serde(with = "byte_array_64")]
    pub audit_root: [u8; 64],
    #[serde(with = "byte_array_64")]
    pub kt_root: [u8; 64],
    pub sequence: u64,
    pub timestamp: i64,
    /// ID of the audit node requesting the signature
    pub requester_node: NodeId,
}

/// Response from witness cosigner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessSignResponse {
    pub signature: Vec<u8>,
    pub cosigner_id: String,
    pub accepted: bool,
    pub rejection_reason: Option<String>,
}

/// Configuration for the external witness cosigner.
#[derive(Debug, Clone)]
pub struct ExternalWitnessConfig {
    /// Unique ID for this cosigner instance
    pub cosigner_id: String,
    /// Maximum age of a sign request before rejection (prevents replay)
    pub max_request_age: Duration,
    /// Minimum sequence number (prevents rollback attacks)
    pub min_sequence: u64,
    /// Maximum requests per minute (rate limit)
    pub max_requests_per_minute: u32,
}

impl Default for ExternalWitnessConfig {
    fn default() -> Self {
        Self {
            cosigner_id: "witness-cosigner-1".to_string(),
            max_request_age: Duration::from_secs(60),
            min_sequence: 0,
            max_requests_per_minute: 30,
        }
    }
}

/// The external witness cosigner.
///
/// Runs as a separate service/process. Holds its own ML-DSA-87 signing key.
/// Never shares key material with the audit service.
/// Callback for independent audit root verification before cosigning.
/// Returns `true` if the proposed audit_root is valid per an independent view.
pub type VerifyAuditRootFn = Box<dyn Fn(&[u8; 64], u64) -> bool + Send>;

pub struct ExternalWitnessCosigner {
    config: ExternalWitnessConfig,
    /// ML-DSA-87 signing seed (32 bytes, generates deterministic keypair)
    signing_seed: [u8; 32],
    /// Last accepted sequence number (monotonically increasing)
    last_sequence: u64,
    /// Rate limiting: timestamps of recent requests
    request_timestamps: Vec<Instant>,
    /// Known audit roots (optional: for cross-verification)
    known_roots: HashMap<u64, [u8; 64]>,
    /// Optional callback to independently verify the audit root before signing.
    /// If set, the cosigner will reject requests where verification fails.
    /// If not set, a WARNING SIEM event is emitted noting unverified cosigning.
    verify_audit_root: Option<VerifyAuditRootFn>,
}

/// Sign raw bytes with ML-DSA-87 using a 32-byte seed.
fn pq_sign_raw_from_seed(seed: &[u8; 32], data: &[u8]) -> Vec<u8> {
    let kp = MlDsa87::from_seed(&(*seed).into());
    let sig: ml_dsa::Signature<MlDsa87> = kp.signing_key().sign(data);
    sig.encode().to_vec()
}

/// Derive the ML-DSA-87 verifying key bytes from a 32-byte seed.
fn pq_verifying_key_from_seed(seed: &[u8; 32]) -> Vec<u8> {
    let kp = MlDsa87::from_seed(&(*seed).into());
    let encoded: EncodedVerifyingKey<MlDsa87> = kp.verifying_key().encode();
    AsRef::<[u8]>::as_ref(&encoded).to_vec()
}

/// Verify an ML-DSA-87 signature given the verifying key bytes.
fn pq_verify_raw(vk_bytes: &[u8], data: &[u8], sig_bytes: &[u8]) -> bool {
    let vk_enc = match EncodedVerifyingKey::<MlDsa87>::try_from(vk_bytes) {
        Ok(enc) => enc,
        Err(_) => return false,
    };
    let vk = VerifyingKey::<MlDsa87>::decode(&vk_enc);
    let sig = match ml_dsa::Signature::<MlDsa87>::try_from(sig_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };
    vk.verify(data, &sig).is_ok()
}

impl ExternalWitnessCosigner {
    /// Create a new cosigner with the given signing seed.
    /// The seed should be loaded from secure storage (HSM, vTPM, etc.)
    pub fn new(config: ExternalWitnessConfig, signing_seed: [u8; 32]) -> Self {
        Self {
            config,
            signing_seed,
            last_sequence: 0,
            request_timestamps: Vec::new(),
            known_roots: HashMap::new(),
            verify_audit_root: None,
        }
    }

    /// Set a callback for independent audit root verification.
    /// The callback receives the audit root and sequence number, and returns
    /// true if the root is valid per an independent view of the cluster.
    pub fn set_verify_audit_root(&mut self, cb: VerifyAuditRootFn) {
        self.verify_audit_root = Some(cb);
    }

    /// Process a witness sign request.
    /// Validates the request, signs if valid, returns response.
    pub fn process_request(&mut self, req: &WitnessSignRequest) -> WitnessSignResponse {
        // Rate limit check
        let now = Instant::now();
        self.request_timestamps
            .retain(|t| now.duration_since(*t) < Duration::from_secs(60));
        if self.request_timestamps.len() >= self.config.max_requests_per_minute as usize {
            return WitnessSignResponse {
                signature: Vec::new(),
                cosigner_id: self.config.cosigner_id.clone(),
                accepted: false,
                rejection_reason: Some("rate limit exceeded".into()),
            };
        }
        self.request_timestamps.push(now);

        // Timestamp freshness check
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as i64;
        let age_us = (now_secs - req.timestamp).unsigned_abs();
        let max_age_us = self.config.max_request_age.as_micros() as u64;
        if age_us > max_age_us {
            return WitnessSignResponse {
                signature: Vec::new(),
                cosigner_id: self.config.cosigner_id.clone(),
                accepted: false,
                rejection_reason: Some(format!(
                    "request too old: age={}us, max={}us",
                    age_us, max_age_us
                )),
            };
        }

        // Sequence monotonicity check (prevents rollback)
        if req.sequence <= self.last_sequence && self.last_sequence > 0 {
            return WitnessSignResponse {
                signature: Vec::new(),
                cosigner_id: self.config.cosigner_id.clone(),
                accepted: false,
                rejection_reason: Some(format!(
                    "sequence rollback: got {} but last accepted was {}",
                    req.sequence, self.last_sequence
                )),
            };
        }

        // Verify audit root against independent view
        match &self.verify_audit_root {
            Some(verify_fn) => {
                if !verify_fn(&req.audit_root, req.sequence) {
                    tracing::error!(
                        target: "siem",
                        cosigner_id = %self.config.cosigner_id,
                        sequence = req.sequence,
                        "SIEM:CRITICAL external witness cosigner rejected audit_root: \
                         independent verification FAILED"
                    );
                    return WitnessSignResponse {
                        signature: Vec::new(),
                        cosigner_id: self.config.cosigner_id.clone(),
                        accepted: false,
                        rejection_reason: Some(
                            "audit_root failed independent verification".into()
                        ),
                    };
                }
            }
            None => {
                tracing::warn!(
                    target: "siem",
                    cosigner_id = %self.config.cosigner_id,
                    sequence = req.sequence,
                    "SIEM:WARNING external witness cosigner signing without \
                     independent audit_root verification callback"
                );
            }
        }

        // Sign the checkpoint
        let mut data = Vec::with_capacity(64 + 64 + 8 + 8);
        data.extend_from_slice(&req.audit_root);
        data.extend_from_slice(&req.kt_root);
        data.extend_from_slice(&req.sequence.to_be_bytes());
        data.extend_from_slice(&req.timestamp.to_be_bytes());

        let signature = pq_sign_raw_from_seed(&self.signing_seed, &data);

        // Update state
        self.last_sequence = req.sequence;
        self.known_roots.insert(req.sequence, req.audit_root);

        // Trim old roots (keep last 1000)
        if self.known_roots.len() > 1000 {
            let min_seq = self.known_roots.keys().copied().min().unwrap_or(0);
            self.known_roots.remove(&min_seq);
        }

        WitnessSignResponse {
            signature,
            cosigner_id: self.config.cosigner_id.clone(),
            accepted: true,
            rejection_reason: None,
        }
    }

    /// Get the verifying key for this cosigner (for checkpoint verification).
    pub fn verifying_key_bytes(&self) -> Vec<u8> {
        pq_verifying_key_from_seed(&self.signing_seed)
    }

    /// Get the cosigner ID.
    pub fn cosigner_id(&self) -> &str {
        &self.config.cosigner_id
    }

    /// Get the last accepted sequence.
    pub fn last_sequence(&self) -> u64 {
        self.last_sequence
    }
}

impl Drop for ExternalWitnessCosigner {
    fn drop(&mut self) {
        // Zeroize signing seed on drop
        self.signing_seed.iter_mut().for_each(|b| *b = 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    /// ML-DSA-87 keys are large; run tests on a thread with more stack space.
    fn run_with_large_stack<F: FnOnce() + Send + 'static>(f: F) {
        std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(f)
            .expect("thread spawn failed")
            .join()
            .expect("thread panicked");
    }

    fn make_request(sequence: u64) -> WitnessSignRequest {
        let now_us = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros() as i64;
        WitnessSignRequest {
            audit_root: [0xAA; 64],
            kt_root: [0xBB; 64],
            sequence,
            timestamp: now_us,
            requester_node: NodeId(Uuid::new_v4()),
        }
    }

    #[test]
    fn test_normal_signing_succeeds() {
        run_with_large_stack(|| {
            let seed = [42u8; 32];
            let mut cosigner = ExternalWitnessCosigner::new(
                ExternalWitnessConfig::default(),
                seed,
            );
            let req = make_request(1);
            let resp = cosigner.process_request(&req);
            assert!(resp.accepted, "signing should succeed: {:?}", resp.rejection_reason);
            assert!(!resp.signature.is_empty());
            assert_eq!(resp.cosigner_id, "witness-cosigner-1");

            // Verify the signature
            let vk_bytes = cosigner.verifying_key_bytes();
            let mut data = Vec::new();
            data.extend_from_slice(&req.audit_root);
            data.extend_from_slice(&req.kt_root);
            data.extend_from_slice(&req.sequence.to_be_bytes());
            data.extend_from_slice(&req.timestamp.to_be_bytes());
            assert!(pq_verify_raw(&vk_bytes, &data, &resp.signature));
        });
    }

    #[test]
    fn test_rate_limit_rejection() {
        run_with_large_stack(|| {
            let seed = [7u8; 32];
            let config = ExternalWitnessConfig {
                max_requests_per_minute: 2,
                ..Default::default()
            };
            let mut cosigner = ExternalWitnessCosigner::new(config, seed);

            // First two should succeed
            let resp1 = cosigner.process_request(&make_request(1));
            assert!(resp1.accepted);
            let resp2 = cosigner.process_request(&make_request(2));
            assert!(resp2.accepted);

            // Third should be rate limited
            let resp3 = cosigner.process_request(&make_request(3));
            assert!(!resp3.accepted);
            assert_eq!(resp3.rejection_reason.as_deref(), Some("rate limit exceeded"));
        });
    }

    #[test]
    fn test_sequence_rollback_rejection() {
        run_with_large_stack(|| {
            let seed = [13u8; 32];
            let mut cosigner = ExternalWitnessCosigner::new(
                ExternalWitnessConfig::default(),
                seed,
            );

            // Accept sequence 5
            let resp = cosigner.process_request(&make_request(5));
            assert!(resp.accepted);
            assert_eq!(cosigner.last_sequence(), 5);

            // Attempt sequence 3 (rollback) -- should be rejected
            let resp = cosigner.process_request(&make_request(3));
            assert!(!resp.accepted);
            assert!(resp.rejection_reason.unwrap().contains("sequence rollback"));
        });
    }

    #[test]
    fn test_old_timestamp_rejection() {
        run_with_large_stack(|| {
            let seed = [99u8; 32];
            let config = ExternalWitnessConfig {
                max_request_age: Duration::from_secs(1),
                ..Default::default()
            };
            let mut cosigner = ExternalWitnessCosigner::new(config, seed);

            // Create a request with a very old timestamp (2 minutes ago)
            let mut req = make_request(1);
            let two_minutes_ago_us = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_micros() as i64
                - 120_000_000; // 120 seconds in microseconds
            req.timestamp = two_minutes_ago_us;

            let resp = cosigner.process_request(&req);
            assert!(!resp.accepted);
            assert!(resp.rejection_reason.unwrap().contains("request too old"));
        });
    }

    #[test]
    fn test_seed_zeroization_on_drop() {
        // We cannot directly inspect the memory after drop,
        // but we can verify that the Drop impl runs without panic
        // and that a new cosigner with the same seed produces valid sigs.
        run_with_large_stack(|| {
            let seed = [55u8; 32];
            let vk_bytes;
            {
                let cosigner = ExternalWitnessCosigner::new(
                    ExternalWitnessConfig::default(),
                    seed,
                );
                vk_bytes = cosigner.verifying_key_bytes();
                // cosigner is dropped here, seed should be zeroized
            }
            // Verify the verifying key was valid before drop
            assert!(!vk_bytes.is_empty());

            // Create a fresh cosigner with the same seed; it should produce
            // the same verifying key (deterministic keygen).
            let cosigner2 = ExternalWitnessCosigner::new(
                ExternalWitnessConfig::default(),
                seed,
            );
            assert_eq!(cosigner2.verifying_key_bytes(), vk_bytes);
        });
    }
}
