//! Quorum Certificate (QC): cryptographic proof that a quorum of nodes
//! agreed on a particular value.
//!
//! Bundles individual ML-DSA-87 signatures from quorum members into a
//! verifiable certificate. The value being agreed upon is represented by
//! its SHA-512 hash.
//!
//! Used for: proving consensus was reached, auditable proof of agreement,
//! cross-region state transfer with proof of origin-region consensus.

use ml_dsa::{
    signature::Verifier,
    MlDsa87, SigningKey, VerifyingKey,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Serde helper for `[u8; 64]` fields.
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

/// ML-DSA-87 type aliases local to this module.
pub type QcSigningKey = SigningKey<MlDsa87>;
pub type QcVerifyingKey = VerifyingKey<MlDsa87>;
type QcSignature = ml_dsa::Signature<MlDsa87>;

/// A Quorum Certificate proves that `quorum_size` distinct nodes signed
/// the same `value_hash` in a given `epoch`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuorumCertificate {
    /// The epoch (consensus round) this certificate belongs to.
    pub epoch: u64,
    /// SHA-512 hash of the agreed-upon value.
    #[serde(with = "byte_array_64")]
    pub value_hash: [u8; 64],
    /// Node IDs of the signers, in order of signature addition.
    pub signers: Vec<String>,
    /// ML-DSA-87 signatures corresponding to each signer.
    pub signatures: Vec<Vec<u8>>,
    /// Number of signatures required for the quorum to be complete.
    pub quorum_size: usize,
    /// Microsecond timestamp of certificate creation.
    pub timestamp: i64,
}

impl QuorumCertificate {
    /// Create a new empty quorum certificate for the given epoch and value hash.
    ///
    /// `quorum_size` is the minimum number of signatures required.
    pub fn new(epoch: u64, value_hash: [u8; 64], quorum_size: usize) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as i64;
        Self {
            epoch,
            value_hash,
            signers: Vec::with_capacity(quorum_size),
            signatures: Vec::with_capacity(quorum_size),
            quorum_size,
            timestamp,
        }
    }

    /// Compute the canonical message that signers sign: SHA-512(epoch || value_hash).
    fn signing_payload(&self) -> Vec<u8> {
        let mut hasher = Sha512::new();
        hasher.update(self.epoch.to_le_bytes());
        hasher.update(self.value_hash);
        hasher.finalize().to_vec()
    }

    /// Add a signer's ML-DSA-87 signature. Returns `Err` if the node already signed.
    pub fn add_signature(
        &mut self,
        node_id: impl Into<String>,
        signature: Vec<u8>,
    ) -> Result<(), &'static str> {
        let node_id = node_id.into();
        if self.signers.contains(&node_id) {
            return Err("duplicate signer: node already contributed a signature");
        }
        self.signers.push(node_id);
        self.signatures.push(signature);
        Ok(())
    }

    /// Returns true if enough signatures have been collected to meet the quorum.
    pub fn is_complete(&self) -> bool {
        self.signers.len() >= self.quorum_size
    }

    /// Number of signatures still needed to reach quorum.
    pub fn signatures_needed(&self) -> usize {
        self.quorum_size.saturating_sub(self.signers.len())
    }

    /// Verify all collected signatures against the provided verifying keys.
    ///
    /// Each signer's signature is verified against the canonical signing payload
    /// using their ML-DSA-87 verifying key. Returns `Ok(())` if every signature
    /// is valid and the quorum is met, or `Err` with details on failure.
    pub fn verify(
        &self,
        verifying_keys: &HashMap<String, QcVerifyingKey>,
    ) -> Result<(), String> {
        if !self.is_complete() {
            return Err(format!(
                "quorum not met: have {} signatures, need {}",
                self.signers.len(),
                self.quorum_size
            ));
        }

        let payload = self.signing_payload();

        for (i, node_id) in self.signers.iter().enumerate() {
            let vk = verifying_keys
                .get(node_id)
                .ok_or_else(|| format!("missing verifying key for node {}", node_id))?;

            let sig = QcSignature::try_from(self.signatures[i].as_slice())
                .map_err(|_| format!("malformed signature from node {}", node_id))?;

            vk.verify(&payload, &sig)
                .map_err(|_| format!("invalid signature from node {}", node_id))?;
        }

        Ok(())
    }

    /// Verify that this QC certifies the expected value hash.
    pub fn verify_value(&self, expected_hash: &[u8; 64]) -> bool {
        self.value_hash == *expected_hash
    }

    /// Serialize to bytes using postcard.
    pub fn to_bytes(&self) -> Vec<u8> {
        postcard::to_allocvec(self).unwrap_or_else(|e| {
            tracing::error!("QuorumCertificate serialization failed: {e}");
            Vec::new()
        })
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, postcard::Error> {
        postcard::from_bytes(bytes)
    }

    /// Compute a SHA-512 hash of raw data, suitable for use as `value_hash`.
    pub fn hash_value(data: &[u8]) -> [u8; 64] {
        let digest = Sha512::digest(data);
        let mut hash = [0u8; 64];
        hash.copy_from_slice(&digest);
        hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ml_dsa::{signature::Signer, KeyGen};

    fn generate_keypair() -> (QcSigningKey, QcVerifyingKey) {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).expect("OS CSPRNG unavailable");
        let kp = MlDsa87::from_seed(&seed.into());
        seed.iter_mut().for_each(|b| *b = 0);
        (kp.signing_key().clone(), kp.verifying_key().clone())
    }

    fn sign_raw(sk: &QcSigningKey, data: &[u8]) -> Vec<u8> {
        let sig: QcSignature = sk.sign(data);
        sig.encode().to_vec()
    }

    fn setup_keys(n: usize) -> (Vec<String>, HashMap<String, QcVerifyingKey>, Vec<QcSigningKey>) {
        let mut names = Vec::new();
        let mut vks = HashMap::new();
        let mut sks = Vec::new();
        for i in 0..n {
            let name = format!("node-{}", i);
            let (sk, vk) = generate_keypair();
            vks.insert(name.clone(), vk);
            sks.push(sk);
            names.push(name);
        }
        (names, vks, sks)
    }

    fn sign_qc(qc: &QuorumCertificate, sk: &QcSigningKey) -> Vec<u8> {
        let payload = {
            let mut hasher = Sha512::new();
            hasher.update(qc.epoch.to_le_bytes());
            hasher.update(qc.value_hash);
            hasher.finalize().to_vec()
        };
        sign_raw(sk, &payload)
    }

    #[test]
    fn empty_qc_is_not_complete() {
        let qc = QuorumCertificate::new(1, [0u8; 64], 3);
        assert!(!qc.is_complete());
        assert_eq!(qc.signatures_needed(), 3);
    }

    #[test]
    fn duplicate_signer_rejected() {
        let mut qc = QuorumCertificate::new(1, [0u8; 64], 3);
        qc.add_signature("node-0", vec![1, 2, 3]).unwrap();
        let err = qc.add_signature("node-0", vec![4, 5, 6]).unwrap_err();
        assert!(err.contains("duplicate"));
    }

    #[test]
    fn quorum_completion_and_verification() {
        let (names, vks, sks) = setup_keys(5);
        let value = b"consensus value";
        let value_hash = QuorumCertificate::hash_value(value);
        let mut qc = QuorumCertificate::new(42, value_hash, 3);

        for i in 0..3 {
            let sig = sign_qc(&qc, &sks[i]);
            qc.add_signature(&names[i], sig).unwrap();
        }

        assert!(qc.is_complete());
        assert!(qc.verify_value(&value_hash));
        qc.verify(&vks).unwrap();
    }

    #[test]
    fn verification_fails_with_wrong_key() {
        let (names, mut vks, sks) = setup_keys(3);
        let value_hash = QuorumCertificate::hash_value(b"data");
        let mut qc = QuorumCertificate::new(1, value_hash, 3);

        for i in 0..3 {
            let sig = sign_qc(&qc, &sks[i]);
            qc.add_signature(&names[i], sig).unwrap();
        }

        // Replace one verifying key with a different one.
        let (_, wrong_vk) = generate_keypair();
        vks.insert(names[0].clone(), wrong_vk);

        let err = qc.verify(&vks).unwrap_err();
        assert!(err.contains("invalid signature"));
    }

    #[test]
    fn verification_fails_below_quorum() {
        let (names, vks, sks) = setup_keys(3);
        let value_hash = QuorumCertificate::hash_value(b"data");
        let mut qc = QuorumCertificate::new(1, value_hash, 3);

        // Only add 2 of 3 required signatures.
        for i in 0..2 {
            let sig = sign_qc(&qc, &sks[i]);
            qc.add_signature(&names[i], sig).unwrap();
        }

        let err = qc.verify(&vks).unwrap_err();
        assert!(err.contains("quorum not met"));
    }

    #[test]
    fn verify_value_mismatch() {
        let hash_a = QuorumCertificate::hash_value(b"value A");
        let hash_b = QuorumCertificate::hash_value(b"value B");
        let qc = QuorumCertificate::new(1, hash_a, 1);
        assert!(qc.verify_value(&hash_a));
        assert!(!qc.verify_value(&hash_b));
    }

    #[test]
    fn serialization_roundtrip() {
        let (names, _, sks) = setup_keys(3);
        let value_hash = QuorumCertificate::hash_value(b"roundtrip");
        let mut qc = QuorumCertificate::new(99, value_hash, 2);

        for i in 0..2 {
            let sig = sign_qc(&qc, &sks[i]);
            qc.add_signature(&names[i], sig).unwrap();
        }

        let bytes = qc.to_bytes();
        let restored = QuorumCertificate::from_bytes(&bytes).unwrap();

        assert_eq!(qc.epoch, restored.epoch);
        assert_eq!(qc.value_hash, restored.value_hash);
        assert_eq!(qc.signers, restored.signers);
        assert_eq!(qc.signatures, restored.signatures);
        assert_eq!(qc.quorum_size, restored.quorum_size);
    }
}
