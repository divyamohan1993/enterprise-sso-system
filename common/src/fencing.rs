//! Fencing tokens prevent stale leaders from making decisions after
//! being replaced. Every leader operation includes a fencing token.
//! Storage/services reject operations with stale tokens.
//!
//! Properties:
//! - Monotonically increasing epoch
//! - Signed by the leader's ML-DSA-87 key
//! - Verified by all receivers before accepting operations

use ml_dsa::{
    signature::{Signer, Verifier},
    MlDsa87, SigningKey, VerifyingKey,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;

/// ML-DSA-87 type aliases local to this module.
pub type FencingSigningKey = SigningKey<MlDsa87>;
pub type FencingVerifyingKey = VerifyingKey<MlDsa87>;
type FencingSignature = ml_dsa::Signature<MlDsa87>;

/// A signed fencing token proving a leader's authority in a given epoch.
///
/// The signature covers `SHA-512(epoch || leader_node_id)`, binding the
/// token to exactly one leader in exactly one epoch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FencingToken {
    /// The epoch (term) this token was issued in.
    pub epoch: u64,
    /// The node ID of the leader that issued this token.
    pub leader_node_id: String,
    /// ML-DSA-87 signature over the canonical payload.
    pub signature: Vec<u8>,
}

impl FencingToken {
    /// Create a new fencing token signed by the leader.
    pub fn new(epoch: u64, leader_node_id: impl Into<String>, signing_key: &FencingSigningKey) -> Self {
        let leader_node_id = leader_node_id.into();
        let payload = Self::signing_payload(epoch, &leader_node_id);
        let sig: FencingSignature = signing_key.sign(&payload);
        let signature = sig.encode().to_vec();
        Self {
            epoch,
            leader_node_id,
            signature,
        }
    }

    /// Compute the canonical signing payload: SHA-512(epoch || leader_node_id).
    fn signing_payload(epoch: u64, leader_node_id: &str) -> Vec<u8> {
        let mut hasher = Sha512::new();
        hasher.update(epoch.to_le_bytes());
        hasher.update(leader_node_id.as_bytes());
        hasher.finalize().to_vec()
    }

    /// Verify this token's signature against the given verifying key.
    pub fn verify_signature(&self, verifying_key: &FencingVerifyingKey) -> bool {
        let payload = Self::signing_payload(self.epoch, &self.leader_node_id);
        let sig = match FencingSignature::try_from(self.signature.as_slice()) {
            Ok(s) => s,
            Err(_) => return false,
        };
        verifying_key.verify(&payload, &sig).is_ok()
    }

    /// Serialize to bytes using postcard.
    pub fn to_bytes(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("FencingToken serialization cannot fail")
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, postcard::Error> {
        postcard::from_bytes(bytes)
    }
}

/// Validates fencing tokens, enforcing monotonicity and leader identity.
///
/// Thread-safe: `highest_seen` uses `AtomicU64`, `known_leaders` uses `RwLock`.
pub struct FencingValidator {
    /// Highest epoch seen so far. Tokens with epoch <= this are stale.
    highest_seen: AtomicU64,
    /// Map of epoch -> leader_node_id for all accepted tokens.
    known_leaders: RwLock<HashMap<u64, String>>,
}

impl FencingValidator {
    /// Create a new validator with no history.
    pub fn new() -> Self {
        Self {
            highest_seen: AtomicU64::new(0),
            known_leaders: RwLock::new(HashMap::new()),
        }
    }

    /// Validate a fencing token:
    ///
    /// 1. The epoch must be > highest_seen (monotonicity).
    /// 2. The leader's verifying key must be in the provided key map.
    /// 3. The ML-DSA-87 signature must verify.
    ///
    /// On success, updates the highest_seen epoch and records the leader.
    pub fn validate(
        &self,
        token: &FencingToken,
        verifying_keys: &HashMap<String, FencingVerifyingKey>,
    ) -> Result<(), String> {
        // Check monotonicity.
        let current = self.highest_seen.load(Ordering::Acquire);
        if token.epoch <= current {
            return Err(format!(
                "stale fencing token: epoch {} <= current highest {}",
                token.epoch, current
            ));
        }

        // Look up the leader's verifying key.
        let vk = verifying_keys
            .get(&token.leader_node_id)
            .ok_or_else(|| {
                format!(
                    "unknown leader node: no verifying key for {}",
                    token.leader_node_id
                )
            })?;

        // Verify the signature.
        if !token.verify_signature(vk) {
            return Err(format!(
                "invalid fencing token signature from node {}",
                token.leader_node_id
            ));
        }

        // Atomically advance highest_seen. Use compare_exchange to avoid
        // regressing if another thread raced ahead.
        let mut expected = current;
        loop {
            if token.epoch <= expected {
                break;
            }
            match self.highest_seen.compare_exchange_weak(
                expected,
                token.epoch,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(actual) => expected = actual,
            }
        }

        // Record the leader for this epoch.
        let mut leaders = self.known_leaders.write().unwrap();
        leaders.insert(token.epoch, token.leader_node_id.clone());

        Ok(())
    }

    /// Check if the given epoch is behind the current highest.
    pub fn is_stale(&self, epoch: u64) -> bool {
        epoch <= self.highest_seen.load(Ordering::Acquire)
    }

    /// Return the current highest epoch seen.
    pub fn highest_epoch(&self) -> u64 {
        self.highest_seen.load(Ordering::Acquire)
    }

    /// Look up which leader was recorded for a given epoch.
    pub fn leader_for_epoch(&self, epoch: u64) -> Option<String> {
        self.known_leaders
            .read()
            .unwrap()
            .get(&epoch)
            .cloned()
    }
}

impl Default for FencingValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ml_dsa::KeyGen;

    fn generate_keypair() -> (FencingSigningKey, FencingVerifyingKey) {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).expect("OS CSPRNG unavailable");
        let kp = MlDsa87::from_seed(&seed.into());
        seed.iter_mut().for_each(|b| *b = 0);
        (kp.signing_key().clone(), kp.verifying_key().clone())
    }

    fn make_keys(node_id: &str) -> (String, FencingSigningKey, HashMap<String, FencingVerifyingKey>) {
        let (sk, vk) = generate_keypair();
        let mut keys = HashMap::new();
        keys.insert(node_id.to_string(), vk);
        (node_id.to_string(), sk, keys)
    }

    #[test]
    fn valid_fencing_token() {
        let (id, sk, keys) = make_keys("leader-1");
        let token = FencingToken::new(1, &id, &sk);
        assert!(token.verify_signature(keys.get(&id).unwrap()));
    }

    #[test]
    fn tampered_token_fails_verification() {
        let (id, sk, keys) = make_keys("leader-1");
        let mut token = FencingToken::new(1, &id, &sk);
        token.epoch = 999; // tamper
        assert!(!token.verify_signature(keys.get(&id).unwrap()));
    }

    #[test]
    fn validator_accepts_monotonic_tokens() {
        let (id, sk, keys) = make_keys("leader-A");
        let validator = FencingValidator::new();

        let t1 = FencingToken::new(1, &id, &sk);
        let t2 = FencingToken::new(2, &id, &sk);
        let t3 = FencingToken::new(3, &id, &sk);

        validator.validate(&t1, &keys).unwrap();
        validator.validate(&t2, &keys).unwrap();
        validator.validate(&t3, &keys).unwrap();

        assert_eq!(validator.highest_epoch(), 3);
    }

    #[test]
    fn validator_rejects_stale_token() {
        let (id, sk, keys) = make_keys("leader-A");
        let validator = FencingValidator::new();

        let t2 = FencingToken::new(2, &id, &sk);
        let t1 = FencingToken::new(1, &id, &sk);

        validator.validate(&t2, &keys).unwrap();
        let err = validator.validate(&t1, &keys).unwrap_err();
        assert!(err.contains("stale"));
    }

    #[test]
    fn validator_rejects_equal_epoch() {
        let (id, sk, keys) = make_keys("leader-A");
        let validator = FencingValidator::new();

        let t1a = FencingToken::new(1, &id, &sk);
        let t1b = FencingToken::new(1, &id, &sk);

        validator.validate(&t1a, &keys).unwrap();
        let err = validator.validate(&t1b, &keys).unwrap_err();
        assert!(err.contains("stale"));
    }

    #[test]
    fn validator_rejects_unknown_leader() {
        let (id, sk, _) = make_keys("leader-A");
        let validator = FencingValidator::new();
        let empty_keys: HashMap<String, FencingVerifyingKey> = HashMap::new();

        let token = FencingToken::new(1, &id, &sk);
        let err = validator.validate(&token, &empty_keys).unwrap_err();
        assert!(err.contains("unknown leader"));
    }

    #[test]
    fn validator_rejects_bad_signature() {
        let (id_a, sk_a, _) = make_keys("leader-A");
        let (_, _, keys_b) = make_keys("leader-A"); // different key for same name

        let validator = FencingValidator::new();
        let token = FencingToken::new(1, &id_a, &sk_a);

        let err = validator.validate(&token, &keys_b).unwrap_err();
        assert!(err.contains("invalid fencing token signature"));
    }

    #[test]
    fn is_stale_check() {
        let (id, sk, keys) = make_keys("leader-A");
        let validator = FencingValidator::new();

        assert!(!validator.is_stale(1));

        let token = FencingToken::new(5, &id, &sk);
        validator.validate(&token, &keys).unwrap();

        assert!(validator.is_stale(1));
        assert!(validator.is_stale(5));
        assert!(!validator.is_stale(6));
    }

    #[test]
    fn leader_tracking() {
        let (id_a, sk_a, mut keys) = make_keys("leader-A");
        let (sk_b, vk_b) = generate_keypair();
        keys.insert("leader-B".to_string(), vk_b);

        let validator = FencingValidator::new();

        let t1 = FencingToken::new(1, &id_a, &sk_a);
        let t2 = FencingToken::new(2, "leader-B", &sk_b);

        validator.validate(&t1, &keys).unwrap();
        validator.validate(&t2, &keys).unwrap();

        assert_eq!(validator.leader_for_epoch(1), Some("leader-A".to_string()));
        assert_eq!(validator.leader_for_epoch(2), Some("leader-B".to_string()));
        assert_eq!(validator.leader_for_epoch(3), None);
    }

    #[test]
    fn serialization_roundtrip() {
        let (id, sk, _) = make_keys("leader-X");
        let token = FencingToken::new(42, &id, &sk);

        let bytes = token.to_bytes();
        let restored = FencingToken::from_bytes(&bytes).unwrap();

        assert_eq!(token.epoch, restored.epoch);
        assert_eq!(token.leader_node_id, restored.leader_node_id);
        assert_eq!(token.signature, restored.signature);
    }
}
