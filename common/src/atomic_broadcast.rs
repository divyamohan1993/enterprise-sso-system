//! Atomic broadcast — total ordering of messages across distributed nodes.
//!
//! PROPERTIES (Hadzilacos & Toueg):
//! - Validity:    If a correct node broadcasts m, all correct nodes eventually deliver m.
//! - Agreement:   If a correct node delivers m, all correct nodes eventually deliver m.
//! - Total Order: If correct nodes p and q both deliver m1 and m2, they deliver in the same order.
//! - Integrity:   Every message is delivered at most once, and only if previously broadcast.
//!
//! DESIGN:
//! Messages are assigned monotonically increasing sequence numbers.
//! A message is "deliverable" once a quorum of nodes have acknowledged it.
//! Delivery happens strictly in sequence order — no gaps allowed.
//! This builds on top of BFT consensus for ack collection.
//!
//! INVARIANTS:
//! - Sequence numbers are gap-free and monotonically increasing.
//! - No message is delivered without quorum acks.
//! - No message is delivered out of order.
//! - No message is delivered twice.
//! - SIEM event on each delivery batch.

use crate::siem::{PanelSiemEvent, SiemPanel, SiemSeverity};
use sha2::{Digest, Sha512};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

/// A message in the atomic broadcast protocol.
#[derive(Debug, Clone)]
pub struct BroadcastMessage {
    /// Monotonically increasing sequence number (gap-free).
    pub sequence: u64,
    /// SHA-512 hash of the payload (the payload itself is application-level).
    pub payload_hash: [u8; 64],
    /// Node ID of the sender.
    pub sender: String,
    /// Unix-epoch seconds when broadcast was initiated.
    pub timestamp: i64,
    /// Acknowledgements: (node_id, signature over sequence||payload_hash).
    pub acks: Vec<(String, Vec<u8>)>,
}

impl BroadcastMessage {
    /// Compute the digest that ack signatures should cover.
    /// SHA-512(sequence_le_bytes || payload_hash).
    pub fn ack_digest(&self) -> [u8; 64] {
        let mut hasher = Sha512::new();
        hasher.update(self.sequence.to_le_bytes());
        hasher.update(self.payload_hash);
        let result = hasher.finalize();
        let mut digest = [0u8; 64];
        digest.copy_from_slice(&result);
        digest
    }

    /// Check if a specific node has acked this message.
    pub fn has_ack_from(&self, node_id: &str) -> bool {
        self.acks.iter().any(|(id, _)| id == node_id)
    }
}

/// Atomic broadcast engine. Ensures total ordering and quorum delivery.
pub struct AtomicBroadcast {
    /// Next sequence number to assign.
    next_sequence: AtomicU64,
    /// Messages pending delivery (awaiting quorum acks), keyed by sequence.
    pending: RwLock<BTreeMap<u64, BroadcastMessage>>,
    /// Messages that have been delivered in order.
    delivered: RwLock<Vec<BroadcastMessage>>,
    /// Next sequence number expected for delivery (ensures gap-free).
    next_deliver_seq: AtomicU64,
    /// Number of acks required for delivery.
    quorum_size: usize,
    /// Set of delivered payload hashes (integrity: no duplicates).
    delivered_hashes: RwLock<HashSet<[u8; 64]>>,
    /// ML-DSA-87 verifying keys for ack signature verification, keyed by node_id.
    verifying_keys: RwLock<HashMap<String, Vec<u8>>>,
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

impl AtomicBroadcast {
    /// Create a new atomic broadcast engine.
    ///
    /// `quorum_size` is the number of acks required before a message is deliverable.
    /// For BFT with n=3f+1 nodes, quorum_size = 2f+1.
    pub fn new(quorum_size: usize) -> Self {
        assert!(quorum_size >= 1, "quorum size must be >= 1");
        Self {
            next_sequence: AtomicU64::new(1),
            pending: RwLock::new(BTreeMap::new()),
            delivered: RwLock::new(Vec::new()),
            next_deliver_seq: AtomicU64::new(1),
            quorum_size,
            delivered_hashes: RwLock::new(HashSet::new()),
            verifying_keys: RwLock::new(HashMap::new()),
        }
    }

    /// Register an ML-DSA-87 verifying key for a node.
    /// Ack signatures from this node will be verified against this key.
    pub fn register_verifying_key(&self, node_id: &str, key_bytes: Vec<u8>) {
        let mut keys = crate::sync::siem_write(&self.verifying_keys, "atomic_broadcast::register_key");
        keys.insert(node_id.to_string(), key_bytes);
    }

    /// Broadcast a payload: assign a sequence number and create a pending message.
    ///
    /// Returns the assigned sequence number. The message enters the pending set
    /// and will be delivered once quorum acks are collected.
    pub fn broadcast(&self, payload: &[u8], sender: &str) -> Result<u64, String> {
        let sequence = self.next_sequence.fetch_add(1, Ordering::SeqCst);

        let payload_hash = {
            let result = Sha512::digest(payload);
            let mut hash = [0u8; 64];
            hash.copy_from_slice(&result);
            hash
        };

        // Integrity check: reject duplicate payload hashes
        {
            let hashes = crate::sync::siem_read(&self.delivered_hashes, "atomic_broadcast::propose_hashes");
            if hashes.contains(&payload_hash) {
                return Err("duplicate payload: already delivered".into());
            }
        }
        {
            let pending = crate::sync::siem_read(&self.pending, "atomic_broadcast::propose_pending");
            for msg in pending.values() {
                if msg.payload_hash == payload_hash {
                    return Err("duplicate payload: already pending".into());
                }
            }
        }

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let message = BroadcastMessage {
            sequence,
            payload_hash,
            sender: sender.to_string(),
            timestamp,
            acks: Vec::new(),
        };

        let mut pending = crate::sync::siem_write(&self.pending, "atomic_broadcast::propose_insert");
        pending.insert(sequence, message);

        Ok(sequence)
    }

    /// Receive an acknowledgement for a pending message.
    ///
    /// `node_id` is the acknowledging node, `signature` is the ML-DSA-87
    /// signature over the ack digest.
    pub fn receive_ack(
        &self,
        sequence: u64,
        node_id: &str,
        signature: Vec<u8>,
    ) -> Result<(), String> {
        let mut pending = crate::sync::siem_write(&self.pending, "atomic_broadcast::receive_ack");

        let msg = pending.get_mut(&sequence).ok_or_else(|| {
            format!("no pending message with sequence {sequence}")
        })?;

        // Reject duplicate acks from same node
        if msg.has_ack_from(node_id) {
            return Err(format!("{node_id} already acked sequence {sequence}"));
        }

        // Verify ML-DSA-87 signature over ack_digest.
        if signature.is_empty() {
            return Err("empty ack signature".into());
        }

        {
            let keys = crate::sync::siem_read(&self.verifying_keys, "atomic_broadcast::verify_ack");
            if let Some(key_bytes) = keys.get(node_id) {
                let ack_digest = msg.ack_digest();
                if !verify_ack_signature(node_id, &ack_digest, &signature, key_bytes) {
                    PanelSiemEvent::new(
                        SiemPanel::KeyManagement,
                        SiemSeverity::Critical,
                        "ack_signature_verification_failed",
                        format!("ML-DSA-87 ack signature from {} failed verification for seq {}", node_id, sequence),
                        file!(),
                        line!(),
                        module_path!(),
                    )
                    .emit();
                    return Err(format!("ack signature verification failed for {node_id}"));
                }
                // Signature verified successfully — fall through to accept.
            } else {
                // SECURITY: Reject acks from nodes with no registered key.
                // A missing key means the node has not completed key enrollment.
                // Accepting unsigned acks would allow phantom nodes to forge quorum.
                return Err(format!(
                    "no verifying key registered for node '{node_id}'; \
                     ack rejected — register key before participating in broadcast"
                ));
            }
        }

        msg.acks.push((node_id.to_string(), signature));

        Ok(())
    }

    /// Deliver messages that have reached quorum, in strict sequence order.
    ///
    /// Returns the newly delivered messages. Messages are only delivered if:
    /// 1. They have >= quorum_size acks.
    /// 2. All prior sequence numbers have been delivered (gap-free).
    pub fn deliver(&self) -> Vec<BroadcastMessage> {
        let mut pending = crate::sync::siem_write(&self.pending, "atomic_broadcast::deliver_pending");
        let mut delivered = crate::sync::siem_write(&self.delivered, "atomic_broadcast::deliver_delivered");
        let mut hashes = crate::sync::siem_write(&self.delivered_hashes, "atomic_broadcast::deliver_hashes");

        let mut newly_delivered = Vec::new();

        loop {
            let next_seq = self.next_deliver_seq.load(Ordering::SeqCst);

            let ready = match pending.get(&next_seq) {
                Some(msg) => msg.acks.len() >= self.quorum_size,
                None => false,
            };

            if !ready {
                break;
            }

            let msg = pending.remove(&next_seq).unwrap();
            hashes.insert(msg.payload_hash);
            self.next_deliver_seq.fetch_add(1, Ordering::SeqCst);
            delivered.push(msg.clone());
            newly_delivered.push(msg);
        }

        if !newly_delivered.is_empty() {
            PanelSiemEvent::new(
                SiemPanel::KeyManagement,
                SiemSeverity::Info,
                "atomic_broadcast_deliver",
                format!(
                    "Delivered {} messages (sequences {}-{})",
                    newly_delivered.len(),
                    newly_delivered.first().unwrap().sequence,
                    newly_delivered.last().unwrap().sequence,
                ),
                file!(),
                line!(),
                module_path!(),
            )
            .emit();
        }

        newly_delivered
    }

    /// Verify the total order invariant over delivered messages.
    ///
    /// Returns Ok(()) if all delivered messages are in strictly increasing
    /// sequence order with no gaps, or Err with the violation.
    pub fn verify_order(&self) -> Result<(), String> {
        let delivered = crate::sync::siem_read(&self.delivered, "atomic_broadcast::verify_order");
        Self::verify_message_order(&delivered)
    }

    /// Verify total order on an arbitrary message slice.
    pub fn verify_message_order(messages: &[BroadcastMessage]) -> Result<(), String> {
        if messages.is_empty() {
            return Ok(());
        }

        let mut prev_seq = messages[0].sequence;
        // First message should have sequence 1 (or whatever the starting point is)
        for (i, msg) in messages.iter().enumerate().skip(1) {
            if msg.sequence != prev_seq + 1 {
                return Err(format!(
                    "total order violation at index {i}: expected sequence {}, got {}",
                    prev_seq + 1,
                    msg.sequence
                ));
            }
            prev_seq = msg.sequence;
        }

        // Check for duplicate payload hashes
        let mut seen_hashes = HashSet::new();
        for msg in messages {
            if !seen_hashes.insert(msg.payload_hash) {
                return Err(format!(
                    "integrity violation: duplicate payload hash at sequence {}",
                    msg.sequence
                ));
            }
        }

        Ok(())
    }

    /// Number of messages currently pending delivery.
    pub fn pending_count(&self) -> usize {
        let pending = crate::sync::siem_read(&self.pending, "atomic_broadcast::pending_count");
        pending.len()
    }

    /// Number of messages successfully delivered.
    pub fn delivered_count(&self) -> usize {
        let delivered = crate::sync::siem_read(&self.delivered, "atomic_broadcast::delivered_count");
        delivered.len()
    }

    /// Get the next sequence number that will be assigned.
    pub fn next_sequence(&self) -> u64 {
        self.next_sequence.load(Ordering::SeqCst)
    }

    /// Get all delivered messages (clone).
    pub fn delivered_messages(&self) -> Vec<BroadcastMessage> {
        let delivered = crate::sync::siem_read(&self.delivered, "atomic_broadcast::delivered_messages");
        delivered.clone()
    }
}

/// Verify an ML-DSA-87 ack signature.
/// Returns true if the signature over ack_digest is valid for the given key bytes.
fn verify_ack_signature(
    node_id: &str,
    ack_digest: &[u8; 64],
    signature: &[u8],
    verifying_key_bytes: &[u8],
) -> bool {
    use ml_dsa::{signature::Verifier, EncodedVerifyingKey, MlDsa87, VerifyingKey};
    let vk_enc = match EncodedVerifyingKey::<MlDsa87>::try_from(verifying_key_bytes) {
        Ok(e) => e,
        Err(e) => {
            tracing::error!(
                node_id = node_id,
                error = %e,
                "failed to deserialize ML-DSA-87 verifying key for ack verification"
            );
            return false;
        }
    };
    let vk = VerifyingKey::<MlDsa87>::decode(&vk_enc);
    let sig = match ml_dsa::Signature::<MlDsa87>::try_from(signature) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(
                node_id = node_id,
                error = %e,
                "failed to deserialize ML-DSA-87 signature for ack verification"
            );
            return false;
        }
    };
    vk.verify(ack_digest, &sig).is_ok()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ml_dsa::{KeyGen, MlDsa87, SigningKey, signature::Signer};

    /// Generate a real ML-DSA-87 keypair from a random seed.
    /// Returns (signing_key, verifying_key_bytes) for test use.
    fn make_test_keypair() -> (SigningKey<MlDsa87>, Vec<u8>) {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).expect("getrandom for test keypair");
        let kp = MlDsa87::from_seed(&seed.into());
        let sk = kp.signing_key().clone();
        let vk_bytes = kp.verifying_key().encode().to_vec();
        (sk, vk_bytes)
    }

    /// Sign an ack digest with the given signing key, returning the encoded signature bytes.
    fn sign_ack(sk: &SigningKey<MlDsa87>, ab: &AtomicBroadcast, seq: u64) -> Vec<u8> {
        let pending = crate::sync::siem_read(&ab.pending, "test::sign_ack");
        let msg = pending.get(&seq).expect("message must exist for signing");
        let digest = msg.ack_digest();
        let sig: ml_dsa::Signature<MlDsa87> = sk.sign(&digest);
        sig.encode().to_vec()
    }

    /// Register a node's ML-DSA-87 key and return its signing key for producing valid acks.
    fn register_node(ab: &AtomicBroadcast, node_id: &str) -> SigningKey<MlDsa87> {
        let (sk, vk_bytes) = make_test_keypair();
        ab.register_verifying_key(node_id, vk_bytes);
        sk
    }

    #[test]
    fn broadcast_assigns_sequential_numbers() {
        let ab = AtomicBroadcast::new(1);
        let s1 = ab.broadcast(b"msg1", "node-1").unwrap();
        let s2 = ab.broadcast(b"msg2", "node-1").unwrap();
        let s3 = ab.broadcast(b"msg3", "node-1").unwrap();
        assert_eq!(s1, 1);
        assert_eq!(s2, 2);
        assert_eq!(s3, 3);
    }

    #[test]
    fn deliver_requires_quorum_acks() {
        let ab = AtomicBroadcast::new(3);
        let sk2 = register_node(&ab, "node-2");
        let sk3 = register_node(&ab, "node-3");
        let sk4 = register_node(&ab, "node-4");
        let seq = ab.broadcast(b"hello", "node-1").unwrap();

        // No acks yet
        assert!(ab.deliver().is_empty());

        // 1 ack — still not enough
        ab.receive_ack(seq, "node-2", sign_ack(&sk2, &ab, seq)).unwrap();
        assert!(ab.deliver().is_empty());

        // 2 acks — still not enough
        ab.receive_ack(seq, "node-3", sign_ack(&sk3, &ab, seq)).unwrap();
        assert!(ab.deliver().is_empty());

        // 3 acks — quorum reached
        ab.receive_ack(seq, "node-4", sign_ack(&sk4, &ab, seq)).unwrap();
        let delivered = ab.deliver();
        assert_eq!(delivered.len(), 1);
        assert_eq!(delivered[0].sequence, seq);
        assert_eq!(delivered[0].acks.len(), 3);
    }

    #[test]
    fn deliver_respects_total_order() {
        let ab = AtomicBroadcast::new(1);
        let sk1 = register_node(&ab, "node-1");

        // Broadcast 3 messages
        let s1 = ab.broadcast(b"first", "node-1").unwrap();
        let s2 = ab.broadcast(b"second", "node-1").unwrap();
        let s3 = ab.broadcast(b"third", "node-1").unwrap();

        // Ack in reverse order: s3, s1, s2
        ab.receive_ack(s3, "node-1", sign_ack(&sk1, &ab, s3)).unwrap();
        ab.receive_ack(s1, "node-1", sign_ack(&sk1, &ab, s1)).unwrap();

        // Only s1 can deliver (s2 blocks s3)
        let d1 = ab.deliver();
        assert_eq!(d1.len(), 1);
        assert_eq!(d1[0].sequence, s1);

        // Ack s2
        ab.receive_ack(s2, "node-1", sign_ack(&sk1, &ab, s2)).unwrap();

        // Now s2 and s3 can deliver in order
        let d2 = ab.deliver();
        assert_eq!(d2.len(), 2);
        assert_eq!(d2[0].sequence, s2);
        assert_eq!(d2[1].sequence, s3);
    }

    #[test]
    fn deliver_gap_blocks_later_messages() {
        let ab = AtomicBroadcast::new(1);
        let sk1 = register_node(&ab, "node-1");

        let _s1 = ab.broadcast(b"one", "node-1").unwrap();
        let s2 = ab.broadcast(b"two", "node-1").unwrap();

        // Only ack s2, not s1
        ab.receive_ack(s2, "node-1", sign_ack(&sk1, &ab, s2)).unwrap();

        // Cannot deliver s2 because s1 hasn't been delivered yet
        assert!(ab.deliver().is_empty());
        assert_eq!(ab.pending_count(), 2);
    }

    #[test]
    fn duplicate_ack_rejected() {
        let ab = AtomicBroadcast::new(1);
        let sk2 = register_node(&ab, "node-2");
        let seq = ab.broadcast(b"msg", "node-1").unwrap();

        let sig = sign_ack(&sk2, &ab, seq);
        ab.receive_ack(seq, "node-2", sig.clone()).unwrap();
        assert!(ab.receive_ack(seq, "node-2", sig).is_err());
    }

    #[test]
    fn ack_nonexistent_sequence_rejected() {
        let ab = AtomicBroadcast::new(1);
        // Sequence 999 was never broadcast, so this must fail regardless of signature.
        assert!(ab.receive_ack(999, "node-1", vec![0x01; 64]).is_err());
    }

    #[test]
    fn empty_ack_signature_rejected() {
        let ab = AtomicBroadcast::new(1);
        let seq = ab.broadcast(b"msg", "node-1").unwrap();
        assert!(ab.receive_ack(seq, "node-2", Vec::new()).is_err());
    }

    #[test]
    fn duplicate_payload_rejected() {
        let ab = AtomicBroadcast::new(1);
        ab.broadcast(b"same-payload", "node-1").unwrap();
        assert!(ab.broadcast(b"same-payload", "node-2").is_err());
    }

    #[test]
    fn duplicate_payload_rejected_after_delivery() {
        let ab = AtomicBroadcast::new(1);
        let sk1 = register_node(&ab, "node-1");
        let seq = ab.broadcast(b"delivered-payload", "node-1").unwrap();
        ab.receive_ack(seq, "node-1", sign_ack(&sk1, &ab, seq)).unwrap();
        ab.deliver();

        // Try to broadcast same payload again
        assert!(ab.broadcast(b"delivered-payload", "node-2").is_err());
    }

    #[test]
    fn verify_order_valid() {
        let ab = AtomicBroadcast::new(1);
        let sk1 = register_node(&ab, "node-1");

        for i in 0..5 {
            let seq = ab.broadcast(format!("msg-{i}").as_bytes(), "node-1").unwrap();
            ab.receive_ack(seq, "node-1", sign_ack(&sk1, &ab, seq)).unwrap();
        }
        ab.deliver();

        ab.verify_order().unwrap();
    }

    #[test]
    fn verify_order_detects_gap() {
        let messages = vec![
            BroadcastMessage {
                sequence: 1,
                payload_hash: [0x01; 64],
                sender: "a".into(),
                timestamp: 0,
                acks: Vec::new(),
            },
            BroadcastMessage {
                sequence: 3, // gap: missing 2
                payload_hash: [0x02; 64],
                sender: "a".into(),
                timestamp: 0,
                acks: Vec::new(),
            },
        ];
        assert!(AtomicBroadcast::verify_message_order(&messages).is_err());
    }

    #[test]
    fn verify_order_detects_duplicate_hash() {
        let messages = vec![
            BroadcastMessage {
                sequence: 1,
                payload_hash: [0x01; 64],
                sender: "a".into(),
                timestamp: 0,
                acks: Vec::new(),
            },
            BroadcastMessage {
                sequence: 2,
                payload_hash: [0x01; 64], // same hash
                sender: "b".into(),
                timestamp: 0,
                acks: Vec::new(),
            },
        ];
        assert!(AtomicBroadcast::verify_message_order(&messages).is_err());
    }

    #[test]
    fn verify_order_empty_is_ok() {
        assert!(AtomicBroadcast::verify_message_order(&[]).is_ok());
    }

    #[test]
    fn ack_digest_is_deterministic() {
        let msg = BroadcastMessage {
            sequence: 42,
            payload_hash: [0xAB; 64],
            sender: "node-1".into(),
            timestamp: 1234567890,
            acks: Vec::new(),
        };
        let d1 = msg.ack_digest();
        let d2 = msg.ack_digest();
        assert_eq!(d1, d2);
    }

    #[test]
    fn ack_digest_differs_for_different_sequence() {
        let msg1 = BroadcastMessage {
            sequence: 1,
            payload_hash: [0xAB; 64],
            sender: "a".into(),
            timestamp: 0,
            acks: Vec::new(),
        };
        let msg2 = BroadcastMessage {
            sequence: 2,
            payload_hash: [0xAB; 64],
            sender: "a".into(),
            timestamp: 0,
            acks: Vec::new(),
        };
        assert_ne!(msg1.ack_digest(), msg2.ack_digest());
    }

    #[test]
    fn delivered_count_and_pending_count() {
        let ab = AtomicBroadcast::new(1);
        let sk1 = register_node(&ab, "n1");
        assert_eq!(ab.delivered_count(), 0);
        assert_eq!(ab.pending_count(), 0);

        let s1 = ab.broadcast(b"a", "n1").unwrap();
        let _s2 = ab.broadcast(b"b", "n1").unwrap();
        assert_eq!(ab.pending_count(), 2);

        ab.receive_ack(s1, "n1", sign_ack(&sk1, &ab, s1)).unwrap();
        ab.deliver();
        assert_eq!(ab.delivered_count(), 1);
        assert_eq!(ab.pending_count(), 1);
    }

    #[test]
    fn has_ack_from_works() {
        let ab = AtomicBroadcast::new(2);
        let sk_a = register_node(&ab, "node-a");
        let seq = ab.broadcast(b"test", "sender").unwrap();

        ab.receive_ack(seq, "node-a", sign_ack(&sk_a, &ab, seq)).unwrap();

        let pending = ab.pending.read().unwrap();
        let msg = pending.get(&seq).unwrap();
        assert!(msg.has_ack_from("node-a"));
        assert!(!msg.has_ack_from("node-b"));
    }

    #[test]
    fn large_scale_ordering() {
        let ab = AtomicBroadcast::new(2);
        let sk1 = register_node(&ab, "n1");
        let sk2 = register_node(&ab, "n2");
        let node_ids = ["n1", "n2", "n3"];

        // Broadcast 100 messages
        let mut sequences = Vec::new();
        for i in 0..100 {
            let payload = format!("payload-{i}");
            let seq = ab.broadcast(payload.as_bytes(), node_ids[i % 3]).unwrap();
            sequences.push(seq);
        }

        // Ack all from 2 nodes (quorum)
        for &seq in &sequences {
            ab.receive_ack(seq, "n1", sign_ack(&sk1, &ab, seq)).unwrap();
            ab.receive_ack(seq, "n2", sign_ack(&sk2, &ab, seq)).unwrap();
        }

        let delivered = ab.deliver();
        assert_eq!(delivered.len(), 100);
        ab.verify_order().unwrap();

        // Verify strict sequential order
        for (i, msg) in delivered.iter().enumerate() {
            assert_eq!(msg.sequence, (i + 1) as u64);
        }
    }
}
