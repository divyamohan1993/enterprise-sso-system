//! Distributed binary attestation mesh.
//!
//! Every node periodically:
//! 1. Computes SHA-512 hash of its own binary (/proc/self/exe)
//! 2. Broadcasts its hash to all peers
//! 3. Receives hashes from all peers
//! 4. Compares against the expected "golden" hash (from initial cluster formation)
//! 5. If mismatch: reports tampering via Raft ClusterCommand
//!
//! The golden hash is established during initial cluster formation:
//! - First node to join sets the golden hash
//! - Subsequent nodes must match (or be rejected)
//! - Hash is replicated in the Raft log as a MemberJoin metadata field
#![forbid(unsafe_code)]

use crate::raft::NodeId;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;
use subtle::ConstantTimeEq;

// ── Core types ───────────────────────────────────────────────────────────────

/// SHA-512 hash of a service binary.
pub type BinaryHash = [u8; 64];

/// Result of attesting one peer.
#[derive(Debug, Clone)]
pub struct AttestationResult {
    pub node_id: NodeId,
    pub reported_hash: BinaryHash,
    pub expected_hash: BinaryHash,
    pub matches: bool,
    pub timestamp: i64,
}

/// Configuration for the attestation mesh.
#[derive(Debug, Clone)]
pub struct AttestationMeshConfig {
    /// How often to verify peers (default: 30s).
    pub verify_interval: Duration,
    /// Maximum number of consecutive mismatches before declaring tampered (default: 2).
    pub tamper_threshold: u32,
    /// Path to the golden hash file (persisted across restarts).
    pub golden_hash_path: Option<PathBuf>,
}

impl Default for AttestationMeshConfig {
    fn default() -> Self {
        Self {
            verify_interval: Duration::from_secs(30),
            tamper_threshold: 2,
            golden_hash_path: None,
        }
    }
}

// ── Peer state ───────────────────────────────────────────────────────────────

struct PeerAttestationState {
    last_reported_hash: Option<BinaryHash>,
    consecutive_mismatches: u32,
    tampered: bool,
}

impl PeerAttestationState {
    fn new() -> Self {
        Self {
            last_reported_hash: None,
            consecutive_mismatches: 0,
            tampered: false,
        }
    }
}

// ── Attestation mesh ─────────────────────────────────────────────────────────

/// The attestation mesh state.
pub struct AttestationMesh {
    config: AttestationMeshConfig,
    /// This node's binary hash (computed at startup).
    own_hash: BinaryHash,
    /// The cluster-agreed golden hash.
    golden_hash: Option<BinaryHash>,
    /// Per-peer attestation state.
    peer_state: HashMap<NodeId, PeerAttestationState>,
}

impl AttestationMesh {
    /// Create a new attestation mesh, computing own hash from /proc/self/exe.
    pub fn new(config: AttestationMeshConfig) -> Result<Self, String> {
        let own_hash = compute_binary_hash()?;
        Ok(Self {
            config,
            own_hash,
            golden_hash: None,
            peer_state: HashMap::new(),
        })
    }

    /// Create an attestation mesh with a pre-computed hash (useful for testing).
    pub fn with_hash(config: AttestationMeshConfig, own_hash: BinaryHash) -> Self {
        Self {
            config,
            own_hash,
            golden_hash: None,
            peer_state: HashMap::new(),
        }
    }

    /// Set the expected golden hash (from Raft log).
    pub fn set_golden_hash(&mut self, hash: BinaryHash) {
        self.golden_hash = Some(hash);
    }

    /// Verify a peer's reported hash against the golden hash.
    ///
    /// Returns an `AttestationResult`. If the peer has exceeded the tamper
    /// threshold for consecutive mismatches, it is marked as tampered.
    pub fn verify_peer_hash(
        &mut self,
        node_id: NodeId,
        reported_hash: BinaryHash,
    ) -> AttestationResult {
        let expected = self.golden_hash.unwrap_or(self.own_hash);

        // Constant-time comparison
        let matches: bool = reported_hash
            .as_slice()
            .ct_eq(expected.as_slice())
            .into();

        let state = self
            .peer_state
            .entry(node_id)
            .or_insert_with(PeerAttestationState::new);

        state.last_reported_hash = Some(reported_hash);

        if matches {
            state.consecutive_mismatches = 0;
            // Once a peer matches again, clear tampered flag (healed).
        } else {
            state.consecutive_mismatches += 1;
            if state.consecutive_mismatches >= self.config.tamper_threshold {
                state.tampered = true;
            }
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        AttestationResult {
            node_id,
            reported_hash,
            expected_hash: expected,
            matches,
            timestamp: now,
        }
    }

    /// Check whether a specific peer is considered tampered.
    pub fn is_tampered(&self, node_id: &NodeId) -> bool {
        self.peer_state
            .get(node_id)
            .map(|s| s.tampered)
            .unwrap_or(false)
    }

    /// Return all nodes currently flagged as tampered.
    pub fn tampered_nodes(&self) -> Vec<NodeId> {
        self.peer_state
            .iter()
            .filter(|(_, s)| s.tampered)
            .map(|(id, _)| *id)
            .collect()
    }

    /// This node's own binary hash.
    pub fn own_hash(&self) -> &BinaryHash {
        &self.own_hash
    }

    /// The cluster-agreed golden hash, if set.
    pub fn golden_hash(&self) -> Option<&BinaryHash> {
        self.golden_hash.as_ref()
    }
}

// ── Standalone helper ────────────────────────────────────────────────────────

/// Compute the SHA-512 hash of the running binary (/proc/self/exe).
pub fn compute_binary_hash() -> Result<BinaryHash, String> {
    let exe_path = std::fs::read_link("/proc/self/exe")
        .map_err(|e| format!("failed to resolve /proc/self/exe: {e}"))?;
    let data = std::fs::read(&exe_path)
        .map_err(|e| format!("failed to read binary at {}: {e}", exe_path.display()))?;
    let mut hasher = Sha512::new();
    hasher.update(&data);
    let result = hasher.finalize();
    let mut hash = [0u8; 64];
    hash.copy_from_slice(&result);
    Ok(hash)
}

// ── Wire messages ────────────────────────────────────────────────────────────

/// Message type for binary attestation exchange between nodes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AttestationMessage {
    /// "Here is my binary hash" -- sent periodically.
    HashReport { hash: BinaryHash, timestamp: i64 },
    /// "Your hash doesn't match -- you may be tampered" -- sent to suspect node.
    TamperAlert {
        expected: BinaryHash,
        received: BinaryHash,
    },
    /// "Send me a copy of the correct binary" -- healing request.
    HealRequest { requester: NodeId },
    /// "Here is the binary" -- healing response (chunked transfer).
    HealResponse {
        chunk_index: u32,
        total_chunks: u32,
        data: Vec<u8>,
        hash: BinaryHash,
    },
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn test_node(n: u8) -> NodeId {
        let mut bytes = [0u8; 16];
        bytes[15] = n;
        NodeId(Uuid::from_bytes(bytes))
    }

    fn make_hash(fill: u8) -> BinaryHash {
        [fill; 64]
    }

    #[test]
    fn mesh_with_hash_sets_own_hash() {
        let mesh = AttestationMesh::with_hash(AttestationMeshConfig::default(), make_hash(0xAA));
        assert_eq!(mesh.own_hash()[0], 0xAA);
        assert_eq!(mesh.own_hash().len(), 64);
    }

    #[test]
    fn golden_hash_initially_none() {
        let mesh = AttestationMesh::with_hash(AttestationMeshConfig::default(), make_hash(0x01));
        assert!(mesh.golden_hash().is_none());
    }

    #[test]
    fn set_golden_hash_works() {
        let mut mesh =
            AttestationMesh::with_hash(AttestationMeshConfig::default(), make_hash(0x01));
        mesh.set_golden_hash(make_hash(0x02));
        assert_eq!(mesh.golden_hash().unwrap(), &make_hash(0x02));
    }

    #[test]
    fn verify_matching_hash_returns_match() {
        let golden = make_hash(0xBB);
        let mut mesh =
            AttestationMesh::with_hash(AttestationMeshConfig::default(), make_hash(0x01));
        mesh.set_golden_hash(golden);

        let result = mesh.verify_peer_hash(test_node(1), golden);
        assert!(result.matches);
        assert!(!mesh.is_tampered(&test_node(1)));
    }

    #[test]
    fn verify_mismatched_hash_below_threshold_not_tampered() {
        let golden = make_hash(0xBB);
        let bad = make_hash(0xCC);
        let mut mesh =
            AttestationMesh::with_hash(AttestationMeshConfig::default(), make_hash(0x01));
        mesh.set_golden_hash(golden);

        // One mismatch (threshold is 2)
        let result = mesh.verify_peer_hash(test_node(1), bad);
        assert!(!result.matches);
        assert!(!mesh.is_tampered(&test_node(1)));
    }

    #[test]
    fn verify_mismatched_hash_at_threshold_marks_tampered() {
        let golden = make_hash(0xBB);
        let bad = make_hash(0xCC);
        let mut mesh =
            AttestationMesh::with_hash(AttestationMeshConfig::default(), make_hash(0x01));
        mesh.set_golden_hash(golden);

        // Two consecutive mismatches -> tampered
        mesh.verify_peer_hash(test_node(1), bad);
        mesh.verify_peer_hash(test_node(1), bad);
        assert!(mesh.is_tampered(&test_node(1)));
    }

    #[test]
    fn matching_hash_resets_mismatch_counter() {
        let golden = make_hash(0xBB);
        let bad = make_hash(0xCC);
        let mut mesh =
            AttestationMesh::with_hash(AttestationMeshConfig::default(), make_hash(0x01));
        mesh.set_golden_hash(golden);

        // One mismatch, then match -> counter resets
        mesh.verify_peer_hash(test_node(1), bad);
        mesh.verify_peer_hash(test_node(1), golden);

        // Another single mismatch should NOT trigger tampered
        mesh.verify_peer_hash(test_node(1), bad);
        assert!(!mesh.is_tampered(&test_node(1)));
    }

    #[test]
    fn tampered_nodes_returns_all_tampered() {
        let golden = make_hash(0xBB);
        let bad = make_hash(0xCC);
        let mut mesh =
            AttestationMesh::with_hash(AttestationMeshConfig::default(), make_hash(0x01));
        mesh.set_golden_hash(golden);

        // Tamper node 1
        mesh.verify_peer_hash(test_node(1), bad);
        mesh.verify_peer_hash(test_node(1), bad);

        // Node 2 is fine
        mesh.verify_peer_hash(test_node(2), golden);

        // Tamper node 3
        mesh.verify_peer_hash(test_node(3), bad);
        mesh.verify_peer_hash(test_node(3), bad);

        let tampered = mesh.tampered_nodes();
        assert_eq!(tampered.len(), 2);
        assert!(tampered.contains(&test_node(1)));
        assert!(tampered.contains(&test_node(3)));
    }

    #[test]
    fn unknown_node_not_tampered() {
        let mesh = AttestationMesh::with_hash(AttestationMeshConfig::default(), make_hash(0x01));
        assert!(!mesh.is_tampered(&test_node(99)));
    }

    #[test]
    fn without_golden_hash_uses_own_hash() {
        let own = make_hash(0xAA);
        let mut mesh = AttestationMesh::with_hash(AttestationMeshConfig::default(), own);

        let result = mesh.verify_peer_hash(test_node(1), own);
        assert!(result.matches);
    }

    #[test]
    fn custom_tamper_threshold() {
        let golden = make_hash(0xBB);
        let bad = make_hash(0xCC);
        let config = AttestationMeshConfig {
            tamper_threshold: 5,
            ..Default::default()
        };
        let mut mesh = AttestationMesh::with_hash(config, make_hash(0x01));
        mesh.set_golden_hash(golden);

        for _ in 0..4 {
            mesh.verify_peer_hash(test_node(1), bad);
        }
        assert!(!mesh.is_tampered(&test_node(1)));

        mesh.verify_peer_hash(test_node(1), bad);
        assert!(mesh.is_tampered(&test_node(1)));
    }

    #[test]
    fn attestation_result_has_correct_fields() {
        let golden = make_hash(0xBB);
        let reported = make_hash(0xCC);
        let mut mesh =
            AttestationMesh::with_hash(AttestationMeshConfig::default(), make_hash(0x01));
        mesh.set_golden_hash(golden);

        let result = mesh.verify_peer_hash(test_node(7), reported);
        assert_eq!(result.node_id, test_node(7));
        assert_eq!(result.reported_hash, reported);
        assert_eq!(result.expected_hash, golden);
        assert!(!result.matches);
        assert!(result.timestamp > 0);
    }

    #[test]
    fn attestation_message_serialize_roundtrip() {
        let msg = AttestationMessage::HashReport {
            hash: make_hash(0xAB),
            timestamp: 1234567890,
        };
        let bytes = postcard::to_allocvec(&msg).expect("serialize");
        let decoded: AttestationMessage = postcard::from_bytes(&bytes).expect("deserialize");
        match decoded {
            AttestationMessage::HashReport { hash, timestamp } => {
                assert_eq!(hash, make_hash(0xAB));
                assert_eq!(timestamp, 1234567890);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn attestation_message_tamper_alert_roundtrip() {
        let msg = AttestationMessage::TamperAlert {
            expected: make_hash(0x11),
            received: make_hash(0x22),
        };
        let bytes = postcard::to_allocvec(&msg).expect("serialize");
        let decoded: AttestationMessage = postcard::from_bytes(&bytes).expect("deserialize");
        match decoded {
            AttestationMessage::TamperAlert { expected, received } => {
                assert_eq!(expected, make_hash(0x11));
                assert_eq!(received, make_hash(0x22));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn attestation_message_heal_request_roundtrip() {
        let msg = AttestationMessage::HealRequest {
            requester: test_node(5),
        };
        let bytes = postcard::to_allocvec(&msg).expect("serialize");
        let decoded: AttestationMessage = postcard::from_bytes(&bytes).expect("deserialize");
        match decoded {
            AttestationMessage::HealRequest { requester } => {
                assert_eq!(requester, test_node(5));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn attestation_message_heal_response_roundtrip() {
        let msg = AttestationMessage::HealResponse {
            chunk_index: 3,
            total_chunks: 10,
            data: vec![0xDE, 0xAD, 0xBE, 0xEF],
            hash: make_hash(0xFF),
        };
        let bytes = postcard::to_allocvec(&msg).expect("serialize");
        let decoded: AttestationMessage = postcard::from_bytes(&bytes).expect("deserialize");
        match decoded {
            AttestationMessage::HealResponse {
                chunk_index,
                total_chunks,
                data,
                hash,
            } => {
                assert_eq!(chunk_index, 3);
                assert_eq!(total_chunks, 10);
                assert_eq!(data, vec![0xDE, 0xAD, 0xBE, 0xEF]);
                assert_eq!(hash, make_hash(0xFF));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn default_config_values() {
        let config = AttestationMeshConfig::default();
        assert_eq!(config.verify_interval, Duration::from_secs(30));
        assert_eq!(config.tamper_threshold, 2);
        assert!(config.golden_hash_path.is_none());
    }

    #[test]
    fn constant_time_comparison_rejects_single_bit_difference() {
        let golden = make_hash(0x00);
        let mut almost = make_hash(0x00);
        almost[63] = 0x01; // single bit flip in last byte

        let mut mesh =
            AttestationMesh::with_hash(AttestationMeshConfig::default(), make_hash(0x01));
        mesh.set_golden_hash(golden);

        let result = mesh.verify_peer_hash(test_node(1), almost);
        assert!(!result.matches);
    }
}
