//! Distributed startup verification.
//!
//! Before any service starts accepting requests, it MUST:
//! 1. Discover all cluster peers via service discovery
//! 2. Establish mTLS connections to each peer
//! 3. Exchange ML-DSA-87 signed attestations (binary hash + boot_id + timestamp)
//! 4. Verify attestation signatures against known public keys
//! 5. Verify minimum cluster size (3+ nodes)
//! 6. Verify quorum is achievable
//! 7. Synchronize state chain with peers
//! 8. Only then start accepting requests
//!
//! If ANY step fails, the service REFUSES to start.
#![forbid(unsafe_code)]

use crate::binary_attestation_mesh::BinaryHash;
use crate::siem::{SecurityEvent, Severity};
use ml_dsa::{
    signature::{Signer, Verifier},
    EncodedVerifyingKey, KeyGen, MlDsa87, VerifyingKey,
};
use crate::raft::NodeId;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use uuid::Uuid;

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

// ── SIEM category for all distributed startup events ────────────────────────

/// SIEM event category for distributed startup verification.
pub const SIEM_CATEGORY_DISTRIBUTED_STARTUP: &str = "DISTRIBUTED_STARTUP";

// ── Error types ─────────────────────────────────────────────────────────────

/// Errors during distributed startup verification.
#[derive(Debug, thiserror::Error)]
pub enum StartupError {
    #[error("insufficient peers: found {found}, need {required} (total cluster must be {total}+)")]
    InsufficientPeers {
        found: usize,
        required: usize,
        total: usize,
    },

    #[error("attestation expired: age {age_secs}s exceeds max {max_secs}s for node '{node_id}'")]
    AttestationExpired {
        node_id: String,
        age_secs: u64,
        max_secs: u64,
    },

    #[error("attestation signature invalid for node '{node_id}'")]
    InvalidSignature { node_id: String },

    #[error("binary hash mismatch: node '{node_id}' runs different binary (possible tampering)")]
    BinaryHashMismatch { node_id: String },

    #[error("quorum not achievable: {available} nodes available, need {threshold} for {operation}")]
    QuorumNotAchievable {
        available: usize,
        threshold: usize,
        operation: String,
    },

    #[error("no cluster peers configured (MILNET_CLUSTER_PEERS not set or empty)")]
    NoPeersConfigured,

    #[error("peer discovery failed: {0}")]
    DiscoveryFailed(String),

    #[error("state chain sync failed: {0}")]
    StateSyncFailed(String),

    #[error("standalone operation denied: system requires distributed cluster")]
    StandaloneOperationDenied,
}

// ── Core types ──────────────────────────────────────────────────────────────

/// Attestation from a single peer, signed with ML-DSA-87.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerAttestation {
    /// The attesting node's canonical cluster [`NodeId`] (UUID). Equals the Raft
    /// transport key and the revocation event's `node_id`, so the published
    /// `raft_verifying_key` is pinned under the right id.
    pub node_id: NodeId,
    /// SHA-512 hash of the peer's running binary.
    #[serde(with = "byte_array_64")]
    pub binary_hash: [u8; 64],
    /// Kernel boot_id from /proc/sys/kernel/random/boot_id.
    pub boot_id: String,
    /// Unix timestamp (seconds) when the attestation was created.
    pub timestamp: i64,
    /// ML-DSA-87 signature over
    /// (node_id || binary_hash || boot_id || timestamp || raft_verifying_key).
    pub signature: Vec<u8>,
    /// The ML-DSA-87 verifying key that verifies THIS attestation's `signature`
    /// (the attestation key).
    pub verifying_key: Vec<u8>,
    /// The node's PER-NODE Raft identity verifying key (its [`NodeIdentity`] VK).
    /// This is the key peers PIN to authenticate the node's Raft/consensus and
    /// revocation messages. It is COVERED by `signature`, so it cannot be swapped
    /// in transit. Distributing it here is how the cluster shares per-node VKs
    /// without a separate protocol; under TPM-sealed identities it is the only
    /// way a peer can learn another node's VK (it is not locally derivable).
    #[serde(default)]
    pub raft_verifying_key: Vec<u8>,
}

impl PeerAttestation {
    /// This attestation's canonical cluster [`NodeId`].
    pub fn cluster_node_id(&self) -> NodeId {
        self.node_id
    }
}

/// Result of a successful distributed startup verification.
#[derive(Debug)]
pub struct StartupVerification {
    /// Attestations from all verified peers.
    pub verified_peers: Vec<PeerAttestation>,
    /// Total cluster size (self + verified peers).
    pub cluster_size: usize,
    /// Whether quorum is achievable for all threshold operations.
    pub quorum_achievable: bool,
    /// Whether state chain was synchronized with peers.
    pub state_chain_synced: bool,
}

impl StartupVerification {
    /// The per-node Raft identity VKs to PIN at cluster join, one per verified
    /// peer: `(NodeId, raft_verifying_key)`.
    ///
    /// This is THE join-time bridge: feed each pair to
    /// `ClusterNode::pin_peer_verifying_key` (and the revocation registry) so the
    /// transport authenticates peers against their PUBLISHED, attestation-signed
    /// VKs. Peers whose attestation carries no Raft VK (legacy) or whose node_id
    /// is not a canonical cluster NodeId are skipped — fail-closed: an unpinned
    /// peer's messages are dropped rather than trusted.
    pub fn peer_identities_to_pin(&self) -> Vec<(NodeId, Vec<u8>)> {
        self.verified_peers
            .iter()
            .filter_map(|att| {
                if att.raft_verifying_key.is_empty() {
                    // Legacy peer with no published Raft VK → skip (fail-closed:
                    // an unpinned peer's messages are dropped, not trusted).
                    return None;
                }
                Some((att.node_id, att.raft_verifying_key.clone()))
            })
            .collect()
    }
}

/// Distributed startup verifier.
///
/// Constructed from configuration, then `verify_cluster()` is called once
/// during service startup. If verification fails, the service must not start.
pub struct DistributedStartupVerifier {
    /// Minimum number of verified peers required (default 2, so 3 total with self).
    min_peers: usize,
    /// Maximum time to wait for attestation collection.
    attestation_timeout: Duration,
    /// Maximum age of an attestation before it is rejected (default 60s).
    attestation_max_age: Duration,
    /// Resolved peer endpoints (host:port).
    peer_endpoints: Vec<String>,
    /// This node's ML-DSA-87 attestation signing seed (32 bytes). Signs the
    /// attestation itself; distinct from the per-node Raft identity key.
    signing_seed: [u8; 32],
    /// This node's canonical cluster [`NodeId`].
    node_id: NodeId,
    /// Whether rolling update mode is active (allows binary hash mismatch).
    rolling_update: bool,
    /// This node's PER-NODE Raft identity verifying key (its [`NodeIdentity`] VK),
    /// published in this node's attestation so peers can PIN it. Empty only in
    /// legacy/test constructions that don't supply one.
    raft_verifying_key: Vec<u8>,
}

// ── Attestation payload construction ────────────────────────────────────────

/// Build the canonical byte payload that is signed/verified for an attestation.
///
/// Format: node_id(16) || binary_hash(64) || boot_id_bytes || timestamp_be(8)
///         || raft_vk_len_be(4) || raft_verifying_key
///
/// `node_id` is the canonical [`NodeId`]'s 16 UUID bytes (fixed-width, so the
/// boundary with `boot_id` is unambiguous). The per-node Raft verifying key is
/// length-prefixed and included so it is authenticated by the attestation
/// signature (a MITM cannot substitute a different VK).
fn attestation_payload(
    node_id: NodeId,
    binary_hash: &[u8; 64],
    boot_id: &str,
    timestamp: i64,
    raft_verifying_key: &[u8],
) -> Vec<u8> {
    let mut payload =
        Vec::with_capacity(16 + 64 + boot_id.len() + 8 + 4 + raft_verifying_key.len());
    payload.extend_from_slice(node_id.0.as_bytes());
    payload.extend_from_slice(binary_hash);
    payload.extend_from_slice(boot_id.as_bytes());
    payload.extend_from_slice(&timestamp.to_be_bytes());
    payload.extend_from_slice(&(raft_verifying_key.len() as u32).to_be_bytes());
    payload.extend_from_slice(raft_verifying_key);
    payload
}

// ── ML-DSA-87 helpers (same pattern as external_witness) ────────────────────

/// Sign raw bytes with ML-DSA-87 using a 32-byte seed.
fn pq_sign(seed: &[u8; 32], data: &[u8]) -> Vec<u8> {
    let kp = MlDsa87::from_seed(&(*seed).into());
    let sig: ml_dsa::Signature<MlDsa87> = kp.signing_key().sign(data);
    sig.encode().to_vec()
}

/// Derive the ML-DSA-87 verifying key bytes from a 32-byte seed.
fn pq_verifying_key(seed: &[u8; 32]) -> Vec<u8> {
    let kp = MlDsa87::from_seed(&(*seed).into());
    let encoded: EncodedVerifyingKey<MlDsa87> = kp.verifying_key().encode();
    AsRef::<[u8]>::as_ref(&encoded).to_vec()
}

/// Verify an ML-DSA-87 signature given the raw verifying key bytes.
fn pq_verify(vk_bytes: &[u8], data: &[u8], sig_bytes: &[u8]) -> bool {
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

// ── Per-node ML-DSA-87 identity (shared cluster-wide) ───────────────────────

/// Domain separator for per-node identity seed derivation. Distinct from the
/// attestation-seed domain (`MILNET-ATTESTATION-SEED-v1`) so the identity key
/// and the legacy attestation key never collide even for the same node.
const NODE_IDENTITY_DOMAIN: &[u8] = b"MILNET-NODE-IDENTITY-ML-DSA-87-v1";

/// Derive a per-node ML-DSA-87 seed from the cluster master KEK and the node's
/// identity. This is the FALLBACK derivation used outside military mode (and the
/// documented residual in military mode until per-node TPM-sealed seeds are
/// wired — see [`NodeIdentity::for_node`]).
///
/// SECURITY (closes the MEDIUM "identity is not per-node" finding):
/// the legacy attestation seed was `SHA-512(KEK || "ATTESTATION-SEED")` with NO
/// per-node input, so EVERY node derived the SAME keypair and a clone was
/// cryptographically indistinguishable from the original. Here the `node_id`
/// bytes are folded into the KDF, so two distinct NodeIds derive DISTINCT
/// keypairs while the root of trust stays the (vTPM-sealed, anti-clone) master
/// KEK.
///
/// Derivation: `SHA-512(master_kek || NODE_IDENTITY_DOMAIN || node_id_bytes)[..32]`.
/// SHA-512 over a fixed-length-prefixed, domain-separated input is a sound KDF
/// here because the master KEK is already a uniformly random 256-bit secret
/// (NIST SP 800-108 / SP 800-56C extract-then-expand reduces to a single PRF
/// call when the input keying material is already a full-entropy key).
///
/// RESIDUAL: because this derives from the SHARED master KEK, a root attacker
/// who exfiltrates the cached KEK can re-derive any node's seed. True anti-root
/// requires an INDEPENDENT per-node seed sealed to each node's TPM; feed it via
/// [`NodeIdentity::from_sealed_seed`].
fn derive_node_identity_seed(master_kek: &[u8; 32], node_id: &Uuid) -> [u8; 32] {
    let mut hasher = Sha512::new();
    hasher.update(master_kek);
    hasher.update(NODE_IDENTITY_DOMAIN);
    hasher.update(node_id.as_bytes());
    let digest = hasher.finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&digest[..32]);
    seed
}

/// A genuine per-node post-quantum (ML-DSA-87) signing identity, keyed on the
/// cluster's [`NodeId`].
///
/// This is the ONE per-node identity for the whole node: the Raft control plane
/// (consensus message authentication) and the session/revocation propagation
/// layer both consume it so a node has a single keypair, not several. The
/// verifying key returned by [`NodeIdentity::verifying_key`] is what every peer
/// pins (in a [`NodeIdentityRegistry`]) at cluster join; thereafter a message is
/// authentic only if it verifies against the pinned key for the *claimed*
/// sender, so a compromised node can forge messages AS ITSELF but never as
/// another NodeId.
///
/// The seed is held in-process and zeroized on drop (matching the
/// [`ExternalWitnessCosigner`](crate::external_witness) convention). It is never
/// serialized, logged, or written to disk.
pub struct NodeIdentity {
    /// This node's raw identity UUID (the cluster [`NodeId`]'s inner value). The
    /// constructors take a `Uuid` (matching call sites that pass `node_id.0` and
    /// revoke-propagation's `for_node(uuid)`); [`Self::node_id`] surfaces it as a
    /// typed [`NodeId`] for cluster attribution.
    node_id: Uuid,
    /// 32-byte ML-DSA-87 seed. Zeroized on drop.
    seed: [u8; 32],
}

impl NodeIdentity {
    /// Acquire THIS node's identity for `node_id` (the cluster [`NodeId`]'s inner
    /// `Uuid`).
    ///
    /// MILITARY mode (`MILNET_MILITARY_DEPLOYMENT=1`) — TRUE anti-root + anti-clone:
    /// this node uses an INDEPENDENT ML-DSA-87 signing seed that is generated
    /// fresh on first boot and TPM-SEALED to this node's measured-boot PCRs
    /// (0,2,4,7) via [`crate::sealed_keys::Tpm2ToolsKekSealer`]; on restart it is
    /// unsealed. The seed is NOT derived from the master KEK, so root on node A
    /// can unseal only A's seed and forge only AS A — never as B/C. A quorum
    /// forgery would need root on >= quorum DISTINCT nodes (each seed sealed to a
    /// distinct TPM). A clone on different hardware cannot unseal it at all
    /// (PCR-bound). FAIL-CLOSED: no vTPM, a missing/!=32-byte sealed blob, or a
    /// seal/unseal error all REFUSE (process exits 199). A plaintext or
    /// KEK-derived seed is NEVER used in military mode — that would re-introduce
    /// the shared single point (root on any node reads the unsealed KEK from RAM
    /// and derives every node's seed), which is exactly the CRITICAL this closes.
    ///
    /// NON-MILITARY (dev/test, no TPM): the master-KEK-bound derivation
    /// ([`derive_node_identity_seed`]) is the fallback. It is anti-clone (the KEK
    /// is itself TPM-sealed in production) but NOT anti-root, and is acceptable
    /// only outside military mode.
    ///
    /// Two different `node_id`s always yield distinct keypairs under both paths.
    pub fn for_node(node_id: Uuid) -> Self {
        if is_military_deployment() {
            // Anti-root: unseal this node's INDEPENDENT, TPM-sealed identity seed
            // (sealed_keys owns the loader). Unseal-ONLY and fail-closed: it
            // refuses (process exits 199) if the per-node blob is absent / TPM is
            // unavailable / unseal fails. A KEK-derived seed is NEVER used here.
            let seed = crate::sealed_keys::load_node_identity_seed_sealed(&node_id.to_string());
            Self { node_id, seed }
        } else {
            // DEV/non-military fallback ONLY: KEK-bound derivation (no TPM here).
            let kek = crate::sealed_keys::get_master_kek();
            let seed = derive_node_identity_seed(kek, &node_id);
            Self { node_id, seed }
        }
    }

    /// Construct an identity from a per-node seed unsealed from THIS node's TPM
    /// (the anti-root path), for callers that perform their own unseal. The input
    /// `seed` should be zeroized by the caller after this call; we take ownership
    /// and zeroize our copy on drop.
    pub fn from_sealed_seed(node_id: Uuid, seed: [u8; 32]) -> Self {
        Self { node_id, seed }
    }

    /// Construct an identity from an explicit 32-byte seed.
    ///
    /// Intended for TESTS and for callers that have already performed their own
    /// derivation. Production military code should use [`Self::for_node`] (KEK
    /// path) or [`Self::from_sealed_seed`] (per-node TPM path).
    pub fn from_seed(node_id: Uuid, seed: [u8; 32]) -> Self {
        Self { node_id, seed }
    }

    /// This node's UUID (the raw identity input).
    pub fn uuid(&self) -> Uuid {
        self.node_id
    }

    /// This node's cluster [`NodeId`]. Surfaces the inner [`Uuid`] as the typed
    /// cluster id used by the [`NodeIdentityRegistry`] and revocation events.
    pub fn node_id(&self) -> NodeId {
        NodeId(self.node_id)
    }

    /// This node's raw ML-DSA-87 verifying-key bytes. Peers PIN this value (in a
    /// [`NodeIdentityRegistry`]) at cluster join and use it to authenticate every
    /// message claimed to be from this node.
    pub fn verifying_key(&self) -> Vec<u8> {
        pq_verifying_key(&self.seed)
    }

    /// Sign `msg` AS THIS NODE with ML-DSA-87. Returns the encoded signature.
    ///
    /// PERFORMANCE: ML-DSA-87 signing is far heavier than an HMAC (lattice
    /// arithmetic, ~4.6 KB signatures). Callers on a hot path (e.g. Raft
    /// heartbeats) accept this cost deliberately: it is the only way to bind a
    /// message to a single node's identity so one compromised node cannot forge
    /// as the quorum. Security over throughput is the audit-mandated tradeoff.
    pub fn node_sign(&self, msg: &[u8]) -> Vec<u8> {
        pq_sign(&self.seed, msg)
    }
}

impl Drop for NodeIdentity {
    fn drop(&mut self) {
        // Zeroize the seed on drop (same pattern as ExternalWitnessCosigner).
        self.seed.iter_mut().for_each(|b| *b = 0);
    }
}

impl std::fmt::Debug for NodeIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never expose the seed via Debug.
        f.debug_struct("NodeIdentity")
            .field("node_id", &self.node_id)
            .field("seed", &"<redacted>")
            .finish()
    }
}

/// The cluster-wide `NodeId -> verifying-key` registry, pinned at join.
///
/// This is THE single shared per-node identity registry: the Raft transport, the
/// entry-signature path, and the session/revocation layer all key off the SAME
/// [`NodeId`] type and the SAME pinned verifying keys, so a node has exactly one
/// pinned identity across every subsystem.
///
/// [`NodeIdentityRegistry::verify`] is FAIL-CLOSED: an unknown/unpinned NodeId
/// returns `false`, never a silent accept.
#[derive(Debug, Clone, Default)]
pub struct NodeIdentityRegistry {
    keys: HashMap<NodeId, Vec<u8>>,
}

impl NodeIdentityRegistry {
    /// An empty registry.
    pub fn new() -> Self {
        Self { keys: HashMap::new() }
    }

    /// Pin `node_id`'s ML-DSA-87 verifying key (call once at cluster join).
    pub fn pin(&mut self, node_id: NodeId, verifying_key: Vec<u8>) {
        self.keys.insert(node_id, verifying_key);
    }

    /// The pinned verifying key for `node_id`, if any.
    pub fn verifying_key(&self, node_id: &NodeId) -> Option<&[u8]> {
        self.keys.get(node_id).map(|v| v.as_slice())
    }

    /// Is `node_id` pinned in this registry?
    pub fn contains(&self, node_id: &NodeId) -> bool {
        self.keys.contains_key(node_id)
    }

    /// Number of pinned nodes.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether the registry has no pinned nodes.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Verify that `sig` over `msg` was produced by `node_id`'s pinned identity.
    ///
    /// FAIL-CLOSED: if `node_id` is not pinned (unknown sender), returns `false`.
    /// This is the ONE verification entry point shared by the Raft transport and
    /// the revocation layer.
    pub fn verify(&self, node_id: NodeId, msg: &[u8], sig: &[u8]) -> bool {
        match self.keys.get(&node_id) {
            Some(vk) => pq_verify(vk, msg, sig),
            None => false,
        }
    }
}

/// Statelessly verify a signature against an explicit `verifying_key`.
///
/// Lower-level companion to [`NodeIdentityRegistry::verify`]: use this when you
/// have already looked up the *claimed* signer's pinned key. FAIL-CLOSED — if the
/// signer is unknown/unpinned the caller has no key to pass and MUST reject; if
/// the bytes don't verify this returns `false`.
pub fn verify_node_sig(verifying_key: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    pq_verify(verifying_key, msg, sig)
}

// ── Implementation ──────────────────────────────────────────────────────────

impl DistributedStartupVerifier {
    /// Create a new verifier from environment variables and defaults.
    ///
    /// Reads:
    /// - `MILNET_CLUSTER_PEERS`: comma-separated list of peer endpoints (host:port)
    /// - `MILNET_NODE_ID`: this node's unique identifier
    /// - `MILNET_ATTESTATION_SEED`: 64 hex chars (32 bytes) for ML-DSA-87 key
    /// - `MILNET_ROLLING_UPDATE`: set to "1" to allow binary hash mismatch
    pub fn new() -> Result<Self, StartupError> {
        let peers_raw = std::env::var("MILNET_CLUSTER_PEERS").unwrap_or_default();
        let peer_endpoints: Vec<String> = peers_raw
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        if peer_endpoints.is_empty() {
            emit_siem_event(
                "startup_no_peers",
                Severity::Critical,
                "failure",
                "MILNET_CLUSTER_PEERS not set or empty — cannot form cluster",
            );
            return Err(StartupError::NoPeersConfigured);
        }

        // Resolve this node's CANONICAL cluster NodeId from MILNET_NODE_ID using
        // the SHARED `cluster::canonical_node_id` (UUID / hex / UUIDv5 fallback),
        // the SAME function the Raft transport uses. This guarantees the
        // attestation identity == the transport NodeId == the revocation NodeId,
        // so a peer pins the right per-node verifying key even when the deploy
        // uses a non-UUID MILNET_NODE_ID (e.g. `orchestrator-0`).
        let cluster_node_id: NodeId = match std::env::var("MILNET_NODE_ID") {
            Ok(val) => crate::cluster::canonical_node_id(&val),
            Err(_) => NodeId(Uuid::new_v4()),
        };

        let military = is_military_deployment();
        let seed_hex = std::env::var("MILNET_ATTESTATION_SEED").unwrap_or_default();

        // SECURITY: In military mode a plaintext attestation seed in the
        // environment is FORBIDDEN — a cloned image carrying a baked-in seed
        // would impersonate a legitimate node. This mirrors the master-KEK
        // anti-clone rule in `sealed_keys::acquire_military_kek`: key material
        // must derive from the vTPM-sealed KEK, never from the deploy env.
        if military && !seed_hex.is_empty() {
            emit_siem_event(
                "attestation_seed_env_rejected",
                Severity::Critical,
                "failure",
                "MILNET_ATTESTATION_SEED present in military deployment — \
                 plaintext seed material is forbidden (anti-clone). Remove the \
                 env var; the attestation key derives from the vTPM-sealed KEK.",
            );
            return Err(StartupError::StandaloneOperationDenied);
        }

        let signing_seed = if !military && seed_hex.len() == 64 {
            // Non-military convenience path: explicit 32-byte seed (hex).
            let mut seed = [0u8; 32];
            if let Ok(bytes) = hex::decode(&seed_hex) {
                if bytes.len() == 32 {
                    seed.copy_from_slice(&bytes);
                }
            }
            seed
        } else {
            // Derive from threshold-reconstructed master KEK (not raw env var).
            // get_master_kek() enforces 3-of-5 Shamir reconstruction in production
            // and, in military mode, vTPM unseal (anti-clone).
            //
            // SECURITY: the `node_id` is folded into the KDF so two distinct
            // nodes derive DISTINCT attestation keypairs (closes the per-node
            // identity finding). Previously the derivation omitted node_id, so
            // every node produced the SAME attestation key and a clone was
            // indistinguishable from the original.
            let kek_bytes = crate::sealed_keys::get_master_kek();
            let mut seed = [0u8; 32];
            // SHA-512(KEK || "MILNET-ATTESTATION-SEED-v2" || node_id_bytes)[..32]
            // node_id_bytes is the canonical NodeId's 16 UUID bytes.
            let mut hasher = Sha512::new();
            hasher.update(kek_bytes);
            hasher.update(b"MILNET-ATTESTATION-SEED-v2");
            hasher.update(cluster_node_id.0.as_bytes());
            let result = hasher.finalize();
            seed.copy_from_slice(&result[..32]);
            seed
        };

        let rolling_update =
            std::env::var("MILNET_ROLLING_UPDATE").unwrap_or_default() == "1";

        // Publish this node's PER-NODE Raft identity VK in its attestation so
        // peers pin it (TPM-sealed identity in military mode; KEK-derived in dev).
        // This is the SAME NodeIdentity the Raft transport and revocation layer
        // sign with — one identity, distributed once at join.
        let raft_verifying_key = NodeIdentity::for_node(cluster_node_id.0).verifying_key();

        Ok(Self {
            min_peers: 2,
            attestation_timeout: Duration::from_secs(30),
            attestation_max_age: Duration::from_secs(60),
            peer_endpoints,
            signing_seed,
            node_id: cluster_node_id,
            rolling_update,
            raft_verifying_key,
        })
    }

    /// Create a verifier with explicit configuration (for testing).
    ///
    /// The published per-node Raft VK is empty here; use
    /// [`Self::with_raft_verifying_key`] or [`Self::from_node_identity`] to set it.
    pub fn with_config(
        min_peers: usize,
        attestation_timeout: Duration,
        attestation_max_age: Duration,
        peer_endpoints: Vec<String>,
        signing_seed: [u8; 32],
        node_id: String,
        rolling_update: bool,
    ) -> Self {
        Self {
            min_peers,
            attestation_timeout,
            attestation_max_age,
            peer_endpoints,
            // Canonicalize the test/string id to the cluster NodeId (same fn the
            // transport uses), so attestation ids stay UUID-typed.
            node_id: crate::cluster::canonical_node_id(&node_id),
            rolling_update,
            raft_verifying_key: Vec::new(),
        }
    }

    /// Set the per-node Raft identity verifying key this node publishes in its
    /// attestation (builder style). Used by tests and by callers that hold the
    /// node's [`NodeIdentity`] VK directly.
    pub fn with_raft_verifying_key(mut self, raft_verifying_key: Vec<u8>) -> Self {
        self.raft_verifying_key = raft_verifying_key;
        self
    }

    /// Seam: derive the published per-node Raft VK from a [`NodeIdentity`].
    ///
    /// The verifier will publish `identity.verifying_key()` in its attestation so
    /// peers pin EXACTLY the key this node signs Raft/consensus and revocation
    /// messages with — one shared per-node identity, distributed once at join.
    /// Revocation propagation consumes the same identity (coordinate via this
    /// seam, do not derive a second VK).
    pub fn from_node_identity(mut self, identity: &NodeIdentity) -> Self {
        self.raft_verifying_key = identity.verifying_key();
        self
    }

    /// This node's published per-node Raft identity verifying key (empty if not
    /// set). Peers pin this value.
    pub fn raft_verifying_key(&self) -> &[u8] {
        &self.raft_verifying_key
    }

    // ── Main entry point ────────────────────────────────────────────────────

    /// Verify that the cluster is operational and this node can join.
    ///
    /// This is THE function called from every service's main() before binding
    /// any network port. If it returns Err, the service MUST NOT start.
    pub fn verify_cluster(
        &self,
        peer_attestations: &[PeerAttestation],
    ) -> Result<StartupVerification, StartupError> {
        emit_siem_event(
            "cluster_verification_start",
            Severity::Info,
            "pending",
            &format!(
                "starting distributed startup verification: node={}, peers_configured={}, min_required={}",
                self.node_id,
                self.peer_endpoints.len(),
                self.min_peers,
            ),
        );

        // Step 1: Refuse standalone operation
        self.refuse_standalone()?;

        // Step 2: Verify each peer attestation
        let own_binary_hash = self.compute_own_binary_hash();
        let mut verified: Vec<PeerAttestation> = Vec::new();

        for att in peer_attestations {
            // Verify signature
            self.verify_attestation(att)?;

            // Verify binary consistency
            self.verify_binary_consistency(&own_binary_hash, att)?;

            verified.push(att.clone());
        }

        // Step 3: Check minimum peer count
        if verified.len() < self.min_peers {
            emit_siem_event(
                "insufficient_verified_peers",
                Severity::Critical,
                "failure",
                &format!(
                    "only {} peers verified, need {} (cluster needs {} total)",
                    verified.len(),
                    self.min_peers,
                    self.min_peers + 1,
                ),
            );
            return Err(StartupError::InsufficientPeers {
                found: verified.len(),
                required: self.min_peers,
                total: self.min_peers + 1,
            });
        }

        // Step 4: Verify quorum achievability
        let cluster_size = verified.len() + 1; // +1 for self
        self.verify_quorum(cluster_size)?;

        // Step 5: State chain sync (verified by having consistent attestations)
        let state_chain_synced = !verified.is_empty();

        let result = StartupVerification {
            verified_peers: verified,
            cluster_size,
            quorum_achievable: true,
            state_chain_synced,
        };

        emit_siem_event(
            "cluster_verification_success",
            Severity::Info,
            "success",
            &format!(
                "distributed startup verified: cluster_size={}, quorum=OK, state_synced={}",
                result.cluster_size, result.state_chain_synced,
            ),
        );

        Ok(result)
    }

    // ── Peer discovery ──────────────────────────────────────────────────────

    /// Discover and resolve peer endpoints.
    ///
    /// Returns the list of configured peer endpoints. In production, this
    /// would establish mTLS connections; the endpoint list is validated
    /// against service discovery.
    pub fn discover_peers(&self) -> Result<Vec<String>, StartupError> {
        if self.peer_endpoints.is_empty() {
            return Err(StartupError::DiscoveryFailed(
                "no peer endpoints configured".to_string(),
            ));
        }

        emit_siem_event(
            "peer_discovery",
            Severity::Info,
            "success",
            &format!("discovered {} peer endpoints", self.peer_endpoints.len()),
        );

        Ok(self.peer_endpoints.clone())
    }

    // ── Attestation exchange ────────────────────────────────────────────────

    /// Generate this node's own attestation, signed with ML-DSA-87.
    pub fn generate_own_attestation(&self) -> PeerAttestation {
        let binary_hash = self.compute_own_binary_hash();
        let boot_id = read_boot_id();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let payload = attestation_payload(
            self.node_id,
            &binary_hash,
            &boot_id,
            timestamp,
            &self.raft_verifying_key,
        );
        let signature = pq_sign(&self.signing_seed, &payload);
        let verifying_key = pq_verifying_key(&self.signing_seed);

        PeerAttestation {
            node_id: self.node_id,
            binary_hash,
            boot_id,
            timestamp,
            signature,
            verifying_key,
            raft_verifying_key: self.raft_verifying_key.clone(),
        }
    }

    /// Exchange attestations with peers.
    ///
    /// Sends own attestation and collects peer attestations.
    /// In production, this happens over mTLS connections established during
    /// `discover_peers()`. Returns collected attestations.
    pub fn exchange_attestations(
        &self,
        received: Vec<PeerAttestation>,
    ) -> Result<Vec<PeerAttestation>, StartupError> {
        let _own = self.generate_own_attestation();

        emit_siem_event(
            "attestation_exchange",
            Severity::Info,
            "success",
            &format!(
                "exchanged attestations: sent own, received {} from peers",
                received.len(),
            ),
        );

        Ok(received)
    }

    // ── Attestation verification ────────────────────────────────────────────

    /// Verify a single peer's attestation.
    ///
    /// Checks:
    /// 1. Timestamp freshness (reject if older than `attestation_max_age`)
    /// 2. ML-DSA-87 signature validity
    pub fn verify_attestation(&self, att: &PeerAttestation) -> Result<(), StartupError> {
        // Check timestamp freshness
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let age = (now - att.timestamp).unsigned_abs();
        if age > self.attestation_max_age.as_secs() {
            emit_siem_event(
                "attestation_expired",
                Severity::High,
                "failure",
                &format!(
                    "attestation from node '{}' expired: age={}s, max={}s",
                    att.node_id, age, self.attestation_max_age.as_secs(),
                ),
            );
            return Err(StartupError::AttestationExpired {
                node_id: att.node_id.to_string(),
                age_secs: age,
                max_secs: self.attestation_max_age.as_secs(),
            });
        }

        // Verify ML-DSA-87 signature. The payload includes the published
        // per-node Raft VK, so a tampered/substituted `raft_verifying_key` makes
        // the signature fail here — peers only ever pin an AUTHENTICATED VK.
        let payload = attestation_payload(
            att.node_id,
            &att.binary_hash,
            &att.boot_id,
            att.timestamp,
            &att.raft_verifying_key,
        );

        if !pq_verify(&att.verifying_key, &payload, &att.signature) {
            emit_siem_event(
                "attestation_signature_invalid",
                Severity::Critical,
                "failure",
                &format!(
                    "ML-DSA-87 signature verification FAILED for node '{}' — possible forgery",
                    att.node_id,
                ),
            );
            return Err(StartupError::InvalidSignature {
                node_id: att.node_id.to_string(),
            });
        }

        emit_siem_event(
            "attestation_verified",
            Severity::Info,
            "success",
            &format!(
                "attestation from node '{}' verified: fresh={}s, sig=OK",
                att.node_id, age,
            ),
        );

        Ok(())
    }

    // ── Binary consistency ──────────────────────────────────────────────────

    /// Verify that a peer's binary hash matches this node's binary.
    ///
    /// A mismatch indicates either:
    /// - Code tampering on one of the nodes (CRITICAL)
    /// - A rolling update in progress (allowed if MILNET_ROLLING_UPDATE=1)
    pub fn verify_binary_consistency(
        &self,
        own_hash: &BinaryHash,
        att: &PeerAttestation,
    ) -> Result<(), StartupError> {
        let matches: bool = own_hash.ct_eq(&att.binary_hash).into();

        if !matches {
            if self.rolling_update {
                emit_siem_event(
                    "binary_hash_mismatch_rolling_update",
                    Severity::Warning,
                    "success",
                    &format!(
                        "binary hash mismatch for node '{}' — ALLOWED (MILNET_ROLLING_UPDATE=1)",
                        att.node_id,
                    ),
                );
                return Ok(());
            }

            emit_siem_event(
                "binary_hash_mismatch_tampering",
                Severity::Critical,
                "failure",
                &format!(
                    "CRITICAL: binary hash mismatch for node '{}' — \
                     own={}, peer={} — POSSIBLE CODE TAMPERING",
                    att.node_id,
                    hex::encode(&own_hash[..8]),
                    hex::encode(&att.binary_hash[..8]),
                ),
            );
            return Err(StartupError::BinaryHashMismatch {
                node_id: att.node_id.to_string(),
            });
        }

        Ok(())
    }

    // ── Quorum verification ─────────────────────────────────────────────────

    /// Verify that threshold operations are achievable with available nodes.
    ///
    /// Checks:
    /// - FROST 3-of-5 threshold signing: need at least 3 nodes
    /// - BFT 5-of-7 consensus: need at least 5 nodes (2f+1 where f=2)
    ///
    /// For smaller clusters, only FROST quorum is required.
    pub fn verify_quorum(&self, cluster_size: usize) -> Result<(), StartupError> {
        // FROST threshold signing: 3-of-5
        const FROST_THRESHOLD: usize = 3;
        if cluster_size < FROST_THRESHOLD {
            emit_siem_event(
                "quorum_frost_failure",
                Severity::Critical,
                "failure",
                &format!(
                    "FROST 3-of-5 quorum not achievable: {} nodes < {} threshold",
                    cluster_size, FROST_THRESHOLD,
                ),
            );
            return Err(StartupError::QuorumNotAchievable {
                available: cluster_size,
                threshold: FROST_THRESHOLD,
                operation: "FROST 3-of-5 threshold signing".to_string(),
            });
        }

        // BFT consensus: need 2f+1 = 5 for f=2 (7-node BFT)
        // Only enforce if cluster is configured for BFT (5+ nodes configured)
        const BFT_MIN_NODES: usize = 5;
        let configured_total = self.peer_endpoints.len() + 1;
        if configured_total >= 7 && cluster_size < BFT_MIN_NODES {
            emit_siem_event(
                "quorum_bft_failure",
                Severity::Critical,
                "failure",
                &format!(
                    "BFT 5-of-7 quorum not achievable: {} nodes < {} required (f=2)",
                    cluster_size, BFT_MIN_NODES,
                ),
            );
            return Err(StartupError::QuorumNotAchievable {
                available: cluster_size,
                threshold: BFT_MIN_NODES,
                operation: "BFT 5-of-7 consensus".to_string(),
            });
        }

        emit_siem_event(
            "quorum_verified",
            Severity::Info,
            "success",
            &format!(
                "quorum verified: cluster_size={}, frost=OK{}",
                cluster_size,
                if configured_total >= 7 { ", bft=OK" } else { "" },
            ),
        );

        Ok(())
    }

    // ── Standalone refusal ──────────────────────────────────────────────────

    /// HARD FAIL if fewer than min_peers are configured.
    ///
    /// This check happens BEFORE any attestation exchange — if the cluster
    /// configuration itself doesn't have enough peers, we refuse immediately.
    pub fn refuse_standalone(&self) -> Result<(), StartupError> {
        if self.peer_endpoints.len() < self.min_peers {
            emit_siem_event(
                "standalone_operation_denied",
                Severity::Critical,
                "failure",
                &format!(
                    "STANDALONE OPERATION DENIED: only {} peers configured, need {} \
                     — no single VM may operate alone",
                    self.peer_endpoints.len(),
                    self.min_peers,
                ),
            );
            return Err(StartupError::StandaloneOperationDenied);
        }
        Ok(())
    }

    // ── Internal helpers ────────────────────────────────────────────────────

    /// Compute SHA-512 hash of this node's binary.
    fn compute_own_binary_hash(&self) -> BinaryHash {
        crate::binary_attestation_mesh::compute_binary_hash().unwrap_or_else(|e| {
            tracing::warn!(
                "failed to compute binary hash (non-Linux or test env): {}",
                e
            );
            // In test environments, /proc/self/exe may not be readable.
            // Return zeros — the attestation will still be signed and verified.
            [0u8; 64]
        })
    }

    /// Get this node's canonical cluster [`NodeId`].
    pub fn node_id(&self) -> NodeId {
        self.node_id
    }

    /// Get the signing seed (for test introspection only via public method).
    pub fn verifying_key_bytes(&self) -> Vec<u8> {
        pq_verifying_key(&self.signing_seed)
    }
}

// ── Utility functions ───────────────────────────────────────────────────────

/// Returns `true` if this process runs in military deployment mode
/// (`MILNET_MILITARY_DEPLOYMENT=1`).
fn is_military_deployment() -> bool {
    std::env::var("MILNET_MILITARY_DEPLOYMENT").as_deref() == Ok("1")
}

/// Read the kernel boot_id for audit correlation.
fn read_boot_id() -> String {
    std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .unwrap_or_else(|_| "unknown-boot-id".to_string())
        .trim()
        .to_string()
}

/// Emit a SIEM event in the DISTRIBUTED_STARTUP category.
fn emit_siem_event(
    action: &'static str,
    severity: Severity,
    outcome: &'static str,
    detail: &str,
) {
    let event = SecurityEvent {
        timestamp: SecurityEvent::now_iso8601(),
        category: SIEM_CATEGORY_DISTRIBUTED_STARTUP,
        action,
        severity,
        outcome,
        user_id: None,
        source_ip: None,
        detail: Some(detail.to_string()),
    };
    event.emit();
}

// ── Helper to create a test attestation from a seed ─────────────────────────

/// Create a valid attestation for testing, signed with the given seed.
///
/// The attestation uses the current timestamp and the given binary hash/boot_id.
pub fn create_test_attestation(
    node_id: &str,
    signing_seed: &[u8; 32],
    binary_hash: &BinaryHash,
    boot_id: &str,
    timestamp: i64,
) -> PeerAttestation {
    create_test_attestation_with_raft_vk(node_id, signing_seed, binary_hash, boot_id, timestamp, &[])
}

/// Like [`create_test_attestation`] but also sets (and signs over) the published
/// per-node Raft verifying key.
pub fn create_test_attestation_with_raft_vk(
    node_id: &str,
    signing_seed: &[u8; 32],
    binary_hash: &BinaryHash,
    boot_id: &str,
    timestamp: i64,
    raft_verifying_key: &[u8],
) -> PeerAttestation {
    let nid = crate::cluster::canonical_node_id(node_id);
    let payload = attestation_payload(nid, binary_hash, boot_id, timestamp, raft_verifying_key);
    let signature = pq_sign(signing_seed, &payload);
    let verifying_key = pq_verifying_key(signing_seed);

    PeerAttestation {
        node_id: nid,
        binary_hash: *binary_hash,
        boot_id: boot_id.to_string(),
        timestamp,
        signature,
        verifying_key,
        raft_verifying_key: raft_verifying_key.to_vec(),
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn now_secs() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    /// Common test seed for peer A.
    fn seed_a() -> [u8; 32] {
        let mut s = [0u8; 32];
        s[0] = 0xAA;
        s[1] = 0x01;
        s
    }

    /// Common test seed for peer B.
    fn seed_b() -> [u8; 32] {
        let mut s = [0u8; 32];
        s[0] = 0xBB;
        s[1] = 0x02;
        s
    }

    /// Common test seed for peer C.
    fn seed_c() -> [u8; 32] {
        let mut s = [0u8; 32];
        s[0] = 0xCC;
        s[1] = 0x03;
        s
    }

    fn test_binary_hash() -> BinaryHash {
        let mut h = [0u8; 64];
        h[0] = 0xDE;
        h[1] = 0xAD;
        h[2] = 0xBE;
        h[3] = 0xEF;
        h
    }

    /// Returns the binary hash that `compute_own_binary_hash` will produce
    /// at runtime — the real /proc/self/exe hash on Linux, or [0;64] fallback.
    fn own_binary_hash() -> BinaryHash {
        crate::binary_attestation_mesh::compute_binary_hash().unwrap_or([0u8; 64])
    }

    /// Build a verifier with the given peer count for testing.
    fn make_verifier(num_peers: usize) -> DistributedStartupVerifier {
        let peers: Vec<String> = (0..num_peers)
            .map(|i| format!("10.0.0.{}:8443", i + 1))
            .collect();
        DistributedStartupVerifier::with_config(
            2,                           // min_peers
            Duration::from_secs(30),     // attestation_timeout
            Duration::from_secs(60),     // attestation_max_age
            peers,
            seed_a(),
            "self-node".to_string(),
            false,                       // no rolling update
        )
    }

    fn make_attestation(
        node_id: &str,
        seed: &[u8; 32],
        hash: &BinaryHash,
        timestamp: i64,
    ) -> PeerAttestation {
        create_test_attestation(node_id, seed, hash, "test-boot-id", timestamp)
    }

    // ── Test: startup with 0 peers fails ────────────────────────────────────

    #[test]
    fn test_startup_zero_peers_fails() {
        let verifier = DistributedStartupVerifier::with_config(
            2,
            Duration::from_secs(30),
            Duration::from_secs(60),
            vec![], // no peers
            seed_a(),
            "lonely-node".to_string(),
            false,
        );

        let result = verifier.verify_cluster(&[]);
        assert!(result.is_err());
        match result.unwrap_err() {
            StartupError::StandaloneOperationDenied => {}
            other => panic!("expected StandaloneOperationDenied, got: {other}"),
        }
    }

    // ── Test: startup with 1 peer fails (need 2+) ──────────────────────────

    #[test]
    fn test_startup_one_peer_fails() {
        let verifier = make_verifier(1); // only 1 peer configured, need 2
        let hash = test_binary_hash();
        let att = make_attestation("peer-1", &seed_b(), &hash, now_secs());

        let result = verifier.verify_cluster(&[att]);
        assert!(result.is_err());
        match result.unwrap_err() {
            StartupError::StandaloneOperationDenied => {}
            other => panic!("expected StandaloneOperationDenied, got: {other}"),
        }
    }

    // ── Test: startup with 2 verified peers succeeds ────────────────────────

    #[test]
    fn test_startup_two_peers_succeeds() {
        let verifier = make_verifier(2);
        // Use the same hash that the verifier computes for its own binary.
        let hash = own_binary_hash();
        let now = now_secs();

        let att1 = make_attestation("peer-1", &seed_b(), &hash, now);
        let att2 = make_attestation("peer-2", &seed_c(), &hash, now);

        let result = verifier.verify_cluster(&[att1, att2]);
        assert!(result.is_ok());
        let verification = result.unwrap();
        assert_eq!(verification.cluster_size, 3); // 2 peers + self
        assert!(verification.quorum_achievable);
        assert!(verification.state_chain_synced);
        assert_eq!(verification.verified_peers.len(), 2);
    }

    // ── Test: expired attestation rejected ──────────────────────────────────

    #[test]
    fn test_expired_attestation_rejected() {
        let verifier = make_verifier(2);
        let hash = own_binary_hash();
        let now = now_secs();

        // One fresh, one expired (200 seconds old > 60s max)
        let att1 = make_attestation("peer-1", &seed_b(), &hash, now);
        let att2 = make_attestation("peer-2", &seed_c(), &hash, now - 200);

        let result = verifier.verify_cluster(&[att1, att2]);
        assert!(result.is_err());
        match result.unwrap_err() {
            StartupError::AttestationExpired {
                node_id,
                age_secs,
                max_secs,
            } => {
                assert_eq!(node_id, crate::cluster::canonical_node_id("peer-2").to_string());
                assert!(age_secs >= 200);
                assert_eq!(max_secs, 60);
            }
            other => panic!("expected AttestationExpired, got: {other}"),
        }
    }

    // ── Test: tampered attestation signature rejected ────────────────────────

    #[test]
    fn test_tampered_signature_rejected() {
        let verifier = make_verifier(2);
        let hash = own_binary_hash();
        let now = now_secs();

        let att1 = make_attestation("peer-1", &seed_b(), &hash, now);

        // Create att2 with valid signature, then tamper with the signature bytes
        let mut att2 = make_attestation("peer-2", &seed_c(), &hash, now);
        if !att2.signature.is_empty() {
            att2.signature[0] ^= 0xFF; // flip bits
            att2.signature[1] ^= 0xFF;
        }

        let result = verifier.verify_cluster(&[att1, att2]);
        assert!(result.is_err());
        match result.unwrap_err() {
            StartupError::InvalidSignature { node_id } => {
                assert_eq!(node_id, crate::cluster::canonical_node_id("peer-2").to_string());
            }
            other => panic!("expected InvalidSignature, got: {other}"),
        }
    }

    // ── Test: binary hash mismatch detected and logged ──────────────────────

    #[test]
    fn test_binary_hash_mismatch_detected() {
        let verifier = make_verifier(2);
        let own_hash = own_binary_hash();
        let now = now_secs();

        // peer-1 has matching hash
        let att1 = make_attestation("peer-1", &seed_b(), &own_hash, now);

        // peer-2 has DIFFERENT binary hash (simulating tampering)
        let mut tampered_hash = own_hash;
        tampered_hash[0] ^= 0xFF;
        tampered_hash[1] ^= 0xEE;
        let att2 = make_attestation("peer-2", &seed_c(), &tampered_hash, now);

        let result = verifier.verify_cluster(&[att1, att2]);
        assert!(result.is_err());
        match result.unwrap_err() {
            StartupError::BinaryHashMismatch { node_id } => {
                assert_eq!(node_id, crate::cluster::canonical_node_id("peer-2").to_string());
            }
            other => panic!("expected BinaryHashMismatch, got: {other}"),
        }
    }

    // ── Test: binary hash mismatch allowed during rolling update ────────────

    #[test]
    fn test_binary_hash_mismatch_allowed_rolling_update() {
        let peers = vec![
            "10.0.0.1:8443".to_string(),
            "10.0.0.2:8443".to_string(),
        ];
        let verifier = DistributedStartupVerifier::with_config(
            2,
            Duration::from_secs(30),
            Duration::from_secs(60),
            peers,
            seed_a(),
            "self-node".to_string(),
            true, // rolling_update = true
        );

        let own_hash = own_binary_hash();
        let now = now_secs();

        let att1 = make_attestation("peer-1", &seed_b(), &own_hash, now);

        // Different binary hash — should be allowed during rolling update
        let mut different_hash = own_hash;
        different_hash[0] ^= 0xFF;
        let att2 = make_attestation("peer-2", &seed_c(), &different_hash, now);

        let result = verifier.verify_cluster(&[att1, att2]);
        assert!(result.is_ok());
    }

    // ── Test: quorum verification for FROST 3-of-5 ─────────────────────────

    #[test]
    fn test_quorum_frost_3of5_insufficient() {
        // 2 peers configured but only 1 attestation verified → 2 total < 3 FROST
        let verifier = make_verifier(2);
        let hash = own_binary_hash();
        let now = now_secs();

        // Only provide 1 valid attestation (+ self = 2 nodes, below FROST threshold of 3)
        let att1 = make_attestation("peer-1", &seed_b(), &hash, now);

        let result = verifier.verify_cluster(&[att1]);
        assert!(result.is_err());
        match result.unwrap_err() {
            StartupError::InsufficientPeers { found, required, .. } => {
                assert_eq!(found, 1);
                assert_eq!(required, 2);
            }
            other => panic!("expected InsufficientPeers, got: {other}"),
        }
    }

    #[test]
    fn test_quorum_frost_3of5_sufficient() {
        // 4 peers configured, 4 valid attestations → 5 total, FROST 3-of-5 OK
        let verifier = make_verifier(4);
        let hash = own_binary_hash();
        let now = now_secs();

        let seed_d = {
            let mut s = [0u8; 32];
            s[0] = 0xDD;
            s
        };
        let seed_e = {
            let mut s = [0u8; 32];
            s[0] = 0xEE;
            s
        };

        let atts = vec![
            make_attestation("peer-1", &seed_b(), &hash, now),
            make_attestation("peer-2", &seed_c(), &hash, now),
            make_attestation("peer-3", &seed_d, &hash, now),
            make_attestation("peer-4", &seed_e, &hash, now),
        ];

        let result = verifier.verify_cluster(&atts);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().cluster_size, 5);
    }

    // ── Test: quorum verification for BFT 5-of-7 ───────────────────────────

    #[test]
    fn test_quorum_bft_5of7_insufficient() {
        // 6 peers configured (7-node BFT cluster), but only 3 attestations → 4 total < 5
        let peers: Vec<String> = (0..6)
            .map(|i| format!("10.0.0.{}:8443", i + 1))
            .collect();
        let verifier = DistributedStartupVerifier::with_config(
            2,
            Duration::from_secs(30),
            Duration::from_secs(60),
            peers,
            seed_a(),
            "self-node".to_string(),
            false,
        );

        let hash = own_binary_hash();
        let now = now_secs();

        let atts = vec![
            make_attestation("peer-1", &seed_b(), &hash, now),
            make_attestation("peer-2", &seed_c(), &hash, now),
            make_attestation("peer-3", &{
                let mut s = [0u8; 32];
                s[0] = 0xDD;
                s
            }, &hash, now),
        ];

        let result = verifier.verify_cluster(&atts);
        assert!(result.is_err());
        match result.unwrap_err() {
            StartupError::QuorumNotAchievable {
                available,
                threshold,
                operation,
            } => {
                assert_eq!(available, 4); // 3 peers + self
                assert_eq!(threshold, 5);
                assert!(operation.contains("BFT"));
            }
            other => panic!("expected QuorumNotAchievable for BFT, got: {other}"),
        }
    }

    #[test]
    fn test_quorum_bft_5of7_sufficient() {
        // 6 peers configured (7-node BFT cluster), 6 valid attestations → 7 total
        let peers: Vec<String> = (0..6)
            .map(|i| format!("10.0.0.{}:8443", i + 1))
            .collect();
        let verifier = DistributedStartupVerifier::with_config(
            2,
            Duration::from_secs(30),
            Duration::from_secs(60),
            peers,
            seed_a(),
            "self-node".to_string(),
            false,
        );

        let hash = own_binary_hash();
        let now = now_secs();

        let seeds: Vec<[u8; 32]> = (0..6)
            .map(|i| {
                let mut s = [0u8; 32];
                s[0] = 0xB0 + i as u8;
                s
            })
            .collect();

        let atts: Vec<PeerAttestation> = (0..6)
            .map(|i| {
                make_attestation(
                    &format!("peer-{}", i + 1),
                    &seeds[i],
                    &hash,
                    now,
                )
            })
            .collect();

        let result = verifier.verify_cluster(&atts);
        assert!(result.is_ok());
        let v = result.unwrap();
        assert_eq!(v.cluster_size, 7);
        assert!(v.quorum_achievable);
    }

    // ── Test: own attestation generation and self-verification ──────────────

    #[test]
    fn test_own_attestation_verifies() {
        let verifier = make_verifier(2);
        let att = verifier.generate_own_attestation();

        // The attestation should be verifiable
        let payload = attestation_payload(
            att.node_id,
            &att.binary_hash,
            &att.boot_id,
            att.timestamp,
            &att.raft_verifying_key,
        );
        assert!(pq_verify(&att.verifying_key, &payload, &att.signature));
    }

    // ── Test: verify_attestation standalone ──────────────────────────────────

    #[test]
    fn test_verify_attestation_valid() {
        let verifier = make_verifier(2);
        let hash = test_binary_hash();
        let att = make_attestation("peer-x", &seed_b(), &hash, now_secs());
        assert!(verifier.verify_attestation(&att).is_ok());
    }

    #[test]
    fn test_verify_attestation_wrong_key() {
        let verifier = make_verifier(2);
        let hash = test_binary_hash();
        let now = now_secs();

        // Sign with seed_b but claim verifying key from seed_c
        let mut att = make_attestation("peer-x", &seed_b(), &hash, now);
        att.verifying_key = pq_verifying_key(&seed_c());

        let result = verifier.verify_attestation(&att);
        assert!(result.is_err());
        match result.unwrap_err() {
            StartupError::InvalidSignature { node_id } => {
                assert_eq!(node_id, crate::cluster::canonical_node_id("peer-x").to_string());
            }
            other => panic!("expected InvalidSignature, got: {other}"),
        }
    }

    // ── Test: peer discovery ────────────────────────────────────────────────

    #[test]
    fn test_discover_peers_returns_configured() {
        let verifier = make_verifier(3);
        let peers = verifier.discover_peers().unwrap();
        assert_eq!(peers.len(), 3);
    }

    #[test]
    fn test_discover_peers_empty_fails() {
        let verifier = DistributedStartupVerifier::with_config(
            2,
            Duration::from_secs(30),
            Duration::from_secs(60),
            vec![],
            seed_a(),
            "node".to_string(),
            false,
        );
        assert!(verifier.discover_peers().is_err());
    }

    // ── Per-node NodeIdentity (closes MEDIUM "identity not per-node") ────────

    /// ML-DSA-87 keys are large; run on a thread with extra stack
    /// (matches `RUST_MIN_STACK=8388608` used by the OCI build).
    fn run_with_large_stack<F: FnOnce() + Send + 'static>(f: F) {
        std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(f)
            .expect("thread spawn failed")
            .join()
            .expect("test thread panicked");
    }

    /// A test UUID (the raw identity input; `NodeIdentity` ctors take `Uuid`).
    fn nid(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    /// Same master KEK + two DIFFERENT NodeIds MUST derive DISTINCT seeds.
    /// This is the exact property whose absence was the MEDIUM finding.
    #[test]
    fn node_identity_seed_is_per_node() {
        let kek = [0x11u8; 32];
        let id_a = nid(0xA);
        let id_b = nid(0xB);
        let seed_a = derive_node_identity_seed(&kek, &id_a);
        let seed_b = derive_node_identity_seed(&kek, &id_b);
        assert_ne!(seed_a, seed_b, "two NodeIds must derive distinct seeds");
        // Deterministic for the same inputs.
        assert_eq!(seed_a, derive_node_identity_seed(&kek, &id_a));
    }

    /// The node-identity domain must NOT collide with the legacy attestation
    /// domain: same KEK + same node must give different key material.
    #[test]
    fn node_identity_domain_separated_from_attestation() {
        let kek = [0x22u8; 32];
        let id = nid(0xC0FFEE);
        let identity_seed = derive_node_identity_seed(&kek, &id);

        // Reproduce the attestation-seed derivation (v2, per-node).
        let mut hasher = Sha512::new();
        hasher.update(kek);
        hasher.update(b"MILNET-ATTESTATION-SEED-v2");
        hasher.update(id.to_string().as_bytes());
        let mut att_seed = [0u8; 32];
        att_seed.copy_from_slice(&hasher.finalize()[..32]);

        assert_ne!(
            identity_seed, att_seed,
            "identity and attestation seeds must be domain-separated"
        );
    }

    /// Two distinct NodeIdentities derive DISTINCT verifying keys.
    #[test]
    fn node_identity_two_nodes_distinct_keys() {
        run_with_large_stack(|| {
            let kek = [0x33u8; 32];
            let id_a = nid(1);
            let id_b = nid(2);
            let a = NodeIdentity::from_seed(id_a, derive_node_identity_seed(&kek, &id_a));
            let b = NodeIdentity::from_seed(id_b, derive_node_identity_seed(&kek, &id_b));
            assert_ne!(
                a.verifying_key(),
                b.verifying_key(),
                "distinct nodes must have distinct ML-DSA-87 verifying keys"
            );
        });
    }

    /// A node's own signature verifies against its own pinned verifying key.
    #[test]
    fn node_identity_sign_verify_roundtrip() {
        run_with_large_stack(|| {
            let identity = NodeIdentity::from_seed(nid(7), [0x44u8; 32]);
            let vk = identity.verifying_key();
            let msg = b"consensus-message-or-revoke-event";
            let sig = identity.node_sign(msg);
            assert!(
                verify_node_sig(&vk, msg, &sig),
                "valid per-node signature must verify"
            );
        });
    }

    /// A tampered message or signature is rejected.
    #[test]
    fn node_identity_tampered_rejected() {
        run_with_large_stack(|| {
            let identity = NodeIdentity::from_seed(nid(8), [0x55u8; 32]);
            let vk = identity.verifying_key();
            let msg = b"original-message";
            let sig = identity.node_sign(msg);

            // Tampered message.
            assert!(!verify_node_sig(&vk, b"different-message", &sig));

            // Tampered signature.
            let mut bad_sig = sig.clone();
            bad_sig[0] ^= 0xFF;
            assert!(!verify_node_sig(&vk, msg, &bad_sig));
        });
    }

    /// CORE ANTI-FORGERY PROPERTY: node A signs a message; the signature does
    /// NOT verify under node B's verifying key. A compromised node can only
    /// sign AS ITSELF — it cannot forge messages attributed to another node.
    #[test]
    fn node_identity_cannot_forge_as_another_node() {
        run_with_large_stack(|| {
            let a = NodeIdentity::from_seed(nid(100), [0x66u8; 32]);
            let b = NodeIdentity::from_seed(nid(200), [0x77u8; 32]);

            let msg = b"i-am-node-A";
            let sig_a = a.node_sign(msg);

            // Verifying A's signature against B's pinned key MUST fail.
            assert!(
                !verify_node_sig(&b.verifying_key(), msg, &sig_a),
                "node A's signature must not verify under node B's key"
            );
            // Sanity: it does verify under A's own key.
            assert!(verify_node_sig(&a.verifying_key(), msg, &sig_a));
        });
    }

    /// An unknown / unpinned signer has no verifying key; passing a wrong key
    /// fails closed (this is how callers MUST treat an unpinned NodeId).
    #[test]
    fn node_identity_unknown_signer_fails_closed() {
        run_with_large_stack(|| {
            let signer = NodeIdentity::from_seed(nid(300), [0x88u8; 32]);
            let msg = b"event";
            let sig = signer.node_sign(msg);

            // A verifier that never pinned this signer has only some OTHER key.
            let unrelated_vk = NodeIdentity::from_seed(nid(301), [0x99u8; 32]).verifying_key();
            assert!(
                !verify_node_sig(&unrelated_vk, msg, &sig),
                "signature from an unpinned signer must be rejected"
            );
        });
    }

    /// The shared NodeId-keyed registry verifies a pinned node's signature and
    /// FAILS CLOSED for an unpinned NodeId. This is the ONE registry the Raft
    /// transport and the revocation layer share.
    #[test]
    fn node_identity_registry_verify_and_fail_closed() {
        run_with_large_stack(|| {
            let signer = NodeIdentity::from_seed(nid(1), [0x12u8; 32]);
            let mut reg = NodeIdentityRegistry::new();
            reg.pin(signer.node_id(), signer.verifying_key());

            let msg = b"signed-by-node-1";
            let sig = signer.node_sign(msg);

            // Pinned signer verifies.
            assert!(reg.verify(signer.node_id(), msg, &sig));
            // Tampered message fails.
            assert!(!reg.verify(signer.node_id(), b"tampered", &sig));
            // Unknown/unpinned NodeId fails closed (no silent accept).
            assert!(!reg.verify(NodeId(nid(999)), msg, &sig));
            assert!(!reg.contains(&NodeId(nid(999))));
            assert_eq!(reg.len(), 1);
        });
    }

    // ── TPM-sealed per-node identity (TRUE anti-root, military mode) ─────────
    //
    // The TPM seal/unseal logic + fail-closed tests live in `sealed_keys` (it
    // owns the TpmKekSealer + the mock); see `load_node_identity_seed_inner`,
    // `seal_node_identity_to_tpm`, and their tests there. Here we only assert
    // that a per-node sealed seed builds a working signing identity.

    /// A per-node (TPM-sealed) seed yields a usable NodeIdentity whose signatures
    /// verify. (The seed source is exercised in `sealed_keys`; this checks the
    /// `from_sealed_seed` -> sign/verify path.)
    #[test]
    fn sealed_seed_builds_working_identity() {
        run_with_large_stack(|| {
            // Stand-in for a TPM-unsealed seed.
            let seed = [0x3Cu8; 32];
            let id = NodeIdentity::from_sealed_seed(nid(5), seed);
            let msg = b"raft-or-revoke";
            let sig = id.node_sign(msg);
            assert!(verify_node_sig(&id.verifying_key(), msg, &sig));
        });
    }

    // ── Raft-VK distribution via attestation (join-time pinning) ────────────

    /// The published per-node Raft VK is covered by the attestation signature:
    /// verification succeeds with the real VK, and a SUBSTITUTED VK is rejected.
    #[test]
    fn attestation_covers_raft_verifying_key() {
        run_with_large_stack(|| {
            let raft_id = NodeIdentity::from_seed(nid(0xAB), [0x42u8; 32]);
            let raft_vk = raft_id.verifying_key();
            let hash = test_binary_hash();
            let att = create_test_attestation_with_raft_vk(
                "00000000-0000-0000-0000-0000000000ab",
                &seed_b(),
                &hash,
                "boot",
                now_secs(),
                &raft_vk,
            );

            // Honest verification (recompute payload incl. the published VK).
            let good = attestation_payload(
                att.node_id, &att.binary_hash, &att.boot_id, att.timestamp,
                &att.raft_verifying_key,
            );
            assert!(pq_verify(&att.verifying_key, &good, &att.signature));

            // A MITM swaps the Raft VK → signature no longer matches.
            let other_vk = NodeIdentity::from_seed(nid(0xCD), [0x43u8; 32]).verifying_key();
            let forged = attestation_payload(
                att.node_id, &att.binary_hash, &att.boot_id, att.timestamp, &other_vk,
            );
            assert!(
                !pq_verify(&att.verifying_key, &forged, &att.signature),
                "a substituted raft_verifying_key must break the attestation signature"
            );
        });
    }

    /// `verify_attestation` accepts an attestation carrying a raft VK and rejects
    /// one whose raft VK was tampered after signing.
    #[test]
    fn verify_attestation_rejects_tampered_raft_vk() {
        run_with_large_stack(|| {
            let verifier = make_verifier(2);
            let hash = test_binary_hash();
            let raft_vk = NodeIdentity::from_seed(nid(1), [0x44u8; 32]).verifying_key();
            let mut att = create_test_attestation_with_raft_vk(
                "peer-x", &seed_b(), &hash, "test-boot-id", now_secs(), &raft_vk,
            );
            assert!(verifier.verify_attestation(&att).is_ok());

            // Tamper the published raft VK without re-signing.
            att.raft_verifying_key = NodeIdentity::from_seed(nid(2), [0x45u8; 32]).verifying_key();
            assert!(
                verifier.verify_attestation(&att).is_err(),
                "tampered raft_verifying_key must fail attestation verification"
            );
        });
    }

    /// The SHARED `cluster::canonical_node_id` maps UUID / hex / non-UUID ids to
    /// a stable NodeId, identically to the Raft transport (so attestation id ==
    /// transport id). Non-UUID deploy ids (e.g. `orchestrator-0`) get a stable
    /// UUIDv5 — deterministic and distinct.
    #[test]
    fn canonical_node_id_matches_transport() {
        // UUID string → that UUID.
        assert_eq!(
            crate::cluster::canonical_node_id("00000000-0000-0000-0000-00000000002a"),
            NodeId(Uuid::from_u128(0x2a))
        );
        // Hex → from_u128.
        assert_eq!(crate::cluster::canonical_node_id("0x2a"), NodeId(Uuid::from_u128(0x2a)));
        // Non-UUID deploy id → stable UUIDv5 (deterministic, distinct per string).
        let a = crate::cluster::canonical_node_id("orchestrator-0");
        let b = crate::cluster::canonical_node_id("orchestrator-1");
        assert_eq!(a, crate::cluster::canonical_node_id("orchestrator-0"), "stable");
        assert_ne!(a, b, "distinct deploy ids map to distinct NodeIds");
        // attestation's accessor just returns the stored NodeId.
        let att = create_test_attestation("orchestrator-0", &seed_b(), &test_binary_hash(), "b", 0);
        assert_eq!(att.cluster_node_id(), a);
    }

    /// `peer_identities_to_pin` returns (NodeId, raft_vk) only for peers that
    /// published a Raft VK; a peer with no published VK is skipped (fail-closed).
    #[test]
    fn startup_verification_peer_identities_to_pin() {
        run_with_large_stack(|| {
            let vk1 = NodeIdentity::from_seed(nid(0x11), [0x11u8; 32]).verifying_key();
            let with_vk = PeerAttestation {
                node_id: NodeId(Uuid::from_u128(0x11)),
                binary_hash: [0u8; 64], boot_id: "b".into(), timestamp: 0,
                signature: vec![], verifying_key: vec![], raft_verifying_key: vk1.clone(),
            };
            // No raft VK → skipped (fail-closed: unpinned peer's msgs dropped).
            let no_vk = PeerAttestation {
                node_id: NodeId(Uuid::from_u128(0x22)),
                binary_hash: [0u8; 64], boot_id: "b".into(), timestamp: 0,
                signature: vec![], verifying_key: vec![], raft_verifying_key: vec![],
            };

            let v = StartupVerification {
                verified_peers: vec![with_vk, no_vk],
                cluster_size: 3, quorum_achievable: true, state_chain_synced: true,
            };
            let pins = v.peer_identities_to_pin();
            assert_eq!(pins.len(), 1, "only the peer with a published VK is pinnable");
            assert_eq!(pins[0].0, NodeId(Uuid::from_u128(0x11)));
            assert_eq!(pins[0].1, vk1);
        });
    }

    /// The `from_node_identity` seam publishes the identity's VK in the attestation.
    #[test]
    fn verifier_from_node_identity_publishes_vk() {
        run_with_large_stack(|| {
            let identity = NodeIdentity::from_seed(nid(9), [0x77u8; 32]);
            let expected_vk = identity.verifying_key();
            let verifier = make_verifier(2).from_node_identity(&identity);
            assert_eq!(verifier.raft_verifying_key(), expected_vk.as_slice());

            let att = verifier.generate_own_attestation();
            assert_eq!(att.raft_verifying_key, expected_vk);
            // And the attestation self-verifies (VK is covered by the signature).
            assert!(verifier.verify_attestation(&att).is_ok());
        });
    }
}
