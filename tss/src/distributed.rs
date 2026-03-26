//! Distributed FROST signing across separate signer processes.
//! Each signer holds exactly ONE share. The coordinator aggregates.

use frost_ristretto255 as frost;
use frost::keys::{KeyPackage, PublicKeyPackage};
use frost::round1::{SigningCommitments, SigningNonces};
use frost::round2::SignatureShare;
use frost::{Identifier, SigningPackage};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// SignerNode — holds exactly ONE key share (runs in its own task/process)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// SigningCoordinator — holds NO shares, only the public key package
// ---------------------------------------------------------------------------

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

    /// Coordinate a distributed signing ceremony (in-process variant).
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

// ---------------------------------------------------------------------------
// distribute_shares — split DKG result into coordinator + signer nodes
// ---------------------------------------------------------------------------

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

// ===========================================================================
// Remote / Distributed signing over SHARD
// ===========================================================================

/// Messages exchanged between coordinator and remote signer nodes over SHARD.
///
/// Frost types are serialized to bytes using their own `.serialize()` /
/// `::deserialize()` methods and wrapped as `Vec<u8>` for transport.
#[derive(Serialize, Deserialize)]
pub enum SignerMessage {
    /// Coordinator -> Signer: request a commitment for signing.
    CommitRequest,
    /// Signer -> Coordinator: commitment response with serialized nonces and commitments.
    CommitResponse {
        /// Serialized `frost::Identifier` bytes.
        identifier_bytes: Vec<u8>,
        /// Serialized `frost::round1::SigningNonces` bytes.
        nonces_bytes: Vec<u8>,
        /// Serialized `frost::round1::SigningCommitments` bytes.
        commitments_bytes: Vec<u8>,
    },
    /// Coordinator -> Signer: request a signature share.
    SignRequest {
        /// Serialized `frost::SigningPackage` bytes.
        signing_package_bytes: Vec<u8>,
        /// Serialized `frost::round1::SigningNonces` bytes (returned from commit).
        nonces_bytes: Vec<u8>,
    },
    /// Signer -> Coordinator: signature share response.
    SignResponse {
        /// Serialized `frost::Identifier` bytes.
        identifier_bytes: Vec<u8>,
        /// Serialized `frost::round2::SignatureShare` bytes.
        share_bytes: Vec<u8>,
    },
    /// Error from signer.
    Error { message: String },
}

/// A remote signer node that communicates via SHARD over mTLS.
/// The coordinator holds these — one per remote signer process.
pub struct RemoteSignerNode {
    pub identifier: Identifier,
    pub addr: String,
    pub hmac_key: [u8; 64],
}

/// Run a standalone signer process that holds exactly ONE FROST key share.
/// Communicates with the coordinator via SHARD over mTLS.
///
/// Each signer runs in its own tokio task (or separate binary) so that
/// compromising any single process only yields 1 share out of N.
pub async fn run_signer_process(
    node: SignerNode,
    addr: &str,
    hmac_key: [u8; 64],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let signer_name = format!("tss-signer-{:?}", node.identifier());
    let (listener, _ca, _cert_key) = shard::tls_transport::tls_bind(
        addr,
        common::types::ModuleId::Tss,
        hmac_key,
        &signer_name,
    )
    .await?;

    tracing::info!("TSS signer node {:?} listening on {}", node.identifier(), addr);

    // Store node in a tokio mutex for mutable access during signing.
    // Using tokio::sync::Mutex so that the guard is Send-safe across await points.
    let node = tokio::sync::Mutex::new(node);

    loop {
        match listener.accept().await {
            Ok(mut transport) => {
                // Process a single request per connection.
                match transport.recv().await {
                    Ok((_sender, payload)) => {
                        let msg: SignerMessage = match postcard::from_bytes(&payload) {
                            Ok(m) => m,
                            Err(e) => {
                                tracing::error!("signer: deserialize error: {e}");
                                let resp = SignerMessage::Error {
                                    message: format!("deserialize error: {e}"),
                                };
                                let resp_bytes = postcard::to_allocvec(&resp).unwrap();
                                let _ = transport.send(&resp_bytes).await;
                                continue;
                            }
                        };

                        match msg {
                            SignerMessage::CommitRequest => {
                                let mut guard = node.lock().await;
                                let (nonces, commitments) = guard.commit();

                                let identifier_bytes = guard.identifier().serialize();
                                let nonces_bytes = nonces.serialize().unwrap_or_default();
                                let commitments_bytes = commitments.serialize().unwrap_or_default();

                                let resp = SignerMessage::CommitResponse {
                                    identifier_bytes,
                                    nonces_bytes,
                                    commitments_bytes,
                                };
                                let resp_bytes = postcard::to_allocvec(&resp).unwrap();
                                let _ = transport.send(&resp_bytes).await;
                            }
                            SignerMessage::SignRequest {
                                signing_package_bytes,
                                nonces_bytes,
                            } => {
                                let guard = node.lock().await;

                                let signing_package =
                                    match SigningPackage::deserialize(&signing_package_bytes) {
                                        Ok(sp) => sp,
                                        Err(e) => {
                                            let resp = SignerMessage::Error {
                                                message: format!(
                                                    "deserialize signing package: {e}"
                                                ),
                                            };
                                            let resp_bytes =
                                                postcard::to_allocvec(&resp).unwrap();
                                            let _ = transport.send(&resp_bytes).await;
                                            continue;
                                        }
                                    };

                                let nonces = match SigningNonces::deserialize(&nonces_bytes) {
                                    Ok(n) => n,
                                    Err(e) => {
                                        let resp = SignerMessage::Error {
                                            message: format!("deserialize nonces: {e}"),
                                        };
                                        let resp_bytes = postcard::to_allocvec(&resp).unwrap();
                                        let _ = transport.send(&resp_bytes).await;
                                        continue;
                                    }
                                };

                                match guard.sign(&signing_package, &nonces) {
                                    Ok(share) => {
                                        let identifier_bytes = guard.identifier().serialize();
                                        let share_bytes = share.serialize();
                                        let resp = SignerMessage::SignResponse {
                                            identifier_bytes,
                                            share_bytes,
                                        };
                                        let resp_bytes = postcard::to_allocvec(&resp).unwrap();
                                        let _ = transport.send(&resp_bytes).await;
                                    }
                                    Err(e) => {
                                        let resp = SignerMessage::Error {
                                            message: format!("sign failed: {e}"),
                                        };
                                        let resp_bytes = postcard::to_allocvec(&resp).unwrap();
                                        let _ = transport.send(&resp_bytes).await;
                                    }
                                }
                            }
                            _ => {
                                let resp = SignerMessage::Error {
                                    message: "unexpected message type".into(),
                                };
                                let resp_bytes = postcard::to_allocvec(&resp).unwrap();
                                let _ = transport.send(&resp_bytes).await;
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("signer: recv error: {e}");
                    }
                }
            }
            Err(e) => {
                tracing::warn!("signer: accept error: {e}");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// DistributedSigningCoordinator — communicates with remote signers via SHARD
// ---------------------------------------------------------------------------

/// Coordinator that communicates with remote signer nodes via SHARD.
/// Holds NO signing keys — only the public key package and signer addresses.
pub struct DistributedSigningCoordinator {
    pub public_key_package: PublicKeyPackage,
    pub threshold: usize,
    pub signer_addrs: Vec<(Identifier, String)>,
    pub hmac_key: [u8; 64],
}

impl DistributedSigningCoordinator {
    /// Perform a distributed signing ceremony by communicating with remote
    /// signer nodes over SHARD/mTLS.
    ///
    /// 1. Connects to `threshold` signers and sends `CommitRequest`.
    /// 2. Collects commitments, builds the `SigningPackage`.
    /// 3. Sends `SignRequest` to each signer with the signing package + nonces.
    /// 4. Collects signature shares and aggregates into a group signature.
    pub async fn coordinate_signing_remote(
        &self,
        message: &[u8],
    ) -> Result<[u8; 64], String> {
        if self.signer_addrs.len() < self.threshold {
            return Err(format!(
                "need {} signers, got {}",
                self.threshold,
                self.signer_addrs.len()
            ));
        }

        let (connector, _ca, _cert_key) =
            shard::tls_transport::tls_client_setup("tss-coordinator");

        // Select the first `threshold` signers
        let selected: Vec<&(Identifier, String)> =
            self.signer_addrs.iter().take(self.threshold).collect();

        // --- Round 1: Collect commitments ---
        let mut nonces_map: BTreeMap<Identifier, Vec<u8>> = BTreeMap::new();
        let mut commitments_map: BTreeMap<Identifier, SigningCommitments> = BTreeMap::new();

        for (_id, addr) in &selected {
            let mut transport = shard::tls_transport::tls_connect(
                addr,
                common::types::ModuleId::Orchestrator,
                self.hmac_key,
                &connector,
                "localhost",
            )
            .await
            .map_err(|e| format!("connect to signer at {addr}: {e}"))?;

            let req = SignerMessage::CommitRequest;
            let req_bytes =
                postcard::to_allocvec(&req).map_err(|e| format!("serialize commit req: {e}"))?;
            transport
                .send(&req_bytes)
                .await
                .map_err(|e| format!("send commit req to {addr}: {e}"))?;

            let (_sender, resp_payload) = transport
                .recv()
                .await
                .map_err(|e| format!("recv commit resp from {addr}: {e}"))?;

            let resp: SignerMessage = postcard::from_bytes(&resp_payload)
                .map_err(|e| format!("deserialize commit resp from {addr}: {e}"))?;

            match resp {
                SignerMessage::CommitResponse {
                    identifier_bytes,
                    nonces_bytes,
                    commitments_bytes,
                } => {
                    let identifier = Identifier::deserialize(&identifier_bytes)
                        .map_err(|e| format!("deserialize identifier: {e}"))?;
                    let commitments = SigningCommitments::deserialize(&commitments_bytes)
                        .map_err(|e| format!("deserialize commitments: {e}"))?;

                    nonces_map.insert(identifier, nonces_bytes);
                    commitments_map.insert(identifier, commitments);
                }
                SignerMessage::Error { message } => {
                    return Err(format!("signer at {addr} error during commit: {message}"));
                }
                _ => {
                    return Err(format!("unexpected response from signer at {addr}"));
                }
            }
        }

        // Build signing package
        let signing_package = SigningPackage::new(commitments_map, message);
        let signing_package_bytes = signing_package
            .serialize()
            .map_err(|e| format!("serialize signing package: {e}"))?;

        // --- Round 2: Collect signature shares ---
        let mut signature_shares: BTreeMap<Identifier, SignatureShare> = BTreeMap::new();

        for (id, addr) in &selected {
            let nonces_bytes = nonces_map
                .remove(id)
                .ok_or_else(|| format!("missing nonces for signer {:?}", id))?;

            let mut transport = shard::tls_transport::tls_connect(
                addr,
                common::types::ModuleId::Orchestrator,
                self.hmac_key,
                &connector,
                "localhost",
            )
            .await
            .map_err(|e| format!("connect to signer at {addr} for sign: {e}"))?;

            let req = SignerMessage::SignRequest {
                signing_package_bytes: signing_package_bytes.clone(),
                nonces_bytes,
            };
            let req_bytes =
                postcard::to_allocvec(&req).map_err(|e| format!("serialize sign req: {e}"))?;
            transport
                .send(&req_bytes)
                .await
                .map_err(|e| format!("send sign req to {addr}: {e}"))?;

            let (_sender, resp_payload) = transport
                .recv()
                .await
                .map_err(|e| format!("recv sign resp from {addr}: {e}"))?;

            let resp: SignerMessage = postcard::from_bytes(&resp_payload)
                .map_err(|e| format!("deserialize sign resp from {addr}: {e}"))?;

            match resp {
                SignerMessage::SignResponse {
                    identifier_bytes,
                    share_bytes,
                } => {
                    let identifier = Identifier::deserialize(&identifier_bytes)
                        .map_err(|e| format!("deserialize identifier: {e}"))?;
                    let share = SignatureShare::deserialize(&share_bytes)
                        .map_err(|e| format!("deserialize signature share: {e}"))?;
                    signature_shares.insert(identifier, share);
                }
                SignerMessage::Error { message } => {
                    return Err(format!("signer at {addr} error during sign: {message}"));
                }
                _ => {
                    return Err(format!("unexpected response from signer at {addr}"));
                }
            }
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
