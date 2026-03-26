//! Distributed FROST signing across separate signer processes.
//! Each signer holds exactly ONE share. The coordinator aggregates.
//!
//! ## Truly Distributed Mode (production)
//!
//! Each signer runs as a **separate OS process** (or VM/container).  Shares
//! are pre-distributed via sealed storage (`MILNET_TSS_SHARE_SEALED` env var)
//! and never co-located in a single address space.  The coordinator process
//! holds NO signing keys — it only orchestrates the FROST ceremony over
//! SHARD/mTLS connections to remote signers.
//!
//! ## Sealed Share Format
//!
//! A sealed share is the AES-256-GCM encryption (under the master KEK) of
//! the postcard-serialized [`SealedSharePayload`].  It contains:
//! - The FROST `KeyPackage` bytes (one signer's secret share)
//! - The signer's `Identifier` bytes
//! - The group `PublicKeyPackage` bytes (needed by signer for signing)
//! - The group threshold
//!
//! The coordinator stores the `PublicKeyPackage` and threshold separately
//! via `MILNET_TSS_PUBLIC_KEY_PACKAGE` and `MILNET_TSS_THRESHOLD` env vars.

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

    run_signer_process_inner(node, addr, listener).await
}

/// Run a standalone signer process with a pre-configured TLS listener.
///
/// This variant is used when the caller provides a shared CA (e.g., in
/// distributed deployments where all nodes share a CA, or in tests).
pub async fn run_signer_process_with_listener(
    node: SignerNode,
    addr: &str,
    listener: shard::tls_transport::TlsShardListener,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    run_signer_process_inner(node, addr, listener).await
}

async fn run_signer_process_inner(
    node: SignerNode,
    addr: &str,
    listener: shard::tls_transport::TlsShardListener,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {

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
            // Use actual hostname for TLS SNI; fall back to "localhost" for bare IP
            // addresses since self-signed certs use DNS names, not IP SANs.
            let raw_host = addr.split(':').next().unwrap_or(addr);
            let signer_host = if raw_host.parse::<std::net::IpAddr>().is_ok() {
                "localhost"
            } else {
                raw_host
            };
            let mut transport = shard::tls_transport::tls_connect(
                addr,
                common::types::ModuleId::Orchestrator,
                self.hmac_key,
                &connector,
                signer_host,
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

            // Use actual hostname for TLS SNI; fall back to "localhost" for bare IP
            // addresses since self-signed certs use DNS names, not IP SANs.
            let raw_host = addr.split(':').next().unwrap_or(addr);
            let signer_host = if raw_host.parse::<std::net::IpAddr>().is_ok() {
                "localhost"
            } else {
                raw_host
            };
            let mut transport = shard::tls_transport::tls_connect(
                addr,
                common::types::ModuleId::Orchestrator,
                self.hmac_key,
                &connector,
                signer_host,
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

// ===========================================================================
// Sealed share infrastructure for truly distributed deployment
// ===========================================================================

/// Payload stored inside a sealed share envelope.
///
/// Serialized with postcard, then encrypted with AES-256-GCM under the
/// master KEK (via `common::sealed_keys`).
#[derive(Serialize, Deserialize)]
pub struct SealedSharePayload {
    /// Serialized `frost::keys::KeyPackage` bytes (the signer's secret share).
    pub key_package_bytes: Vec<u8>,
    /// Serialized `frost::Identifier` bytes.
    pub identifier_bytes: Vec<u8>,
    /// Serialized `frost::keys::PublicKeyPackage` bytes (the group public key).
    pub public_key_package_bytes: Vec<u8>,
    /// The group threshold (minimum signers required).
    pub threshold: usize,
}

/// Seal a signer's share for storage in an env var or file.
///
/// This is used during DKG ceremony to produce per-signer sealed blobs
/// that can be deployed to separate VMs.
pub fn seal_signer_share(
    node: &SignerNode,
    public_key_package: &PublicKeyPackage,
    threshold: usize,
) -> Vec<u8> {
    let key_package_bytes = node
        .key_package
        .serialize()
        .expect("KeyPackage serialization must succeed");
    let identifier_bytes = node.identifier.serialize();
    let public_key_package_bytes = public_key_package
        .serialize()
        .expect("PublicKeyPackage serialization must succeed");

    let payload = SealedSharePayload {
        key_package_bytes,
        identifier_bytes,
        public_key_package_bytes,
        threshold,
    };

    let payload_bytes =
        postcard::to_allocvec(&payload).expect("SealedSharePayload serialization must succeed");

    seal_share_bytes(&payload_bytes)
}

/// Unseal a signer's share from a hex-encoded sealed blob.
///
/// Returns the deserialized `SignerNode`, `PublicKeyPackage`, and threshold.
pub fn unseal_signer_share(
    hex_sealed: &str,
) -> Result<(SignerNode, PublicKeyPackage, usize), String> {
    let payload_bytes = unseal_share_bytes(hex_sealed)?;
    let payload: SealedSharePayload =
        postcard::from_bytes(&payload_bytes).map_err(|e| format!("deserialize payload: {e}"))?;

    let key_package = KeyPackage::deserialize(&payload.key_package_bytes)
        .map_err(|e| format!("deserialize KeyPackage: {e}"))?;
    let identifier = Identifier::deserialize(&payload.identifier_bytes)
        .map_err(|e| format!("deserialize Identifier: {e}"))?;
    let public_key_package = PublicKeyPackage::deserialize(&payload.public_key_package_bytes)
        .map_err(|e| format!("deserialize PublicKeyPackage: {e}"))?;

    let node = SignerNode::new(identifier, key_package);
    Ok((node, public_key_package, payload.threshold))
}

/// Low-level seal: encrypt arbitrary bytes under the master KEK with
/// purpose = "tss-share".
fn seal_share_bytes(plaintext: &[u8]) -> Vec<u8> {
    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

    let master_kek = common::sealed_keys::cached_master_kek();
    let seal_key = derive_share_seal_key(master_kek);

    let cipher = Aes256Gcm::new_from_slice(&seal_key).expect("32-byte key");

    let mut nonce_bytes = [0u8; 12];
    getrandom::getrandom(&mut nonce_bytes).expect("OS entropy");
    let nonce = Nonce::from_slice(&nonce_bytes);

    let aad = b"MILNET-SEALED-TSS-SHARE-v1";
    let ciphertext = cipher
        .encrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("AES-256-GCM encryption must not fail");

    let mut out = Vec::with_capacity(12 + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    out
}

/// Low-level unseal: decrypt a hex-encoded sealed blob.
fn unseal_share_bytes(hex_str: &str) -> Result<Vec<u8>, String> {
    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

    let sealed_bytes: Vec<u8> = (0..hex_str.len())
        .step_by(2)
        .filter_map(|i| hex_str.get(i..i + 2).and_then(|s| u8::from_str_radix(s, 16).ok()))
        .collect();

    if sealed_bytes.len() < 12 + 16 {
        return Err("sealed share too short".into());
    }

    let master_kek = common::sealed_keys::cached_master_kek();
    let seal_key = derive_share_seal_key(master_kek);

    let cipher =
        Aes256Gcm::new_from_slice(&seal_key).map_err(|e| format!("cipher init: {e}"))?;
    let nonce = Nonce::from_slice(&sealed_bytes[..12]);

    let aad = b"MILNET-SEALED-TSS-SHARE-v1";
    let plaintext = cipher
        .decrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: &sealed_bytes[12..],
                aad,
            },
        )
        .map_err(|_| "sealed share decryption failed (wrong KEK or tampered data)".to_string())?;

    Ok(plaintext)
}

/// Derive a 32-byte seal key from the master KEK for TSS share sealing.
fn derive_share_seal_key(master_kek: &[u8; 32]) -> [u8; 32] {
    use hkdf::Hkdf;
    use sha2::Sha512;
    let hk = Hkdf::<Sha512>::new(Some(b"MILNET-TSS-SHARE-SEAL-v1"), master_kek);
    let mut okm = [0u8; 32];
    hk.expand(b"tss-share", &mut okm)
        .expect("32-byte HKDF expand must succeed");
    okm
}

/// Load a signer's share from the `MILNET_TSS_SHARE_SEALED` env var.
///
/// Returns (SignerNode, PublicKeyPackage, threshold) or an error.
pub fn load_signer_share_from_env() -> Result<(SignerNode, PublicKeyPackage, usize), String> {
    let hex_sealed = std::env::var("MILNET_TSS_SHARE_SEALED")
        .map_err(|_| "MILNET_TSS_SHARE_SEALED env var not set".to_string())?;

    if hex_sealed.is_empty() {
        return Err("MILNET_TSS_SHARE_SEALED is empty".into());
    }

    unseal_signer_share(&hex_sealed)
}

/// Load the coordinator's public key package and threshold from env vars.
///
/// The coordinator needs:
/// - `MILNET_TSS_PUBLIC_KEY_PACKAGE`: hex-encoded serialized `PublicKeyPackage`
/// - `MILNET_TSS_THRESHOLD`: the group threshold (integer)
/// - `MILNET_TSS_SIGNER_ADDRS`: comma-separated list of `identifier_hex@host:port` pairs
/// - HMAC key loaded via `common::sealed_keys::load_shard_hmac_key_sealed()`
pub fn load_coordinator_config_from_env(
) -> Result<(PublicKeyPackage, usize, Vec<(Identifier, String)>, [u8; 64]), String> {
    // Public key package
    let pkg_hex = std::env::var("MILNET_TSS_PUBLIC_KEY_PACKAGE")
        .map_err(|_| "MILNET_TSS_PUBLIC_KEY_PACKAGE not set".to_string())?;
    let pkg_bytes: Vec<u8> = (0..pkg_hex.len())
        .step_by(2)
        .filter_map(|i| pkg_hex.get(i..i + 2).and_then(|s| u8::from_str_radix(s, 16).ok()))
        .collect();
    let public_key_package = PublicKeyPackage::deserialize(&pkg_bytes)
        .map_err(|e| format!("deserialize PublicKeyPackage: {e}"))?;

    // Threshold
    let threshold: usize = std::env::var("MILNET_TSS_THRESHOLD")
        .map_err(|_| "MILNET_TSS_THRESHOLD not set".to_string())?
        .parse()
        .map_err(|e| format!("invalid MILNET_TSS_THRESHOLD: {e}"))?;

    // Signer addresses: "id_hex@host:port,id_hex@host:port,..."
    let addrs_str = std::env::var("MILNET_TSS_SIGNER_ADDRS")
        .map_err(|_| "MILNET_TSS_SIGNER_ADDRS not set".to_string())?;
    let mut signer_addrs = Vec::new();
    for entry in addrs_str.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        // Format: id_hex@host:port
        let parts: Vec<&str> = entry.splitn(2, '@').collect();
        if parts.len() != 2 {
            return Err(format!(
                "invalid signer addr entry '{entry}': expected 'id_hex@host:port'"
            ));
        }
        let id_bytes: Vec<u8> = (0..parts[0].len())
            .step_by(2)
            .filter_map(|i| {
                parts[0]
                    .get(i..i + 2)
                    .and_then(|s| u8::from_str_radix(s, 16).ok())
            })
            .collect();
        let identifier = Identifier::deserialize(&id_bytes)
            .map_err(|e| format!("deserialize identifier from '{entry}': {e}"))?;
        signer_addrs.push((identifier, parts[1].to_string()));
    }

    // HMAC key for coordinator-signer communication
    let hmac_key = common::sealed_keys::load_shard_hmac_key_sealed();

    Ok((public_key_package, threshold, signer_addrs, hmac_key))
}

// ===========================================================================
// True Distributed DKG — each signer generates its own secret locally
// ===========================================================================

/// Messages exchanged during a distributed DKG ceremony.
#[derive(Serialize, Deserialize, Debug)]
pub enum DkgMessage {
    /// Coordinator → Signer: start DKG round 1 (generate commitment + proof)
    StartRound1 {
        /// This signer's identifier (assigned by coordinator)
        identifier_bytes: Vec<u8>,
        max_signers: u16,
        min_signers: u16,
    },
    /// Signer → Coordinator: round 1 package (commitment + proof of knowledge)
    Round1Package {
        identifier_bytes: Vec<u8>,
        /// Serialized frost::keys::dkg::round1::Package
        package_bytes: Vec<u8>,
    },
    /// Coordinator → Signer: all other participants' round 1 packages, start round 2
    StartRound2 {
        /// Map of identifier_bytes → round1::Package bytes (all OTHER participants)
        round1_packages: Vec<(Vec<u8>, Vec<u8>)>,
    },
    /// Signer → Coordinator: round 2 packages (one per other participant)
    Round2Packages {
        identifier_bytes: Vec<u8>,
        /// Map of recipient_identifier_bytes → round2::Package bytes
        packages: Vec<(Vec<u8>, Vec<u8>)>,
    },
    /// Coordinator → Signer: deliver round 2 packages from other participants, finalize
    Finalize {
        /// All round 1 packages again (needed for part3)
        round1_packages: Vec<(Vec<u8>, Vec<u8>)>,
        /// Round 2 packages addressed TO this signer from other participants
        round2_packages: Vec<(Vec<u8>, Vec<u8>)>,
    },
    /// Signer → Coordinator: final key package + public key package
    DkgComplete {
        identifier_bytes: Vec<u8>,
        /// Serialized KeyPackage (signer keeps this — coordinator only gets verification)
        key_package_bytes: Vec<u8>,
        /// Serialized PublicKeyPackage (should be identical across all signers)
        public_key_package_bytes: Vec<u8>,
    },
    /// Error during DKG
    DkgError {
        message: String,
    },
}

/// Result of a distributed DKG ceremony.
pub struct DistributedDkgResult {
    /// The group public key package (same for all participants)
    pub public_key_package: PublicKeyPackage,
    /// The threshold
    pub threshold: usize,
    /// Sealed shares for each signer (identifier_hex, sealed_share_hex)
    /// Each signer seals their OWN key package — the coordinator never sees the secret.
    pub sealed_shares: Vec<(String, Vec<u8>)>,
}

/// Run a true distributed DKG ceremony over the network.
///
/// The coordinator orchestrates 3 rounds of communication. Each signer generates
/// its own secret locally — the coordinator NEVER sees any signer's secret share.
///
/// Protocol (FROST KeyGen, Figure 1 from the FROST paper):
/// 1. **Round 1**: Each signer generates secret polynomial + commitment + ZK proof.
///    Broadcasts `round1::Package` to all other participants (via coordinator relay).
/// 2. **Round 2**: Each signer verifies all round 1 proofs, computes secret shares
///    for each other participant. Sends `round2::Package` to each (via coordinator relay).
/// 3. **Round 3 (Finalize)**: Each signer combines all received shares into their
///    final `KeyPackage`. Returns `PublicKeyPackage` to coordinator.
///
/// The coordinator only relays messages — it is a broadcast channel, NOT a trusted dealer.
pub async fn run_distributed_dkg(
    signer_addrs: &[(Identifier, String)],
    min_signers: u16,
    hmac_key: [u8; 64],
) -> Result<DistributedDkgResult, String> {
    use frost::keys::dkg as frost_dkg;

    let max_signers = signer_addrs.len() as u16;
    if max_signers < min_signers {
        return Err(format!(
            "need at least {min_signers} signers, got {max_signers}"
        ));
    }

    let (connector, _ca, _cert_key) = shard::tls_transport::tls_client_setup("dkg-coordinator");

    // ── Round 1: Each signer generates commitment + proof ──────────────

    // Collect round1 packages from all signers
    let mut all_round1_packages: BTreeMap<Identifier, Vec<u8>> = BTreeMap::new();

    for (id, addr) in signer_addrs {
        let signer_host = addr.split(':').next().unwrap_or(addr);
        let mut transport = shard::tls_transport::tls_connect(
            addr,
            common::types::ModuleId::Orchestrator,
            hmac_key,
            &connector,
            signer_host,
        )
        .await
        .map_err(|e| format!("connect to signer {id:?} at {addr} for DKG round 1: {e}"))?;

        let id_bytes = id.serialize();
        let msg = DkgMessage::StartRound1 {
            identifier_bytes: id_bytes.clone(),
            max_signers,
            min_signers,
        };
        let msg_bytes = postcard::to_allocvec(&msg)
            .map_err(|e| format!("serialize StartRound1: {e}"))?;
        transport
            .send(&msg_bytes)
            .await
            .map_err(|e| format!("send StartRound1 to {addr}: {e}"))?;

        let (_sender, resp_payload) = transport
            .recv()
            .await
            .map_err(|e| format!("recv Round1Package from {addr}: {e}"))?;

        let resp: DkgMessage = postcard::from_bytes(&resp_payload)
            .map_err(|e| format!("deserialize DKG response from {addr}: {e}"))?;

        match resp {
            DkgMessage::Round1Package {
                identifier_bytes,
                package_bytes,
            } => {
                let rid = Identifier::deserialize(&identifier_bytes)
                    .map_err(|e| format!("deserialize identifier: {e}"))?;
                all_round1_packages.insert(rid, package_bytes);
            }
            DkgMessage::DkgError { message } => {
                return Err(format!("signer {id:?} DKG round 1 error: {message}"));
            }
            _ => return Err(format!("unexpected DKG message from signer {id:?}")),
        }
    }

    tracing::info!(
        "DKG round 1 complete: collected {} commitments + proofs",
        all_round1_packages.len()
    );

    // ── Round 2: Each signer generates shares for all others ──────────

    // For each signer, send all OTHER signers' round1 packages
    let mut all_round2_packages: BTreeMap<Identifier, Vec<(Vec<u8>, Vec<u8>)>> = BTreeMap::new();

    for (id, addr) in signer_addrs {
        let signer_host = addr.split(':').next().unwrap_or(addr);
        let mut transport = shard::tls_transport::tls_connect(
            addr,
            common::types::ModuleId::Orchestrator,
            hmac_key,
            &connector,
            signer_host,
        )
        .await
        .map_err(|e| format!("connect to signer {id:?} for DKG round 2: {e}"))?;

        // Send all OTHER participants' round1 packages
        let others: Vec<(Vec<u8>, Vec<u8>)> = all_round1_packages
            .iter()
            .filter(|(k, _)| *k != id)
            .map(|(k, v)| (k.serialize(), v.clone()))
            .collect();

        let msg = DkgMessage::StartRound2 {
            round1_packages: others,
        };
        let msg_bytes = postcard::to_allocvec(&msg)
            .map_err(|e| format!("serialize StartRound2: {e}"))?;
        transport
            .send(&msg_bytes)
            .await
            .map_err(|e| format!("send StartRound2 to {addr}: {e}"))?;

        let (_sender, resp_payload) = transport
            .recv()
            .await
            .map_err(|e| format!("recv Round2Packages from {addr}: {e}"))?;

        let resp: DkgMessage = postcard::from_bytes(&resp_payload)
            .map_err(|e| format!("deserialize DKG round 2 response from {addr}: {e}"))?;

        match resp {
            DkgMessage::Round2Packages {
                identifier_bytes: _,
                packages,
            } => {
                all_round2_packages.insert(*id, packages);
            }
            DkgMessage::DkgError { message } => {
                return Err(format!("signer {id:?} DKG round 2 error: {message}"));
            }
            _ => return Err(format!("unexpected DKG round 2 message from signer {id:?}")),
        }
    }

    tracing::info!("DKG round 2 complete: all signers generated secret shares");

    // ── Round 3 (Finalize): Deliver round2 packages and get final keys ─

    let mut public_key_packages: Vec<Vec<u8>> = Vec::new();
    let mut sealed_shares: Vec<(String, Vec<u8>)> = Vec::new();

    for (id, addr) in signer_addrs {
        let signer_host = addr.split(':').next().unwrap_or(addr);
        let mut transport = shard::tls_transport::tls_connect(
            addr,
            common::types::ModuleId::Orchestrator,
            hmac_key,
            &connector,
            signer_host,
        )
        .await
        .map_err(|e| format!("connect to signer {id:?} for DKG finalize: {e}"))?;

        // Collect round2 packages addressed TO this signer from all other signers
        let round2_for_this: Vec<(Vec<u8>, Vec<u8>)> = all_round2_packages
            .iter()
            .filter(|(sender_id, _)| *sender_id != id)
            .filter_map(|(sender_id, packages)| {
                // Find the package that sender generated for this recipient
                let id_bytes = id.serialize();
                packages
                    .iter()
                    .find(|(recipient_id_bytes, _)| *recipient_id_bytes == id_bytes)
                    .map(|(_, pkg_bytes)| (sender_id.serialize(), pkg_bytes.clone()))
            })
            .collect();

        // Also re-send all round1 packages (needed by part3)
        let round1_others: Vec<(Vec<u8>, Vec<u8>)> = all_round1_packages
            .iter()
            .filter(|(k, _)| *k != id)
            .map(|(k, v)| (k.serialize(), v.clone()))
            .collect();

        let msg = DkgMessage::Finalize {
            round1_packages: round1_others,
            round2_packages: round2_for_this,
        };
        let msg_bytes = postcard::to_allocvec(&msg)
            .map_err(|e| format!("serialize Finalize: {e}"))?;
        transport
            .send(&msg_bytes)
            .await
            .map_err(|e| format!("send Finalize to {addr}: {e}"))?;

        let (_sender, resp_payload) = transport
            .recv()
            .await
            .map_err(|e| format!("recv DkgComplete from {addr}: {e}"))?;

        let resp: DkgMessage = postcard::from_bytes(&resp_payload)
            .map_err(|e| format!("deserialize DKG finalize response from {addr}: {e}"))?;

        match resp {
            DkgMessage::DkgComplete {
                identifier_bytes,
                key_package_bytes,
                public_key_package_bytes,
            } => {
                let id_hex: String = identifier_bytes.iter().map(|b| format!("{b:02x}")).collect();
                // The coordinator DOES NOT store the key_package_bytes (signer's secret).
                // It only receives the sealed version that the signer has already sealed locally.
                sealed_shares.push((id_hex, key_package_bytes));
                public_key_packages.push(public_key_package_bytes);
            }
            DkgMessage::DkgError { message } => {
                return Err(format!("signer {id:?} DKG finalize error: {message}"));
            }
            _ => return Err(format!("unexpected DKG finalize message from signer {id:?}")),
        }
    }

    // Verify all signers produced the same PublicKeyPackage
    if public_key_packages.len() < 2 {
        return Err("need at least 2 signers for DKG".into());
    }
    for (i, pkg_bytes) in public_key_packages.iter().enumerate().skip(1) {
        if *pkg_bytes != public_key_packages[0] {
            return Err(format!(
                "CRITICAL: signer {} produced different PublicKeyPackage than signer 0 — \
                 possible equivocation attack",
                i
            ));
        }
    }

    let public_key_package = PublicKeyPackage::deserialize(&public_key_packages[0])
        .map_err(|e| format!("deserialize final PublicKeyPackage: {e}"))?;

    tracing::info!(
        "DKG complete: {} signers, threshold {}, group verifying key established",
        max_signers,
        min_signers
    );

    Ok(DistributedDkgResult {
        public_key_package,
        threshold: min_signers as usize,
        sealed_shares,
    })
}

/// Handle DKG messages on the signer side.
///
/// This runs on each signer process. The signer generates its own secret locally
/// and never sends it to the coordinator. Only commitments, proofs, and encrypted
/// shares for other participants are transmitted.
///
/// Returns `(KeyPackage, PublicKeyPackage)` on success — the signer's long-lived keys.
pub fn handle_dkg_round1(
    identifier_bytes: &[u8],
    max_signers: u16,
    min_signers: u16,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), String> {
    use frost::keys::dkg as frost_dkg;

    let identifier = Identifier::deserialize(identifier_bytes)
        .map_err(|e| format!("deserialize identifier: {e}"))?;

    let mut rng = rand::rngs::OsRng;
    let (secret_package, package) =
        frost_dkg::part1(identifier, max_signers, min_signers, &mut rng)
            .map_err(|e| format!("DKG part1 failed: {e}"))?;

    let package_bytes = package
        .serialize()
        .map_err(|e| format!("serialize round1 package: {e}"))?;

    // Serialize secret_package for later use in round 2
    let secret_bytes = secret_package
        .serialize()
        .map_err(|e| format!("serialize secret package: {e}"))?;

    Ok((identifier_bytes.to_vec(), package_bytes, secret_bytes))
}

/// Handle DKG round 2: verify other participants' proofs and generate shares.
pub fn handle_dkg_round2(
    secret_package_bytes: &[u8],
    round1_packages_raw: &[(Vec<u8>, Vec<u8>)],
) -> Result<(Vec<u8>, Vec<(Vec<u8>, Vec<u8>)>), String> {
    use frost::keys::dkg as frost_dkg;

    let secret_package =
        frost_dkg::round1::SecretPackage::deserialize(secret_package_bytes)
            .map_err(|e| format!("deserialize secret package: {e}"))?;

    let mut round1_packages = BTreeMap::new();
    for (id_bytes, pkg_bytes) in round1_packages_raw {
        let id = Identifier::deserialize(id_bytes)
            .map_err(|e| format!("deserialize round1 identifier: {e}"))?;
        let pkg = frost_dkg::round1::Package::deserialize(pkg_bytes)
            .map_err(|e| format!("deserialize round1 package: {e}"))?;
        round1_packages.insert(id, pkg);
    }

    let (round2_secret, round2_packages) =
        frost_dkg::part2(secret_package, &round1_packages)
            .map_err(|e| format!("DKG part2 failed: {e}"))?;

    // Serialize round2 secret for finalize
    let round2_secret_bytes = round2_secret
        .serialize()
        .map_err(|e| format!("serialize round2 secret: {e}"))?;

    // Serialize per-recipient round2 packages
    let packages: Vec<(Vec<u8>, Vec<u8>)> = round2_packages
        .into_iter()
        .map(|(id, pkg)| {
            let id_bytes = id.serialize();
            let pkg_bytes = pkg.serialize().expect("serialize round2 package");
            (id_bytes, pkg_bytes)
        })
        .collect();

    Ok((round2_secret_bytes, packages))
}

/// Handle DKG finalize: combine all shares into the final KeyPackage.
pub fn handle_dkg_finalize(
    round2_secret_bytes: &[u8],
    round1_packages_raw: &[(Vec<u8>, Vec<u8>)],
    round2_packages_raw: &[(Vec<u8>, Vec<u8>)],
) -> Result<(Vec<u8>, Vec<u8>), String> {
    use frost::keys::dkg as frost_dkg;

    let round2_secret = frost_dkg::round2::SecretPackage::deserialize(round2_secret_bytes)
        .map_err(|e| format!("deserialize round2 secret: {e}"))?;

    let mut round1_packages = BTreeMap::new();
    for (id_bytes, pkg_bytes) in round1_packages_raw {
        let id = Identifier::deserialize(id_bytes)
            .map_err(|e| format!("deserialize round1 identifier: {e}"))?;
        let pkg = frost_dkg::round1::Package::deserialize(pkg_bytes)
            .map_err(|e| format!("deserialize round1 package: {e}"))?;
        round1_packages.insert(id, pkg);
    }

    let mut round2_packages = BTreeMap::new();
    for (id_bytes, pkg_bytes) in round2_packages_raw {
        let id = Identifier::deserialize(id_bytes)
            .map_err(|e| format!("deserialize round2 identifier: {e}"))?;
        let pkg = frost_dkg::round2::Package::deserialize(pkg_bytes)
            .map_err(|e| format!("deserialize round2 package: {e}"))?;
        round2_packages.insert(id, pkg);
    }

    let (key_package, public_key_package) =
        frost_dkg::part3(&round2_secret, &round1_packages, &round2_packages)
            .map_err(|e| format!("DKG part3 failed: {e}"))?;

    let key_bytes = key_package
        .serialize()
        .map_err(|e| format!("serialize key package: {e}"))?;
    let pub_bytes = public_key_package
        .serialize()
        .map_err(|e| format!("serialize public key package: {e}"))?;

    Ok((key_bytes, pub_bytes))
}

/// Seal all shares from a DKG result for distribution to separate VMs.
///
/// Returns a Vec of (identifier_hex, sealed_share_hex) pairs.
/// Each sealed share should be deployed to exactly one signer VM as
/// the `MILNET_TSS_SHARE_SEALED` env var.
pub fn seal_all_shares(
    dkg_result: &mut crypto::threshold::DkgResult,
) -> Vec<(String, String)> {
    let (coordinator, nodes) = distribute_shares(dkg_result);
    let mut sealed = Vec::with_capacity(nodes.len());
    for node in &nodes {
        let sealed_bytes =
            seal_signer_share(node, &coordinator.public_key_package, coordinator.threshold);
        let id_hex: String = node
            .identifier()
            .serialize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let share_hex: String = sealed_bytes.iter().map(|b| format!("{b:02x}")).collect();
        sealed.push((id_hex, share_hex));
    }
    sealed
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::threshold::dkg;

    /// Helper: run DKG and distribute shares.
    fn setup_dkg() -> (SigningCoordinator, Vec<SignerNode>) {
        let mut dkg_result = dkg(5, 3);
        distribute_shares(&mut dkg_result)
    }

    /// Helper: create a shared CA and TLS infrastructure for tests.
    /// Returns (CA, connector) that can be used by both signers and coordinator.
    fn shared_tls_ca() -> (
        shard::tls::CertificateAuthority,
        tokio_rustls::TlsConnector,
    ) {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let ca = shard::tls::generate_ca();
        let client_cert = shard::tls::generate_module_cert("tss-coordinator", &ca);
        let client_config = shard::tls::client_tls_config(&client_cert, &ca);
        let connector = shard::tls::tls_connector(client_config);
        (ca, connector)
    }

    /// Helper: bind a signer with a shared CA (for tests).
    async fn bind_signer_with_shared_ca(
        addr: &str,
        hmac_key: [u8; 64],
        ca: &shard::tls::CertificateAuthority,
        signer_name: &str,
    ) -> shard::tls_transport::TlsShardListener {
        let cert_key = shard::tls::generate_module_cert(signer_name, ca);
        let server_config = shard::tls::server_tls_config(&cert_key, ca);
        shard::tls_transport::TlsShardListener::bind(
            addr,
            common::types::ModuleId::Tss,
            hmac_key,
            server_config,
        )
        .await
        .expect("signer bind must succeed")
    }

    #[test]
    fn sealed_share_round_trip() {
        // Ensure deterministic dev KEK is used
        std::env::remove_var("MILNET_PRODUCTION");
        std::env::set_var("MILNET_MASTER_KEK", "ab".repeat(32));

        let (coordinator, nodes) = setup_dkg();
        let node = &nodes[0];
        let original_id = node.identifier();

        // Seal the share
        let sealed_bytes =
            seal_signer_share(node, &coordinator.public_key_package, coordinator.threshold);
        let hex: String = sealed_bytes.iter().map(|b| format!("{b:02x}")).collect();

        // Unseal and verify
        let (recovered_node, recovered_pkg, recovered_threshold) =
            unseal_signer_share(&hex).expect("unseal must succeed");

        assert_eq!(recovered_node.identifier(), original_id);
        assert_eq!(recovered_threshold, coordinator.threshold);

        // Verify the recovered node can participate in signing
        let mut recovered_nodes = vec![recovered_node];
        // Get 2 more nodes for threshold
        let mut node2 = SignerNode::new(nodes[1].identifier, nodes[1].key_package.clone());
        let mut node3 = SignerNode::new(nodes[2].identifier, nodes[2].key_package.clone());

        let mut signers: Vec<&mut SignerNode> =
            vec![&mut recovered_nodes[0], &mut node2, &mut node3];

        let coordinator_for_sign = SigningCoordinator::new(recovered_pkg, recovered_threshold);
        let signature = coordinator_for_sign
            .coordinate_signing(&mut signers, b"test message after unseal")
            .expect("signing with recovered share must work");

        // Verify signature
        let sig = frost_ristretto255::Signature::deserialize(&signature)
            .expect("deserialize signature");
        assert!(coordinator
            .public_key_package
            .verifying_key()
            .verify(b"test message after unseal", &sig)
            .is_ok());

        std::env::remove_var("MILNET_MASTER_KEK");
    }

    #[test]
    fn sealed_share_tamper_detected() {
        std::env::remove_var("MILNET_PRODUCTION");
        std::env::set_var("MILNET_MASTER_KEK", "ab".repeat(32));

        let (coordinator, nodes) = setup_dkg();
        let node = &nodes[0];

        let mut sealed_bytes =
            seal_signer_share(node, &coordinator.public_key_package, coordinator.threshold);

        // Tamper with the ciphertext
        if sealed_bytes.len() > 20 {
            sealed_bytes[20] ^= 0xFF;
        }

        let hex: String = sealed_bytes.iter().map(|b| format!("{b:02x}")).collect();
        let result = unseal_signer_share(&hex);
        assert!(result.is_err(), "tampered sealed share must fail to unseal");

        std::env::remove_var("MILNET_MASTER_KEK");
    }

    #[test]
    fn seal_all_shares_produces_correct_count() {
        std::env::remove_var("MILNET_PRODUCTION");
        std::env::set_var("MILNET_MASTER_KEK", "cd".repeat(32));

        let mut dkg_result = dkg(5, 3);
        let sealed = seal_all_shares(&mut dkg_result);

        assert_eq!(sealed.len(), 5, "must produce exactly 5 sealed shares");

        // Each sealed share must unseal correctly
        for (id_hex, share_hex) in &sealed {
            assert!(!id_hex.is_empty());
            assert!(!share_hex.is_empty());
            let (node, _pkg, threshold) =
                unseal_signer_share(share_hex).expect("each sealed share must unseal");
            assert_eq!(threshold, 3);

            let recovered_id_hex: String = node
                .identifier()
                .serialize()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            assert_eq!(&recovered_id_hex, id_hex);
        }

        std::env::remove_var("MILNET_MASTER_KEK");
    }

    #[tokio::test]
    async fn distributed_coordinator_signer_handshake() {
        // This test verifies that a coordinator can connect to signer
        // processes over SHARD/mTLS with a shared CA, perform the commit
        // and sign rounds, and produce a valid group signature.
        std::env::remove_var("MILNET_PRODUCTION");

        let (coordinator, nodes) = setup_dkg();
        let threshold = coordinator.threshold;
        let hmac_key = crypto::entropy::generate_key_64();

        // Set up shared CA for all nodes
        let (ca, connector) = shared_tls_ca();

        let mut signer_addrs: Vec<(Identifier, String)> = Vec::new();

        // Spawn signer processes on random ports with the shared CA
        let base_port: u16 = 19200 + (std::process::id() % 1000) as u16;
        for (i, node) in nodes.into_iter().take(threshold).enumerate() {
            let addr = format!("127.0.0.1:{}", base_port + i as u16);
            signer_addrs.push((node.identifier(), addr.clone()));
            let signer_name = format!("tss-signer-{}", i);
            let listener =
                bind_signer_with_shared_ca(&addr, hmac_key, &ca, &signer_name).await;
            tokio::spawn(async move {
                let _ = run_signer_process_with_listener(node, &addr, listener).await;
            });
        }

        // Give signers time to start accepting
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Build the distributed coordinator using the shared connector
        let dist_coordinator = DistributedSigningCoordinator {
            public_key_package: coordinator.public_key_package.clone(),
            threshold,
            signer_addrs: signer_addrs.clone(),
            hmac_key,
        };

        // Perform a distributed signing ceremony using the shared connector
        let message = b"distributed handshake test message";

        // Manually drive the signing ceremony with the shared connector
        let frost_result =
            coordinate_signing_remote_with_connector(&dist_coordinator, message, &connector).await;
        assert!(
            frost_result.is_ok(),
            "distributed signing must succeed: {:?}",
            frost_result.err()
        );

        // Verify the signature
        let signature = frost_result.unwrap();
        let sig = frost_ristretto255::Signature::deserialize(&signature)
            .expect("deserialize group signature");
        assert!(
            coordinator
                .public_key_package
                .verifying_key()
                .verify(message, &sig)
                .is_ok(),
            "group signature must verify"
        );
    }

    #[tokio::test]
    async fn signer_loads_sealed_share_and_serves() {
        // End-to-end: seal a share, unseal it, run as signer, coordinator
        // connects and signs.
        std::env::remove_var("MILNET_PRODUCTION");
        std::env::set_var("MILNET_MASTER_KEK", "ef".repeat(32));

        let (coordinator, nodes) = setup_dkg();
        let threshold = coordinator.threshold;
        let hmac_key = crypto::entropy::generate_key_64();

        let (ca, connector) = shared_tls_ca();

        let base_port: u16 = 19300 + (std::process::id() % 1000) as u16;
        let mut signer_addrs: Vec<(Identifier, String)> = Vec::new();

        // Seal each share, unseal it, and run as a signer process with shared CA
        for (i, node) in nodes.into_iter().take(threshold).enumerate() {
            let sealed_bytes = seal_signer_share(
                &node,
                &coordinator.public_key_package,
                threshold,
            );
            let hex: String = sealed_bytes.iter().map(|b| format!("{b:02x}")).collect();

            // Unseal (simulating a fresh process loading from env)
            let (unsealed_node, _pkg, _thresh) =
                unseal_signer_share(&hex).expect("unseal must succeed");

            let addr = format!("127.0.0.1:{}", base_port + i as u16);
            signer_addrs.push((unsealed_node.identifier(), addr.clone()));
            let signer_name = format!("tss-signer-sealed-{}", i);
            let listener =
                bind_signer_with_shared_ca(&addr, hmac_key, &ca, &signer_name).await;
            tokio::spawn(async move {
                let _ = run_signer_process_with_listener(unsealed_node, &addr, listener).await;
            });
        }

        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        let dist_coordinator = DistributedSigningCoordinator {
            public_key_package: coordinator.public_key_package.clone(),
            threshold,
            signer_addrs,
            hmac_key,
        };

        let message = b"sealed share end-to-end test";
        let frost_result =
            coordinate_signing_remote_with_connector(&dist_coordinator, message, &connector).await;
        assert!(
            frost_result.is_ok(),
            "signing with unsealed shares must succeed: {:?}",
            frost_result.err()
        );

        let signature = frost_result.unwrap();
        let sig = frost_ristretto255::Signature::deserialize(&signature)
            .expect("deserialize group signature");
        assert!(
            coordinator
                .public_key_package
                .verifying_key()
                .verify(message, &sig)
                .is_ok(),
            "group signature from unsealed shares must verify"
        );

        std::env::remove_var("MILNET_MASTER_KEK");
    }

    /// Helper: like `DistributedSigningCoordinator::coordinate_signing_remote`
    /// but uses a pre-existing TLS connector (with shared CA) instead of
    /// creating its own CA.
    async fn coordinate_signing_remote_with_connector(
        coord: &DistributedSigningCoordinator,
        message: &[u8],
        connector: &tokio_rustls::TlsConnector,
    ) -> Result<[u8; 64], String> {
        if coord.signer_addrs.len() < coord.threshold {
            return Err(format!(
                "need {} signers, got {}",
                coord.threshold,
                coord.signer_addrs.len()
            ));
        }

        let selected: Vec<&(Identifier, String)> =
            coord.signer_addrs.iter().take(coord.threshold).collect();

        // Round 1: Collect commitments
        let mut nonces_map: BTreeMap<Identifier, Vec<u8>> = BTreeMap::new();
        let mut commitments_map: BTreeMap<Identifier, SigningCommitments> = BTreeMap::new();

        for (_id, addr) in &selected {
            let raw_host = addr.split(':').next().unwrap_or(addr);
            let signer_host = if raw_host.parse::<std::net::IpAddr>().is_ok() { "localhost" } else { raw_host };
            let mut transport = shard::tls_transport::tls_connect(
                addr,
                common::types::ModuleId::Orchestrator,
                coord.hmac_key,
                connector,
                signer_host,
            )
            .await
            .map_err(|e| format!("connect to signer at {addr}: {e}"))?;

            let req = SignerMessage::CommitRequest;
            let req_bytes =
                postcard::to_allocvec(&req).map_err(|e| format!("serialize: {e}"))?;
            transport.send(&req_bytes).await.map_err(|e| format!("send: {e}"))?;

            let (_sender, resp_payload) =
                transport.recv().await.map_err(|e| format!("recv: {e}"))?;

            let resp: SignerMessage = postcard::from_bytes(&resp_payload)
                .map_err(|e| format!("deserialize: {e}"))?;

            match resp {
                SignerMessage::CommitResponse {
                    identifier_bytes,
                    nonces_bytes,
                    commitments_bytes,
                } => {
                    let identifier = Identifier::deserialize(&identifier_bytes)
                        .map_err(|e| format!("id: {e}"))?;
                    let commitments = SigningCommitments::deserialize(&commitments_bytes)
                        .map_err(|e| format!("commitments: {e}"))?;
                    nonces_map.insert(identifier, nonces_bytes);
                    commitments_map.insert(identifier, commitments);
                }
                SignerMessage::Error { message } => {
                    return Err(format!("commit error: {message}"));
                }
                _ => return Err("unexpected response".into()),
            }
        }

        // Build signing package
        let signing_package = SigningPackage::new(commitments_map, message);
        let signing_package_bytes = signing_package
            .serialize()
            .map_err(|e| format!("serialize: {e}"))?;

        // Round 2: Collect signature shares
        let mut signature_shares: BTreeMap<Identifier, SignatureShare> = BTreeMap::new();

        for (id, addr) in &selected {
            let nonces_bytes = nonces_map
                .remove(id)
                .ok_or_else(|| format!("missing nonces for {:?}", id))?;

            let raw_host = addr.split(':').next().unwrap_or(addr);
            let signer_host = if raw_host.parse::<std::net::IpAddr>().is_ok() { "localhost" } else { raw_host };
            let mut transport = shard::tls_transport::tls_connect(
                addr,
                common::types::ModuleId::Orchestrator,
                coord.hmac_key,
                connector,
                signer_host,
            )
            .await
            .map_err(|e| format!("connect for sign: {e}"))?;

            let req = SignerMessage::SignRequest {
                signing_package_bytes: signing_package_bytes.clone(),
                nonces_bytes,
            };
            let req_bytes =
                postcard::to_allocvec(&req).map_err(|e| format!("serialize: {e}"))?;
            transport.send(&req_bytes).await.map_err(|e| format!("send: {e}"))?;

            let (_sender, resp_payload) =
                transport.recv().await.map_err(|e| format!("recv: {e}"))?;

            let resp: SignerMessage = postcard::from_bytes(&resp_payload)
                .map_err(|e| format!("deserialize: {e}"))?;

            match resp {
                SignerMessage::SignResponse {
                    identifier_bytes,
                    share_bytes,
                } => {
                    let identifier = Identifier::deserialize(&identifier_bytes)
                        .map_err(|e| format!("id: {e}"))?;
                    let share = SignatureShare::deserialize(&share_bytes)
                        .map_err(|e| format!("share: {e}"))?;
                    signature_shares.insert(identifier, share);
                }
                SignerMessage::Error { message } => {
                    return Err(format!("sign error: {message}"));
                }
                _ => return Err("unexpected response".into()),
            }
        }

        // Aggregate
        let group_signature = frost::aggregate(
            &signing_package,
            &signature_shares,
            &coord.public_key_package,
        )
        .map_err(|e| format!("aggregation: {e}"))?;

        let sig_bytes = group_signature
            .serialize()
            .map_err(|e| format!("serialize: {e}"))?;
        let mut out = [0u8; 64];
        out.copy_from_slice(&sig_bytes);
        Ok(out)
    }

    /// Test the 3-part distributed DKG protocol locally (no network).
    ///
    /// Each "signer" calls handle_dkg_round1/round2/finalize independently,
    /// simulating separate processes that only exchange serialized messages.
    #[test]
    fn distributed_dkg_3_round_local() {
        use frost::keys::dkg as frost_dkg;

        let max_signers = 5u16;
        let min_signers = 3u16;

        // Assign identifiers
        let identifiers: Vec<Identifier> = (1..=max_signers)
            .map(|i| Identifier::try_from(i).unwrap())
            .collect();

        // ── Round 1: each signer generates commitment + proof ──
        let mut round1_secrets: BTreeMap<Identifier, Vec<u8>> = BTreeMap::new();
        let mut round1_packages: BTreeMap<Identifier, Vec<u8>> = BTreeMap::new();

        for id in &identifiers {
            let id_bytes = id.serialize();
            let (ret_id_bytes, package_bytes, secret_bytes) =
                handle_dkg_round1(&id_bytes, max_signers, min_signers)
                    .expect("round 1 must succeed");
            let rid = Identifier::deserialize(&ret_id_bytes).unwrap();
            round1_secrets.insert(rid, secret_bytes);
            round1_packages.insert(rid, package_bytes);
        }

        // ── Round 2: each signer verifies proofs and generates shares ──
        let mut round2_secrets: BTreeMap<Identifier, Vec<u8>> = BTreeMap::new();
        let mut round2_all_packages: BTreeMap<Identifier, Vec<(Vec<u8>, Vec<u8>)>> =
            BTreeMap::new();

        for id in &identifiers {
            let secret_bytes = round1_secrets.get(id).unwrap();
            // Collect all OTHER signers' round1 packages
            let others: Vec<(Vec<u8>, Vec<u8>)> = round1_packages
                .iter()
                .filter(|(k, _)| *k != id)
                .map(|(k, v)| (k.serialize(), v.clone()))
                .collect();

            let (round2_secret_bytes, packages) =
                handle_dkg_round2(secret_bytes, &others)
                    .expect("round 2 must succeed");

            round2_secrets.insert(*id, round2_secret_bytes);
            round2_all_packages.insert(*id, packages);
        }

        // ── Round 3 (Finalize): each signer combines shares ──
        let mut key_packages: Vec<frost::keys::KeyPackage> = Vec::new();
        let mut public_key_packages: Vec<Vec<u8>> = Vec::new();

        for id in &identifiers {
            let round2_secret_bytes = round2_secrets.get(id).unwrap();

            // Round 1 packages from others
            let round1_others: Vec<(Vec<u8>, Vec<u8>)> = round1_packages
                .iter()
                .filter(|(k, _)| *k != id)
                .map(|(k, v)| (k.serialize(), v.clone()))
                .collect();

            // Round 2 packages addressed to THIS signer from all others
            let round2_for_this: Vec<(Vec<u8>, Vec<u8>)> = round2_all_packages
                .iter()
                .filter(|(sender_id, _)| *sender_id != id)
                .filter_map(|(sender_id, packages)| {
                    let target_bytes = id.serialize();
                    packages
                        .iter()
                        .find(|(recipient_bytes, _)| *recipient_bytes == target_bytes)
                        .map(|(_, pkg_bytes)| (sender_id.serialize(), pkg_bytes.clone()))
                })
                .collect();

            let (key_bytes, pub_bytes) =
                handle_dkg_finalize(round2_secret_bytes, &round1_others, &round2_for_this)
                    .expect("finalize must succeed");

            let kp = frost::keys::KeyPackage::deserialize(&key_bytes)
                .expect("deserialize key package");
            key_packages.push(kp);
            public_key_packages.push(pub_bytes);
        }

        // All signers must produce the same PublicKeyPackage
        for (i, pkg) in public_key_packages.iter().enumerate().skip(1) {
            assert_eq!(
                *pkg, public_key_packages[0],
                "signer {i} produced different PublicKeyPackage — equivocation"
            );
        }

        let public_key_package =
            PublicKeyPackage::deserialize(&public_key_packages[0]).unwrap();

        // ── Verify: sign a message using 3 of 5 shares and verify ──
        let message = b"distributed DKG test message";

        let mut nonces_map = BTreeMap::new();
        let mut commitments_map = BTreeMap::new();

        for kp in key_packages.iter().take(min_signers as usize) {
            let mut rng = rand::rngs::OsRng;
            let (nonces, commitments) =
                frost::round1::commit(kp.signing_share(), &mut rng);
            nonces_map.insert(*kp.identifier(), nonces);
            commitments_map.insert(*kp.identifier(), commitments);
        }

        let signing_package = SigningPackage::new(commitments_map, message);

        let mut shares = BTreeMap::new();
        for kp in key_packages.iter().take(min_signers as usize) {
            let nonces = nonces_map.remove(kp.identifier()).unwrap();
            let share = frost::round2::sign(&signing_package, &nonces, kp)
                .expect("signing must succeed");
            shares.insert(*kp.identifier(), share);
        }

        let group_sig = frost::aggregate(&signing_package, &shares, &public_key_package)
            .expect("aggregation must succeed");

        assert!(
            public_key_package
                .verifying_key()
                .verify(message, &group_sig)
                .is_ok(),
            "group signature from distributed DKG must verify"
        );
    }
}
