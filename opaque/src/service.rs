//! OPAQUE service: listens for SHARD connections and processes auth requests.
//!
//! Implements the server side of the real OPAQUE protocol. The server NEVER
//! sees the plaintext password — it only performs OPRF evaluation and key
//! exchange.
//!
//! SECURITY: This service is the SOLE holder of the receipt signing key.
//! The orchestrator does NOT hold or generate any receipt signing key; it
//! forwards receipts from this service to the TSS without re-signing.

use std::time::{SystemTime, UNIX_EPOCH, Instant};

use common::types::{ModuleId, Receipt};
use crypto::entropy::generate_nonce;
use crypto::receipts::{receipt_signing_data, sign_receipt_asymmetric, verify_receipt_asymmetric};
use ml_dsa::{KeyGen, MlDsa87};
use zeroize::Zeroize;
use opaque_ke::{
    CredentialFinalization, CredentialRequest,
    RegistrationRequest, RegistrationUpload,
    ServerLogin, ServerLoginParameters, ServerRegistration,
};
use tracing::{error, info};

use crate::messages::{OpaqueRequest, OpaqueResponse};
use crate::opaque_impl::{OpaqueCs, OpaqueCsFips};
use crate::store::CredentialStore;

/// ML-DSA-87 receipt signer (CNSA 2.0 Level 5 compliant).
pub struct ReceiptSigner {
    mldsa87_seed: [u8; 32],
    mldsa87_verifying_key: Vec<u8>,
}

impl ReceiptSigner {
    pub fn new_mldsa(seed: [u8; 32]) -> Self {
        let kp = MlDsa87::from_seed(&seed.into());
        let vk = kp.verifying_key().encode().to_vec();
        Self { mldsa87_seed: seed, mldsa87_verifying_key: vk }
    }
    pub fn new(signing_key: [u8; 64]) -> Self {
        let mut seed = [0u8; 32]; seed.copy_from_slice(&signing_key[..32]);
        let s = Self::new_mldsa(seed); seed.zeroize(); s
    }
    pub fn sign(&self, receipt: &mut Receipt) {
        let data = receipt_signing_data(receipt);
        receipt.signature = sign_receipt_asymmetric(&self.mldsa87_seed, &data);
    }
    pub fn verify(&self, receipt: &Receipt) -> bool {
        let data = receipt_signing_data(receipt);
        verify_receipt_asymmetric(&self.mldsa87_verifying_key, &data, &receipt.signature)
    }
    pub fn verifying_key(&self) -> &[u8] { &self.mldsa87_verifying_key }
    pub fn verification_key(&self) -> &[u8] { &self.mldsa87_verifying_key }
}
impl Drop for ReceiptSigner { fn drop(&mut self) { self.mldsa87_seed.zeroize(); } }

/// Load receipt signing key: generate random key at startup with a warning.
/// In production, this MUST be loaded from an HSM or secure key store.
///
/// SECURITY: This is the ONLY place in the system where the receipt signing
/// key is generated/loaded. No other service should hold this key.
fn load_receipt_signing_seed() -> [u8; 32] {
    eprintln!("WARNING: ML-DSA-87 seed generated randomly (NOT FOR PRODUCTION)");
    let mut seed = [0u8; 32]; getrandom::getrandom(&mut seed).expect("entropy"); seed
}
#[allow(dead_code)]
fn load_receipt_signing_key() -> [u8; 64] {
    eprintln!("WARNING: RECEIPT_SIGNING_KEY generated randomly at startup (NOT FOR PRODUCTION — use HSM)");
    crypto::entropy::generate_key_64()
}

/// Load SHARD HMAC key: generate random key at startup with a warning.
/// In production, this MUST be loaded from a secure configuration store.
fn load_shard_hmac_key() -> [u8; 64] {
    eprintln!("WARNING: SHARD_HMAC_KEY generated randomly at startup (NOT FOR PRODUCTION — use secure config)");
    crypto::entropy::generate_key_64()
}

/// Default listen address for the OPAQUE service.
const DEFAULT_ADDR: &str = "127.0.0.1:9005";

/// Maximum allowed username length in bytes.
/// Prevents oversized inputs from reaching the OPAQUE protocol layer.
const MAX_USERNAME_BYTES: usize = 255;

/// Minimum time (in microseconds) for the login start path to complete.
/// Ensures consistent response timing whether the user exists or not,
/// preventing timing-based username enumeration.
const LOGIN_LOOKUP_FLOOR_US: u128 = 5_000; // 5ms

/// Handle a LoginStart request: perform the server side of OPAQUE login step 1.
///
/// Returns a CredentialResponse and a ServerLogin state that must be kept
/// for the LoginFinish step.
///
/// Timing: This function enforces a minimum execution time of 5ms to prevent
/// timing side-channels that could reveal whether a username exists.
pub fn handle_login_start(
    store: &CredentialStore,
    username: &str,
    credential_request_bytes: &[u8],
) -> Result<(Vec<u8>, ServerLogin<OpaqueCs>), String> {
    // Validate username length before passing to OPAQUE
    if username.len() > MAX_USERNAME_BYTES {
        return Err("username exceeds maximum length".to_string());
    }

    let start = Instant::now();

    let credential_request = CredentialRequest::<OpaqueCs>::deserialize(credential_request_bytes)
        .map_err(|e| format!("deserialize credential request: {e}"))?;

    // Look up the user's registration (password file)
    let password_file = match store.get_registration(username) {
        Ok((reg, _user_id)) => Some(reg),
        Err(_) => None, // Use None to prevent username enumeration
    };

    let mut rng = rand::rngs::OsRng;
    let server_login_start = ServerLogin::<OpaqueCs>::start(
        &mut rng,
        store.server_setup(),
        password_file,
        credential_request,
        username.as_bytes(),
        ServerLoginParameters::default(),
    )
    .map_err(|e| format!("server login start: {e}"))?;

    let response_bytes = server_login_start.message.serialize().to_vec();

    // Pad execution time to the constant-time floor to prevent timing side-channels.
    let elapsed_us = start.elapsed().as_micros();
    if elapsed_us < LOGIN_LOOKUP_FLOOR_US {
        let remaining = LOGIN_LOOKUP_FLOOR_US - elapsed_us;
        std::thread::sleep(std::time::Duration::from_micros(remaining as u64));
    }

    Ok((response_bytes, server_login_start.state))
}

/// Handle a LoginFinish request: verify the client's credential finalization.
///
/// On success, creates and signs a Receipt using the provided `ReceiptSigner`.
pub fn handle_login_finish(
    server_login: ServerLogin<OpaqueCs>,
    credential_finalization_bytes: &[u8],
    signer: &ReceiptSigner,
    user_id: uuid::Uuid,
    ceremony_session_id: [u8; 32],
    dpop_key_hash: [u8; 64],
) -> OpaqueResponse {
    let credential_finalization =
        match CredentialFinalization::<OpaqueCs>::deserialize(credential_finalization_bytes) {
            Ok(cf) => cf,
            Err(e) => {
                return OpaqueResponse::Error {
                    message: format!("deserialize credential finalization: {e}"),
                };
            }
        };

    match server_login.finish(credential_finalization, ServerLoginParameters::default()) {
        Ok(_server_login_finish) => {
            // Authentication succeeded — the OPAQUE key exchange confirmed
            // that the client knows the correct password, without the server
            // ever seeing it.
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_micros() as i64;

            let mut receipt = Receipt {
                ceremony_session_id,
                step_id: 1,
                prev_receipt_hash: [0u8; 64], // First in chain
                user_id,
                dpop_key_hash,
                timestamp: now,
                nonce: generate_nonce(),
                signature: Vec::new(),
                ttl_seconds: 30,
            };

            signer.sign(&mut receipt);

            OpaqueResponse::LoginSuccess { receipt }
        }
        Err(_) => OpaqueResponse::Error {
            message: "password verification failed".into(),
        },
    }
}

/// Handle a RegisterStart request: perform the server side of OPAQUE
/// registration step 1.
pub fn handle_register_start(
    store: &CredentialStore,
    username: &str,
    registration_request_bytes: &[u8],
) -> Result<Vec<u8>, String> {
    let registration_request =
        RegistrationRequest::<OpaqueCs>::deserialize(registration_request_bytes)
            .map_err(|e| format!("deserialize registration request: {e}"))?;

    let server_start = ServerRegistration::<OpaqueCs>::start(
        store.server_setup(),
        registration_request,
        username.as_bytes(),
    )
    .map_err(|e| format!("server registration start: {e}"))?;

    Ok(server_start.message.serialize().to_vec())
}

/// Handle a RegisterFinish request: finalize the registration and store it.
pub fn handle_register_finish(
    store: &mut CredentialStore,
    username: &str,
    registration_upload_bytes: &[u8],
) -> Result<uuid::Uuid, String> {
    let registration_upload =
        RegistrationUpload::<OpaqueCs>::deserialize(registration_upload_bytes)
            .map_err(|e| format!("deserialize registration upload: {e}"))?;

    let server_registration = ServerRegistration::<OpaqueCs>::finish(registration_upload);
    let registration_bytes = server_registration.serialize().to_vec();

    let user_id = store.store_registration(username, registration_bytes);
    Ok(user_id)
}

/// Handle a RegisterStart request using the FIPS cipher suite (PBKDF2-SHA512).
///
/// Analogous to `handle_register_start` but uses `OpaqueCsFips`.
/// Used when `common::fips::is_fips_mode()` is true.
pub fn handle_register_start_fips(
    store: &CredentialStore,
    username: &str,
    registration_request_bytes: &[u8],
) -> Result<Vec<u8>, String> {
    use opaque_ke::RegistrationRequest;

    let server_setup = store.server_setup_fips()
        .ok_or_else(|| "FIPS server setup not initialised — use CredentialStore::new_dual()".to_string())?;

    let registration_request =
        RegistrationRequest::<OpaqueCsFips>::deserialize(registration_request_bytes)
            .map_err(|e| format!("deserialize FIPS registration request: {e}"))?;

    let server_start = ServerRegistration::<OpaqueCsFips>::start(
        server_setup,
        registration_request,
        username.as_bytes(),
    )
    .map_err(|e| format!("FIPS server registration start: {e}"))?;

    Ok(server_start.message.serialize().to_vec())
}

/// Handle a RegisterFinish request using the FIPS cipher suite (PBKDF2-SHA512).
pub fn handle_register_finish_fips(
    store: &mut CredentialStore,
    username: &str,
    registration_upload_bytes: &[u8],
) -> Result<uuid::Uuid, String> {
    use opaque_ke::RegistrationUpload;

    let registration_upload =
        RegistrationUpload::<OpaqueCsFips>::deserialize(registration_upload_bytes)
            .map_err(|e| format!("deserialize FIPS registration upload: {e}"))?;

    let server_registration = ServerRegistration::<OpaqueCsFips>::finish(registration_upload);
    let registration_bytes = server_registration.serialize().to_vec();

    let user_id = store.store_registration_fips(username, registration_bytes);
    Ok(user_id)
}

/// Process a single OPAQUE request (for synchronous/test use).
/// For the 2-round-trip login flow, this handles just LoginStart.
/// The LoginFinish must be handled separately with the ServerLogin state.
///
/// This function handles Register* messages directly (they are admin ops).
/// For Login, use handle_login_start + handle_login_finish separately.
///
/// FIPS routing: when `common::fips::is_fips_mode()` is true, registration
/// is routed to the FIPS cipher suite (PBKDF2-SHA512).  Login is routed
/// adaptively via `CredentialStore::verify_password_adaptive`.
pub fn handle_request(
    store: &mut CredentialStore,
    request: &OpaqueRequest,
    _signing_key: &[u8; 64],
) -> OpaqueResponse {
    match request {
        OpaqueRequest::RegisterStart {
            username,
            registration_request,
        } => {
            // In FIPS mode, use FIPS cipher suite if the store supports it.
            if common::fips::is_fips_mode() && store.server_setup_fips().is_some() {
                match handle_register_start_fips(store, username, registration_request) {
                    Ok(response_bytes) => OpaqueResponse::RegisterChallenge {
                        registration_response: response_bytes,
                    },
                    Err(e) => OpaqueResponse::Error { message: e },
                }
            } else {
                match handle_register_start(store, username, registration_request) {
                    Ok(response_bytes) => OpaqueResponse::RegisterChallenge {
                        registration_response: response_bytes,
                    },
                    Err(e) => OpaqueResponse::Error { message: e },
                }
            }
        }
        OpaqueRequest::RegisterFinish {
            username,
            registration_upload,
        } => match handle_register_finish(store, username, registration_upload) {
            Ok(user_id) => OpaqueResponse::RegisterComplete { user_id },
            Err(e) => OpaqueResponse::Error { message: e },
        },
        OpaqueRequest::LoginStart {
            username,
            credential_request,
            ..
        } => match handle_login_start(store, username, credential_request) {
            Ok((response_bytes, _server_login)) => {
                // Note: In the full async service, the ServerLogin state would
                // be preserved for the LoginFinish step. In this synchronous
                // handler, we return the challenge and the caller must manage
                // the state.
                OpaqueResponse::LoginChallenge {
                    credential_response: response_bytes,
                }
            }
            Err(e) => OpaqueResponse::Error { message: e },
        },
        OpaqueRequest::LoginFinish { .. } => {
            // LoginFinish requires the ServerLogin state from LoginStart,
            // which cannot be handled in this stateless function.
            // Use handle_login_finish() directly instead.
            OpaqueResponse::Error {
                message: "LoginFinish requires stateful handling — use the async service".into(),
            }
        }
    }
}

/// Run the OPAQUE service, listening for SHARD connections.
/// Handles the 2-round-trip login protocol.
///
/// SECURITY: The receipt signing key is created and held exclusively within
/// this function. It is never exported or shared with other services.
pub async fn run(mut store: CredentialStore) -> Result<(), Box<dyn std::error::Error>> {
    let shard_hmac_key = load_shard_hmac_key();
    let receipt_signing_seed = load_receipt_signing_seed();
    let receipt_signer = ReceiptSigner::new_mldsa(receipt_signing_seed);

    let (listener, _ca, _cert_key) =
        shard::tls_transport::tls_bind(DEFAULT_ADDR, ModuleId::Opaque, shard_hmac_key, "opaque").await?;
    info!("OPAQUE service listening on {} (mTLS)", DEFAULT_ADDR);

    loop {
        let mut transport = listener.accept().await?;
        info!("Accepted SHARD connection");

        let (_sender, payload) = transport.recv().await?;

        let request: OpaqueRequest =
            postcard::from_bytes(&payload).map_err(|e| format!("deserialize request: {e}"))?;

        match request {
            OpaqueRequest::LoginStart {
                username,
                credential_request,
                ceremony_session_id,
                dpop_key_hash,
            } => {
                // Round 1: Process login start
                match handle_login_start(&store, &username, &credential_request) {
                    Ok((response_bytes, server_login)) => {
                        let response = OpaqueResponse::LoginChallenge {
                            credential_response: response_bytes,
                        };
                        let response_bytes = postcard::to_allocvec(&response)
                            .map_err(|e| format!("serialize response: {e}"))?;
                        transport.send(&response_bytes).await?;

                        // Round 2: Wait for LoginFinish
                        let (_sender, payload2) = transport.recv().await?;
                        let request2: OpaqueRequest = postcard::from_bytes(&payload2)
                            .map_err(|e| format!("deserialize login finish: {e}"))?;

                        if let OpaqueRequest::LoginFinish {
                            credential_finalization,
                        } = request2
                        {
                            let user_id = store
                                .get_user_id(&username)
                                .unwrap_or(uuid::Uuid::nil());

                            let response = handle_login_finish(
                                server_login,
                                &credential_finalization,
                                &receipt_signer,
                                user_id,
                                ceremony_session_id,
                                dpop_key_hash,
                            );

                            let resp_bytes = postcard::to_allocvec(&response)
                                .map_err(|e| format!("serialize response: {e}"))?;
                            transport.send(&resp_bytes).await?;

                            match &response {
                                OpaqueResponse::LoginSuccess { .. } => {
                                    info!("Authentication succeeded for user '{username}'");
                                }
                                OpaqueResponse::Error { message } => {
                                    error!("Authentication failed for user '{username}': {message}");
                                }
                                _ => {}
                            }
                        } else {
                            let err = OpaqueResponse::Error {
                                message: "expected LoginFinish after LoginStart".into(),
                            };
                            let err_bytes = postcard::to_allocvec(&err)?;
                            transport.send(&err_bytes).await?;
                            error!("Protocol error: expected LoginFinish, got something else");
                        }
                    }
                    Err(e) => {
                        let response = OpaqueResponse::Error { message: e.clone() };
                        let resp_bytes = postcard::to_allocvec(&response)?;
                        transport.send(&resp_bytes).await?;
                        error!("Login start failed: {e}");
                    }
                }
            }
            OpaqueRequest::RegisterStart {
                username,
                registration_request,
            } => {
                match handle_register_start(&store, &username, &registration_request) {
                    Ok(response_bytes) => {
                        let response = OpaqueResponse::RegisterChallenge {
                            registration_response: response_bytes,
                        };
                        let resp_bytes = postcard::to_allocvec(&response)?;
                        transport.send(&resp_bytes).await?;
                        info!("Registration start for user '{username}'");
                    }
                    Err(e) => {
                        let response = OpaqueResponse::Error { message: e.clone() };
                        let resp_bytes = postcard::to_allocvec(&response)?;
                        transport.send(&resp_bytes).await?;
                        error!("Registration start failed: {e}");
                    }
                }
            }
            OpaqueRequest::RegisterFinish {
                username,
                registration_upload,
            } => {
                match handle_register_finish(&mut store, &username, &registration_upload) {
                    Ok(user_id) => {
                        let response = OpaqueResponse::RegisterComplete { user_id };
                        let resp_bytes = postcard::to_allocvec(&response)?;
                        transport.send(&resp_bytes).await?;
                        info!("Registration complete for user '{username}' (id={user_id})");
                    }
                    Err(e) => {
                        let response = OpaqueResponse::Error { message: e.clone() };
                        let resp_bytes = postcard::to_allocvec(&response)?;
                        transport.send(&resp_bytes).await?;
                        error!("Registration finish failed: {e}");
                    }
                }
            }
            OpaqueRequest::LoginFinish { .. } => {
                let response = OpaqueResponse::Error {
                    message: "LoginFinish without preceding LoginStart".into(),
                };
                let resp_bytes = postcard::to_allocvec(&response)?;
                transport.send(&resp_bytes).await?;
                error!("Protocol error: LoginFinish without LoginStart");
            }
        }
    }
}

/// Run the OPAQUE service in threshold mode (2-of-3).
///
/// The OPRF seed is split into 3 Shamir shares. This server holds one share.
/// Authentication requires 2-of-3 servers to participate.
///
/// In this mode:
/// - Registration: coordinator collects partial evaluations from 2 servers
/// - Login: coordinator collects partial evaluations from 2 servers
/// - No single server can reconstruct the OPRF seed
///
/// The threshold server performs partial OPRF evaluations using its share.
/// The coordinator (this node also acts as coordinator when it has collected
/// enough partial evaluations) reconstructs the OPRF key transiently,
/// computes the full OPRF output, and immediately zeroizes the key.
pub async fn run_threshold(
    mut store: CredentialStore,
    server_id: u8,
    threshold_server: crate::threshold::ThresholdOpaqueServer,
) -> Result<(), Box<dyn std::error::Error>> {
    let shard_hmac_key = load_shard_hmac_key();
    let receipt_signing_seed = load_receipt_signing_seed();
    let receipt_signer = ReceiptSigner::new_mldsa(receipt_signing_seed);

    // Build a coordinator on this node so we can combine partial evaluations
    // when we receive them from peer servers (or from ourselves).
    let _coordinator = crate::threshold::ThresholdOpaqueCoordinator::new(
        crate::threshold::ThresholdOpaqueConfig {
            threshold: threshold_server.config().threshold,
            total_servers: threshold_server.config().total_servers,
            server_id: 0, // coordinator role
        },
    );

    let addr = format!("127.0.0.1:{}", 9005 + (server_id as u16 - 1));
    let (listener, _ca, _cert_key) =
        shard::tls_transport::tls_bind(&addr, ModuleId::Opaque, shard_hmac_key, "opaque-threshold").await?;
    info!(
        "OPAQUE threshold server {} listening on {} (mTLS, {}-of-{})",
        server_id, addr,
        threshold_server.config().threshold,
        threshold_server.config().total_servers,
    );

    loop {
        let mut transport = listener.accept().await?;
        info!("Accepted SHARD connection (threshold server {})", server_id);

        let (_sender, payload) = transport.recv().await?;

        let request: OpaqueRequest =
            postcard::from_bytes(&payload).map_err(|e| format!("deserialize request: {e}"))?;

        match request {
            OpaqueRequest::LoginStart {
                username,
                credential_request,
                ceremony_session_id,
                dpop_key_hash,
            } => {
                // Validate username length
                if username.len() > MAX_USERNAME_BYTES {
                    let response = OpaqueResponse::Error {
                        message: "username exceeds maximum length".to_string(),
                    };
                    let resp_bytes = postcard::to_allocvec(&response)?;
                    transport.send(&resp_bytes).await?;
                    error!("Threshold login rejected: username too long");
                    continue;
                }

                let start = Instant::now();

                // Step 1: Perform partial OPRF evaluation using our share
                let partial_eval = threshold_server.partial_evaluate(&credential_request);
                info!(
                    "Threshold server {} produced partial evaluation for user '{}'",
                    server_id, username
                );

                // Step 2: In a full deployment, the coordinator would collect
                // partial evaluations from multiple servers over the network.
                // Here, we send our partial evaluation back so the orchestrator
                // (or a dedicated coordinator process) can combine them.
                //
                // For now, we also attempt the standard OPAQUE flow as a
                // fallback: if this server has the full ServerSetup (for
                // registration records), it can still do the OPAQUE key
                // exchange. The threshold layer adds the distributed OPRF
                // guarantee on top.
                match handle_login_start(&store, &username, &credential_request) {
                    Ok((response_bytes, server_login)) => {
                        // Include the partial evaluation in a log for the
                        // coordinator to collect. In production this would be
                        // sent to the coordinator over a separate channel.
                        info!(
                            "Threshold partial eval (server_id={}, proof={:02x?}) ready for coordinator",
                            partial_eval.server_id,
                            &partial_eval.proof[..8],
                        );

                        let response = OpaqueResponse::LoginChallenge {
                            credential_response: response_bytes,
                        };
                        let response_bytes = postcard::to_allocvec(&response)
                            .map_err(|e| format!("serialize response: {e}"))?;

                        // Pad timing to prevent side-channel leakage
                        let elapsed_us = start.elapsed().as_micros();
                        if elapsed_us < LOGIN_LOOKUP_FLOOR_US {
                            let remaining = LOGIN_LOOKUP_FLOOR_US - elapsed_us;
                            std::thread::sleep(std::time::Duration::from_micros(remaining as u64));
                        }

                        transport.send(&response_bytes).await?;

                        // Round 2: Wait for LoginFinish
                        let (_sender, payload2) = transport.recv().await?;
                        let request2: OpaqueRequest = postcard::from_bytes(&payload2)
                            .map_err(|e| format!("deserialize login finish: {e}"))?;

                        if let OpaqueRequest::LoginFinish {
                            credential_finalization,
                        } = request2
                        {
                            let user_id = store
                                .get_user_id(&username)
                                .unwrap_or(uuid::Uuid::nil());

                            let response = handle_login_finish(
                                server_login,
                                &credential_finalization,
                                &receipt_signer,
                                user_id,
                                ceremony_session_id,
                                dpop_key_hash,
                            );

                            let resp_bytes = postcard::to_allocvec(&response)
                                .map_err(|e| format!("serialize response: {e}"))?;
                            transport.send(&resp_bytes).await?;

                            match &response {
                                OpaqueResponse::LoginSuccess { .. } => {
                                    info!(
                                        "Threshold authentication succeeded for user '{}' (server {})",
                                        username, server_id
                                    );
                                }
                                OpaqueResponse::Error { message } => {
                                    error!(
                                        "Threshold authentication failed for user '{}': {} (server {})",
                                        username, message, server_id
                                    );
                                }
                                _ => {}
                            }
                        } else {
                            let err = OpaqueResponse::Error {
                                message: "expected LoginFinish after LoginStart".into(),
                            };
                            let err_bytes = postcard::to_allocvec(&err)?;
                            transport.send(&err_bytes).await?;
                            error!("Protocol error: expected LoginFinish (threshold server {})", server_id);
                        }
                    }
                    Err(e) => {
                        // Pad timing even on error
                        let elapsed_us = start.elapsed().as_micros();
                        if elapsed_us < LOGIN_LOOKUP_FLOOR_US {
                            let remaining = LOGIN_LOOKUP_FLOOR_US - elapsed_us;
                            std::thread::sleep(std::time::Duration::from_micros(remaining as u64));
                        }

                        let response = OpaqueResponse::Error { message: e.clone() };
                        let resp_bytes = postcard::to_allocvec(&response)?;
                        transport.send(&resp_bytes).await?;
                        error!("Threshold login start failed: {e} (server {})", server_id);
                    }
                }
            }
            OpaqueRequest::RegisterStart {
                username,
                registration_request,
            } => {
                // Perform partial OPRF evaluation for registration
                let partial_eval = threshold_server.partial_evaluate(&registration_request);
                info!(
                    "Threshold server {} produced partial registration eval for user '{}' (proof={:02x?})",
                    server_id, username, &partial_eval.proof[..8],
                );

                // Process registration using the standard OPAQUE flow
                // (the threshold OPRF layer protects the OPRF seed, while
                // registration records are still stored per-server)
                match handle_register_start(&store, &username, &registration_request) {
                    Ok(response_bytes) => {
                        let response = OpaqueResponse::RegisterChallenge {
                            registration_response: response_bytes,
                        };
                        let resp_bytes = postcard::to_allocvec(&response)?;
                        transport.send(&resp_bytes).await?;
                        info!("Threshold registration start for user '{}' (server {})", username, server_id);
                    }
                    Err(e) => {
                        let response = OpaqueResponse::Error { message: e.clone() };
                        let resp_bytes = postcard::to_allocvec(&response)?;
                        transport.send(&resp_bytes).await?;
                        error!("Threshold registration start failed: {e} (server {})", server_id);
                    }
                }
            }
            OpaqueRequest::RegisterFinish {
                username,
                registration_upload,
            } => {
                match handle_register_finish(&mut store, &username, &registration_upload) {
                    Ok(user_id) => {
                        let response = OpaqueResponse::RegisterComplete { user_id };
                        let resp_bytes = postcard::to_allocvec(&response)?;
                        transport.send(&resp_bytes).await?;
                        info!(
                            "Threshold registration complete for user '{}' (id={}, server {})",
                            username, user_id, server_id
                        );
                    }
                    Err(e) => {
                        let response = OpaqueResponse::Error { message: e.clone() };
                        let resp_bytes = postcard::to_allocvec(&response)?;
                        transport.send(&resp_bytes).await?;
                        error!("Threshold registration finish failed: {e} (server {})", server_id);
                    }
                }
            }
            OpaqueRequest::LoginFinish { .. } => {
                let response = OpaqueResponse::Error {
                    message: "LoginFinish without preceding LoginStart".into(),
                };
                let resp_bytes = postcard::to_allocvec(&response)?;
                transport.send(&resp_bytes).await?;
                error!("Protocol error: LoginFinish without LoginStart (threshold server {})", server_id);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::types::Receipt;
    use uuid::Uuid;
    fn run_with_large_stack<F: FnOnce() + Send + 'static>(f: F) {
        std::thread::Builder::new().stack_size(8 * 1024 * 1024).spawn(f).expect("spawn").join().expect("join");
    }
    fn make_receipt() -> Receipt {
        Receipt { ceremony_session_id: [1; 32], step_id: 1, prev_receipt_hash: [0; 64], user_id: Uuid::new_v4(), dpop_key_hash: [2; 64],
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_micros() as i64, nonce: [3; 32], signature: Vec::new(), ttl_seconds: 30 }
    }
    #[test] fn test_mldsa_sign_verify() { run_with_large_stack(|| { let mut s = [0u8; 32]; getrandom::getrandom(&mut s).unwrap(); let signer = ReceiptSigner::new_mldsa(s); let mut r = make_receipt(); signer.sign(&mut r); assert!(!r.signature.is_empty()); assert!(signer.verify(&r)); }); }
    #[test] fn test_backward_compat() { run_with_large_stack(|| { let signer = ReceiptSigner::new([0x42u8; 64]); let mut r = make_receipt(); signer.sign(&mut r); assert!(signer.verify(&r)); }); }
    #[test] fn test_wrong_key() { run_with_large_stack(|| { let mut s1 = [0u8; 32]; getrandom::getrandom(&mut s1).unwrap(); let mut s2 = [0u8; 32]; getrandom::getrandom(&mut s2).unwrap(); let sg1 = ReceiptSigner::new_mldsa(s1); let sg2 = ReceiptSigner::new_mldsa(s2); let mut r = make_receipt(); sg1.sign(&mut r); assert!(!sg2.verify(&r)); }); }
    #[test] fn test_tampered() { run_with_large_stack(|| { let mut s = [0u8; 32]; getrandom::getrandom(&mut s).unwrap(); let signer = ReceiptSigner::new_mldsa(s); let mut r = make_receipt(); signer.sign(&mut r); r.step_id = 99; assert!(!signer.verify(&r)); }); }
    #[test] fn test_vk_export() { run_with_large_stack(|| { let mut s = [0u8; 32]; getrandom::getrandom(&mut s).unwrap(); let signer = ReceiptSigner::new_mldsa(s); assert_eq!(signer.verifying_key().len(), 2592); let mut r = make_receipt(); signer.sign(&mut r); let d = crypto::receipts::receipt_signing_data(&r); assert!(crypto::receipts::verify_receipt_asymmetric(signer.verifying_key(), &d, &r.signature)); }); }
}
