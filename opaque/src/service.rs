//! OPAQUE service: listens for SHARD connections and processes auth requests.
//!
//! Implements the server side of the real OPAQUE protocol. The server NEVER
//! sees the plaintext password — it only performs OPRF evaluation and key
//! exchange.

use std::time::{SystemTime, UNIX_EPOCH};

use common::types::{ModuleId, Receipt};
use crypto::entropy::generate_nonce;
use crypto::receipts::sign_receipt;
use opaque_ke::{
    CredentialFinalization, CredentialRequest,
    RegistrationRequest, RegistrationUpload,
    ServerLogin, ServerLoginParameters, ServerRegistration,
};
use shard::transport::ShardListener;
use tracing::{error, info};

use crate::messages::{OpaqueRequest, OpaqueResponse};
use crate::opaque_impl::OpaqueCs;
use crate::store::CredentialStore;

/// Load receipt signing key: generate random key at startup with a warning.
/// In production, this MUST be loaded from an HSM or secure key store.
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

/// Handle a LoginStart request: perform the server side of OPAQUE login step 1.
///
/// Returns a CredentialResponse and a ServerLogin state that must be kept
/// for the LoginFinish step.
pub fn handle_login_start(
    store: &CredentialStore,
    username: &str,
    credential_request_bytes: &[u8],
) -> Result<(Vec<u8>, ServerLogin<OpaqueCs>), String> {
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

    Ok((response_bytes, server_login_start.state))
}

/// Handle a LoginFinish request: verify the client's credential finalization.
///
/// On success, creates and signs a Receipt.
pub fn handle_login_finish(
    server_login: ServerLogin<OpaqueCs>,
    credential_finalization_bytes: &[u8],
    signing_key: &[u8; 64],
    user_id: uuid::Uuid,
    ceremony_session_id: [u8; 32],
    dpop_key_hash: [u8; 32],
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

            sign_receipt(&mut receipt, signing_key);

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

/// Process a single OPAQUE request (for synchronous/test use).
/// For the 2-round-trip login flow, this handles just LoginStart.
/// The LoginFinish must be handled separately with the ServerLogin state.
///
/// This function handles Register* messages directly (they are admin ops).
/// For Login, use handle_login_start + handle_login_finish separately.
pub fn handle_request(
    store: &mut CredentialStore,
    request: &OpaqueRequest,
    _signing_key: &[u8; 64],
) -> OpaqueResponse {
    match request {
        OpaqueRequest::RegisterStart {
            username,
            registration_request,
        } => match handle_register_start(store, username, registration_request) {
            Ok(response_bytes) => OpaqueResponse::RegisterChallenge {
                registration_response: response_bytes,
            },
            Err(e) => OpaqueResponse::Error { message: e },
        },
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
pub async fn run(mut store: CredentialStore) -> Result<(), Box<dyn std::error::Error>> {
    let shard_hmac_key = load_shard_hmac_key();
    let receipt_signing_key = load_receipt_signing_key();

    let listener = ShardListener::bind(DEFAULT_ADDR, ModuleId::Opaque, shard_hmac_key).await?;
    info!("OPAQUE service listening on {}", DEFAULT_ADDR);

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
                                &receipt_signing_key,
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
