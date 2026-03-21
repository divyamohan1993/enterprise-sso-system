//! Wire messages for the OPAQUE password service.
//!
//! The OPAQUE protocol requires 2 round-trips between client and server for
//! login (CredentialRequest -> CredentialResponse -> CredentialFinalization).
//! These messages support the full multi-step flow.

use common::types::Receipt;
use serde::{Deserialize, Serialize};

/// Messages from the orchestrator (acting as OPAQUE client) to the OPAQUE service.
#[derive(Serialize, Deserialize)]
pub enum OpaqueRequest {
    /// Login step 1: send the blinded credential request.
    LoginStart {
        username: String,
        /// Serialized `CredentialRequest<OpaqueCs>`.
        credential_request: Vec<u8>,
        ceremony_session_id: [u8; 32],
        dpop_key_hash: [u8; 32],
    },
    /// Login step 2: send the credential finalization.
    LoginFinish {
        /// Serialized `CredentialFinalization<OpaqueCs>`.
        credential_finalization: Vec<u8>,
    },
    /// Registration step 1: send the blinded registration request.
    RegisterStart {
        username: String,
        /// Serialized `RegistrationRequest<OpaqueCs>`.
        registration_request: Vec<u8>,
    },
    /// Registration step 3: send the registration upload (client's finish message).
    RegisterFinish {
        username: String,
        /// Serialized `RegistrationUpload<OpaqueCs>`.
        registration_upload: Vec<u8>,
    },
}

/// Messages from the OPAQUE service back to the orchestrator.
#[derive(Serialize, Deserialize)]
pub enum OpaqueResponse {
    /// Login step 1 response: the server's credential response.
    LoginChallenge {
        /// Serialized `CredentialResponse<OpaqueCs>`.
        credential_response: Vec<u8>,
    },
    /// Login step 2 response: authentication succeeded, here is your receipt.
    LoginSuccess {
        receipt: Receipt,
    },
    /// Registration step 1 response: the server's registration response.
    RegisterChallenge {
        /// Serialized `RegistrationResponse<OpaqueCs>`.
        registration_response: Vec<u8>,
    },
    /// Registration step 3 response: registration is complete.
    RegisterComplete {
        user_id: uuid::Uuid,
    },
    /// Error response for any step.
    Error {
        message: String,
    },
}
