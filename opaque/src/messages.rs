//! Wire messages for the OPAQUE password service.
//!
//! The OPAQUE protocol requires 2 round-trips between client and server for
//! login (CredentialRequest -> CredentialResponse -> CredentialFinalization).
//! These messages support the full multi-step flow.

use common::types::Receipt;
use serde::{Deserialize, Serialize};

/// Serde helper for `[u8; 64]` — serde only supports arrays up to 32 natively.
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

/// Messages from the orchestrator (acting as OPAQUE client) to the OPAQUE service.
#[derive(Serialize, Deserialize)]
pub enum OpaqueRequest {
    /// Login step 1: send the blinded credential request.
    LoginStart {
        username: String,
        /// Serialized `CredentialRequest<OpaqueCs>`.
        credential_request: Vec<u8>,
        ceremony_session_id: [u8; 32],
        #[serde(with = "byte_array_64")]
        dpop_key_hash: [u8; 64],
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
