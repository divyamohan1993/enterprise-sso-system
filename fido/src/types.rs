use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicKeyCredentialCreationOptions {
    pub challenge: Vec<u8>,
    pub rp: RelyingParty,
    pub user: UserEntity,
    pub pub_key_cred_params: Vec<PubKeyCredParam>,
    pub timeout: u64,
    pub attestation: String,
    pub authenticator_selection: AuthenticatorSelection,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude_credentials: Vec<AllowCredential>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelyingParty {
    pub name: String,
    pub id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserEntity {
    pub id: Vec<u8>,
    pub name: String,
    pub display_name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PubKeyCredParam {
    #[serde(rename = "type")]
    pub cred_type: String,
    pub alg: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthenticatorSelection {
    /// `Some("platform")` for Windows Hello / Touch ID;
    /// `None` or `Some("cross-platform")` for security keys.
    pub authenticator_attachment: Option<String>,
    pub resident_key: String,
    pub user_verification: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicKeyCredentialRequestOptions {
    pub challenge: Vec<u8>,
    pub timeout: u64,
    pub rp_id: String,
    pub allow_credentials: Vec<AllowCredential>,
    pub user_verification: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AllowCredential {
    #[serde(rename = "type")]
    pub cred_type: String,
    pub id: Vec<u8>,
}

/// Stored credential for a user.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredCredential {
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub user_id: Uuid,
    pub sign_count: u32,
    /// `"platform"` (Windows Hello, Touch ID) or `"cross-platform"` (YubiKey).
    pub authenticator_type: String,
}

/// Registration result returned by the client.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegistrationResult {
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub attestation_object: Vec<u8>,
    pub client_data: Vec<u8>,
}

/// Authentication result returned by the client.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthenticationResult {
    pub credential_id: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub client_data: Vec<u8>,
    pub signature: Vec<u8>,
}
