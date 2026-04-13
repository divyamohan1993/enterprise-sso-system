use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroize;

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
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct StoredCredential {
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub user_id: Uuid,
    pub sign_count: u32,
    /// `"platform"` (Windows Hello, Touch ID) or `"cross-platform"` (YubiKey).
    pub authenticator_type: String,
    /// FIDO2 AAGUID of the registering authenticator (16 bytes).
    /// Defaults to all-zero for legacy records loaded without an AAGUID.
    #[serde(default = "default_aaguid")]
    pub aaguid: [u8; 16],
    /// B7 — set to `true` when a sign-count rollback is detected. While this
    /// flag is set the credential is locked out and ALL future assertions are
    /// rejected until an admin re-enrolls it via the OPAQUE admin path.
    #[serde(default)]
    pub cloned_flag: bool,
    /// WebAuthn `backupEligible` (BE) flag from the most recent ceremony.
    #[serde(default)]
    pub backup_eligible: bool,
    /// WebAuthn `backupState` (BS) flag from the most recent ceremony.
    #[serde(default)]
    pub backup_state: bool,
}

fn default_aaguid() -> [u8; 16] { [0u8; 16] }

impl std::fmt::Debug for StoredCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredCredential")
            .field("credential_id", &"[REDACTED]")
            .field("public_key", &"[REDACTED]")
            .field("user_id", &self.user_id)
            .field("sign_count", &self.sign_count)
            .field("authenticator_type", &self.authenticator_type)
            .finish()
    }
}

impl Drop for StoredCredential {
    fn drop(&mut self) {
        self.credential_id.zeroize();
        self.public_key.zeroize();
    }
}

/// Registration result returned by the client.
#[derive(Clone, Serialize, Deserialize)]
pub struct RegistrationResult {
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub attestation_object: Vec<u8>,
    pub client_data: Vec<u8>,
}

impl std::fmt::Debug for RegistrationResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegistrationResult")
            .field("credential_id", &format!("[{} bytes]", self.credential_id.len()))
            .field("public_key", &"[REDACTED]")
            .field("attestation_object", &format!("[{} bytes]", self.attestation_object.len()))
            .field("client_data", &format!("[{} bytes]", self.client_data.len()))
            .finish()
    }
}

impl Drop for RegistrationResult {
    fn drop(&mut self) {
        self.credential_id.zeroize();
        self.public_key.zeroize();
        self.attestation_object.zeroize();
        self.client_data.zeroize();
    }
}

/// Authentication result returned by the client.
#[derive(Clone, Serialize, Deserialize)]
pub struct AuthenticationResult {
    pub credential_id: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub client_data: Vec<u8>,
    pub signature: Vec<u8>,
}

impl std::fmt::Debug for AuthenticationResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthenticationResult")
            .field("credential_id", &format!("[{} bytes]", self.credential_id.len()))
            .field("authenticator_data", &format!("[{} bytes]", self.authenticator_data.len()))
            .field("client_data", &format!("[{} bytes]", self.client_data.len()))
            .field("signature", &"[REDACTED]")
            .finish()
    }
}

impl Drop for AuthenticationResult {
    fn drop(&mut self) {
        self.credential_id.zeroize();
        self.authenticator_data.zeroize();
        self.client_data.zeroize();
        self.signature.zeroize();
    }
}
