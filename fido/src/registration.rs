use crate::types::*;
use std::collections::HashMap;
use uuid::Uuid;

/// Create registration options for a new FIDO2 credential.
///
/// Set `prefer_platform` to `true` to request a platform authenticator
/// such as Windows Hello or Touch ID.
pub fn create_registration_options(
    rp_name: &str,
    rp_id: &str,
    user_id: &Uuid,
    user_name: &str,
    prefer_platform: bool,
) -> PublicKeyCredentialCreationOptions {
    let challenge = crypto::entropy::generate_nonce().to_vec();

    PublicKeyCredentialCreationOptions {
        challenge,
        rp: RelyingParty {
            name: rp_name.to_string(),
            id: rp_id.to_string(),
        },
        user: UserEntity {
            id: user_id.as_bytes().to_vec(),
            name: user_name.to_string(),
            display_name: user_name.to_string(),
        },
        pub_key_cred_params: vec![
            PubKeyCredParam {
                cred_type: "public-key".into(),
                alg: -7,
            }, // ES256
            PubKeyCredParam {
                cred_type: "public-key".into(),
                alg: -257,
            }, // RS256
            PubKeyCredParam {
                cred_type: "public-key".into(),
                alg: -8,
            }, // EdDSA
        ],
        timeout: 60000,
        attestation: "direct".into(),
        authenticator_selection: AuthenticatorSelection {
            authenticator_attachment: if prefer_platform {
                Some("platform".into())
            } else {
                None
            },
            resident_key: "preferred".into(),
            user_verification: "required".into(),
        },
    }
}

/// In-memory credential store for FIDO2 credentials.
pub struct CredentialStore {
    credentials: HashMap<Vec<u8>, StoredCredential>,
    challenges: HashMap<Vec<u8>, Uuid>,
}

impl CredentialStore {
    pub fn new() -> Self {
        Self {
            credentials: HashMap::new(),
            challenges: HashMap::new(),
        }
    }

    /// Store a pending challenge associated with a user.
    pub fn store_challenge(&mut self, challenge: &[u8], user_id: Uuid) {
        self.challenges.insert(challenge.to_vec(), user_id);
    }

    /// Consume and validate a challenge, returning the associated user ID.
    pub fn consume_challenge(&mut self, challenge: &[u8]) -> Option<Uuid> {
        self.challenges.remove(challenge)
    }

    /// Store a completed credential registration.
    pub fn store_credential(&mut self, cred: StoredCredential) {
        self.credentials.insert(cred.credential_id.clone(), cred);
    }

    /// Look up a credential by its ID.
    pub fn get_credential(&self, credential_id: &[u8]) -> Option<&StoredCredential> {
        self.credentials.get(credential_id)
    }

    /// Get all credentials belonging to a user.
    pub fn get_user_credentials(&self, user_id: &Uuid) -> Vec<&StoredCredential> {
        self.credentials
            .values()
            .filter(|c| c.user_id == *user_id)
            .collect()
    }

    /// Return the total number of stored credentials.
    pub fn credential_count(&self) -> usize {
        self.credentials.len()
    }
}

impl Default for CredentialStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registration_options_created() {
        let user_id = Uuid::new_v4();
        let opts = create_registration_options(
            "MILNET SSO",
            "sso.milnet.example",
            &user_id,
            "alice",
            false,
        );

        assert_eq!(opts.rp.name, "MILNET SSO");
        assert_eq!(opts.rp.id, "sso.milnet.example");
        assert_eq!(opts.user.name, "alice");
        assert_eq!(opts.user.id, user_id.as_bytes().to_vec());
        assert_eq!(opts.challenge.len(), 32);
        assert_eq!(opts.pub_key_cred_params.len(), 3);
        assert_eq!(opts.timeout, 60000);
        assert_eq!(opts.attestation, "direct");
        assert!(opts.authenticator_selection.authenticator_attachment.is_none());
        assert_eq!(opts.authenticator_selection.user_verification, "required");
    }

    #[test]
    fn test_platform_authenticator_preferred() {
        let user_id = Uuid::new_v4();
        let opts = create_registration_options(
            "MILNET SSO",
            "sso.milnet.example",
            &user_id,
            "bob",
            true, // prefer platform (Windows Hello)
        );

        assert_eq!(
            opts.authenticator_selection.authenticator_attachment,
            Some("platform".to_string())
        );
    }

    #[test]
    fn test_credential_store_operations() {
        let mut store = CredentialStore::new();
        let user_id = Uuid::new_v4();
        let cred_id = vec![1, 2, 3, 4];

        // Store a challenge
        let challenge = vec![10, 20, 30];
        store.store_challenge(&challenge, user_id);
        assert_eq!(store.consume_challenge(&challenge), Some(user_id));
        // Challenge is consumed
        assert_eq!(store.consume_challenge(&challenge), None);

        // Store a credential
        let cred = StoredCredential {
            credential_id: cred_id.clone(),
            public_key: vec![5, 6, 7, 8],
            user_id,
            sign_count: 0,
            authenticator_type: "cross-platform".into(),
        };
        store.store_credential(cred);

        assert!(store.get_credential(&cred_id).is_some());
        assert_eq!(store.get_credential(&cred_id).unwrap().user_id, user_id);
        assert_eq!(store.get_user_credentials(&user_id).len(), 1);
        assert_eq!(store.credential_count(), 1);

        // Unknown credential
        assert!(store.get_credential(&[99]).is_none());

        // Unknown user
        let other = Uuid::new_v4();
        assert!(store.get_user_credentials(&other).is_empty());
    }
}
