use crate::types::*;

/// Create authentication (assertion) options for an existing user's credentials.
pub fn create_authentication_options(
    rp_id: &str,
    credentials: &[&StoredCredential],
) -> PublicKeyCredentialRequestOptions {
    let challenge = crypto::entropy::generate_nonce().to_vec();

    PublicKeyCredentialRequestOptions {
        challenge,
        timeout: 60000,
        rp_id: rp_id.to_string(),
        allow_credentials: credentials
            .iter()
            .map(|c| AllowCredential {
                cred_type: "public-key".into(),
                id: c.credential_id.clone(),
            })
            .collect(),
        user_verification: "required".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn test_authentication_options_created() {
        let user_id = Uuid::new_v4();
        let cred1 = StoredCredential {
            credential_id: vec![1, 2, 3],
            public_key: vec![10, 20, 30],
            user_id,
            sign_count: 5,
            authenticator_type: "platform".into(),
        };
        let cred2 = StoredCredential {
            credential_id: vec![4, 5, 6],
            public_key: vec![40, 50, 60],
            user_id,
            sign_count: 2,
            authenticator_type: "cross-platform".into(),
        };

        let opts = create_authentication_options("sso.milnet.example", &[&cred1, &cred2]);

        assert_eq!(opts.rp_id, "sso.milnet.example");
        assert_eq!(opts.challenge.len(), 32);
        assert_eq!(opts.timeout, 60000);
        assert_eq!(opts.user_verification, "required");
        assert_eq!(opts.allow_credentials.len(), 2);
        assert_eq!(opts.allow_credentials[0].id, vec![1, 2, 3]);
        assert_eq!(opts.allow_credentials[1].id, vec![4, 5, 6]);
        assert_eq!(opts.allow_credentials[0].cred_type, "public-key");
    }

    #[test]
    fn test_authentication_options_empty_credentials() {
        let opts = create_authentication_options("sso.milnet.example", &[]);
        assert!(opts.allow_credentials.is_empty());
        assert_eq!(opts.challenge.len(), 32);
    }
}
