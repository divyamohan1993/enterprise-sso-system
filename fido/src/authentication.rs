use crate::types::*;
use crate::verification;

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

/// Verify an authentication response from the client.
///
/// Validates the authenticator data structure, RP ID hash, user presence/
/// verification flags, sign count (to detect cloned authenticators), and
/// the assertion signature.
///
/// Returns the new sign count on success so the caller can persist it via
/// [`update_sign_count`].
pub fn verify_authentication_response(
    auth_result: &AuthenticationResult,
    stored_credential: &StoredCredential,
    expected_rp_id: &str,
    require_user_verification: bool,
) -> Result<u32, &'static str> {
    verification::verify_authentication_response(
        auth_result,
        stored_credential,
        expected_rp_id,
        require_user_verification,
    )
}

/// Update the stored sign count after a successful authentication.
///
/// The caller must ensure `new_count` came from a successful call to
/// [`verify_authentication_response`], which already validated that it is
/// strictly greater than the stored value (or both are zero).
pub fn update_sign_count(credential: &mut StoredCredential, new_count: u32) -> Result<(), &'static str> {
    // Defence-in-depth: reject non-increasing updates unless both are zero
    // (authenticator does not support counters).
    if new_count < credential.sign_count {
        return Err("New sign count must not be less than stored sign count");
    }
    if new_count == credential.sign_count && new_count != 0 {
        return Err("New sign count must be strictly greater than stored sign count");
    }
    credential.sign_count = new_count;
    Ok(())
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

    #[test]
    fn test_update_sign_count_valid_increase() {
        let mut cred = StoredCredential {
            credential_id: vec![1],
            public_key: vec![2],
            user_id: Uuid::new_v4(),
            sign_count: 5,
            authenticator_type: "platform".into(),
        };
        assert!(update_sign_count(&mut cred, 10).is_ok());
        assert_eq!(cred.sign_count, 10);
    }

    #[test]
    fn test_update_sign_count_zero_to_zero() {
        let mut cred = StoredCredential {
            credential_id: vec![1],
            public_key: vec![2],
            user_id: Uuid::new_v4(),
            sign_count: 0,
            authenticator_type: "cross-platform".into(),
        };
        // 0 -> 0 is allowed (authenticator doesn't support counters)
        assert!(update_sign_count(&mut cred, 0).is_ok());
        assert_eq!(cred.sign_count, 0);
    }

    #[test]
    fn test_update_sign_count_rejects_decrease() {
        let mut cred = StoredCredential {
            credential_id: vec![1],
            public_key: vec![2],
            user_id: Uuid::new_v4(),
            sign_count: 10,
            authenticator_type: "platform".into(),
        };
        let err = update_sign_count(&mut cred, 5).unwrap_err();
        assert_eq!(err, "New sign count must not be less than stored sign count");
        // Credential unchanged
        assert_eq!(cred.sign_count, 10);
    }

    #[test]
    fn test_update_sign_count_rejects_equal_nonzero() {
        let mut cred = StoredCredential {
            credential_id: vec![1],
            public_key: vec![2],
            user_id: Uuid::new_v4(),
            sign_count: 7,
            authenticator_type: "platform".into(),
        };
        let err = update_sign_count(&mut cred, 7).unwrap_err();
        assert_eq!(
            err,
            "New sign count must be strictly greater than stored sign count"
        );
        assert_eq!(cred.sign_count, 7);
    }
}
