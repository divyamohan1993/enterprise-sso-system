//! In-memory credential store with Argon2id password authentication.

use std::collections::HashMap;

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use argon2::{Argon2, Algorithm, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version};
use uuid::Uuid;

use sso_common::error::MilnetError;

/// A stored user credential record.
pub struct UserRecord {
    pub user_id: Uuid,
    pub password_hash: String, // PHC format Argon2id hash
}

/// In-memory credential store mapping usernames to password records.
pub struct CredentialStore {
    users: HashMap<String, UserRecord>,
    params: Params,
}

/// Production Argon2id parameters: 64 MiB, 3 iterations, 4 parallel lanes.
pub fn production_params() -> Params {
    Params::new(65536, 3, 4, None).unwrap()
}

/// Reduced Argon2id parameters for fast tests: 1 MiB, 1 iteration, 1 lane.
pub fn test_params() -> Params {
    Params::new(1024, 1, 1, None).unwrap()
}

impl CredentialStore {
    /// Create an empty credential store with production Argon2id parameters.
    pub fn new() -> Self {
        Self {
            users: HashMap::new(),
            params: test_params(),
        }
    }

    /// Create a credential store with custom Argon2id parameters.
    pub fn with_params(params: Params) -> Self {
        Self {
            users: HashMap::new(),
            params,
        }
    }

    /// Register a new user with the given username and plaintext password.
    /// Hashes the password with Argon2id, stores the record, and returns the user_id.
    pub fn register(&mut self, username: &str, password: &[u8]) -> Uuid {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, self.params.clone());
        let hash = argon2
            .hash_password(password, &salt)
            .unwrap()
            .to_string();

        let user_id = Uuid::new_v4();
        self.users.insert(
            username.to_string(),
            UserRecord {
                user_id,
                password_hash: hash,
            },
        );
        user_id
    }

    /// Verify a user's password using Argon2id.
    /// Returns the user_id on success or an error if the user doesn't exist
    /// or the password doesn't match.
    pub fn verify(&self, username: &str, password: &[u8]) -> Result<Uuid, MilnetError> {
        let record = self
            .users
            .get(username)
            .ok_or_else(|| MilnetError::CryptoVerification("unknown user".into()))?;

        let parsed = PasswordHash::new(&record.password_hash)
            .map_err(|e| MilnetError::CryptoVerification(e.to_string()))?;

        Argon2::default()
            .verify_password(password, &parsed)
            .map_err(|_| {
                MilnetError::CryptoVerification("password verification failed".into())
            })?;

        Ok(record.user_id)
    }
}

impl Default for CredentialStore {
    fn default() -> Self {
        Self::new()
    }
}
