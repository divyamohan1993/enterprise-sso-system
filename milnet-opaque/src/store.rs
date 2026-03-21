//! In-memory credential store for simulated OPAQUE password authentication.

use std::collections::HashMap;

use sha2::{Digest, Sha256};
use uuid::Uuid;

use milnet_common::error::MilnetError;
use milnet_crypto::ct::ct_eq;

/// A stored user credential record.
pub struct UserRecord {
    pub user_id: Uuid,
    pub password_hash: [u8; 32], // SHA-256 of password (simplified; real OPAQUE later)
}

/// In-memory credential store mapping usernames to password records.
pub struct CredentialStore {
    users: HashMap<String, UserRecord>,
}

impl CredentialStore {
    /// Create an empty credential store.
    pub fn new() -> Self {
        Self {
            users: HashMap::new(),
        }
    }

    /// Register a new user with the given username and plaintext password.
    /// Hashes the password with SHA-256, stores the record, and returns the user_id.
    pub fn register(&mut self, username: &str, password: &[u8]) -> Uuid {
        let mut hasher = Sha256::new();
        hasher.update(password);
        let hash = hasher.finalize();

        let mut password_hash = [0u8; 32];
        password_hash.copy_from_slice(&hash);

        let user_id = Uuid::new_v4();
        self.users.insert(
            username.to_string(),
            UserRecord {
                user_id,
                password_hash,
            },
        );
        user_id
    }

    /// Verify a user's password hash using constant-time comparison.
    /// Returns the user_id on success or an error if the user doesn't exist
    /// or the password hash doesn't match.
    pub fn verify(&self, username: &str, password_hash: &[u8; 32]) -> Result<Uuid, MilnetError> {
        let record = self.users.get(username).ok_or_else(|| {
            MilnetError::CryptoVerification("unknown user".into())
        })?;

        if !ct_eq(&record.password_hash, password_hash) {
            return Err(MilnetError::CryptoVerification(
                "password verification failed".into(),
            ));
        }

        Ok(record.user_id)
    }
}

impl Default for CredentialStore {
    fn default() -> Self {
        Self::new()
    }
}
