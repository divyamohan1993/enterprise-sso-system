use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Hash a client secret with Argon2id for storage at rest.
///
/// Uses the client_id as a domain-separated salt to avoid rainbow tables.
/// Returns hex-encoded hash.
fn hash_client_secret(client_id: &str, plaintext_secret: &str) -> Result<String, String> {
    // Domain-separated salt: SHA-256("milnet-client-secret:" || client_id)
    let mut salt_hasher = Sha256::new();
    salt_hasher.update(b"milnet-client-secret:");
    salt_hasher.update(client_id.as_bytes());
    let salt = salt_hasher.finalize();

    // Use the crypto crate's Argon2id KSF (64MiB, 3 iterations, 4 threads, 32-byte output)
    let derived = common::siem_unwrap!(
        crypto::kdf::stretch_password(plaintext_secret.as_bytes(), &salt[..16]),
        "argon2id stretch for client secret hashing",
        CRYPTO_FAILURE
    );
    Ok(hex::encode(derived))
}

/// Verify a plaintext secret against a stored Argon2id hash using constant-time comparison.
fn verify_client_secret(client_id: &str, plaintext_secret: &str, stored_hash: &str) -> bool {
    let candidate_hash = match hash_client_secret(client_id, plaintext_secret) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!("client secret verification failed (argon2id error): {e}");
            return false; // Fail-closed: deny access on crypto failure
        }
    };
    crypto::ct::ct_eq(candidate_hash.as_bytes(), stored_hash.as_bytes())
}

#[derive(Clone, Serialize, Deserialize)]
pub struct OAuthClient {
    pub client_id: String,
    /// Argon2id hash of the client secret (never stored in plaintext).
    pub client_secret: String,
    pub redirect_uris: Vec<String>,
    pub name: String,
    pub allowed_scopes: Vec<String>,
}

/// Custom Debug for OAuthClient — redacts the secret hash to prevent log leakage.
impl std::fmt::Debug for OAuthClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthClient")
            .field("client_id", &self.client_id)
            .field("client_secret", &"[REDACTED]")
            .field("redirect_uris", &self.redirect_uris)
            .field("name", &self.name)
            .field("allowed_scopes", &self.allowed_scopes)
            .finish()
    }
}

/// Registration result returned to the caller, containing the plaintext secret
/// exactly once. The registry only stores the Argon2id hash.
pub struct ClientRegistrationResult {
    pub client_id: String,
    pub plaintext_secret: zeroize::Zeroizing<String>,
    pub redirect_uris: Vec<String>,
    pub name: String,
    pub allowed_scopes: Vec<String>,
}

/// Custom Debug for ClientRegistrationResult — redacts the plaintext secret.
impl std::fmt::Debug for ClientRegistrationResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientRegistrationResult")
            .field("client_id", &self.client_id)
            .field("plaintext_secret", &"[REDACTED]")
            .field("redirect_uris", &self.redirect_uris)
            .field("name", &self.name)
            .field("allowed_scopes", &self.allowed_scopes)
            .finish()
    }
}

pub struct ClientRegistry {
    clients: std::collections::HashMap<String, OAuthClient>,
}

impl ClientRegistry {
    pub fn new() -> Self {
        Self {
            clients: std::collections::HashMap::new(),
        }
    }

    pub fn register(&mut self, name: &str, redirect_uris: Vec<String>) -> Result<ClientRegistrationResult, String> {
        let client_id = Uuid::new_v4().to_string();
        let plaintext_secret = hex::encode(crypto::entropy::generate_nonce());
        let secret_hash = hash_client_secret(&client_id, &plaintext_secret)?;
        let client = OAuthClient {
            client_id: client_id.clone(),
            client_secret: secret_hash,
            redirect_uris: redirect_uris.clone(),
            name: name.to_string(),
            allowed_scopes: vec!["openid".into(), "profile".into()],
        };
        let result = ClientRegistrationResult {
            client_id: client_id.clone(),
            plaintext_secret: zeroize::Zeroizing::new(plaintext_secret),
            redirect_uris,
            name: name.to_string(),
            allowed_scopes: client.allowed_scopes.clone(),
        };
        self.clients.insert(client_id, client);
        Ok(result)
    }

    /// Register a client with a specific client_id and secret (for pre-seeding).
    /// The provided secret is hashed with Argon2id before storage.
    pub fn register_with_id(
        &mut self,
        client_id: &str,
        client_secret: &str,
        name: &str,
        redirect_uris: Vec<String>,
    ) -> Result<OAuthClient, String> {
        let secret_hash = hash_client_secret(client_id, client_secret)?;
        let client = OAuthClient {
            client_id: client_id.to_string(),
            client_secret: secret_hash,
            redirect_uris,
            name: name.to_string(),
            allowed_scopes: vec!["openid".into(), "profile".into(), "email".into()],
        };
        self.clients.insert(client.client_id.clone(), client.clone());
        Ok(client)
    }

    /// Validate a client's credentials by hashing the provided secret and
    /// comparing against the stored Argon2id hash using constant-time comparison.
    pub fn validate(&self, client_id: &str, client_secret: &str) -> Option<&OAuthClient> {
        self.clients
            .get(client_id)
            .filter(|c| verify_client_secret(client_id, client_secret, &c.client_secret))
    }

    pub fn get(&self, client_id: &str) -> Option<&OAuthClient> {
        self.clients.get(client_id)
    }
}

impl Default for ClientRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// PersistentClientRegistry -- PostgreSQL-backed OAuth client storage
// ---------------------------------------------------------------------------

/// PostgreSQL-backed OAuth client registry with in-memory L1 cache.
///
/// Client records are stored in the `portals` table with `client_secret`
/// encrypted via `EncryptedPool`. On construction, all client records are
/// loaded from the database. Mutations write through to both the L1 cache
/// and the database.
///
/// If the database is unavailable at startup, a SIEM critical warning is
/// emitted and the store degrades to in-memory only.
pub struct PersistentClientRegistry {
    memory: ClientRegistry,
    pool: common::encrypted_db::EncryptedPool,
}

impl PersistentClientRegistry {
    /// Create a new persistent client registry, loading all existing clients
    /// from the `portals` table.
    pub async fn new(pool: common::encrypted_db::EncryptedPool) -> Result<Self, String> {
        let mut store = Self {
            memory: ClientRegistry::new(),
            pool,
        };
        store.load_from_db().await?;
        Ok(store)
    }

    /// Load all client records from the database into the in-memory cache.
    async fn load_from_db(&mut self) -> Result<(), String> {
        let rows: Vec<(String, Vec<u8>, String, String)> = sqlx::query_as(
            "SELECT client_id, client_secret, name, redirect_uris FROM portals"
        )
        .fetch_all(&self.pool.pool)
        .await
        .map_err(|e| {
            common::siem::emit_runtime_error(
                common::siem::category::RUNTIME_ERROR,
                &format!("Failed to load OAuth clients from DB: {e}. Degrading to in-memory only."),
                "portals load failed",
                file!(), line!(), column!(), module_path!(),
            );
            format!("load portals: {e}")
        })?;

        for (client_id, secret_enc, name, redirect_uris_json) in rows {
            let secret_hash = self.pool.decrypt_field(
                "portals", "client_secret", client_id.as_bytes(), &secret_enc,
            ).unwrap_or_else(|e| {
                common::siem::emit_runtime_error(
                    common::siem::category::CRYPTO_FAILURE,
                    &format!("Failed to decrypt client secret for {}: {e}", client_id),
                    "client secret decryption failed",
                    file!(), line!(), column!(), module_path!(),
                );
                Vec::new()
            });

            if secret_hash.is_empty() {
                continue;
            }

            let redirect_uris: Vec<String> = serde_json::from_str(&redirect_uris_json)
                .unwrap_or_default();

            let client = OAuthClient {
                client_id: client_id.clone(),
                client_secret: String::from_utf8_lossy(&secret_hash).to_string(),
                redirect_uris,
                name,
                allowed_scopes: vec!["openid".into(), "profile".into()],
            };
            self.memory.clients.insert(client_id, client);
        }
        Ok(())
    }

    /// Register a new OAuth client, writing through to the database.
    pub async fn register(&mut self, name: &str, redirect_uris: Vec<String>) -> Result<ClientRegistrationResult, String> {
        let result = self.memory.register(name, redirect_uris.clone())?;

        let client = self.memory.get(&result.client_id)
            .ok_or("client not found after registration")?;

        let secret_enc = self.pool.encrypt_field(
            "portals", "client_secret", result.client_id.as_bytes(),
            client.client_secret.as_bytes(),
        )?;

        let redirect_uris_json = serde_json::to_string(&redirect_uris)
            .map_err(|e| format!("serialize redirect_uris: {e}"))?;

        sqlx::query(
            "INSERT INTO portals (client_id, client_secret, name, redirect_uris) \
             VALUES ($1, $2, $3, $4) ON CONFLICT (client_id) DO UPDATE \
             SET client_secret = $2, name = $3, redirect_uris = $4"
        )
        .bind(&result.client_id)
        .bind(&secret_enc)
        .bind(name)
        .bind(&redirect_uris_json)
        .execute(&self.pool.pool)
        .await
        .map_err(|e| format!("persist client: {e}"))?;

        Ok(result)
    }

    /// Validate a client's credentials (L1 cache lookup).
    pub fn validate(&self, client_id: &str, client_secret: &str) -> Option<&OAuthClient> {
        self.memory.validate(client_id, client_secret)
    }

    /// Look up a client by ID (L1 cache).
    pub fn get(&self, client_id: &str) -> Option<&OAuthClient> {
        self.memory.get(client_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_stores_hash_not_plaintext() {
        let mut reg = ClientRegistry::new();
        let result = reg.register("test", vec!["https://ex.com/cb".into()]).unwrap();
        let stored = reg.get(&result.client_id).unwrap();
        // Stored secret must be the Argon2id hash, not the plaintext.
        assert_ne!(stored.client_secret, *result.plaintext_secret);
        // Validation with the correct plaintext must succeed.
        assert!(reg.validate(&result.client_id, &*result.plaintext_secret).is_some());
    }

    #[test]
    fn test_validate_rejects_wrong_secret() {
        let mut reg = ClientRegistry::new();
        let result = reg.register("test", vec!["https://ex.com/cb".into()]).unwrap();
        assert!(reg.validate(&result.client_id, "wrong-secret").is_none());
    }

    #[test]
    fn test_register_with_id_hashes_secret() {
        let mut reg = ClientRegistry::new();
        let _client = reg.register_with_id("cid", "my-secret", "test", vec![]).unwrap();
        assert!(reg.validate("cid", "my-secret").is_some());
        assert!(reg.validate("cid", "other").is_none());
    }

    #[test]
    fn test_debug_redacts_secret() {
        let mut reg = ClientRegistry::new();
        let result = reg.register("test", vec![]).unwrap();
        let client = reg.get(&result.client_id).unwrap();
        let debug_output = format!("{:?}", client);
        assert!(debug_output.contains("[REDACTED]"));
        assert!(!debug_output.contains(&client.client_secret));
    }

    #[test]
    fn test_registration_result_debug_redacts() {
        let mut reg = ClientRegistry::new();
        let result = reg.register("test", vec![]).unwrap();
        let debug_output = format!("{:?}", result);
        assert!(debug_output.contains("[REDACTED]"));
        assert!(!debug_output.contains(&*result.plaintext_secret));
    }
}
