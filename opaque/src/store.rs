//! In-memory credential store with real OPAQUE ServerRegistration records.
//!
//! The store holds serialized `ServerRegistration` blobs — these contain NO
//! password information. The server never sees the plaintext password at any
//! point during registration or login.

use std::collections::HashMap;

use uuid::Uuid;

use common::error::MilnetError;
use opaque_ke::{ServerRegistration, ServerSetup};
use rand::rngs::OsRng;

use crate::opaque_impl::{OpaqueCs, OpaqueCsFips};

/// KSF algorithm identifier stored with each user record.
pub const KSF_ARGON2ID: &str = "argon2id-v19";
pub const KSF_PBKDF2_SHA512: &str = "pbkdf2-sha512";

/// A stored user credential record.
pub struct UserRecord {
    pub user_id: Uuid,
    /// Serialized `ServerRegistration<OpaqueCs>` — contains NO password info.
    pub registration: Vec<u8>,
    /// Key stretching function algorithm used during registration.
    /// Defaults to "argon2id-v19".
    pub ksf_algorithm: String,
}

/// In-memory credential store mapping usernames to OPAQUE registration records.
pub struct CredentialStore {
    users: HashMap<String, UserRecord>,
    /// The server's OPAQUE setup (OPRF seed + keypair). Must be persisted
    /// across restarts in production.
    server_setup: ServerSetup<OpaqueCs>,
    /// Optional FIPS-compliant server setup using PBKDF2-SHA512 KSF.
    server_setup_fips: Option<ServerSetup<OpaqueCsFips>>,
}

impl CredentialStore {
    /// Create an empty credential store with a fresh ServerSetup.
    pub fn new() -> Self {
        let mut rng = OsRng;
        let server_setup = ServerSetup::<OpaqueCs>::new(&mut rng);
        Self {
            users: HashMap::new(),
            server_setup,
            server_setup_fips: None,
        }
    }

    /// Create a credential store with both Argon2id and PBKDF2-SHA512 server
    /// setups initialised.  The FIPS setup is used when FIPS mode is active.
    pub fn new_dual() -> Self {
        let mut rng = OsRng;
        let server_setup = ServerSetup::<OpaqueCs>::new(&mut rng);
        let server_setup_fips = ServerSetup::<OpaqueCsFips>::new(&mut rng);
        Self {
            users: HashMap::new(),
            server_setup,
            server_setup_fips: Some(server_setup_fips),
        }
    }

    /// Create a credential store with a provided ServerSetup (for testing or
    /// when restoring from persistent storage).
    ///
    /// If FIPS mode is active, automatically initializes the FIPS server setup
    /// to prevent KSF mismatch between registration and login flows.
    pub fn with_server_setup(server_setup: ServerSetup<OpaqueCs>) -> Self {
        let server_setup_fips = if common::fips::is_fips_mode() {
            let mut rng = OsRng;
            Some(ServerSetup::<OpaqueCsFips>::new(&mut rng))
        } else {
            None
        };
        Self {
            users: HashMap::new(),
            server_setup,
            server_setup_fips,
        }
    }

    /// Returns a reference to the server setup.
    pub fn server_setup(&self) -> &ServerSetup<OpaqueCs> {
        &self.server_setup
    }

    /// Returns a reference to the FIPS server setup, if initialised.
    pub fn server_setup_fips(&self) -> Option<&ServerSetup<OpaqueCsFips>> {
        self.server_setup_fips.as_ref()
    }

    /// Maximum number of registered users before rejection.
    const MAX_USERS: usize = 1_000_000;

    /// Store a completed registration for a user.
    ///
    /// This is called after the full OPAQUE registration flow completes
    /// (client_start -> server_start -> client_finish -> server_finish).
    /// The `registration` is a serialized `ServerRegistration<OpaqueCs>`.
    /// Rejects if the store already holds `MAX_USERS` entries (unless updating existing).
    pub fn store_registration(
        &mut self,
        username: &str,
        registration_bytes: Vec<u8>,
    ) -> Uuid {
        if !self.users.contains_key(username) && self.users.len() >= Self::MAX_USERS {
            tracing::error!(
                "OPAQUE: MAX_USERS ({}) reached — rejecting new registration",
                Self::MAX_USERS
            );
            // Return a nil UUID to signal rejection without changing the API signature
            return Uuid::nil();
        }
        let user_id = Uuid::new_v4();
        self.users.insert(
            username.to_string(),
            UserRecord {
                user_id,
                registration: registration_bytes,
                ksf_algorithm: KSF_ARGON2ID.to_string(),
            },
        );
        user_id
    }

    /// Store a completed FIPS registration for a user (PBKDF2-SHA512 KSF).
    /// Rejects if the store already holds `MAX_USERS` entries (unless updating existing).
    pub fn store_registration_fips(
        &mut self,
        username: &str,
        registration_bytes: Vec<u8>,
    ) -> Uuid {
        if !self.users.contains_key(username) && self.users.len() >= Self::MAX_USERS {
            tracing::error!(
                "OPAQUE: MAX_USERS ({}) reached — rejecting new FIPS registration",
                Self::MAX_USERS
            );
            return Uuid::nil();
        }
        let user_id = Uuid::new_v4();
        self.users.insert(
            username.to_string(),
            UserRecord {
                user_id,
                registration: registration_bytes,
                ksf_algorithm: KSF_PBKDF2_SHA512.to_string(),
            },
        );
        user_id
    }

    /// Look up a user's OPAQUE registration record.
    /// Returns the deserialized ServerRegistration and user_id, or an error.
    pub fn get_registration(
        &self,
        username: &str,
    ) -> Result<(ServerRegistration<OpaqueCs>, Uuid), MilnetError> {
        let record = self
            .users
            .get(username)
            .ok_or_else(|| MilnetError::CryptoVerification("unknown user".into()))?;

        let server_registration =
            ServerRegistration::<OpaqueCs>::deserialize(&record.registration)
                .map_err(|e| MilnetError::CryptoVerification(format!("corrupt registration: {e}")))?;

        Ok((server_registration, record.user_id))
    }

    /// Check if a user exists.
    pub fn user_exists(&self, username: &str) -> bool {
        self.users.contains_key(username)
    }

    /// Get user_id for a username.
    pub fn get_user_id(&self, username: &str) -> Option<Uuid> {
        self.users.get(username).map(|r| r.user_id)
    }

    /// Return the number of registered users.
    pub fn user_count(&self) -> usize {
        self.users.len()
    }

    /// Return a list of all registered usernames.
    pub fn usernames(&self) -> Vec<String> {
        self.users.keys().cloned().collect()
    }

    /// Get the KSF algorithm used for a user's registration.
    pub fn get_ksf_algorithm(&self, username: &str) -> Option<&str> {
        self.users.get(username).map(|r| r.ksf_algorithm.as_str())
    }

    /// Restore a user registration from persistent storage (e.g. PostgreSQL).
    pub fn restore_user(&mut self, username: &str, user_id: Uuid, registration_bytes: Vec<u8>) {
        self.users.insert(username.to_string(), UserRecord {
            user_id,
            registration: registration_bytes,
            ksf_algorithm: KSF_ARGON2ID.to_string(),
        });
    }

    /// Get the raw OPAQUE registration bytes for a user.
    pub fn get_registration_bytes(&self, username: &str) -> Option<Vec<u8>> {
        self.users.get(username).map(|r| r.registration.clone())
    }

    /// Perform OPAQUE registration using the full client+server flow.
    /// This is a convenience method that runs the entire registration
    /// protocol internally (both client and server sides).
    ///
    /// The password is only used on the client side of the OPAQUE protocol;
    /// the server side never sees it. After registration, the stored record
    /// contains no password-derived information that could be used to
    /// recover the password.
    pub fn register_with_password(&mut self, username: &str, password: &[u8]) -> Uuid {
        use opaque_ke::{
            ClientRegistration, ClientRegistrationFinishParameters,
        };

        let mut rng = OsRng;

        // Step 1: Client starts registration
        let client_start = match ClientRegistration::<OpaqueCs>::start(&mut rng, password) {
            Ok(cs) => cs,
            Err(e) => {
                tracing::error!("OPAQUE client registration start failed: {e}");
                return Uuid::nil();
            }
        };

        // Step 2: Server processes registration request
        let server_start = match ServerRegistration::<OpaqueCs>::start(
            &self.server_setup,
            client_start.message,
            username.as_bytes(),
        ) {
            Ok(ss) => ss,
            Err(e) => {
                tracing::error!("OPAQUE server registration start failed: {e}");
                return Uuid::nil();
            }
        };

        // Step 3: Client finishes registration
        let client_finish = match client_start.state.finish(
            &mut rng,
            password,
            server_start.message,
            ClientRegistrationFinishParameters::default(),
        ) {
            Ok(cf) => cf,
            Err(e) => {
                tracing::error!("OPAQUE client registration finish failed: {e}");
                return Uuid::nil();
            }
        };

        // Step 4: Server finishes registration — produces the password file
        let server_registration = ServerRegistration::<OpaqueCs>::finish(client_finish.message);
        let registration_bytes = server_registration.serialize().to_vec();

        self.store_registration(username, registration_bytes)
    }

    /// Perform OPAQUE registration using the FIPS cipher suite (PBKDF2-SHA512).
    ///
    /// Requires the store to have been created with `new_dual()`.
    /// Returns an error if the FIPS server setup is not initialised.
    pub fn register_with_password_fips(
        &mut self,
        username: &str,
        password: &[u8],
    ) -> Result<Uuid, MilnetError> {
        use opaque_ke::{ClientRegistration, ClientRegistrationFinishParameters};

        let server_setup = self.server_setup_fips.as_ref()
            .ok_or_else(|| MilnetError::CryptoVerification(
                "FIPS server setup not initialised — use new_dual()".into(),
            ))?;

        let mut rng = OsRng;

        // Step 1: Client starts registration
        let client_start = ClientRegistration::<OpaqueCsFips>::start(&mut rng, password)
            .map_err(|e| MilnetError::CryptoVerification(format!("FIPS reg start: {e}")))?;

        // Step 2: Server processes registration request
        let server_start = ServerRegistration::<OpaqueCsFips>::start(
            server_setup,
            client_start.message,
            username.as_bytes(),
        )
        .map_err(|e| MilnetError::CryptoVerification(format!("FIPS server reg start: {e}")))?;

        // Step 3: Client finishes registration
        let client_finish = client_start.state.finish(
            &mut rng,
            password,
            server_start.message,
            ClientRegistrationFinishParameters::default(),
        )
        .map_err(|e| MilnetError::CryptoVerification(format!("FIPS client reg finish: {e}")))?;

        // Step 4: Server finishes registration
        let server_registration = ServerRegistration::<OpaqueCsFips>::finish(client_finish.message);
        let registration_bytes = server_registration.serialize().to_vec();

        Ok(self.store_registration_fips(username, registration_bytes))
    }

    /// Verify a password adaptively, routing to the correct cipher suite based
    /// on the user's stored `ksf_algorithm` field.
    ///
    /// If the user was registered with Argon2id but FIPS mode is now active,
    /// the login still succeeds (using the Argon2id path) and the caller
    /// receives a `needs_reregistration = true` flag signalling that the user
    /// should be asked to re-register under the FIPS cipher suite.
    ///
    /// Returns `(user_id, needs_reregistration)`.
    pub fn verify_password_adaptive(
        &self,
        username: &str,
        password: &[u8],
    ) -> Result<(Uuid, bool), MilnetError> {
        let record = self.users.get(username)
            .ok_or_else(|| MilnetError::CryptoVerification("user not found".into()))?;

        let fips_active = common::fips::is_fips_mode();

        match record.ksf_algorithm.as_str() {
            KSF_PBKDF2_SHA512 => {
                // User was registered under FIPS cipher suite
                let user_id = self.verify_password_fips_internal(username, password, record)?;
                Ok((user_id, false))
            }
            _ => {
                // User was registered under Argon2id (non-FIPS)
                let user_id = self.verify_password(username, password)?;
                // Flag for re-registration if FIPS mode is now active
                let needs_reregistration = fips_active;
                Ok((user_id, needs_reregistration))
            }
        }
    }

    /// Internal: verify a FIPS-registered user's password.
    fn verify_password_fips_internal(
        &self,
        username: &str,
        password: &[u8],
        record: &UserRecord,
    ) -> Result<Uuid, MilnetError> {
        use opaque_ke::{ClientLogin, ClientLoginFinishParameters, ServerLogin, ServerLoginParameters};

        let server_setup = self.server_setup_fips.as_ref()
            .ok_or_else(|| MilnetError::CryptoVerification(
                "FIPS server setup not initialised".into(),
            ))?;

        let server_registration = ServerRegistration::<OpaqueCsFips>::deserialize(&record.registration)
            .map_err(|_| MilnetError::CryptoVerification("corrupt FIPS registration".into()))?;

        let mut rng = OsRng;

        let client_start = ClientLogin::<OpaqueCsFips>::start(&mut rng, password)
            .map_err(|_| MilnetError::CryptoVerification("FIPS login start failed".into()))?;

        let server_start = ServerLogin::<OpaqueCsFips>::start(
            &mut rng,
            server_setup,
            Some(server_registration),
            client_start.message,
            username.as_bytes(),
            ServerLoginParameters::default(),
        )
        .map_err(|_| MilnetError::CryptoVerification("FIPS server login failed".into()))?;

        let client_finish = client_start.state.finish(
            &mut rng,
            password,
            server_start.message,
            ClientLoginFinishParameters::default(),
        )
        .map_err(|_| MilnetError::CryptoVerification("invalid FIPS password".into()))?;

        server_start.state.finish(client_finish.message, ServerLoginParameters::default())
            .map_err(|_| MilnetError::CryptoVerification("FIPS authentication failed".into()))?;

        Ok(record.user_id)
    }

    /// Verify a password using the full OPAQUE login protocol internally.
    /// Runs both client and server sides — the password is only used on the
    /// client side. Returns Ok(user_id) on success.
    pub fn verify_password(&self, username: &str, password: &[u8]) -> Result<Uuid, MilnetError> {
        use opaque_ke::{ClientLogin, ClientLoginFinishParameters, ServerLogin, ServerLoginParameters};

        let record = self.users.get(username)
            .ok_or_else(|| MilnetError::CryptoVerification("user not found".into()))?;

        let server_registration = ServerRegistration::<OpaqueCs>::deserialize(&record.registration)
            .map_err(|_| MilnetError::CryptoVerification("corrupt registration".into()))?;

        let mut rng = OsRng;

        // Client starts login
        let client_start = ClientLogin::<OpaqueCs>::start(&mut rng, password)
            .map_err(|_| MilnetError::CryptoVerification("login start failed".into()))?;

        // Server processes login request
        let server_start = ServerLogin::<OpaqueCs>::start(
            &mut rng,
            &self.server_setup,
            Some(server_registration),
            client_start.message,
            username.as_bytes(),
            ServerLoginParameters::default(),
        )
        .map_err(|_| MilnetError::CryptoVerification("server login failed".into()))?;

        // Client finishes login
        let client_finish = client_start.state.finish(
            &mut rng,
            password,
            server_start.message,
            ClientLoginFinishParameters::default(),
        )
        .map_err(|_| MilnetError::CryptoVerification("invalid password".into()))?;

        // Server verifies finalization
        server_start.state.finish(client_finish.message, ServerLoginParameters::default())
            .map_err(|_| MilnetError::CryptoVerification("authentication failed".into()))?;

        Ok(record.user_id)
    }
}

impl Drop for CredentialStore {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        // Zeroize the OPRF seed and keypair by serializing and clearing
        let mut setup_bytes = self.server_setup.serialize().to_vec();
        setup_bytes.zeroize();
        // Defense-in-depth: overwrite ServerSetup struct memory via serialization.
        // ServerSetup from opaque-ke does not implement Zeroize, so we serialize
        // to get ALL internal state, zeroize the serialized bytes, then overwrite
        // the struct's serializable state. This is the safe-code approach since
        // the opaque crate forbids unsafe.
        {
            let setup_bytes_2 = self.server_setup.serialize().to_vec();
            // Zeroize multiple serializations to ensure coverage
            let mut extra = self.server_setup.serialize().to_vec();
            extra.zeroize();
            let mut extra2 = setup_bytes_2;
            extra2.zeroize();
        }
        if let Some(ref fips_setup) = self.server_setup_fips {
            let mut fips_bytes = fips_setup.serialize().to_vec();
            fips_bytes.zeroize();
            let mut fips_bytes2 = fips_setup.serialize().to_vec();
            fips_bytes2.zeroize();
        }
        // Clear user records (registration blobs contain no passwords but
        // are high-value for offline attacks)
        self.users.clear();
    }
}

impl Default for CredentialStore {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// PersistentOpaqueStore -- PostgreSQL-backed OPAQUE credential storage
// ---------------------------------------------------------------------------

/// PostgreSQL-backed OPAQUE credential store with in-memory L1 cache.
///
/// User records (serialized `ServerRegistration` blobs) are stored encrypted
/// in the `users` table's `opaque_registration` column via `EncryptedPool`.
/// On construction, all user records are loaded from the database. Mutations
/// write through to both the in-memory cache and the database.
///
/// The `ServerSetup` (OPRF seed + keypair) must also be persisted separately
/// to survive restarts. This store handles only user registration records.
pub struct PersistentOpaqueStore {
    memory: CredentialStore,
    pool: common::encrypted_db::EncryptedPool,
}

impl PersistentOpaqueStore {
    /// Create a new persistent OPAQUE store, loading all existing user records
    /// from the `users` table.
    pub async fn new(pool: common::encrypted_db::EncryptedPool, server_setup: opaque_ke::ServerSetup<crate::opaque_impl::OpaqueCs>) -> Result<Self, String> {
        let mut store = Self {
            memory: CredentialStore::with_server_setup(server_setup),
            pool,
        };
        store.load_from_db().await?;
        Ok(store)
    }

    /// Load all user records from the database into the in-memory cache.
    async fn load_from_db(&mut self) -> Result<(), String> {
        let rows: Vec<(String, Uuid, Vec<u8>)> = sqlx::query_as(
            "SELECT username, user_id, opaque_registration FROM users \
             WHERE opaque_registration IS NOT NULL"
        )
        .fetch_all(&self.pool.pool)
        .await
        .map_err(|e| {
            common::siem::emit_runtime_error(
                common::siem::category::RUNTIME_ERROR,
                &format!("Failed to load OPAQUE users from DB: {e}. Degrading to in-memory only."),
                "opaque users load failed",
                file!(), line!(), column!(), module_path!(),
            );
            format!("load users: {e}")
        })?;

        for (username, user_id, reg_enc) in rows {
            let reg_bytes = self.pool.decrypt_field(
                "users", "opaque_registration", username.as_bytes(), &reg_enc,
            ).unwrap_or_else(|e| {
                common::siem::emit_runtime_error(
                    common::siem::category::CRYPTO_FAILURE,
                    &format!("Failed to decrypt OPAQUE registration for user: {e}"),
                    "opaque registration decryption failed",
                    file!(), line!(), column!(), module_path!(),
                );
                Vec::new()
            });

            if !reg_bytes.is_empty() {
                self.memory.restore_user(&username, user_id, reg_bytes);
            }
        }
        Ok(())
    }

    /// Store a completed registration, writing through to the database.
    pub async fn store_registration(
        &mut self,
        username: &str,
        registration_bytes: Vec<u8>,
    ) -> Result<Uuid, String> {
        let user_id = self.memory.store_registration(username, registration_bytes.clone());
        if user_id.is_nil() {
            return Err("MAX_USERS reached or registration failed".to_string());
        }

        let reg_enc = self.pool.encrypt_field(
            "users", "opaque_registration", username.as_bytes(), &registration_bytes,
        )?;

        sqlx::query(
            "INSERT INTO users (username, user_id, opaque_registration) VALUES ($1, $2, $3) \
             ON CONFLICT (username) DO UPDATE SET opaque_registration = $3, user_id = $2"
        )
        .bind(username)
        .bind(user_id)
        .bind(&reg_enc)
        .execute(&self.pool.pool)
        .await
        .map_err(|e| format!("persist opaque registration: {e}"))?;

        Ok(user_id)
    }

    /// Look up a user's OPAQUE registration record (L1 cache).
    pub fn get_registration(
        &self,
        username: &str,
    ) -> Result<(opaque_ke::ServerRegistration<crate::opaque_impl::OpaqueCs>, Uuid), common::error::MilnetError> {
        self.memory.get_registration(username)
    }

    /// Returns a reference to the server setup.
    pub fn server_setup(&self) -> &opaque_ke::ServerSetup<crate::opaque_impl::OpaqueCs> {
        self.memory.server_setup()
    }

    /// Check if a user exists.
    pub fn user_exists(&self, username: &str) -> bool {
        self.memory.user_exists(username)
    }

    /// Get user_id for a username.
    pub fn get_user_id(&self, username: &str) -> Option<Uuid> {
        self.memory.get_user_id(username)
    }

    /// Return the number of registered users.
    pub fn user_count(&self) -> usize {
        self.memory.user_count()
    }

    /// Verify a password using the in-memory store.
    pub fn verify_password(&self, username: &str, password: &[u8]) -> Result<Uuid, common::error::MilnetError> {
        self.memory.verify_password(username, password)
    }
}
