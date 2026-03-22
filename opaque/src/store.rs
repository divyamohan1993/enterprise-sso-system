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

use crate::opaque_impl::OpaqueCs;

/// A stored user credential record.
pub struct UserRecord {
    pub user_id: Uuid,
    /// Serialized `ServerRegistration<OpaqueCs>` — contains NO password info.
    pub registration: Vec<u8>,
}

/// In-memory credential store mapping usernames to OPAQUE registration records.
pub struct CredentialStore {
    users: HashMap<String, UserRecord>,
    /// The server's OPAQUE setup (OPRF seed + keypair). Must be persisted
    /// across restarts in production.
    server_setup: ServerSetup<OpaqueCs>,
}

impl CredentialStore {
    /// Create an empty credential store with a fresh ServerSetup.
    pub fn new() -> Self {
        let mut rng = OsRng;
        let server_setup = ServerSetup::<OpaqueCs>::new(&mut rng);
        Self {
            users: HashMap::new(),
            server_setup,
        }
    }

    /// Create a credential store with a provided ServerSetup (for testing or
    /// when restoring from persistent storage).
    pub fn with_server_setup(server_setup: ServerSetup<OpaqueCs>) -> Self {
        Self {
            users: HashMap::new(),
            server_setup,
        }
    }

    /// Returns a reference to the server setup.
    pub fn server_setup(&self) -> &ServerSetup<OpaqueCs> {
        &self.server_setup
    }

    /// Store a completed registration for a user.
    ///
    /// This is called after the full OPAQUE registration flow completes
    /// (client_start -> server_start -> client_finish -> server_finish).
    /// The `registration` is a serialized `ServerRegistration<OpaqueCs>`.
    pub fn store_registration(
        &mut self,
        username: &str,
        registration_bytes: Vec<u8>,
    ) -> Uuid {
        let user_id = Uuid::new_v4();
        self.users.insert(
            username.to_string(),
            UserRecord {
                user_id,
                registration: registration_bytes,
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

    /// Restore a user registration from persistent storage (e.g. PostgreSQL).
    pub fn restore_user(&mut self, username: &str, user_id: Uuid, registration_bytes: Vec<u8>) {
        self.users.insert(username.to_string(), UserRecord {
            user_id,
            registration: registration_bytes,
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
        let client_start = ClientRegistration::<OpaqueCs>::start(&mut rng, password)
            .expect("client registration start");

        // Step 2: Server processes registration request
        let server_start = ServerRegistration::<OpaqueCs>::start(
            &self.server_setup,
            client_start.message,
            username.as_bytes(),
        )
        .expect("server registration start");

        // Step 3: Client finishes registration
        let client_finish = client_start.state.finish(
            &mut rng,
            password,
            server_start.message,
            ClientRegistrationFinishParameters::default(),
        )
        .expect("client registration finish");

        // Step 4: Server finishes registration — produces the password file
        let server_registration = ServerRegistration::<OpaqueCs>::finish(client_finish.message);
        let registration_bytes = server_registration.serialize().to_vec();

        self.store_registration(username, registration_bytes)
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

impl Default for CredentialStore {
    fn default() -> Self {
        Self::new()
    }
}
