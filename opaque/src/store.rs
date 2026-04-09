//! In-memory credential store with real OPAQUE ServerRegistration records.
//!
//! The store holds serialized `ServerRegistration` blobs -- these contain NO
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

/// Number of pre-computed fake registrations for timing-safe user-not-found handling.
const FAKE_REGISTRATION_COUNT: usize = 64;

/// Pre-computed pool of fake OPAQUE registrations used to prevent timing oracles.
/// When verify_password or verify_password_adaptive is called for a non-existent user,
/// the full OPAQUE login protocol runs against one of these fake registrations so that
/// both code paths (user exists vs. not) take approximately equal time.
struct FakeRegistrationPool {
    registrations: Vec<Vec<u8>>,
}

impl FakeRegistrationPool {
    fn generate(server_setup: &ServerSetup<OpaqueCs>, count: usize) -> Self {
        use opaque_ke::{ClientRegistration, ClientRegistrationFinishParameters};

        let mut rng = OsRng;
        let mut registrations = Vec::with_capacity(count);

        for i in 0..count {
            let fake_password = format!("__fake_timing_pad_{i}__");
            let fake_username = format!("__nonexistent_timing_pad_{i}__");

            let client_start =
                ClientRegistration::<OpaqueCs>::start(&mut rng, fake_password.as_bytes())
                    .expect("fake registration client start must succeed");
            let server_start = ServerRegistration::<OpaqueCs>::start(
                server_setup,
                client_start.message,
                fake_username.as_bytes(),
            )
            .expect("fake registration server start must succeed");
            let client_finish = client_start
                .state
                .finish(
                    &mut rng,
                    fake_password.as_bytes(),
                    server_start.message,
                    ClientRegistrationFinishParameters::default(),
                )
                .expect("fake registration client finish must succeed");
            let server_reg = ServerRegistration::<OpaqueCs>::finish(client_finish.message);
            registrations.push(server_reg.serialize().to_vec());
        }

        Self { registrations }
    }

    /// Select a fake registration deterministically based on username.
    /// Uses HMAC-SHA512 so repeated queries for the same non-existent username
    /// produce identical timing profiles (prevents variance-based oracles).
    fn select_for_username(&self, username: &str) -> &[u8] {
        use hmac::{Hmac, Mac};
        use sha2::Sha512;

        const SELECTION_KEY: &[u8; 32] = b"MILNET_FAKE_REG_SELECT_KEY_V1\x00\x00\x00";

        let mut mac =
            <Hmac<Sha512>>::new_from_slice(SELECTION_KEY).expect("HMAC key length is valid");
        mac.update(username.as_bytes());
        let result = mac.finalize().into_bytes();

        let idx_bytes: [u8; 8] = result[..8].try_into().expect("8 bytes");
        let idx = u64::from_le_bytes(idx_bytes) as usize % self.registrations.len();

        &self.registrations[idx]
    }
}

/// A stored user credential record.
pub struct UserRecord {
    pub user_id: Uuid,
    /// Serialized `ServerRegistration<OpaqueCs>` -- contains NO password info.
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
    /// Pre-computed fake registrations for timing-safe user-not-found handling.
    fake_registrations: FakeRegistrationPool,
}

impl CredentialStore {
    /// Create an empty credential store with a fresh ServerSetup.
    pub fn new() -> Self {
        let mut rng = OsRng;
        let server_setup = ServerSetup::<OpaqueCs>::new(&mut rng);
        let fake_registrations =
            FakeRegistrationPool::generate(&server_setup, FAKE_REGISTRATION_COUNT);
        Self {
            users: HashMap::new(),
            server_setup,
            server_setup_fips: None,
            fake_registrations,
        }
    }

    /// Create a credential store with both Argon2id and PBKDF2-SHA512 server
    /// setups initialised.  The FIPS setup is used when FIPS mode is active.
    pub fn new_dual() -> Self {
        let mut rng = OsRng;
        let server_setup = ServerSetup::<OpaqueCs>::new(&mut rng);
        let server_setup_fips = ServerSetup::<OpaqueCsFips>::new(&mut rng);
        let fake_registrations =
            FakeRegistrationPool::generate(&server_setup, FAKE_REGISTRATION_COUNT);
        Self {
            users: HashMap::new(),
            server_setup,
            server_setup_fips: Some(server_setup_fips),
            fake_registrations,
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
        let fake_registrations =
            FakeRegistrationPool::generate(&server_setup, FAKE_REGISTRATION_COUNT);
        Self {
            users: HashMap::new(),
            server_setup,
            server_setup_fips,
            fake_registrations,
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
    ) -> Result<Uuid, MilnetError> {
        if self.users.contains_key(username) {
            tracing::error!(
                "OPAQUE: registration overwrite attempt for existing user"
            );
            return Err(MilnetError::AlreadyRegistered(
                "use re_register_user for authorized re-registration".into(),
            ));
        }
        if self.users.len() >= Self::MAX_USERS {
            tracing::error!(
                "OPAQUE: MAX_USERS ({}) reached -- rejecting new registration",
                Self::MAX_USERS
            );
            return Err(MilnetError::CapacityExceeded(format!(
                "maximum {} users reached",
                Self::MAX_USERS
            )));
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
        Ok(user_id)
    }

    /// Re-register an existing user (authorized re-registration).
    /// Overwrites the existing registration with a new one and assigns a new UUID.
    /// Returns error if the user does not already exist.
    pub fn re_register_user(
        &mut self,
        username: &str,
        registration_bytes: Vec<u8>,
    ) -> Result<Uuid, MilnetError> {
        if !self.users.contains_key(username) {
            return Err(MilnetError::CryptoVerification(
                "cannot re-register non-existent user".into(),
            ));
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
        Ok(user_id)
    }

    /// Store a completed FIPS registration for a user (PBKDF2-SHA512 KSF).
    /// Rejects if the store already holds `MAX_USERS` entries (unless updating existing).
    pub fn store_registration_fips(
        &mut self,
        username: &str,
        registration_bytes: Vec<u8>,
    ) -> Result<Uuid, MilnetError> {
        if self.users.contains_key(username) {
            tracing::error!(
                "OPAQUE: FIPS registration overwrite attempt for existing user"
            );
            return Err(MilnetError::AlreadyRegistered(
                "use re_register_user for authorized re-registration".into(),
            ));
        }
        if self.users.len() >= Self::MAX_USERS {
            tracing::error!(
                "OPAQUE: MAX_USERS ({}) reached -- rejecting new FIPS registration",
                Self::MAX_USERS
            );
            return Err(MilnetError::CapacityExceeded(format!(
                "maximum {} users reached",
                Self::MAX_USERS
            )));
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
        Ok(user_id)
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
    pub fn register_with_password(&mut self, username: &str, password: &[u8]) -> Result<Uuid, MilnetError> {
        use opaque_ke::{
            ClientRegistration, ClientRegistrationFinishParameters,
        };

        let mut rng = OsRng;

        // Step 1: Client starts registration
        let client_start = match ClientRegistration::<OpaqueCs>::start(&mut rng, password) {
            Ok(cs) => cs,
            Err(e) => {
                tracing::error!("OPAQUE client registration start failed: {e}");
                return Err(MilnetError::CryptoVerification(format!("client reg start: {e}")));
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
                return Err(MilnetError::CryptoVerification(format!("server reg start: {e}")));
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
                return Err(MilnetError::CryptoVerification(format!("client reg finish: {e}")));
            }
        };

        // Step 4: Server finishes registration -- produces the password file
        let server_registration = ServerRegistration::<OpaqueCs>::finish(client_finish.message);
        let registration_bytes = server_registration.serialize().to_vec();

        self.store_registration(username, registration_bytes)
    }

    /// Authorized re-registration with password. Runs the full OPAQUE protocol
    /// and overwrites the existing user record. Fails if user does not exist.
    pub fn re_register_with_password(&mut self, username: &str, password: &[u8]) -> Result<Uuid, MilnetError> {
        use opaque_ke::{ClientRegistration, ClientRegistrationFinishParameters};

        let mut rng = OsRng;

        let client_start = ClientRegistration::<OpaqueCs>::start(&mut rng, password)
            .map_err(|e| MilnetError::CryptoVerification(format!("client reg start: {e}")))?;

        let server_start = ServerRegistration::<OpaqueCs>::start(
            &self.server_setup,
            client_start.message,
            username.as_bytes(),
        )
        .map_err(|e| MilnetError::CryptoVerification(format!("server reg start: {e}")))?;

        let client_finish = client_start.state.finish(
            &mut rng,
            password,
            server_start.message,
            ClientRegistrationFinishParameters::default(),
        )
        .map_err(|e| MilnetError::CryptoVerification(format!("client reg finish: {e}")))?;

        let server_registration = ServerRegistration::<OpaqueCs>::finish(client_finish.message);
        let registration_bytes = server_registration.serialize().to_vec();

        self.re_register_user(username, registration_bytes)
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
                "FIPS server setup not initialised -- use new_dual()".into(),
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

        self.store_registration_fips(username, registration_bytes)
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
    ///
    /// SECURITY: When the user does not exist, the full OPAQUE protocol is still
    /// executed against a pre-computed fake registration via verify_password().
    /// This prevents timing oracles that would reveal username existence.
    pub fn verify_password_adaptive(
        &self,
        username: &str,
        password: &[u8],
    ) -> Result<(Uuid, bool), MilnetError> {
        let record = match self.users.get(username) {
            Some(r) => r,
            None => {
                // User not found: delegate to verify_password which runs the
                // full OPAQUE protocol against a fake registration, producing
                // an indistinguishable "authentication failed" error and timing.
                return self.verify_password(username, password).map(|uid| (uid, false));
            }
        };

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
    /// Runs both client and server sides -- the password is only used on the
    /// client side. Returns Ok(user_id) on success.
    ///
    /// SECURITY: When the user does not exist, the full OPAQUE protocol is
    /// executed against a pre-computed fake registration. This prevents timing
    /// oracles that would reveal whether a username is registered.
    pub fn verify_password(&self, username: &str, password: &[u8]) -> Result<Uuid, MilnetError> {
        use opaque_ke::{
            ClientLogin, ClientLoginFinishParameters, ServerLogin, ServerLoginParameters,
        };

        // Look up user. If not found, use a fake registration to prevent timing oracle.
        let (server_registration, user_id, is_fake) = match self.users.get(username) {
            Some(record) => {
                let reg = ServerRegistration::<OpaqueCs>::deserialize(&record.registration)
                    .map_err(|_| {
                        MilnetError::CryptoVerification("corrupt registration".into())
                    })?;
                (reg, record.user_id, false)
            }
            None => {
                let fake_bytes = self.fake_registrations.select_for_username(username);
                let reg = ServerRegistration::<OpaqueCs>::deserialize(fake_bytes)
                    .map_err(|_| MilnetError::CryptoVerification("internal error".into()))?;
                (reg, Uuid::nil(), true)
            }
        };

        let mut rng = OsRng;

        // Client starts login
        let client_start = ClientLogin::<OpaqueCs>::start(&mut rng, password)
            .map_err(|_| MilnetError::CryptoVerification("login start failed".into()))?;

        // Server processes login request (full OPAQUE OPRF regardless of user existence)
        let server_start = ServerLogin::<OpaqueCs>::start(
            &mut rng,
            &self.server_setup,
            Some(server_registration),
            client_start.message,
            username.as_bytes(),
            ServerLoginParameters::default(),
        )
        .map_err(|_| MilnetError::CryptoVerification("authentication failed".into()))?;

        // Client finishes login
        let client_finish = client_start
            .state
            .finish(
                &mut rng,
                password,
                server_start.message,
                ClientLoginFinishParameters::default(),
            )
            .map_err(|_| MilnetError::CryptoVerification("authentication failed".into()))?;

        // Server verifies finalization
        server_start
            .state
            .finish(client_finish.message, ServerLoginParameters::default())
            .map_err(|_| MilnetError::CryptoVerification("authentication failed".into()))?;

        // Defensive guard: fake registrations should always fail above, but
        // if somehow they don't, never return a valid user_id.
        if is_fake {
            return Err(MilnetError::CryptoVerification(
                "authentication failed".into(),
            ));
        }

        Ok(user_id)
    }
}

impl Drop for CredentialStore {
    fn drop(&mut self) {
        use zeroize::Zeroize;

        // SECURITY: opaque-ke ServerSetup does not impl Zeroize. We serialize and
        // zeroize the serialized form. The original struct memory will be zeroed
        // when the allocator reuses it, but there is a window where the OPRF seed
        // and keypair remain in process memory. This is a known limitation tracked
        // for upstream fix. The crate uses #![forbid(unsafe_code)] so we cannot
        // use ptr::write_volatile to scrub the struct directly.

        let setup_size = std::mem::size_of_val(&self.server_setup);
        tracing::debug!(
            setup_bytes_size = setup_size,
            "CredentialStore::drop -- zeroizing serialized ServerSetup ({setup_size} bytes struct)"
        );

        let mut setup_bytes = self.server_setup.serialize().to_vec();
        setup_bytes.zeroize();

        if let Some(ref fips_setup) = self.server_setup_fips {
            let fips_size = std::mem::size_of_val(fips_setup);
            tracing::debug!(
                fips_setup_bytes_size = fips_size,
                "CredentialStore::drop -- zeroizing serialized FIPS ServerSetup ({fips_size} bytes struct)"
            );
            let mut fips_bytes = fips_setup.serialize().to_vec();
            fips_bytes.zeroize();
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

#[cfg(test)]
mod tests {
    use super::*;

    // -- Construction -----------------------------------------------------------

    #[test]
    fn new_creates_empty_store() {
        let store = CredentialStore::new();
        assert_eq!(store.user_count(), 0);
        assert!(store.usernames().is_empty());
    }

    #[test]
    fn new_dual_creates_empty_store_with_fips_setup() {
        let store = CredentialStore::new_dual();
        assert_eq!(store.user_count(), 0);
        assert!(store.server_setup_fips().is_some(), "dual store must have FIPS setup");
    }

    #[test]
    fn new_single_has_no_fips_setup() {
        let store = CredentialStore::new();
        assert!(store.server_setup_fips().is_none());
    }

    #[test]
    fn default_is_same_as_new() {
        let store = CredentialStore::default();
        assert_eq!(store.user_count(), 0);
        assert!(store.server_setup_fips().is_none());
    }

    #[test]
    fn with_server_setup_preserves_setup() {
        let store1 = CredentialStore::new();
        let setup_bytes_1 = store1.server_setup().serialize().to_vec();

        let store2 = CredentialStore::with_server_setup(store1.server_setup().clone());
        let setup_bytes_2 = store2.server_setup().serialize().to_vec();

        assert_eq!(setup_bytes_1, setup_bytes_2, "server setup must be preserved");
    }

    // -- Registration flow ------------------------------------------------------

    #[test]
    fn register_with_password_returns_valid_uuid() {
        let mut store = CredentialStore::new();
        let uid = store.register_with_password("alice", b"pw123").unwrap();
        assert!(!uid.is_nil(), "registration must return non-nil UUID");
    }

    #[test]
    fn register_with_password_makes_user_exist() {
        let mut store = CredentialStore::new();
        assert!(!store.user_exists("alice"));
        store.register_with_password("alice", b"pw").unwrap();
        assert!(store.user_exists("alice"));
        assert_eq!(store.user_count(), 1);
    }

    #[test]
    fn register_sets_argon2id_ksf() {
        let mut store = CredentialStore::new();
        store.register_with_password("alice", b"pw").unwrap();
        assert_eq!(store.get_ksf_algorithm("alice"), Some(KSF_ARGON2ID));
    }

    #[test]
    fn register_fips_sets_pbkdf2_ksf() {
        let mut store = CredentialStore::new_dual();
        store.register_with_password_fips("alice", b"pw").unwrap();
        assert_eq!(store.get_ksf_algorithm("alice"), Some(KSF_PBKDF2_SHA512));
    }

    #[test]
    fn register_fips_without_dual_fails() {
        let mut store = CredentialStore::new();
        let result = store.register_with_password_fips("alice", b"pw");
        assert!(result.is_err());
    }

    // -- Duplicate username handling --------------------------------------------

    #[test]
    fn duplicate_username_is_rejected() {
        let mut store = CredentialStore::new();
        let uid1 = store.register_with_password("alice", b"pw1").unwrap();
        let result = store.register_with_password("alice", b"pw2");
        assert!(result.is_err(), "duplicate registration must be rejected");
        assert_eq!(store.user_count(), 1);
        assert_eq!(store.get_user_id("alice"), Some(uid1), "original UUID preserved");
    }

    #[test]
    fn re_register_user_overwrites_existing() {
        let mut store = CredentialStore::new();
        let uid1 = store.register_with_password("alice", b"pw1").unwrap();
        let uid2 = store.re_register_user("alice", store.get_registration_bytes("alice").unwrap()).unwrap();
        assert_ne!(uid1, uid2);
        assert_eq!(store.user_count(), 1);
        assert_eq!(store.get_user_id("alice"), Some(uid2));
    }

    #[test]
    fn re_register_nonexistent_user_fails() {
        let mut store = CredentialStore::new();
        let result = store.re_register_user("ghost", vec![0xAA; 32]);
        assert!(result.is_err());
    }

    // -- MAX_USERS limit -------------------------------------------------------

    #[test]
    fn store_registration_rejects_duplicate() {
        let mut store = CredentialStore::new();
        for i in 0..10 {
            store.store_registration(&format!("user{i}"), vec![0xAA; 32]).unwrap();
        }
        assert_eq!(store.user_count(), 10);

        // Duplicate should be rejected
        let result = store.store_registration("user0", vec![0xBB; 32]);
        assert!(result.is_err(), "duplicate store_registration must fail");

        // Re-register should work for existing user
        let uid = store.re_register_user("user0", vec![0xBB; 32]);
        assert!(uid.is_ok(), "re_register_user for existing user must succeed");
    }

    #[test]
    fn store_registration_fips_rejects_duplicate() {
        let mut store = CredentialStore::new_dual();
        store.store_registration_fips("existing", vec![0xAA; 32]).unwrap();
        let result = store.store_registration_fips("existing", vec![0xBB; 32]);
        assert!(result.is_err(), "duplicate FIPS registration must fail");
        assert_eq!(store.get_ksf_algorithm("existing"), Some(KSF_PBKDF2_SHA512));
    }

    // -- get_registration_bytes -------------------------------------------------

    #[test]
    fn get_registration_bytes_returns_stored_bytes() {
        let mut store = CredentialStore::new();
        store.register_with_password("alice", b"pw").unwrap();

        let bytes = store.get_registration_bytes("alice");
        assert!(bytes.is_some());
        assert!(!bytes.unwrap().is_empty());
    }

    #[test]
    fn get_registration_bytes_none_for_missing_user() {
        let store = CredentialStore::new();
        assert!(store.get_registration_bytes("nobody").is_none());
    }

    #[test]
    fn get_registration_bytes_roundtrips_through_deserialization() {
        let mut store = CredentialStore::new();
        store.register_with_password("bob", b"password").unwrap();

        let bytes = store.get_registration_bytes("bob").unwrap();
        let reg = ServerRegistration::<OpaqueCs>::deserialize(&bytes);
        assert!(reg.is_ok(), "stored bytes must deserialize to ServerRegistration");
    }

    // -- get_registration -------------------------------------------------------

    #[test]
    fn get_registration_returns_correct_user_id() {
        let mut store = CredentialStore::new();
        let uid = store.register_with_password("charlie", b"pw").unwrap();
        let (_, stored_uid) = store.get_registration("charlie").unwrap();
        assert_eq!(uid, stored_uid);
    }

    #[test]
    fn get_registration_unknown_user_is_error() {
        let store = CredentialStore::new();
        assert!(store.get_registration("ghost").is_err());
    }

    #[test]
    fn get_registration_corrupt_bytes_is_error() {
        let mut store = CredentialStore::new();
        store.store_registration("corrupt", vec![0xFF; 3]).unwrap();
        assert!(store.get_registration("corrupt").is_err());
    }

    // -- Login flow ------------------------------------------------------------

    #[test]
    fn verify_password_succeeds_with_correct_password() {
        let mut store = CredentialStore::new();
        let uid = store.register_with_password("dave", b"correct").unwrap();
        let result = store.verify_password("dave", b"correct");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), uid);
    }

    #[test]
    fn verify_password_fails_with_wrong_password() {
        let mut store = CredentialStore::new();
        store.register_with_password("dave", b"correct").unwrap();
        let result = store.verify_password("dave", b"wrong");
        assert!(result.is_err());
    }

    #[test]
    fn verify_password_fails_for_unknown_user() {
        let store = CredentialStore::new();
        assert!(store.verify_password("nobody", b"pw").is_err());
    }

    #[test]
    fn verify_password_adaptive_routes_argon2id() {
        let mut store = CredentialStore::new();
        let uid = store.register_with_password("user", b"pw").unwrap();
        let (verified_uid, needs_rereg) = store
            .verify_password_adaptive("user", b"pw")
            .unwrap();
        assert_eq!(verified_uid, uid);
        assert!(!needs_rereg);
    }

    #[test]
    fn verify_password_adaptive_routes_fips() {
        let mut store = CredentialStore::new_dual();
        let uid = store.register_with_password_fips("fuser", b"pw").unwrap();
        let (verified_uid, needs_rereg) = store
            .verify_password_adaptive("fuser", b"pw")
            .unwrap();
        assert_eq!(verified_uid, uid);
        assert!(!needs_rereg, "FIPS user never needs re-registration");
    }

    #[test]
    fn verify_password_adaptive_unknown_user_is_error() {
        let store = CredentialStore::new();
        assert!(store.verify_password_adaptive("ghost", b"pw").is_err());
    }

    // -- Utility methods -------------------------------------------------------

    #[test]
    fn usernames_returns_all_registered() {
        let mut store = CredentialStore::new();
        store.register_with_password("z", b"pw").unwrap();
        store.register_with_password("a", b"pw").unwrap();
        let mut names = store.usernames();
        names.sort();
        assert_eq!(names, vec!["a", "z"]);
    }

    #[test]
    fn get_user_id_none_for_missing() {
        let store = CredentialStore::new();
        assert!(store.get_user_id("missing").is_none());
    }

    #[test]
    fn get_ksf_algorithm_none_for_missing() {
        let store = CredentialStore::new();
        assert!(store.get_ksf_algorithm("missing").is_none());
    }

    // -- restore_user ----------------------------------------------------------

    #[test]
    fn restore_user_makes_user_accessible() {
        let mut store = CredentialStore::new();
        let uid = store.register_with_password("orig", b"pw").unwrap();
        let bytes = store.get_registration_bytes("orig").unwrap();

        let mut store2 = CredentialStore::with_server_setup(store.server_setup().clone());
        store2.restore_user("orig", uid, bytes);

        assert!(store2.user_exists("orig"));
        assert_eq!(store2.get_user_id("orig"), Some(uid));
        assert_eq!(store2.get_ksf_algorithm("orig"), Some(KSF_ARGON2ID));
    }

    #[test]
    fn restore_user_can_verify_password() {
        let mut store = CredentialStore::new();
        let uid = store.register_with_password("orig", b"pw").unwrap();
        let bytes = store.get_registration_bytes("orig").unwrap();

        let mut store2 = CredentialStore::with_server_setup(store.server_setup().clone());
        store2.restore_user("orig", uid, bytes);

        let result = store2.verify_password("orig", b"pw");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), uid);
    }

    // -- Drop/zeroization ------------------------------------------------------

    #[test]
    fn drop_does_not_panic() {
        let mut store = CredentialStore::new();
        store.register_with_password("u1", b"pw1").unwrap();
        store.register_with_password("u2", b"pw2").unwrap();
        drop(store);
        // reaching here means Drop ran without panic
    }

    #[test]
    fn drop_dual_does_not_panic() {
        let mut store = CredentialStore::new_dual();
        store.register_with_password("u1", b"pw1").unwrap();
        store.register_with_password_fips("u2", b"pw2").unwrap();
        drop(store);
    }

    // -- Thread safety ---------------------------------------------------------

    #[test]
    fn store_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<CredentialStore>();
    }

    // -- KSF constant values ---------------------------------------------------

    #[test]
    fn ksf_constants_are_distinct() {
        assert_ne!(KSF_ARGON2ID, KSF_PBKDF2_SHA512);
    }

    #[test]
    fn ksf_argon2id_value() {
        assert_eq!(KSF_ARGON2ID, "argon2id-v19");
    }

    #[test]
    fn ksf_pbkdf2_sha512_value() {
        assert_eq!(KSF_PBKDF2_SHA512, "pbkdf2-sha512");
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
        let user_id = self.memory.store_registration(username, registration_bytes.clone())
            .map_err(|e| format!("{e}"))?;

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
