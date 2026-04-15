use crate::types::*;
use crate::verification;
use std::collections::HashMap;
use std::time::Instant;
use uuid::Uuid;

/// Maximum age for a FIDO2 challenge before it is considered expired (seconds).
const CHALLENGE_MAX_AGE_SECS: u64 = 60;

/// Create registration options for a new FIDO2 credential.
///
/// Set `prefer_platform` to `true` to request a platform authenticator
/// such as Windows Hello or Touch ID.
///
/// `existing_credential_ids` lists credential IDs already registered for this
/// user.  They are sent as `excludeCredentials` so the browser can skip
/// authenticators that would produce a duplicate.
pub fn create_registration_options(
    rp_name: &str,
    rp_id: &str,
    user_id: &Uuid,
    user_name: &str,
    prefer_platform: bool,
) -> PublicKeyCredentialCreationOptions {
    create_registration_options_with_excludes(
        rp_name,
        rp_id,
        user_id,
        user_name,
        prefer_platform,
        &[],
    )
}

/// Whether military deployment mode is active.
///
/// When true, discoverable credentials (resident keys) are required for
/// CAC/PIV-based usernameless authentication flows per DoD policy.
/// Controlled by the `MILNET_MILITARY_DEPLOYMENT` environment variable
/// (defaults to `true`).
fn is_military_deployment() -> bool {
    match std::env::var("MILNET_MILITARY_DEPLOYMENT") {
        Ok(val) => val != "0" && val.to_lowercase() != "false",
        Err(_) => true,
    }
}

/// Like [`create_registration_options`] but allows passing existing credential
/// IDs to populate the `excludeCredentials` list.
pub fn create_registration_options_with_excludes(
    rp_name: &str,
    rp_id: &str,
    user_id: &Uuid,
    user_name: &str,
    prefer_platform: bool,
    existing_credential_ids: &[Vec<u8>],
) -> PublicKeyCredentialCreationOptions {
    let challenge = crypto::entropy::generate_nonce().to_vec();

    let exclude_credentials: Vec<AllowCredential> = existing_credential_ids
        .iter()
        .map(|id| AllowCredential {
            cred_type: "public-key".into(),
            id: id.clone(),
        })
        .collect();

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
            resident_key: if is_military_deployment() { "required" } else { "preferred" }.into(),
            user_verification: "required".into(),
        },
        exclude_credentials,
    }
}

/// In-memory credential store for FIDO2 credentials.
pub struct CredentialStore {
    credentials: HashMap<Vec<u8>, StoredCredential>,
    challenges: HashMap<Vec<u8>, (Uuid, Instant)>,
}

impl CredentialStore {
    pub fn new() -> Self {
        Self {
            credentials: HashMap::new(),
            challenges: HashMap::new(),
        }
    }

    /// Maximum number of stored credentials before rejection.
    const MAX_CREDENTIALS: usize = 100_000;
    /// Maximum number of pending challenges before rejection.
    const MAX_CHALLENGES: usize = 10_000;

    /// Store a pending challenge associated with a user.
    ///
    /// Runs garbage collection of expired challenges before inserting.
    /// Rejects if the store already holds `MAX_CHALLENGES` entries.
    pub fn store_challenge(&mut self, challenge: &[u8], user_id: Uuid) {
        self.cleanup_expired_challenges();
        if self.challenges.len() >= Self::MAX_CHALLENGES {
            tracing::error!(
                "FIDO: MAX_CHALLENGES ({}) reached — rejecting new challenge",
                Self::MAX_CHALLENGES
            );
            return;
        }
        self.challenges.insert(challenge.to_vec(), (user_id, Instant::now()));
    }

    /// Consume and validate a challenge, returning the associated user ID.
    ///
    /// Rejects challenges older than `CHALLENGE_MAX_AGE_SECS` seconds.
    pub fn consume_challenge(&mut self, challenge: &[u8]) -> Option<Uuid> {
        let (user_id, created_at) = self.challenges.remove(challenge)?;
        if created_at.elapsed().as_secs() > CHALLENGE_MAX_AGE_SECS {
            // Challenge expired — treat as if it never existed.
            None
        } else {
            Some(user_id)
        }
    }

    /// Consume a pending challenge for a specific user, returning true if one was found.
    /// This removes the first non-expired challenge associated with the given user ID.
    pub fn consume_challenge_for_user(&mut self, user_id: &Uuid) -> bool {
        let key = self.challenges
            .iter()
            .find(|(_, (uid, created_at))| {
                *uid == *user_id && created_at.elapsed().as_secs() <= CHALLENGE_MAX_AGE_SECS
            })
            .map(|(k, _)| k.clone());
        if let Some(k) = key {
            self.challenges.remove(&k);
            true
        } else {
            false
        }
    }

    /// Check whether a non-expired pending challenge exists for the given user.
    pub fn has_pending_challenge(&self, user_id: &Uuid) -> bool {
        self.challenges.values().any(|(uid, created_at)| {
            uid == user_id && created_at.elapsed().as_secs() <= CHALLENGE_MAX_AGE_SECS
        })
    }

    /// Remove all expired challenges from the store.
    pub fn cleanup_expired_challenges(&mut self) {
        self.challenges.retain(|_, (_, created_at)| {
            created_at.elapsed().as_secs() <= CHALLENGE_MAX_AGE_SECS
        });
    }

    /// Store a completed credential registration.
    /// Rejects if the store already holds `MAX_CREDENTIALS` entries.
    pub fn store_credential(&mut self, cred: StoredCredential) {
        if self.credentials.len() >= Self::MAX_CREDENTIALS {
            tracing::error!(
                "FIDO: MAX_CREDENTIALS ({}) reached — rejecting new credential",
                Self::MAX_CREDENTIALS
            );
            return;
        }
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

    /// Count credentials that lack a PQ attestation binding.
    pub fn credentials_missing_pq_binding(&self) -> usize {
        self.credentials
            .values()
            .filter(|c| c.pq_attestation.is_empty())
            .count()
    }

    /// Check whether a credential ID is already registered.
    pub fn credential_exists(&self, credential_id: &[u8]) -> bool {
        self.credentials.contains_key(credential_id)
    }

    /// Get a mutable reference to a stored credential (for sign count updates).
    pub fn get_credential_mut(&mut self, credential_id: &[u8]) -> Option<&mut StoredCredential> {
        self.credentials.get_mut(credential_id)
    }

    /// Remove all credentials and pending challenges belonging to a user.
    /// Used for GDPR Article 17 right-to-erasure compliance.
    pub fn remove_user_credentials(&mut self, user_id: &Uuid) {
        self.credentials.retain(|_, cred| cred.user_id != *user_id);
        self.challenges.retain(|_, (uid, _)| uid != user_id);
    }
}

/// Validate an attestation response and register the credential.
///
/// Performs the following checks before storing:
/// 1. Parse the authenticator data from the attestation.
/// 2. Validate the RP ID hash matches `expected_rp_id`.
/// 3. Validate the User Present flag is set.
/// 4. Validate the Attested Credential Data flag is set.
/// 5. Extract the credential ID and public key.
/// 6. Reject duplicate credential IDs.
/// 7. Store the credential.
///
/// Returns the stored credential on success.
pub fn validate_and_register(
    store: &mut CredentialStore,
    auth_data: &[u8],
    expected_rp_id: &str,
    user_id: Uuid,
    authenticator_type: &str,
) -> Result<StoredCredential, &'static str> {
    validate_and_register_pq(
        store, auth_data, expected_rp_id, user_id, authenticator_type,
        &[], &[], &[],
    )
}

/// CAT-A task 1: registration with mandatory PQ attestation binding.
pub fn validate_and_register_pq(
    store: &mut CredentialStore,
    auth_data: &[u8],
    expected_rp_id: &str,
    user_id: Uuid,
    authenticator_type: &str,
    classical_att_bytes: &[u8],
    client_data_hash: &[u8],
    pq_attestation: &[u8],
) -> Result<StoredCredential, &'static str> {
    let att_data = verification::parse_attestation_auth_data(auth_data, expected_rp_id)?;

    crate::policy::enforce_aaguid(&att_data.aaguid)?;

    if att_data.backup_state && crate::policy::reject_backed_up_credentials() {
        return Err("Registration rejected: backupState=1 not allowed in military mode");
    }

    crate::policy::enforce_pq_attestation(
        pq_attestation, classical_att_bytes, auth_data, client_data_hash,
    )?;

    if store.credential_exists(&att_data.credential_id) {
        return Err("Credential ID already registered (duplicate registration rejected)");
    }

    let cred = StoredCredential {
        credential_id: att_data.credential_id,
        public_key: att_data.public_key_cose,
        user_id,
        sign_count: att_data.sign_count,
        authenticator_type: authenticator_type.to_string(),
        aaguid: att_data.aaguid,
        cloned_flag: false,
        backup_eligible: att_data.backup_eligible,
        backup_state: att_data.backup_state,
        pq_attestation: pq_attestation.to_vec(),
    };

    store.store_credential(cred.clone());
    Ok(cred)
}

impl Default for CredentialStore {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// PersistentCredentialStore — PostgreSQL-backed FIDO2 credential storage
// ---------------------------------------------------------------------------

/// PostgreSQL-backed FIDO2 credential store with in-memory L1 cache.
///
/// Credentials are stored encrypted in the `fido_credentials` table using
/// `EncryptedPool` envelope encryption. Challenges remain memory-only (ephemeral,
/// 60s TTL). On construction, all credentials are loaded from the database into
/// the in-memory store for O(1) read access. Mutations write through to both
/// the L1 cache and the database.
///
/// If the database is unavailable during construction, the store degrades to
/// in-memory only with a SIEM critical warning. Write failures are logged but
/// do not block the in-memory operation (availability over consistency for reads,
/// consistency enforced on writes where possible).
pub struct PersistentCredentialStore {
    memory: CredentialStore,
    pool: common::encrypted_db::EncryptedPool,
}

impl PersistentCredentialStore {
    /// Create a new persistent credential store, loading all existing credentials
    /// from the `fido_credentials` table.
    pub async fn new(pool: common::encrypted_db::EncryptedPool) -> Result<Self, String> {
        let mut store = Self {
            memory: CredentialStore::new(),
            pool,
        };
        store.load_from_db().await?;
        let missing = store.memory.credentials_missing_pq_binding();
        crate::policy::enforce_pq_binding_invariant(missing)
            .map_err(|e| format!("PQ binding invariant: {e}"))?;
        Ok(store)
    }

    /// Load all credentials from the database into the in-memory cache.
    async fn load_from_db(&mut self) -> Result<(), String> {
        let rows = sqlx::query(
            "SELECT credential_id, public_key, user_id, sign_count, authenticator_type \
             FROM fido_credentials"
        )
        .fetch_all(&self.pool.pool)
        .await
        .map_err(|e| {
            tracing::error!(
                target: "siem",
                "SIEM:ERROR Failed to load FIDO credentials from DB: {e}. Degrading to in-memory only."
            );
            format!("load fido_credentials: {e}")
        })?;

        for row in rows {
            use sqlx::Row;
            let cred_id_enc: Vec<u8> = row.get("credential_id");
            let pubkey_enc: Vec<u8> = row.get("public_key");
            let user_id: Uuid = row.get("user_id");
            let sign_count: i32 = row.get("sign_count");
            let auth_type: String = row.get("authenticator_type");

            let pubkey = self.pool.decrypt_field(
                "fido_credentials", "public_key", &cred_id_enc, &pubkey_enc,
            ).unwrap_or_else(|e| {
                tracing::error!(
                    target: "siem",
                    "SIEM:ERROR Failed to decrypt FIDO credential public key: {e}"
                );
                Vec::new()
            });

            if !pubkey.is_empty() {
                self.memory.store_credential(StoredCredential {
                    credential_id: cred_id_enc.to_vec(),
                    public_key: pubkey,
                    user_id,
                    sign_count: sign_count as u32,
                    authenticator_type: auth_type,
                    aaguid: [0u8; 16],
                    cloned_flag: false,
                    backup_eligible: false,
                    backup_state: false,
                    pq_attestation: Vec::new(),
                });
            }
        }
        Ok(())
    }

    /// Store a credential in both the database and in-memory cache.
    pub async fn store_credential(&mut self, cred: StoredCredential) -> Result<(), String> {
        let pubkey_enc = self.pool.encrypt_field(
            "fido_credentials", "public_key", &cred.credential_id, &cred.public_key,
        )?;

        sqlx::query(
            "INSERT INTO fido_credentials (credential_id, public_key, user_id, sign_count, authenticator_type) \
             VALUES ($1, $2, $3, $4, $5) ON CONFLICT (credential_id) DO UPDATE \
             SET public_key = $2, sign_count = $4"
        )
        .bind(&cred.credential_id)
        .bind(&pubkey_enc)
        .bind(cred.user_id)
        .bind(cred.sign_count as i64)
        .bind(&cred.authenticator_type)
        .execute(&self.pool.pool)
        .await
        .map_err(|e| format!("persist fido credential: {e}"))?;

        self.memory.store_credential(cred);
        Ok(())
    }

    /// Look up a credential by its ID (L1 cache hit).
    pub fn get_credential(&self, credential_id: &[u8]) -> Option<&StoredCredential> {
        self.memory.get_credential(credential_id)
    }

    /// Get all credentials belonging to a user.
    pub fn get_user_credentials(&self, user_id: &Uuid) -> Vec<&StoredCredential> {
        self.memory.get_user_credentials(user_id)
    }

    /// Check whether a credential ID is already registered.
    pub fn credential_exists(&self, credential_id: &[u8]) -> bool {
        self.memory.credential_exists(credential_id)
    }

    /// Return the total number of stored credentials.
    pub fn credential_count(&self) -> usize {
        self.memory.credential_count()
    }

    /// Store a pending challenge (memory-only, ephemeral).
    pub fn store_challenge(&mut self, challenge: &[u8], user_id: Uuid) {
        self.memory.store_challenge(challenge, user_id);
    }

    /// Consume a pending challenge (memory-only, ephemeral).
    pub fn consume_challenge(&mut self, challenge: &[u8]) -> Option<Uuid> {
        self.memory.consume_challenge(challenge)
    }

    /// Update sign count in both DB and memory after successful authentication.
    pub async fn update_sign_count(&mut self, credential_id: &[u8], new_count: u32) -> Result<(), String> {
        sqlx::query("UPDATE fido_credentials SET sign_count = $1 WHERE credential_id = $2")
            .bind(new_count as i64)
            .bind(credential_id)
            .execute(&self.pool.pool)
            .await
            .map_err(|e| format!("update sign count: {e}"))?;

        if let Some(cred) = self.memory.get_credential_mut(credential_id) {
            cred.sign_count = new_count;
        }
        Ok(())
    }

    /// Remove all credentials for a user (GDPR Article 17 right-to-erasure).
    pub async fn remove_user_credentials(&mut self, user_id: &Uuid) -> Result<(), String> {
        sqlx::query("DELETE FROM fido_credentials WHERE user_id = $1")
            .bind(user_id)
            .execute(&self.pool.pool)
            .await
            .map_err(|e| format!("delete user fido credentials: {e}"))?;

        self.memory.remove_user_credentials(user_id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use sha2::{Digest, Sha256};

    /// Helper: build auth data with attested credential data.
    fn make_attestation_auth_data(
        rp_id: &str,
        flags: u8,
        sign_count: u32,
        credential_id: &[u8],
        public_key_cose: &[u8],
    ) -> Vec<u8> {
        let rp_hash = Sha256::digest(rp_id.as_bytes());
        let mut data = Vec::new();
        data.extend_from_slice(&rp_hash);
        data.push(flags);
        data.extend_from_slice(&sign_count.to_be_bytes());
        // AAGUID (16 zero bytes)
        data.extend_from_slice(&[0u8; 16]);
        // credential ID length
        let cred_len = credential_id.len() as u16;
        data.extend_from_slice(&cred_len.to_be_bytes());
        // credential ID
        data.extend_from_slice(credential_id);
        // COSE public key
        data.extend_from_slice(public_key_cose);
        data
    }

    #[test]
    #[serial]
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
        aaguid: [0u8; 16],
        cloned_flag: false,
        backup_eligible: false,
        backup_state: false,
        pq_attestation: Vec::new()
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

    #[test]
    fn test_validate_and_register_success() {
        let mut store = CredentialStore::new();
        let rp_id = "sso.milnet.example";
        let user_id = Uuid::new_v4();
        let cred_id = vec![0xAA, 0xBB, 0xCC];
        let cose_key = vec![0x01, 0x02, 0x03];

        // flags: UP | UV | AT = 0x45
        let auth_data = make_attestation_auth_data(rp_id, 0x45, 0, &cred_id, &cose_key);

        let result = validate_and_register(&mut store, &auth_data, rp_id, user_id, "cross-platform");
        assert!(result.is_ok());

        let cred = result.unwrap();
        assert_eq!(cred.credential_id, cred_id);
        assert_eq!(cred.public_key, cose_key);
        assert_eq!(cred.user_id, user_id);
        assert_eq!(cred.sign_count, 0);
        assert_eq!(cred.authenticator_type, "cross-platform");

        // Verify it was stored
        assert_eq!(store.credential_count(), 1);
        assert!(store.get_credential(&cred_id).is_some());
    }

    #[test]
    fn test_validate_and_register_duplicate_rejected() {
        let mut store = CredentialStore::new();
        let rp_id = "sso.milnet.example";
        let user_id = Uuid::new_v4();
        let cred_id = vec![0xAA, 0xBB];
        let cose_key = vec![0x01];

        let auth_data = make_attestation_auth_data(rp_id, 0x45, 0, &cred_id, &cose_key);

        // First registration succeeds
        assert!(validate_and_register(&mut store, &auth_data, rp_id, user_id, "platform").is_ok());

        // Second registration with same credential ID is rejected
        let err = validate_and_register(&mut store, &auth_data, rp_id, user_id, "platform").unwrap_err();
        assert_eq!(err, "Credential ID already registered (duplicate registration rejected)");
        assert_eq!(store.credential_count(), 1);
    }

    #[test]
    fn test_validate_and_register_rp_id_mismatch() {
        let mut store = CredentialStore::new();
        let cred_id = vec![0xAA];
        let cose_key = vec![0x01];

        // Auth data for "evil.com"
        let auth_data = make_attestation_auth_data("evil.com", 0x45, 0, &cred_id, &cose_key);

        let err = validate_and_register(
            &mut store,
            &auth_data,
            "sso.milnet.example",
            Uuid::new_v4(),
            "platform",
        )
        .unwrap_err();
        assert_eq!(err, "RP ID hash mismatch");
        assert_eq!(store.credential_count(), 0);
    }

    #[test]
    fn test_validate_and_register_no_at_flag() {
        let mut store = CredentialStore::new();
        let rp_id = "sso.milnet.example";

        // flags: UP | UV = 0x05 (no AT flag) — just 37 bytes, no attested data
        let rp_hash = Sha256::digest(rp_id.as_bytes());
        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(&rp_hash);
        auth_data.push(0x05); // UP | UV, no AT
        auth_data.extend_from_slice(&0u32.to_be_bytes());

        let err = validate_and_register(&mut store, &auth_data, rp_id, Uuid::new_v4(), "platform")
            .unwrap_err();
        assert_eq!(err, "Attested credential data flag not set in registration response");
    }

    #[test]
    fn test_credential_exists() {
        let mut store = CredentialStore::new();
        let cred_id = vec![1, 2, 3];
        assert!(!store.credential_exists(&cred_id));

        store.store_credential(StoredCredential {
            credential_id: cred_id.clone(),
            public_key: vec![4],
            user_id: Uuid::new_v4(),
            sign_count: 0,
            authenticator_type: "platform".into(),
        aaguid: [0u8; 16],
        cloned_flag: false,
        backup_eligible: false,
        backup_state: false,
        pq_attestation: Vec::new()
        });
        assert!(store.credential_exists(&cred_id));
    }

    #[test]
    #[serial]
    fn test_military_mode_resident_key_required() {
        std::env::remove_var("MILNET_MILITARY_DEPLOYMENT");
        let user_id = Uuid::new_v4();
        let opts = create_registration_options(
            "MILNET SSO", "sso.milnet.example", &user_id, "alice", false,
        );
        assert_eq!(opts.authenticator_selection.resident_key, "required");
    }

    #[test]
    #[serial]
    fn test_military_mode_explicit_true() {
        std::env::set_var("MILNET_MILITARY_DEPLOYMENT", "true");
        let user_id = Uuid::new_v4();
        let opts = create_registration_options(
            "MILNET SSO", "sso.milnet.example", &user_id, "alice", false,
        );
        assert_eq!(opts.authenticator_selection.resident_key, "required");
        std::env::remove_var("MILNET_MILITARY_DEPLOYMENT");
    }

    #[test]
    #[serial]
    fn test_non_military_mode_resident_key_preferred() {
        std::env::set_var("MILNET_MILITARY_DEPLOYMENT", "false");
        let user_id = Uuid::new_v4();
        let opts = create_registration_options(
            "MILNET SSO", "sso.milnet.example", &user_id, "alice", false,
        );
        assert_eq!(opts.authenticator_selection.resident_key, "preferred");
        std::env::remove_var("MILNET_MILITARY_DEPLOYMENT");
    }
}
