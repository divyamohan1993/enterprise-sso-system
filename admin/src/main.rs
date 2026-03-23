use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tokio::sync::RwLock;

use admin::routes::{api_router, AppState};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    // Platform integrity: vTPM check, process hardening, self-attestation, monitor
    let (_platform_report, _monitor_handle, _monitor) =
        common::startup_checks::run_platform_checks(crypto::memguard::harden_process);

    // Derive admin API key deterministically from the master KEK via HKDF-SHA512.
    // This avoids printing secrets and ensures the key is stable across restarts.
    let api_key = std::env::var("ADMIN_API_KEY").unwrap_or_else(|_| {
        let master_kek = common::sealed_keys::load_master_kek();
        let derived = {
            use hkdf::Hkdf;
            use sha2::Sha512;
            let hk = Hkdf::<Sha512>::new(Some(b"MILNET-ADMIN-API-KEY-v1"), &master_kek);
            let mut okm = [0u8; 32];
            hk.expand(b"admin-api-key", &mut okm)
                .expect("HKDF expand");
            okm
        };
        let key = hex::encode(derived);
        tracing::info!("Admin API key derived from master KEK (HKDF-SHA512)");
        key
    });

    let db_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://localhost/milnet_sso".to_string());
    let pool = common::db::init_database(&db_url).await;
    tracing::info!("Connected to PostgreSQL");

    // Pre-seed OAuth clients for known applications
    let mut oauth_clients = sso_protocol::clients::ClientRegistry::new();

    // Register demo app as OAuth client only in demo mode
    if std::env::var("MILNET_DEMO_MODE").is_ok() {
        let demo_redirect = std::env::var("DEMO_REDIRECT_URI")
            .unwrap_or_else(|_| "https://sso-system-demo.dmj.one/callback".to_string());
        oauth_clients.register_with_id(
            "demo-app",
            "demo-secret",
            "Demo Application",
            vec![demo_redirect],
        );
        tracing::warn!("Pre-seeded demo OAuth client: demo-app (MILNET_DEMO_MODE is set)");
    }

    // Try to load existing ServerSetup from DB
    let server_setup_bytes: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT value FROM server_config WHERE key = 'opaque_server_setup'"
    )
        .fetch_optional(&pool)
        .await
        .ok()
        .flatten();

    let credential_store = if let Some(setup_bytes) = server_setup_bytes {
        // Restore existing ServerSetup — all previous user registrations remain valid
        use opaque_ke::ServerSetup;
        let server_setup = ServerSetup::<opaque::opaque_impl::OpaqueCs>::deserialize(&setup_bytes)
            .expect("Failed to deserialize stored ServerSetup");
        tracing::info!("Restored OPAQUE ServerSetup from database");
        opaque::store::CredentialStore::with_server_setup(server_setup)
    } else {
        // First run — create new ServerSetup and persist it
        let store = opaque::store::CredentialStore::new();
        let setup_bytes: Vec<u8> = store.server_setup().serialize().to_vec();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
        sqlx::query("INSERT INTO server_config (key, value, created_at) VALUES ($1, $2, $3)")
            .bind("opaque_server_setup")
            .bind(&setup_bytes)
            .bind(now)
            .execute(&pool)
            .await
            .expect("Failed to persist ServerSetup");
        tracing::info!("Created and persisted new OPAQUE ServerSetup");
        store
    };

    // Restore user registrations from PostgreSQL
    let rows = sqlx::query_as::<_, (uuid::Uuid, String, Vec<u8>)>(
        "SELECT id, username, opaque_registration FROM users WHERE opaque_registration IS NOT NULL"
    )
        .fetch_all(&pool)
        .await
        .unwrap_or_default();

    let mut store = credential_store;
    for (user_id, username, registration) in rows {
        store.restore_user(&username, user_id, registration);
    }
    tracing::info!("Restored {} user registrations from database", store.user_count());

    let google_config = match (
        std::env::var("GOOGLE_CLIENT_ID"),
        std::env::var("GOOGLE_CLIENT_SECRET"),
        std::env::var("SSO_BASE_URL"),
    ) {
        (Ok(cid), Ok(csec), Ok(base)) => {
            tracing::info!("Google OAuth configured");
            Some(admin::google_oauth::GoogleOAuthConfig {
                client_id: cid,
                client_secret: csec,
                redirect_uri: format!("{base}/oauth/google/callback"),
            })
        }
        _ => {
            tracing::warn!("Google OAuth not configured — set GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, SSO_BASE_URL");
            None
        }
    };

    // Generate ML-DSA-87 signing key for audit log entries.
    // ML-DSA-87 keys are large (~4KB); generate on a thread with 8MB stack to avoid overflow.
    let pq_signing_key = std::thread::Builder::new()
        .name("pq-keygen".into())
        .stack_size(8 * 1024 * 1024)
        .spawn(|| crypto::pq_sign::generate_pq_keypair().0)
        .expect("failed to spawn PQ keygen thread")
        .join()
        .expect("PQ keygen thread panicked");
    tracing::info!("Generated ML-DSA-87 signing key for audit log");

    let state = Arc::new(AppState {
        db: pool,
        credential_store: RwLock::new(store),
        device_registry: RwLock::new(risk::tiers::DeviceRegistry::new()),
        audit_log: RwLock::new(audit::log::AuditLog::new()),
        kt_tree: RwLock::new(kt::merkle::MerkleTree::new()),
        portals: RwLock::new(Vec::new()),
        oauth_clients: RwLock::new(oauth_clients),
        auth_codes: RwLock::new(sso_protocol::authorize::AuthorizationStore::new()),
        oidc_signing_key: sso_protocol::tokens::OidcSigningKey::generate(),
        admin_api_key: api_key,
        fido_store: RwLock::new(fido::registration::CredentialStore::new()),
        setup_complete: Arc::new(AtomicBool::new(false)),
        pending_ceremonies: RwLock::new(std::collections::HashMap::new()),
        last_level4_ceremony: RwLock::new(None),
        level4_count_72h: RwLock::new(Vec::new()),
        google_config,
        pending_google: RwLock::new(admin::google_oauth::PendingGoogleStore::new()),
        google_jwks_cache: admin::google_oauth::GoogleJwksCache::new(),
        http_client: reqwest::Client::new(),
        access_tokens: RwLock::new(std::collections::HashMap::new()),
        session_activity: RwLock::new(std::collections::HashMap::new()),
        login_attempts: RwLock::new(std::collections::HashMap::new()),
        pq_signing_key: pq_signing_key,
        session_tracker: Arc::new(common::session_limits::SessionTracker::new(
            common::config::SecurityConfig::default().max_concurrent_sessions_per_user,
        )),
    });

    // Start the key rotation monitor in the background
    let _rotation_shutdown = common::key_rotation::start_rotation_monitor(
        common::key_rotation::RotationSchedule::default(),
        || {
            tracing::info!("Key rotation callback invoked (manual rotation required)");
            Ok(())
        },
    );

    let app = api_router(state);

    let port = std::env::var("ADMIN_PORT").unwrap_or_else(|_| "8080".to_string());
    let is_production = std::env::var("MILNET_PRODUCTION").is_ok();
    // In production, default to loopback; override with ADMIN_BIND_ADDR if needed.
    let default_bind = if is_production { "127.0.0.1" } else { "0.0.0.0" };
    let bind_addr = std::env::var("ADMIN_BIND_ADDR").unwrap_or_else(|_| default_bind.to_string());

    if bind_addr == "0.0.0.0" {
        tracing::warn!("WARNING: Binding to all interfaces (0.0.0.0). Use a TLS-terminating reverse proxy in production.");
        if is_production {
            tracing::warn!("MILNET_PRODUCTION is set but binding to 0.0.0.0 — set ADMIN_BIND_ADDR=127.0.0.1 for loopback-only.");
        }
    }

    let listener = tokio::net::TcpListener::bind(format!("{bind_addr}:{port}"))
        .await
        .unwrap();
    tracing::info!("Admin API listening on {bind_addr}:{port}");
    axum::serve(listener, app).await.unwrap();
}
