use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tokio::sync::RwLock;

use admin::routes::{api_router, AppState};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    // Harden process: disable core dumps, prevent ptrace escalation
    crypto::memguard::harden_process();

    let api_key = std::env::var("ADMIN_API_KEY").unwrap_or_else(|_| {
        let key = hex::encode(crypto::entropy::generate_nonce());
        eprintln!("Generated admin API key: {key}");
        key
    });

    let db_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://localhost/milnet_sso".to_string());
    let pool = common::db::init_database(&db_url).await;
    tracing::info!("Connected to PostgreSQL");

    // Pre-seed OAuth clients for known applications
    let mut oauth_clients = sso_protocol::clients::ClientRegistry::new();

    // Register demo app as OAuth client (always available)
    let demo_redirect = std::env::var("DEMO_REDIRECT_URI")
        .unwrap_or_else(|_| "https://sso-system-demo.dmj.one/callback".to_string());
    oauth_clients.register_with_id(
        "demo-app",
        "demo-secret",
        "Demo Application",
        vec![demo_redirect],
    );
    tracing::info!("Pre-seeded OAuth client: demo-app");

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
        http_client: reqwest::Client::new(),
        access_tokens: RwLock::new(std::collections::HashMap::new()),
        login_attempts: RwLock::new(std::collections::HashMap::new()),
    });

    let app = api_router(state);

    let port = std::env::var("ADMIN_PORT").unwrap_or_else(|_| "8080".to_string());
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}"))
        .await
        .unwrap();
    tracing::info!("Admin API listening on port {port}");
    axum::serve(listener, app).await.unwrap();
}
