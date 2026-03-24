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

    // Register demo app as OAuth client only in demo mode.
    // SECURITY: If MILNET_PRODUCTION is set, refuse demo mode entirely.
    let is_demo = std::env::var("MILNET_DEMO_MODE").is_ok();
    let is_production = std::env::var("MILNET_PRODUCTION").is_ok();
    if is_production && is_demo {
        panic!(
            "FATAL: MILNET_PRODUCTION and MILNET_DEMO_MODE are both set. \
             Demo mode with hardcoded credentials is forbidden in production. \
             Unset MILNET_DEMO_MODE to proceed."
        );
    }
    if is_demo && !is_production {
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
        opaque_tokens: RwLock::new(std::collections::HashMap::new()),
        used_csrf_tokens: RwLock::new(std::collections::HashSet::new()),
        pq_signing_key: pq_signing_key,
        session_tracker: Arc::new(common::session_limits::SessionTracker::new(
            common::config::SecurityConfig::default().max_concurrent_sessions_per_user,
        )),
        revocation_list: RwLock::new(admin::routes::RevocationList::new()),
        developer_mode: std::sync::atomic::AtomicBool::new(false),
        developer_log_level: std::sync::atomic::AtomicU8::new(common::config::LogLevel::Error as u8),
    });

    // Start the key rotation monitor in the background
    let _rotation_shutdown = common::key_rotation::start_rotation_monitor(
        common::key_rotation::RotationSchedule::default(),
        || {
            tracing::info!("Key rotation callback invoked (manual rotation required)");
            Ok(())
        },
    );

    // Start background cleanup task for bounded HashMap growth
    admin::routes::spawn_ttl_eviction_task(state.clone());

    let app = api_router(state);

    let port = std::env::var("ADMIN_PORT").unwrap_or_else(|_| "8080".to_string());
    let is_production = std::env::var("MILNET_PRODUCTION").is_ok();
    // In production, default to loopback; override with ADMIN_BIND_ADDR if needed.
    let default_bind = if is_production { "127.0.0.1" } else { "0.0.0.0" };
    let bind_addr = std::env::var("ADMIN_BIND_ADDR").unwrap_or_else(|_| default_bind.to_string());

    // TLS configuration check
    let tls_cert = std::env::var("ADMIN_TLS_CERT").ok();
    let tls_key = std::env::var("ADMIN_TLS_KEY").ok();
    let require_tls = std::env::var("REQUIRE_TLS")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);
    let has_tls = tls_cert.is_some() && tls_key.is_some();

    // If REQUIRE_TLS is set but no cert/key provided, refuse to start
    if require_tls && !has_tls {
        tracing::error!(
            "REQUIRE_TLS=true but ADMIN_TLS_CERT and/or ADMIN_TLS_KEY not set. \
             Refusing to start without TLS configuration."
        );
        std::process::exit(1);
    }

    if bind_addr == "0.0.0.0" && !has_tls {
        if is_production {
            tracing::error!(
                "SECURITY: Binding to all interfaces (0.0.0.0) without TLS in production mode. \
                 Set ADMIN_TLS_CERT and ADMIN_TLS_KEY, or use ADMIN_BIND_ADDR=127.0.0.1 \
                 behind a TLS-terminating reverse proxy."
            );
        } else {
            tracing::warn!(
                "WARNING: Binding to all interfaces (0.0.0.0) without TLS. \
                 Use a TLS-terminating reverse proxy in production."
            );
        }
    } else if bind_addr == "127.0.0.1" && !has_tls {
        tracing::warn!(
            "Admin API running without TLS on loopback. \
             Ensure a TLS-terminating reverse proxy is in front of this service."
        );
    }

    // Add HSTS header middleware to all responses (signals to browsers/proxies
    // that this service should only be accessed over HTTPS)
    let app = app.layer(axum::middleware::from_fn(hsts_middleware));

    if has_tls {
        // TLS cert/key paths were provided — validate they exist and are readable
        let cert_path = tls_cert.as_deref().unwrap();
        let key_path = tls_key.as_deref().unwrap();

        if !std::path::Path::new(cert_path).exists() {
            tracing::error!("ADMIN_TLS_CERT path does not exist: {cert_path}");
            std::process::exit(1);
        }
        if !std::path::Path::new(key_path).exists() {
            tracing::error!("ADMIN_TLS_KEY path does not exist: {key_path}");
            std::process::exit(1);
        }

        tracing::info!(
            "TLS certificate and key configured (cert={cert_path}, key={key_path}). \
             Use a TLS-terminating reverse proxy (e.g., nginx, envoy) pointed at these \
             files, or deploy with axum-server-rustls for native TLS termination."
        );
    }

    let listener = tokio::net::TcpListener::bind(format!("{bind_addr}:{port}"))
        .await
        .unwrap();
    tracing::info!(
        "Admin API listening on {bind_addr}:{port} (TLS={})",
        if has_tls { "configured" } else { "disabled" }
    );
    axum::serve(listener, app).await.unwrap();
}

/// Middleware that adds Strict-Transport-Security header to all responses.
async fn hsts_middleware(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        axum::http::header::STRICT_TRANSPORT_SECURITY,
        axum::http::HeaderValue::from_static("max-age=63072000; includeSubDomains; preload"),
    );
    response
}
