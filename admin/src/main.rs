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
        // Bind admin key to deployment identity for domain separation.
        // v2: includes deployment-specific context to prevent key reuse.
        let deployment_id = std::env::var("MILNET_DEPLOYMENT_ID")
            .unwrap_or_else(|_| "default-deployment".to_string());
        let salt = format!("MILNET-ADMIN-API-KEY-v2:{}", deployment_id);
        let derived = {
            use hkdf::Hkdf;
            use sha2::Sha512;
            let hk = Hkdf::<Sha512>::new(Some(salt.as_bytes()), &master_kek);
            let mut okm = [0u8; 32];
            hk.expand(b"admin-api-key-v2", &mut okm)
                .expect("HKDF expand");
            okm
        };
        let key = hex::encode(derived);
        tracing::info!("Admin API key derived from master KEK (HKDF-SHA512, deployment-bound)");
        key
    });

    let db_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://localhost/milnet_sso".to_string());
    let pool = common::db::init_database(&db_url).await;
    tracing::info!("Connected to PostgreSQL");

    // ── HA pool with primary/replica routing ──
    let replica_urls: Vec<String> = std::env::var("DATABASE_REPLICA_URLS")
        .unwrap_or_default()
        .split(',')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect();

    let ha_config = {
        let mut replicas = Vec::new();
        for (i, url) in replica_urls.iter().enumerate() {
            replicas.push(common::db_ha::NodeConfig {
                node_id: format!("replica-{}", i + 1),
                connection_url: url.clone(),
                role: common::db_ha::NodeRole::Replica,
                max_connections: 10,
            });
        }
        common::db_ha::HaConfig {
            primary: common::db_ha::NodeConfig {
                node_id: "primary-1".into(),
                connection_url: db_url.clone(),
                role: common::db_ha::NodeRole::Primary,
                max_connections: 20,
            },
            replicas,
            ..common::db_ha::HaConfig::default()
        }
    };

    if replica_urls.is_empty() {
        tracing::warn!("No DATABASE_REPLICA_URLS configured — running without read replicas");
    } else {
        tracing::info!("HA pool configured with {} read replica(s)", replica_urls.len());
    }

    let ha_pool = common::db_ha::HaPool::new(ha_config);

    // ── Envelope encryption for DB fields ──
    let master_kek = common::sealed_keys::load_master_kek();
    let encrypted_pool = common::encrypted_db::EncryptedPool::new(pool.clone(), master_kek);
    tracing::info!("Envelope encryption initialized (AES-256-GCM, HKDF-SHA512 per-table KEKs)");

    // ── Distributed session store (encrypted at rest) ──
    let session_encryption_key = {
        let encryptor = common::encrypted_db::FieldEncryptor::new(
            common::sealed_keys::load_master_kek(),
        );
        encryptor.table_kek("sessions")
    };
    let session_store = common::distributed_session::DistributedSessionStore::new(
        session_encryption_key,
        common::distributed_session::SessionStoreConfig::default(),
    );
    tracing::info!("Distributed session store initialized (AES-256-GCM encrypted, tier-based TTLs)");

    // Pre-seed OAuth clients for known applications
    let mut oauth_clients = sso_protocol::clients::ClientRegistry::new();

    // Register demo app as OAuth client only in demo mode.
    // SECURITY: If MILNET_PRODUCTION is set, refuse demo mode entirely.
    let is_demo = std::env::var("MILNET_DEMO_MODE").is_ok();
    let is_production = std::env::var("MILNET_PRODUCTION").is_ok();
    if is_production && is_demo {
        tracing::error!(
            "FATAL: MILNET_PRODUCTION and MILNET_DEMO_MODE are both set. \
             Demo mode with hardcoded credentials is forbidden in production. \
             Unset MILNET_DEMO_MODE to proceed."
        );
        std::process::exit(1);
    }
    if is_demo && !is_production {
        let demo_redirect = std::env::var("DEMO_REDIRECT_URI")
            .unwrap_or_else(|_| "https://sso-system-demo.dmj.one/callback".to_string());
        // SECURITY: Never hardcode secrets. Derive the demo client secret from the
        // master KEK via HKDF-SHA512 with a unique domain separator.
        // This is only reachable when is_demo && !is_production, so load_master_kek
        // will return a deterministic dev key if MILNET_MASTER_KEK is not set.
        let demo_secret = {
            let master_kek = common::sealed_keys::load_master_kek();
            use hkdf::Hkdf;
            use sha2::Sha512;
            let hk = Hkdf::<Sha512>::new(
                Some(b"MILNET-DEMO-CLIENT-SECRET-v1"),
                &master_kek,
            );
            let mut okm = [0u8; 32];
            hk.expand(b"demo-app-client-secret", &mut okm)
                .expect("HKDF expand");
            hex::encode(okm)
        };
        oauth_clients.register_with_id(
            "demo-app",
            &demo_secret,
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

    // SECURITY: OPAQUE ServerSetup contains the OPRF seed and server keypair.
    // It MUST be encrypted at rest using envelope encryption with the master KEK.
    // Derive a dedicated KEK for OPAQUE server setup via HKDF-SHA512.
    let opaque_setup_kek = {
        let master = common::sealed_keys::cached_master_kek();
        use hkdf::Hkdf;
        use sha2::Sha512;
        let hk = Hkdf::<Sha512>::new(Some(b"MILNET-OPAQUE-SETUP-KEK-v1"), master);
        let mut kek = [0u8; 32];
        hk.expand(b"opaque-server-setup-encryption", &mut kek)
            .expect("HKDF expand for OPAQUE setup KEK");
        kek
    };

    let credential_store = if let Some(encrypted_bytes) = server_setup_bytes {
        // Restore existing ServerSetup — decrypt first
        use opaque_ke::ServerSetup;
        let setup_bytes = {
            use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
            use aes_gcm::aead::generic_array::GenericArray;
            if encrypted_bytes.len() < 12 + 16 {
                panic!("FATAL: OPAQUE ServerSetup ciphertext too short — data corruption");
            }
            let nonce = GenericArray::from_slice(&encrypted_bytes[..12]);
            let ciphertext = &encrypted_bytes[12..];
            let cipher = Aes256Gcm::new(GenericArray::from_slice(&opaque_setup_kek));
            cipher.decrypt(nonce, ciphertext)
                .expect("FATAL: Failed to decrypt OPAQUE ServerSetup — KEK mismatch or data corruption")
        };
        let server_setup = ServerSetup::<opaque::opaque_impl::OpaqueCs>::deserialize(&setup_bytes)
            .expect("Failed to deserialize stored ServerSetup");
        tracing::info!("Restored and decrypted OPAQUE ServerSetup from database");
        opaque::store::CredentialStore::with_server_setup(server_setup)
    } else {
        // First run — create new ServerSetup, encrypt, and persist it
        let store = opaque::store::CredentialStore::new();
        let setup_bytes: Vec<u8> = store.server_setup().serialize().to_vec();
        let encrypted_bytes = {
            use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
            use aes_gcm::aead::generic_array::GenericArray;
            let cipher = Aes256Gcm::new(GenericArray::from_slice(&opaque_setup_kek));
            let mut nonce_bytes = [0u8; 12];
            getrandom::getrandom(&mut nonce_bytes).expect("CSPRNG failure");
            let nonce = GenericArray::from_slice(&nonce_bytes);
            let ciphertext = cipher.encrypt(nonce, setup_bytes.as_ref())
                .expect("AES-256-GCM encryption failed");
            let mut result = Vec::with_capacity(12 + ciphertext.len());
            result.extend_from_slice(&nonce_bytes);
            result.extend_from_slice(&ciphertext);
            result
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
        sqlx::query("INSERT INTO server_config (key, value, created_at) VALUES ($1, $2, $3)")
            .bind("opaque_server_setup")
            .bind(&encrypted_bytes)
            .bind(now)
            .execute(&pool)
            .await
            .expect("Failed to persist encrypted ServerSetup");
        tracing::info!("Created, encrypted, and persisted new OPAQUE ServerSetup");
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
        pending_admin_actions: RwLock::new(std::collections::HashMap::new()),
        ha_pool: std::sync::Mutex::new(ha_pool),
        encrypted_pool,
        session_store: RwLock::new(session_store),
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

    // Spawn health check endpoint
    let health_start = std::time::Instant::now();
    let admin_port: u16 = port.parse().unwrap_or(8080);
    let _health_handle = common::health::spawn_health_endpoint(
        "admin".to_string(),
        admin_port,
        health_start,
        || {
            vec![common::health::HealthCheck {
                name: "admin_service".to_string(),
                ok: true,
                detail: None,
                latency_ms: None,
            }]
        },
    );

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

    // In production, refuse to start without TLS — no exceptions.
    if is_production && !has_tls {
        tracing::error!(
            "FATAL: Admin API requires TLS in production. \
             Set ADMIN_TLS_CERT and ADMIN_TLS_KEY, or use a TLS-terminating reverse proxy \
             with REQUIRE_TLS=false and ADMIN_BIND_ADDR=127.0.0.1."
        );
        std::process::exit(1);
    }

    if bind_addr == "0.0.0.0" && !has_tls {
        {
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

/// Middleware that adds comprehensive security headers to all responses.
async fn hsts_middleware(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        axum::http::header::STRICT_TRANSPORT_SECURITY,
        axum::http::HeaderValue::from_static("max-age=63072000; includeSubDomains; preload"),
    );
    headers.insert(
        axum::http::header::X_CONTENT_TYPE_OPTIONS,
        axum::http::HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        axum::http::header::X_FRAME_OPTIONS,
        axum::http::HeaderValue::from_static("DENY"),
    );
    headers.insert(
        axum::http::header::CONTENT_SECURITY_POLICY,
        axum::http::HeaderValue::from_static(
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; \
             img-src 'self' data:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
        ),
    );
    headers.insert(
        axum::http::header::HeaderName::from_static("x-xss-protection"),
        axum::http::HeaderValue::from_static("0"),
    );
    headers.insert(
        axum::http::header::REFERRER_POLICY,
        axum::http::HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    headers.insert(
        axum::http::header::HeaderName::from_static("permissions-policy"),
        axum::http::HeaderValue::from_static("camera=(), microphone=(), geolocation=(), payment=()"),
    );
    headers.insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store, no-cache, must-revalidate"),
    );
    headers.insert(
        axum::http::header::PRAGMA,
        axum::http::HeaderValue::from_static("no-cache"),
    );
    response
}
