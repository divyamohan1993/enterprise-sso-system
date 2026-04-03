use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tokio::sync::RwLock;
use zeroize::Zeroize;

use admin::routes::{api_router, AppState};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    // Platform integrity: vTPM check, process hardening, self-attestation, monitor
    let (_platform_report, _monitor_handle, _monitor) =
        common::startup_checks::run_platform_checks(crypto::memguard::harden_process);

    // Start runtime defense: stealth detection + auto-response pipeline
    let _defense = common::runtime_defense::start_runtime_defense(
        "admin",
        8080,
        _platform_report.binary_hash,
    );

    // SECURITY: Admin API key MUST be explicitly provisioned. No derivation fallback.
    // Previous versions derived the key from master KEK, creating a single-point-of-
    // compromise: if KEK leaks, attacker can regenerate the admin key offline.
    let api_key = match std::env::var("ADMIN_API_KEY") {
        Ok(key) if key.len() >= 32 => key,
        Ok(key) => {
            tracing::error!(
                "FATAL: ADMIN_API_KEY is too short ({} chars, minimum 32). \
                 Admin API key must be a high-entropy secret provisioned externally.",
                key.len()
            );
            std::process::exit(1);
        }
        Err(_) => {
            tracing::error!(
                "FATAL: ADMIN_API_KEY environment variable not set. \
                 Admin API key must be explicitly provisioned -- derivation from \
                 master KEK is disabled to prevent single-point-of-compromise."
            );
            std::process::exit(1);
        }
    };

    // SECURITY: Remove ADMIN_API_KEY from environment after reading to prevent
    // leakage via /proc/pid/environ or child process inheritance.
    std::env::remove_var("ADMIN_API_KEY");

    let db_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://localhost/milnet_sso".to_string());
    let pool = match common::db::init_database(&db_url).await {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("FATAL: database initialization failed: {e}");
            std::process::exit(1);
        }
    };
    tracing::info!("Connected to PostgreSQL");

    // SECURITY: Remove DATABASE_URL from environment now that the connection
    // pool is established. Credentials must not linger in /proc/pid/environ.
    std::env::remove_var("DATABASE_URL");

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

    // SECURITY: Remove replica connection strings from environment after use.
    std::env::remove_var("DATABASE_REPLICA_URLS");

    if replica_urls.is_empty() {
        tracing::warn!("No DATABASE_REPLICA_URLS configured — running without read replicas");
    } else {
        tracing::info!("HA pool configured with {} read replica(s)", replica_urls.len());
    }

    let ha_pool = common::db_ha::HaPool::new(ha_config);

    // ── Envelope encryption for DB fields ──
    let master_kek = *common::sealed_keys::get_master_kek();
    let encrypted_pool = common::encrypted_db::EncryptedPool::new(pool.clone(), master_kek);
    tracing::info!("Envelope encryption initialized (AES-256-GCM, HKDF-SHA512 per-table KEKs)");

    // ── Distributed session store (encrypted at rest) ──
    let session_encryption_key = {
        let encryptor = common::encrypted_db::FieldEncryptor::new(
            *common::sealed_keys::get_master_kek(),
        );
        match encryptor.table_kek("sessions") {
            Ok(k) => k,
            Err(e) => {
                tracing::error!("FATAL: failed to derive session encryption key: {e}");
                std::process::exit(1);
            }
        }
    };
    let session_store = common::distributed_session::DistributedSessionStore::new(
        session_encryption_key,
        common::distributed_session::SessionStoreConfig::default(),
    );
    tracing::info!("Distributed session store initialized (AES-256-GCM encrypted, tier-based TTLs)");

    // Pre-seed OAuth clients for known applications
    let mut oauth_clients = sso_protocol::clients::ClientRegistry::new();

    // Demo mode is forbidden — system is always production.

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
    // The KEK is wrapped in a zeroizing container to ensure it is cleared on drop.
    let mut opaque_setup_kek = {
        let master = common::sealed_keys::cached_master_kek();
        use hkdf::Hkdf;
        use sha2::Sha512;
        let hk = Hkdf::<Sha512>::new(Some(b"MILNET-OPAQUE-SETUP-KEK-v1"), master);
        let mut kek = [0u8; 32];
        if let Err(e) = hk.expand(b"opaque-server-setup-encryption", &mut kek) {
            tracing::error!("FATAL: HKDF expand for OPAQUE setup KEK failed: {e}");
            std::process::exit(1);
        }
        kek
    };

    let credential_store = if let Some(encrypted_bytes) = server_setup_bytes {
        // Restore existing ServerSetup — decrypt first
        use opaque_ke::ServerSetup;
        let setup_bytes = {
            use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
            use aes_gcm::aead::generic_array::GenericArray;
            if encrypted_bytes.len() < 12 + 16 {
                tracing::error!("FATAL: OPAQUE ServerSetup ciphertext too short — data corruption");
                std::process::exit(1);
            }
            let nonce = GenericArray::from_slice(&encrypted_bytes[..12]);
            let ciphertext = &encrypted_bytes[12..];
            let cipher = Aes256Gcm::new(GenericArray::from_slice(&opaque_setup_kek));
            match cipher.decrypt(nonce, ciphertext) {
                Ok(plaintext) => plaintext,
                Err(_) => {
                    tracing::error!("FATAL: Failed to decrypt OPAQUE ServerSetup — KEK mismatch or data corruption");
                    std::process::exit(1);
                }
            }
        };
        let server_setup = match ServerSetup::<opaque::opaque_impl::OpaqueCs>::deserialize(&setup_bytes) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("FATAL: Failed to deserialize stored ServerSetup: {e}");
                std::process::exit(1);
            }
        };
        tracing::info!("Restored and decrypted OPAQUE ServerSetup from database");
        opaque::store::CredentialStore::with_server_setup(server_setup)
    } else {
        // First run — create new ServerSetup, encrypt, and persist it.
        // Use dual mode if FIPS is active so both Argon2id and PBKDF2-SHA512
        // cipher suites are available from the start (prevents KSF mismatch).
        let store = if common::fips::is_fips_mode() {
            opaque::store::CredentialStore::new_dual()
        } else {
            opaque::store::CredentialStore::new()
        };
        let setup_bytes: Vec<u8> = store.server_setup().serialize().to_vec();
        let encrypted_bytes = {
            use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
            use aes_gcm::aead::generic_array::GenericArray;
            let cipher = Aes256Gcm::new(GenericArray::from_slice(&opaque_setup_kek));
            let mut nonce_bytes = [0u8; 12];
            if let Err(e) = getrandom::getrandom(&mut nonce_bytes) {
                tracing::error!("FATAL: CSPRNG failure: {e}");
                std::process::exit(1);
            }
            let nonce = GenericArray::from_slice(&nonce_bytes);
            let ciphertext = match cipher.encrypt(nonce, setup_bytes.as_ref()) {
                Ok(ct) => ct,
                Err(e) => {
                    tracing::error!("FATAL: AES-256-GCM encryption failed: {e}");
                    std::process::exit(1);
                }
            };
            let mut result = Vec::with_capacity(12 + ciphertext.len());
            result.extend_from_slice(&nonce_bytes);
            result.extend_from_slice(&ciphertext);
            result
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(std::time::Duration::ZERO).as_secs() as i64;
        sqlx::query("INSERT INTO server_config (key, value, created_at) VALUES ($1, $2, $3)")
            .bind("opaque_server_setup")
            .bind(&encrypted_bytes)
            .bind(now)
            .execute(&pool)
            .await
            .unwrap_or_else(|e| {
                tracing::error!("FATAL: Failed to persist encrypted ServerSetup: {e}");
                std::process::exit(1);
            });
        tracing::info!("Created, encrypted, and persisted new OPAQUE ServerSetup");
        store
    };

    // SECURITY: Zeroize the OPAQUE setup KEK now that encryption/decryption is done.
    // The KEK must not remain in memory longer than necessary.
    opaque_setup_kek.zeroize();

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
            // SECURITY: Remove OAuth secrets from environment after reading.
            // These must not linger in /proc/pid/environ.
            std::env::remove_var("GOOGLE_CLIENT_ID");
            std::env::remove_var("GOOGLE_CLIENT_SECRET");
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
    let pq_signing_key = match std::thread::Builder::new()
        .name("pq-keygen".into())
        .stack_size(8 * 1024 * 1024)
        .spawn(|| crypto::pq_sign::generate_pq_keypair().0)
    {
        Ok(handle) => match handle.join() {
            Ok(key) => key,
            Err(_) => {
                tracing::error!("FATAL: PQ keygen thread panicked");
                std::process::exit(1);
            }
        },
        Err(e) => {
            tracing::error!("FATAL: failed to spawn PQ keygen thread: {e}");
            std::process::exit(1);
        }
    };
    tracing::info!("Generated ML-DSA-87 signing key for audit log");

    // ── Load super admin keys from DB (if any exist from prior setup) ──
    let super_admin_keys = {
        let mut map = std::collections::HashMap::new();
        let rows: Vec<(uuid::Uuid, String, Vec<u8>, Option<String>)> = sqlx::query_as(
            "SELECT id, label, key_hash, region FROM super_admins"
        )
        .fetch_all(&pool)
        .await
        .unwrap_or_default();
        for (id, label, key_hash, region) in rows {
            map.insert(id, admin::routes::SuperAdminEntry {
                id,
                label: label.clone(),
                key_hash,
                region,
            });
        }
        if !map.is_empty() {
            tracing::info!("Loaded {} super admin(s) from database", map.len());
        }
        map
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
        super_admin_keys: RwLock::new(super_admin_keys),
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
        developer_log_level: std::sync::atomic::AtomicU8::new(common::config::ErrorLevel::Verbose as u8),
        pending_admin_actions: RwLock::new(std::collections::HashMap::new()),
        ha_pool: std::sync::Mutex::new(ha_pool),
        encrypted_pool,
        session_store: RwLock::new(session_store),
        refresh_token_store: RwLock::new(sso_protocol::tokens::RefreshTokenStore::new()),
    });

    // Start the key rotation monitor in the background
    let _rotation_shutdown = match common::key_rotation::start_rotation_monitor(
        common::key_rotation::RotationSchedule::default(),
        || {
            tracing::info!("Key rotation callback invoked (manual rotation required)");
            Ok(())
        },
    ) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("Failed to start key rotation monitor: {e}");
            std::process::exit(1);
        }
    };

    // Start background cleanup task for bounded HashMap growth
    admin::routes::spawn_ttl_eviction_task(state.clone());

    let app = api_router(state);

    // Note: ADMIN_PORT is auto-set by K8s service discovery (e.g. "tcp://10.x.x.x:8080").
    // Use MILNET_ADMIN_PORT to avoid collision.
    let port = std::env::var("MILNET_ADMIN_PORT")
        .or_else(|_| std::env::var("ADMIN_PORT").and_then(|v| {
            if v.chars().all(|c| c.is_ascii_digit()) { Ok(v) } else { Err(std::env::VarError::NotPresent) }
        }))
        .unwrap_or_else(|_| "8080".to_string());

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

    // Always production — default to loopback; override with ADMIN_BIND_ADDR if needed.
    let default_bind = "127.0.0.1";
    let bind_addr = std::env::var("ADMIN_BIND_ADDR").unwrap_or_else(|_| default_bind.to_string());

    // TLS configuration check
    let tls_cert = std::env::var("ADMIN_TLS_CERT").ok();
    let tls_key = std::env::var("ADMIN_TLS_KEY").ok();

    // SECURITY: Remove TLS key path from environment after reading.
    // The path itself can reveal filesystem layout to an attacker.
    std::env::remove_var("ADMIN_TLS_KEY");

    let require_tls = std::env::var("REQUIRE_TLS")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);
    let has_tls = tls_cert.is_some() && tls_key.is_some();

    // TLS is always required.
    if !has_tls {
        tracing::error!(
            "FATAL: Admin API requires TLS. \
             Set ADMIN_TLS_CERT and ADMIN_TLS_KEY, or use a TLS-terminating reverse proxy."
        );
        std::process::exit(1);
    }

    // Add HSTS header middleware to all responses (signals to browsers/proxies
    // that this service should only be accessed over HTTPS)
    let app = app.layer(axum::middleware::from_fn(hsts_middleware));

    if has_tls {
        // TLS cert/key paths were provided — validate they exist and are readable
        let cert_path = match tls_cert.as_deref() {
            Some(p) => p,
            None => {
                tracing::error!("FATAL: ADMIN_TLS_CERT not set");
                std::process::exit(1);
            }
        };
        let key_path = match tls_key.as_deref() {
            Some(p) => p,
            None => {
                tracing::error!("FATAL: ADMIN_TLS_KEY not set");
                std::process::exit(1);
            }
        };

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

    // SECURITY: Remove ALL sensitive env vars from /proc/PID/environ IMMEDIATELY
    // after the last env var read. Secrets must not linger in the process environment
    // any longer than necessary to prevent leakage via /proc/PID/environ or
    // child process inheritance.
    common::startup_checks::sanitize_environment();

    // SECURITY: Verify kernel security posture (ptrace_scope, BPF restrictions)
    common::startup_checks::verify_kernel_security_posture();

    // SECURITY: Verify process hardening flags and apply anti-ptrace
    crypto::seccomp::apply_anti_ptrace();
    crypto::seccomp::verify_process_hardening();

    let listener = match tokio::net::TcpListener::bind(format!("{bind_addr}:{port}")).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("FATAL: failed to bind admin listener on {bind_addr}:{port}: {e}");
            std::process::exit(1);
        }
    };
    tracing::info!(
        "Admin API listening on {bind_addr}:{port} (TLS={})",
        if has_tls { "configured" } else { "disabled" }
    );

    // SECURITY: Graceful shutdown on SIGTERM/SIGINT.
    // - Stops accepting new HTTP connections via axum's graceful shutdown
    // - Waits for in-flight requests to complete (30s timeout)
    // - Zeroizes sensitive memory (API keys, KEK) before exit
    let shutdown_signal = async {
        let mut sigterm = match tokio::signal::unix::signal(
            tokio::signal::unix::SignalKind::terminate(),
        ) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("FATAL: failed to install SIGTERM handler: {e}");
                std::process::exit(1);
            }
        };
        let mut sigint = match tokio::signal::unix::signal(
            tokio::signal::unix::SignalKind::interrupt(),
        ) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("FATAL: failed to install SIGINT handler: {e}");
                std::process::exit(1);
            }
        };
        tokio::select! {
            _ = sigterm.recv() => tracing::info!("received SIGTERM, initiating graceful shutdown"),
            _ = sigint.recv() => tracing::info!("received SIGINT, initiating graceful shutdown"),
        }
    };

    if let Err(e) = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal)
        .await
    {
        tracing::error!("FATAL: admin server error: {e}");
        std::process::exit(1);
    }

    // SECURITY: Zeroize master KEK from stack before exit.
    {
        use zeroize::Zeroize;
        let mut kek_copy = master_kek;
        kek_copy.zeroize();
    }
    tracing::info!("admin: graceful shutdown complete");
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
