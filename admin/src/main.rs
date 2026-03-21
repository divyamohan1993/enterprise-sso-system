use std::sync::{Arc, Mutex};
use tokio::sync::RwLock;

use admin::routes::{api_router, AppState};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let api_key = std::env::var("ADMIN_API_KEY").unwrap_or_else(|_| {
        let key = hex::encode(crypto::entropy::generate_nonce());
        eprintln!("Generated admin API key: {key}");
        key
    });

    let db_path = std::env::var("DB_PATH").unwrap_or_else(|_| "milnet-sso.db".to_string());
    let db = common::db::init_database(&db_path);
    tracing::info!("Database opened at {db_path}");

    let state = Arc::new(AppState {
        db: Mutex::new(db),
        credential_store: RwLock::new(opaque::store::CredentialStore::new()),
        device_registry: RwLock::new(risk::tiers::DeviceRegistry::new()),
        audit_log: RwLock::new(audit::log::AuditLog::new()),
        kt_tree: RwLock::new(kt::merkle::MerkleTree::new()),
        portals: RwLock::new(Vec::new()),
        oauth_clients: RwLock::new(sso_protocol::clients::ClientRegistry::new()),
        auth_codes: RwLock::new(sso_protocol::authorize::AuthorizationStore::new()),
        oidc_signing_key: crypto::entropy::generate_key_64(),
        admin_api_key: api_key,
        fido_store: RwLock::new(fido::registration::CredentialStore::new()),
    });

    let app = api_router(state);

    let port = std::env::var("ADMIN_PORT").unwrap_or_else(|_| "8080".to_string());
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}"))
        .await
        .unwrap();
    tracing::info!("Admin API listening on port {port}");
    axum::serve(listener, app).await.unwrap();
}
