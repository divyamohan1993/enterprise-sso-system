use std::sync::Arc;
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

    let db_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://localhost/milnet_sso".to_string());
    let pool = common::db::init_database(&db_url).await;
    tracing::info!("Connected to PostgreSQL");

    let state = Arc::new(AppState {
        db: pool,
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
