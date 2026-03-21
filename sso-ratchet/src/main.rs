#![forbid(unsafe_code)]
//! sso-ratchet: Ratchet Session Manager service.

use sso_ratchet::manager::SessionManager;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    tracing::info!("sso-ratchet: starting ratchet session manager");

    let _manager = SessionManager::new();

    tracing::info!("sso-ratchet: ratchet session manager ready");
}
