#![forbid(unsafe_code)]
//! ratchet: Ratchet Session Manager service.

use ratchet::manager::SessionManager;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    tracing::info!("ratchet: starting ratchet session manager");

    let _manager = SessionManager::new();

    tracing::info!("ratchet: ratchet session manager ready");
}
