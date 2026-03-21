#![forbid(unsafe_code)]
//! opaque: T-OPAQUE Password Service.

use opaque::store::CredentialStore;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let store = CredentialStore::new();
    if let Err(e) = opaque::service::run(store).await {
        eprintln!("OPAQUE service error: {e}");
        std::process::exit(1);
    }
}
