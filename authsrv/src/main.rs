//! `authsrv` binary — runs the OIDC AS on `0.0.0.0:8443` (HTTP for now;
//! TLS termination handled by the gateway). Loads no clients by default;
//! operators register clients via the admin API.

use authsrv::{router, AsState};
use std::sync::Arc;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let state = Arc::new(AsState::default());
    let app = router().with_state(state);
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8443").await?;
    tracing::info!("authsrv listening on 0.0.0.0:8443");
    axum::serve(listener, app).await?;
    Ok(())
}
