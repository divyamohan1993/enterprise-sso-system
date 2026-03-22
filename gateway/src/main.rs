#![forbid(unsafe_code)]
//! gateway binary entry point.

use gateway::server::GatewayServer;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    // Harden process: disable core dumps, prevent ptrace escalation
    crypto::memguard::harden_process();

    let port = std::env::var("GATEWAY_PORT").unwrap_or_else(|_| "9100".into());
    let addr = format!("0.0.0.0:{port}");

    let server = GatewayServer::bind(&addr, 4)
        .await
        .expect("failed to bind gateway");

    server.run().await.expect("gateway server error");
}
