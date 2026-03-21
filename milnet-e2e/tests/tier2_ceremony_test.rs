//! End-to-end integration test: full Tier 2 auth ceremony.
//!
//! Boots all five Phase 2 modules (OPAQUE, TSS, Orchestrator, Gateway, Verifier)
//! as tokio tasks and runs a complete authentication flow from client connection
//! through to token verification.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use milnet_common::types::{ModuleId, Token};
use milnet_crypto::threshold::{dkg, SignerShare, ThresholdGroup};
use milnet_gateway::puzzle::{solve_challenge, PuzzleChallenge, PuzzleSolution};
use milnet_gateway::server::{GatewayServer, OrchestratorConfig};
use milnet_gateway::wire::{AuthRequest, AuthResponse};
use milnet_opaque::messages::OpaqueRequest;
use milnet_opaque::service::handle_request as opaque_handle_request;
use milnet_opaque::store::CredentialStore;
use milnet_orchestrator::service::OrchestratorService;
use milnet_shard::transport::ShardListener;
use milnet_tss::messages::{SigningRequest, SigningResponse};
use milnet_tss::token_builder::build_token;
use milnet_tss::validator::validate_receipt_chain;
use milnet_verifier::verify::verify_token;

/// Fixed 64-byte HMAC key for SHARD communication in tests.
const SHARD_HMAC_KEY: [u8; 64] = [0x37u8; 64];

/// Fixed 64-byte receipt signing key shared between OPAQUE and TSS.
const RECEIPT_SIGNING_KEY: [u8; 64] = [0x42u8; 64];

/// Puzzle difficulty (low for fast tests).
const TEST_DIFFICULTY: u8 = 4;

// ── Wire helpers (length-prefixed postcard over TCP) ────────────────────

async fn send_frame<T: serde::Serialize>(stream: &mut TcpStream, value: &T) -> Result<(), String> {
    let payload = postcard::to_allocvec(value).map_err(|e| format!("serialize: {e}"))?;
    let len = payload.len() as u32;
    stream
        .write_all(&len.to_be_bytes())
        .await
        .map_err(|e| format!("write length: {e}"))?;
    stream
        .write_all(&payload)
        .await
        .map_err(|e| format!("write payload: {e}"))?;
    stream.flush().await.map_err(|e| format!("flush: {e}"))?;
    Ok(())
}

async fn recv_frame<T: serde::de::DeserializeOwned>(stream: &mut TcpStream) -> Result<T, String> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| format!("read length: {e}"))?;
    let len = u32::from_be_bytes(len_buf);
    let mut buf = vec![0u8; len as usize];
    stream
        .read_exact(&mut buf)
        .await
        .map_err(|e| format!("read payload: {e}"))?;
    postcard::from_bytes(&buf).map_err(|e| format!("deserialize: {e}"))
}

// ── Service boot helpers ────────────────────────────────────────────────

/// Boot the OPAQUE service as a SHARD listener. Returns the bound address.
async fn boot_opaque(store: CredentialStore) -> String {
    let listener = ShardListener::bind("127.0.0.1:0", ModuleId::Opaque, SHARD_HMAC_KEY)
        .await
        .expect("bind OPAQUE listener");
    let addr = listener
        .local_addr()
        .expect("OPAQUE local_addr")
        .to_string();

    tokio::spawn(async move {
        loop {
            let mut transport = match listener.accept().await {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("OPAQUE accept error: {e}");
                    continue;
                }
            };

            let (_sender, payload) = match transport.recv().await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("OPAQUE recv error: {e}");
                    continue;
                }
            };

            let request: OpaqueRequest = match postcard::from_bytes(&payload) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("OPAQUE deserialize error: {e}");
                    continue;
                }
            };

            let response = opaque_handle_request(&store, &request, &RECEIPT_SIGNING_KEY);

            let response_bytes =
                postcard::to_allocvec(&response).expect("serialize OPAQUE response");

            if let Err(e) = transport.send(&response_bytes).await {
                eprintln!("OPAQUE send error: {e}");
            }
        }
    });

    addr
}

/// Boot the TSS service as a SHARD listener. Returns the bound address.
/// Needs signer shares and threshold group from DKG.
async fn boot_tss(mut signers: Vec<SignerShare>, group: ThresholdGroup) -> String {
    let listener = ShardListener::bind("127.0.0.1:0", ModuleId::Tss, SHARD_HMAC_KEY)
        .await
        .expect("bind TSS listener");
    let addr = listener.local_addr().expect("TSS local_addr").to_string();

    // TSS holds its own copy of the receipt signing key at init (CRIT-1)
    let tss_receipt_signing_key = RECEIPT_SIGNING_KEY;

    tokio::spawn(async move {
        loop {
            let mut transport = match listener.accept().await {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("TSS accept error: {e}");
                    continue;
                }
            };

            let (_sender, payload) = match transport.recv().await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("TSS recv error: {e}");
                    continue;
                }
            };

            let request: SigningRequest = match postcard::from_bytes(&payload) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("TSS deserialize error: {e}");
                    let resp = SigningResponse {
                        success: false,
                        token: None,
                        error: Some(format!("deserialize: {e}")),
                    };
                    let resp_bytes = postcard::to_allocvec(&resp).unwrap();
                    let _ = transport.send(&resp_bytes).await;
                    continue;
                }
            };

            // Validate receipt chain using TSS's own key (not from request)
            let response =
                match validate_receipt_chain(&request.receipts, &tss_receipt_signing_key) {
                    Ok(()) => {
                        // Build threshold-signed token
                        match build_token(&request.claims, &mut signers, &group) {
                            Ok(token) => {
                                let token_bytes =
                                    postcard::to_allocvec(&token).expect("serialize token");
                                SigningResponse {
                                    success: true,
                                    token: Some(token_bytes),
                                    error: None,
                                }
                            }
                            Err(e) => SigningResponse {
                                success: false,
                                token: None,
                                error: Some(format!("token build: {e}")),
                            },
                        }
                    }
                    Err(e) => SigningResponse {
                        success: false,
                        token: None,
                        error: Some(format!("receipt validation: {e}")),
                    },
                };

            let response_bytes = postcard::to_allocvec(&response).expect("serialize TSS response");

            if let Err(e) = transport.send(&response_bytes).await {
                eprintln!("TSS send error: {e}");
            }
        }
    });

    addr
}

/// Boot the Orchestrator as a SHARD listener. Returns the bound address.
async fn boot_orchestrator(opaque_addr: String, tss_addr: String) -> String {
    let listener = ShardListener::bind("127.0.0.1:0", ModuleId::Orchestrator, SHARD_HMAC_KEY)
        .await
        .expect("bind Orchestrator listener");
    let addr = listener
        .local_addr()
        .expect("Orchestrator local_addr")
        .to_string();

    let service =
        OrchestratorService::new(SHARD_HMAC_KEY, opaque_addr, tss_addr, RECEIPT_SIGNING_KEY);

    tokio::spawn(async move {
        loop {
            let mut transport = match listener.accept().await {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("Orchestrator accept error: {e}");
                    continue;
                }
            };

            let (_sender, req_bytes) = match transport.recv().await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("Orchestrator recv error: {e}");
                    continue;
                }
            };

            let request: milnet_orchestrator::messages::OrchestratorRequest =
                match postcard::from_bytes(&req_bytes) {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("Orchestrator deserialize error: {e}");
                        continue;
                    }
                };

            let response = service.process_auth(&request).await;

            let resp_bytes =
                postcard::to_allocvec(&response).expect("serialize Orchestrator response");

            if let Err(e) = transport.send(&resp_bytes).await {
                eprintln!("Orchestrator send error: {e}");
            }
        }
    });

    addr
}

/// Boot the Gateway as a TCP listener with orchestrator forwarding. Returns the bound address.
async fn boot_gateway(orchestrator_addr: String) -> String {
    let gateway = GatewayServer::bind_with_orchestrator(
        "127.0.0.1:0",
        TEST_DIFFICULTY,
        OrchestratorConfig {
            addr: orchestrator_addr,
            hmac_key: SHARD_HMAC_KEY,
        },
    )
    .await
    .expect("bind Gateway");

    let addr = gateway
        .local_addr()
        .expect("Gateway local_addr")
        .to_string();

    tokio::spawn(async move {
        gateway.run().await.expect("Gateway run");
    });

    addr
}

// ── Tests ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn tier2_full_ceremony_success() {
    // 1. Setup crypto: DKG(5,3)
    let dkg_result = dkg(5, 3);
    let group_verifying_key = dkg_result.group.public_key_package.clone();

    // Take only 3 shares (threshold) for the TSS
    let signers: Vec<SignerShare> = dkg_result.shares.into_iter().take(3).collect();

    // 2. Boot services in dependency order
    let opaque_addr = boot_opaque({
        let mut store = CredentialStore::new();
        store.register("alice", b"password123");
        store
    })
    .await;

    let tss_addr = boot_tss(signers, dkg_result.group).await;

    // Small delay to let listeners bind
    tokio::time::sleep(Duration::from_millis(50)).await;

    let orchestrator_addr = boot_orchestrator(opaque_addr, tss_addr).await;

    tokio::time::sleep(Duration::from_millis(50)).await;

    let gateway_addr = boot_gateway(orchestrator_addr).await;

    tokio::time::sleep(Duration::from_millis(50)).await;

    // 3. Run the client flow
    let mut stream = TcpStream::connect(&gateway_addr)
        .await
        .expect("connect to gateway");

    // Receive puzzle challenge
    let challenge: PuzzleChallenge = recv_frame(&mut stream)
        .await
        .expect("receive puzzle challenge");
    assert_eq!(challenge.difficulty, TEST_DIFFICULTY);

    // Solve puzzle
    let solution_bytes = solve_challenge(&challenge);
    let solution = PuzzleSolution {
        nonce: challenge.nonce,
        solution: solution_bytes,
    };
    send_frame(&mut stream, &solution)
        .await
        .expect("send puzzle solution");

    // Send auth request with correct password
    let auth_req = AuthRequest {
        username: "alice".to_string(),
        password: b"password123".to_vec(),
    };
    send_frame(&mut stream, &auth_req)
        .await
        .expect("send auth request");

    // Receive auth response
    let auth_resp: AuthResponse = recv_frame(&mut stream)
        .await
        .expect("receive auth response");

    assert!(
        auth_resp.success,
        "auth should succeed, got error: {:?}",
        auth_resp.error
    );
    assert!(auth_resp.token.is_some(), "token should be present");

    // 4. Verify the token
    let token_bytes = auth_resp.token.unwrap();
    let token: Token = postcard::from_bytes(&token_bytes).expect("deserialize token");

    let claims =
        verify_token(&token, &group_verifying_key).expect("token verification should succeed");

    // Assert tier == 2 (Operational)
    assert_eq!(claims.tier, 2, "token tier should be 2");

    // Assert token is not expired
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros() as i64;
    assert!(claims.exp > now, "token should not be expired");

    // Assert token header matches
    assert_eq!(token.header.version, 1);
    assert_eq!(token.header.tier, 2);
}

#[tokio::test]
async fn tier2_wrong_password_fails() {
    // 1. Setup crypto: DKG(5,3)
    let dkg_result = dkg(5, 3);
    let signers: Vec<SignerShare> = dkg_result.shares.into_iter().take(3).collect();

    // 2. Boot services
    let opaque_addr = boot_opaque({
        let mut store = CredentialStore::new();
        store.register("alice", b"password123");
        store
    })
    .await;

    let tss_addr = boot_tss(signers, dkg_result.group).await;

    tokio::time::sleep(Duration::from_millis(50)).await;

    let orchestrator_addr = boot_orchestrator(opaque_addr, tss_addr).await;

    tokio::time::sleep(Duration::from_millis(50)).await;

    let gateway_addr = boot_gateway(orchestrator_addr).await;

    tokio::time::sleep(Duration::from_millis(50)).await;

    // 3. Run the client flow with WRONG password
    let mut stream = TcpStream::connect(&gateway_addr)
        .await
        .expect("connect to gateway");

    // Receive and solve puzzle
    let challenge: PuzzleChallenge = recv_frame(&mut stream)
        .await
        .expect("receive puzzle challenge");

    let solution_bytes = solve_challenge(&challenge);
    let solution = PuzzleSolution {
        nonce: challenge.nonce,
        solution: solution_bytes,
    };
    send_frame(&mut stream, &solution)
        .await
        .expect("send puzzle solution");

    // Send auth request with WRONG password
    let auth_req = AuthRequest {
        username: "alice".to_string(),
        password: b"wrong_password".to_vec(),
    };
    send_frame(&mut stream, &auth_req)
        .await
        .expect("send auth request");

    // Receive auth response — should be failure
    let auth_resp: AuthResponse = recv_frame(&mut stream)
        .await
        .expect("receive auth response");

    assert!(!auth_resp.success, "auth should fail with wrong password");
    assert!(auth_resp.token.is_none(), "no token on failure");
    assert!(auth_resp.error.is_some(), "error message should be present");
}
