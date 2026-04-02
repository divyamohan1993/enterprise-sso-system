//! End-to-end integration test: full Tier 2 auth ceremony.
//!
//! Boots all five Phase 2 modules (OPAQUE, TSS, Orchestrator, Gateway, Verifier)
//! as tokio tasks and runs a complete authentication flow from client connection
//! through to token verification.
//!
//! Uses real OPAQUE protocol: the OPAQUE service never sees plaintext passwords.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use common::types::{ModuleId, Token};
use crypto::pq_sign::PqVerifyingKey;
use crypto::threshold::dkg;
use frost_ristretto255::keys::PublicKeyPackage;
use gateway::server::{GatewayServer, OrchestratorConfig};
use opaque::store::CredentialStore;
use orchestrator::service::OrchestratorService;
use shard::tls_transport;
use tss::distributed::{distribute_shares, SignerNode, SigningCoordinator};
use tss::messages::{SigningRequest, SigningResponse};
use tss::token_builder::build_token_distributed;
use tss::validator::{validate_receipt_chain, validate_receipt_chain_with_key, ReceiptVerificationKey};
use verifier::verify::verify_token_bound;

use e2e::{client_auth, client_auth_with_dpop};

/// Fixed 64-byte HMAC key for SHARD communication in tests.
const SHARD_HMAC_KEY: [u8; 64] = [0x37u8; 64];

/// Fixed 64-byte receipt signing key shared between OPAQUE and TSS.
const RECEIPT_SIGNING_KEY: [u8; 64] = [0x42u8; 64];

/// Puzzle difficulty (low for fast tests).
const TEST_DIFFICULTY: u8 = 4;

/// ML-DSA-87 verifying key for receipt verification (derived from RECEIPT_SIGNING_KEY seed).
static RECEIPT_MLDSA87_VK: std::sync::LazyLock<Vec<u8>> =
    std::sync::LazyLock::new(|| {
        use ml_dsa::{KeyGen, MlDsa87};
        let seed: [u8; 32] = RECEIPT_SIGNING_KEY[..32].try_into().unwrap();
        let kp = MlDsa87::from_seed(&seed.into());
        kp.verifying_key().encode().to_vec()
    });

// ── Service boot helpers ────────────────────────────────────────────────

/// Boot the OPAQUE service as a SHARD listener with real OPAQUE protocol.
/// Handles 2-round-trip login and registration flows.
async fn boot_opaque(store: CredentialStore, ca: &shard::tls::CertificateAuthority) -> String {
    use std::sync::{Arc, Mutex};
    use opaque::messages::{OpaqueRequest, OpaqueResponse};

    let store = Arc::new(Mutex::new(store));
    let cert_key = shard::tls::generate_module_cert("localhost", ca);
    let server_config = shard::tls::server_tls_config(&cert_key, ca);
    let listener = tls_transport::TlsShardListener::bind(
        "127.0.0.1:0", ModuleId::Opaque, SHARD_HMAC_KEY, server_config
    ).await.expect("bind OPAQUE TLS listener");
    let addr = listener.local_addr().expect("OPAQUE local_addr").to_string();

    tokio::spawn(async move {
        loop {
            let mut transport = match listener.accept().await {
                Ok(t) => t,
                Err(_) => continue,
            };
            let store = Arc::clone(&store);
            tokio::spawn(async move {
                let (_sender, payload) = match transport.recv().await {
                    Ok(r) => r,
                    Err(_) => return,
                };
                let request: OpaqueRequest = match postcard::from_bytes(&payload) {
                    Ok(r) => r,
                    Err(_) => return,
                };
                match request {
                    OpaqueRequest::LoginStart { username, credential_request, ceremony_session_id, dpop_key_hash } => {
                        // Extract all data from store while holding lock, then drop lock before any await
                        let login_result_and_id = {
                            let store_guard = store.lock().unwrap();
                            let login_result = opaque::service::handle_login_start(&store_guard, &username, &credential_request);
                            let user_id = store_guard.get_user_id(&username).unwrap_or(uuid::Uuid::nil());
                            (login_result, user_id)
                        }; // MutexGuard dropped here, before any await
                        let (login_result, user_id) = login_result_and_id;
                        match login_result {
                            Ok((response_bytes, server_login)) => {
                                let resp = OpaqueResponse::LoginChallenge { credential_response: response_bytes };
                                let resp_bytes = postcard::to_allocvec(&resp).unwrap();
                                if transport.send(&resp_bytes).await.is_err() { return; }
                                let (_sender, payload2) = match transport.recv().await { Ok(r) => r, Err(_) => return };
                                let req2: OpaqueRequest = match postcard::from_bytes(&payload2) { Ok(r) => r, Err(_) => return };
                                if let OpaqueRequest::LoginFinish { credential_finalization } = req2 {
                                    let receipt_signer = opaque::service::ReceiptSigner::new(RECEIPT_SIGNING_KEY);
                                    let response = opaque::service::handle_login_finish(server_login, &credential_finalization, &receipt_signer, user_id, ceremony_session_id, dpop_key_hash);
                                    let resp_bytes = postcard::to_allocvec(&response).unwrap();
                                    let _ = transport.send(&resp_bytes).await;
                                }
                            }
                            Err(e) => {
                                let resp = OpaqueResponse::Error { message: e };
                                let resp_bytes = postcard::to_allocvec(&resp).unwrap();
                                let _ = transport.send(&resp_bytes).await;
                            }
                        }
                    }
                    _ => {
                        let resp = OpaqueResponse::Error { message: "unexpected request type".into() };
                        let resp_bytes = postcard::to_allocvec(&resp).unwrap();
                        let _ = transport.send(&resp_bytes).await;
                    }
                }
            });
        }
    });

    addr
}

/// Boot the TSS service as a SHARD listener using distributed signing.
/// The coordinator holds NO keys; each SignerNode holds exactly one share.
async fn boot_tss(coordinator: SigningCoordinator, mut nodes: Vec<SignerNode>, pq_signing_key: Box<crypto::pq_sign::PqSigningKey>, ca: &shard::tls::CertificateAuthority) -> String {
    let cert_key = shard::tls::generate_module_cert("localhost", ca);
    let server_config = shard::tls::server_tls_config(&cert_key, ca);
    let listener = tls_transport::TlsShardListener::bind(
        "127.0.0.1:0", ModuleId::Tss, SHARD_HMAC_KEY, server_config
    ).await.expect("bind TSS TLS listener");
    let addr = listener.local_addr().expect("TSS local_addr").to_string();

    tokio::spawn(async move {
        loop {
            let mut transport = match listener.accept().await {
                Ok(t) => t,
                Err(_) => continue,
            };
            let (_sender, payload) = match transport.recv().await {
                Ok(r) => r,
                Err(_) => continue,
            };
            let request: SigningRequest = match postcard::from_bytes(&payload) {
                Ok(r) => r,
                Err(e) => {
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
            let vk = &*RECEIPT_MLDSA87_VK;
            let verification_key = ReceiptVerificationKey::Both {
                hmac_key: &RECEIPT_SIGNING_KEY,
                mldsa87_key: vk,
            };
            let response =
                match validate_receipt_chain_with_key(&request.receipts, &verification_key) {
                    Ok(()) => {
                        let mut signers: Vec<&mut _> =
                            nodes.iter_mut().take(coordinator.threshold).collect();
                        match build_token_distributed(&request.claims, &coordinator, &mut signers, &request.ratchet_key, &pq_signing_key, None) {
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
                    },
                    Err(e) => SigningResponse {
                        success: false,
                        token: None,
                        error: Some(format!("receipt validation: {e}")),
                    },
                };
            let response_bytes =
                postcard::to_allocvec(&response).expect("serialize TSS response");
            let _ = transport.send(&response_bytes).await;
        }
    });

    addr
}

/// Boot the Orchestrator as a SHARD listener. Returns the bound address.
async fn boot_orchestrator(opaque_addr: String, tss_addr: String, ca: &shard::tls::CertificateAuthority) -> String {
    let cert_key = shard::tls::generate_module_cert("localhost", ca);
    let server_config = shard::tls::server_tls_config(&cert_key, ca);
    let listener = tls_transport::TlsShardListener::bind(
        "127.0.0.1:0", ModuleId::Orchestrator, SHARD_HMAC_KEY, server_config
    ).await.expect("bind Orchestrator TLS listener");
    let addr = listener
        .local_addr()
        .expect("Orchestrator local_addr")
        .to_string();

    // Create TLS connector that trusts the shared CA
    let client_cert = shard::tls::generate_module_cert("orchestrator-client", ca);
    let client_config = shard::tls::client_tls_config(&client_cert, ca);
    let connector = shard::tls::tls_connector(client_config);

    let service = std::sync::Arc::new(
        OrchestratorService::new_with_tls_and_receipt_key(SHARD_HMAC_KEY, RECEIPT_SIGNING_KEY, opaque_addr, tss_addr, connector),
    );

    tokio::spawn(async move {
        loop {
            let mut transport = match listener.accept().await {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("Orchestrator accept error: {e}");
                    continue;
                }
            };

            let svc = std::sync::Arc::clone(&service);
            tokio::spawn(async move {
                let (_sender, req_bytes) = match transport.recv().await {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("Orchestrator recv error: {e}");
                        return;
                    }
                };

                let request: orchestrator::messages::OrchestratorRequest =
                    match postcard::from_bytes(&req_bytes) {
                        Ok(r) => r,
                        Err(e) => {
                            eprintln!("Orchestrator deserialize error: {e}");
                            return;
                        }
                    };

                let response = svc.process_auth(&request).await;

                let resp_bytes =
                    postcard::to_allocvec(&response).expect("serialize Orchestrator response");

                if let Err(e) = transport.send(&resp_bytes).await {
                    eprintln!("Orchestrator send error: {e}");
                }
            });
        }
    });

    addr
}

/// Boot the Gateway as a TCP listener with orchestrator forwarding. Returns the bound address.
async fn boot_gateway(orchestrator_addr: String, ca: &shard::tls::CertificateAuthority) -> String {
    let gateway_cert = shard::tls::generate_module_cert("gateway-client", ca);
    let gateway_client_config = shard::tls::client_tls_config(&gateway_cert, ca);
    let gateway_connector = shard::tls::tls_connector(gateway_client_config);

    let gateway = GatewayServer::bind_with_orchestrator(
        "127.0.0.1:0",
        TEST_DIFFICULTY,
        OrchestratorConfig {
            addr: orchestrator_addr,
            hmac_key: SHARD_HMAC_KEY,
            tls_connector: gateway_connector,
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

/// Boot all five services and return (gateway_addr, group_verifying_key, pq_verifying_key).
///
/// Extracted into a separate async function so that the large intermediate crypto
/// objects (DKG state, signing keys, TLS certificates) are confined to this
/// function's Future state and don't inflate the caller's async state machine —
/// which would otherwise cause stack overflow in debug builds due to ML-DSA-87
/// and FROST key sizes.
async fn boot_full_system(
    store: CredentialStore,
) -> (String, PublicKeyPackage, PqVerifyingKey) {
    // Run DKG and PQ keygen on a blocking thread (large stack usage in debug builds)
    let (group_verifying_key, coordinator, nodes, pq_sk, pq_vk) =
        tokio::task::spawn_blocking(|| {
            let mut dkg_result = dkg(5, 3);
            let group_verifying_key = dkg_result.group.public_key_package.clone();
            let (coordinator, nodes) = distribute_shares(&mut dkg_result);
            let (pq_sk, pq_vk) = crypto::pq_sign::generate_pq_keypair();
            (group_verifying_key, coordinator, nodes, pq_sk, pq_vk)
        })
        .await
        .expect("DKG/keygen task");

    // Generate shared CA for all inter-service mTLS
    let ca = shard::tls::generate_ca();

    // Boot services in dependency order
    let opaque_addr = boot_opaque(store, &ca).await;
    let tss_addr = boot_tss(coordinator, nodes, Box::new(pq_sk), &ca).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let orchestrator_addr = boot_orchestrator(opaque_addr, tss_addr, &ca).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let gateway_addr = boot_gateway(orchestrator_addr, &ca).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    (gateway_addr, group_verifying_key, pq_vk)
}

// ── Tests ───────────────────────────────────────────────────────────────

/// Helper: build a tokio runtime with enough stack for post-quantum crypto
/// operations (ML-DSA-87, FROST DKG) that use significant stack in debug builds.
fn build_pq_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_stack_size(16 * 1024 * 1024)
        .enable_all()
        .build()
        .expect("build test runtime")
}

#[test]
fn tier2_full_ceremony_success() {
    let rt = build_pq_runtime();
    rt.block_on(rt.spawn(async {
        // 1. Boot all services
        let mut store = CredentialStore::new();
        store.register_with_password("alice", b"password123");
        let (gateway_addr, group_verifying_key, pq_vk) = boot_full_system(store).await;

        // 2. Run the client flow using encrypted X-Wing channel
        let (auth_resp, dpop_key) = client_auth_with_dpop(&gateway_addr, "alice", b"password123").await;

        assert!(
            auth_resp.success,
            "auth should succeed, got error: {:?}",
            auth_resp.error
        );
        assert!(auth_resp.token.is_some(), "token should be present");

        // 3. Verify the token on a blocking thread (ML-DSA-87 verification uses
        //    significant stack space that can overflow async task stacks in debug builds)
        let token_bytes = auth_resp.token.unwrap();
        let token: Token = postcard::from_bytes(&token_bytes).expect("deserialize token");

        let token_header = token.header.clone();
        let claims = tokio::task::spawn_blocking(move || {
            verify_token_bound(&token, &group_verifying_key, &pq_vk, &dpop_key)
        })
        .await
        .expect("verify task")
        .expect("token verification should succeed");

        // Assert tier == 2 (Operational)
        assert_eq!(claims.tier, 2, "token tier should be 2");

        // Assert token is not expired
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros() as i64;
        assert!(claims.exp > now, "token should not be expired");

        // Assert token header matches
        assert_eq!(token_header.version, 1);
        assert_eq!(token_header.tier, 2);
    })).expect("test task");
}

#[test]
fn tier2_wrong_password_fails() {
    let rt = build_pq_runtime();
    rt.block_on(rt.spawn(async {
        // 1. Boot all services
        let mut store = CredentialStore::new();
        store.register_with_password("alice", b"password123");
        let (gateway_addr, _group_verifying_key, _pq_vk) = boot_full_system(store).await;

        // 2. Run the client flow with WRONG password using encrypted X-Wing channel
        let auth_resp = client_auth(&gateway_addr, "alice", b"wrong_password").await;

        assert!(!auth_resp.success, "auth should fail with wrong password");
        assert!(auth_resp.token.is_none(), "no token on failure");
        assert!(auth_resp.error.is_some(), "error message should be present");
    })).expect("test task");
}
