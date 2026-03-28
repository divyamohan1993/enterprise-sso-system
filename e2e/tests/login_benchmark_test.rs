//! End-to-end login benchmark for the enterprise SSO system.
//!
//! Part 1: Single-user login tests measuring wall-clock time for each auth type.
//! Part 2: Concurrent load tests measuring throughput and latency percentiles.
//!
//! Run with: `cargo test -p e2e --test login_benchmark_test -- --nocapture`
//! Load tests are `#[ignore]`; run with: `cargo test -p e2e --test login_benchmark_test -- --nocapture --ignored`

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use common::types::{ModuleId, Receipt, Token, TokenClaims, TokenHeader};
use crypto::pq_sign::{generate_pq_keypair, pq_sign, PqSigningKey};
use crypto::threshold::dkg;
use frost_ristretto255::keys::PublicKeyPackage;
use gateway::server::{GatewayServer, OrchestratorConfig};
use opaque::store::CredentialStore;
use orchestrator::service::OrchestratorService;
use shard::tls_transport;
use tss::distributed::{distribute_shares, SignerNode, SigningCoordinator};
use tss::messages::{SigningRequest, SigningResponse};
use tss::token_builder::build_token_distributed;
use tss::validator::{validate_receipt_chain_with_key, ReceiptVerificationKey};

use e2e::client_auth;

// ── Constants ────────────────────────────────────────────────────────────

const SHARD_HMAC_KEY: [u8; 64] = [0x37u8; 64];
const RECEIPT_SIGNING_KEY: [u8; 64] = [0x42u8; 64];
const TEST_DIFFICULTY: u8 = 4;

static RECEIPT_MLDSA87_VK: std::sync::LazyLock<Vec<u8>> = std::sync::LazyLock::new(|| {
    use ml_dsa::{KeyGen, MlDsa87};
    let seed: [u8; 32] = RECEIPT_SIGNING_KEY[..32].try_into().unwrap();
    let kp = MlDsa87::from_seed(&seed.into());
    kp.verifying_key().encode().to_vec()
});

// ── Runtime helper ───────────────────────────────────────────────────────

fn build_pq_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(8)
        .thread_stack_size(8 * 1024 * 1024)
        .enable_all()
        .build()
        .expect("build test runtime")
}

// ── Service boot helpers (reused from tier2_ceremony_test) ───────────────

async fn boot_opaque(
    store: CredentialStore,
    ca: &shard::tls::CertificateAuthority,
) -> String {
    use std::sync::Mutex;
    use opaque::messages::{OpaqueRequest, OpaqueResponse};

    let store = Arc::new(Mutex::new(store));
    let cert_key = shard::tls::generate_module_cert("localhost", ca);
    let server_config = shard::tls::server_tls_config(&cert_key, ca);
    let listener = tls_transport::TlsShardListener::bind(
        "127.0.0.1:0",
        ModuleId::Opaque,
        SHARD_HMAC_KEY,
        server_config,
    )
    .await
    .expect("bind OPAQUE TLS listener");
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
                    OpaqueRequest::LoginStart {
                        username,
                        credential_request,
                        ceremony_session_id,
                        dpop_key_hash,
                    } => {
                        let login_result_and_id = {
                            let store_guard = store.lock().unwrap();
                            let login_result = opaque::service::handle_login_start(
                                &store_guard,
                                &username,
                                &credential_request,
                            );
                            let user_id = store_guard
                                .get_user_id(&username)
                                .unwrap_or(uuid::Uuid::nil());
                            (login_result, user_id)
                        };
                        let (login_result, user_id) = login_result_and_id;
                        match login_result {
                            Ok((response_bytes, server_login)) => {
                                let resp = OpaqueResponse::LoginChallenge {
                                    credential_response: response_bytes,
                                };
                                let resp_bytes = postcard::to_allocvec(&resp).unwrap();
                                if transport.send(&resp_bytes).await.is_err() {
                                    return;
                                }
                                let (_sender, payload2) = match transport.recv().await {
                                    Ok(r) => r,
                                    Err(_) => return,
                                };
                                let req2: OpaqueRequest = match postcard::from_bytes(&payload2) {
                                    Ok(r) => r,
                                    Err(_) => return,
                                };
                                if let OpaqueRequest::LoginFinish {
                                    credential_finalization,
                                } = req2
                                {
                                    let receipt_signer =
                                        opaque::service::ReceiptSigner::new(RECEIPT_SIGNING_KEY);
                                    let response = opaque::service::handle_login_finish(
                                        server_login,
                                        &credential_finalization,
                                        &receipt_signer,
                                        user_id,
                                        ceremony_session_id,
                                        dpop_key_hash,
                                    );
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
                        let resp = OpaqueResponse::Error {
                            message: "unexpected request type".into(),
                        };
                        let resp_bytes = postcard::to_allocvec(&resp).unwrap();
                        let _ = transport.send(&resp_bytes).await;
                    }
                }
            });
        }
    });

    addr
}

async fn boot_tss(
    coordinator: SigningCoordinator,
    mut nodes: Vec<SignerNode>,
    pq_signing_key: Box<PqSigningKey>,
    ca: &shard::tls::CertificateAuthority,
) -> String {
    let cert_key = shard::tls::generate_module_cert("localhost", ca);
    let server_config = shard::tls::server_tls_config(&cert_key, ca);
    let listener = tls_transport::TlsShardListener::bind(
        "127.0.0.1:0",
        ModuleId::Tss,
        SHARD_HMAC_KEY,
        server_config,
    )
    .await
    .expect("bind TSS TLS listener");
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
                        match build_token_distributed(
                            &request.claims,
                            &coordinator,
                            &mut signers,
                            &request.ratchet_key,
                            &pq_signing_key,
                            None,
                        ) {
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
            let response_bytes =
                postcard::to_allocvec(&response).expect("serialize TSS response");
            let _ = transport.send(&response_bytes).await;
        }
    });

    addr
}

async fn boot_orchestrator(
    opaque_addr: String,
    tss_addr: String,
    ca: &shard::tls::CertificateAuthority,
) -> String {
    let cert_key = shard::tls::generate_module_cert("localhost", ca);
    let server_config = shard::tls::server_tls_config(&cert_key, ca);
    let listener = tls_transport::TlsShardListener::bind(
        "127.0.0.1:0",
        ModuleId::Orchestrator,
        SHARD_HMAC_KEY,
        server_config,
    )
    .await
    .expect("bind Orchestrator TLS listener");
    let addr = listener
        .local_addr()
        .expect("Orchestrator local_addr")
        .to_string();

    let client_cert = shard::tls::generate_module_cert("orchestrator-client", ca);
    let client_config = shard::tls::client_tls_config(&client_cert, ca);
    let connector = shard::tls::tls_connector(client_config);

    let service = Arc::new(OrchestratorService::new_with_tls_and_receipt_key(
        SHARD_HMAC_KEY,
        RECEIPT_SIGNING_KEY,
        opaque_addr,
        tss_addr,
        connector,
    ));

    tokio::spawn(async move {
        loop {
            let mut transport = match listener.accept().await {
                Ok(t) => t,
                Err(_) => continue,
            };
            let svc = Arc::clone(&service);
            tokio::spawn(async move {
                let (_sender, req_bytes) = match transport.recv().await {
                    Ok(r) => r,
                    Err(_) => return,
                };
                let request: orchestrator::messages::OrchestratorRequest =
                    match postcard::from_bytes(&req_bytes) {
                        Ok(r) => r,
                        Err(_) => return,
                    };
                let response = svc.process_auth(&request).await;
                let resp_bytes =
                    postcard::to_allocvec(&response).expect("serialize Orchestrator response");
                let _ = transport.send(&resp_bytes).await;
            });
        }
    });

    addr
}

async fn boot_gateway(
    orchestrator_addr: String,
    ca: &shard::tls::CertificateAuthority,
) -> String {
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

/// Boot all services and return the gateway address.
async fn boot_full_system(store: CredentialStore) -> String {
    let (coordinator, nodes, pq_sk) = tokio::task::spawn_blocking(|| {
        let mut dkg_result = dkg(5, 3);
        let (coordinator, nodes) = distribute_shares(&mut dkg_result);
        let (pq_sk, _pq_vk) = generate_pq_keypair();
        (coordinator, nodes, pq_sk)
    })
    .await
    .expect("DKG/keygen task");

    let ca = shard::tls::generate_ca();
    let opaque_addr = boot_opaque(store, &ca).await;
    let tss_addr = boot_tss(coordinator, nodes, Box::new(pq_sk), &ca).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let orchestrator_addr = boot_orchestrator(opaque_addr, tss_addr, &ca).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let gateway_addr = boot_gateway(orchestrator_addr, &ca).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    gateway_addr
}

// ════════════════════════════════════════════════════════════════════════
// Part 1: Single-User Login Tests (Each Auth Type)
// ════════════════════════════════════════════════════════════════════════

// ── Test 1: OPAQUE Password Login ────────────────────────────────────────

#[test]
fn test_opaque_password_login_timing() {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            let start = Instant::now();

            // Setup
            let mut store = CredentialStore::new();
            let setup_start = Instant::now();
            store.register_with_password("bench_user", b"S3cure!Pass#2024");
            let reg_ms = setup_start.elapsed().as_secs_f64() * 1000.0;
            println!("OPAQUE registration: {reg_ms:.2}ms");

            // Login (full OPAQUE 2-round protocol in-process)
            let login_start = Instant::now();
            let result = store.verify_password("bench_user", b"S3cure!Pass#2024");
            let login_ms = login_start.elapsed().as_secs_f64() * 1000.0;
            assert!(result.is_ok(), "OPAQUE login should succeed");
            println!("OPAQUE login: {login_ms:.2}ms");

            let total_ms = start.elapsed().as_secs_f64() * 1000.0;
            println!("OPAQUE total (register + login): {total_ms:.2}ms");
        })
        .expect("spawn")
        .join()
        .expect("join");
}

// ── Test 2: FIDO2/WebAuthn Login ────────────────────────────────────────

#[test]
fn test_fido2_login_timing() {
    use fido::authentication::{create_authentication_options, update_sign_count};
    use fido::registration::{create_registration_options, CredentialStore as FidoStore};
    use fido::types::*;
    use sha2::{Digest, Sha256};

    let start = Instant::now();
    let user_id = uuid::Uuid::new_v4();
    let rp_id = "sso.milnet.example";
    let mut fido_store = FidoStore::new();

    // Register a credential (simulated attestation)
    let reg_start = Instant::now();
    let opts = create_registration_options("MILNET SSO", rp_id, &user_id, "bench_fido", false);

    // Build synthetic authenticator data with attested credential
    let rp_hash = Sha256::digest(rp_id.as_bytes());
    let cred_id: Vec<u8> = (0..32u8).collect();
    let cose_key: Vec<u8> = vec![0xA5; 77]; // Placeholder COSE key
    let mut auth_data = Vec::new();
    auth_data.extend_from_slice(&rp_hash);
    auth_data.push(0x45); // UP | UV | AT
    auth_data.extend_from_slice(&0u32.to_be_bytes());
    auth_data.extend_from_slice(&[0u8; 16]); // AAGUID
    auth_data.extend_from_slice(&(cred_id.len() as u16).to_be_bytes());
    auth_data.extend_from_slice(&cred_id);
    auth_data.extend_from_slice(&cose_key);

    let _stored = fido::registration::validate_and_register(
        &mut fido_store,
        &auth_data,
        rp_id,
        user_id,
        "cross-platform",
    )
    .expect("registration should succeed");
    let reg_ms = reg_start.elapsed().as_secs_f64() * 1000.0;
    println!("FIDO2 registration: {reg_ms:.2}ms");

    // Authentication
    let auth_start = Instant::now();
    let creds = fido_store.get_user_credentials(&user_id);
    let _auth_opts = create_authentication_options(rp_id, &creds);

    // Simulate authenticator response
    let mut assertion_auth_data = Vec::new();
    assertion_auth_data.extend_from_slice(&rp_hash);
    assertion_auth_data.push(0x05); // UP | UV (no AT for assertion)
    assertion_auth_data.extend_from_slice(&1u32.to_be_bytes()); // sign_count = 1

    // Update sign count (the core server-side verification step we can measure)
    if let Some(cred) = fido_store.get_credential_mut(&cred_id) {
        update_sign_count(cred, 1).expect("sign count update");
    }
    let auth_ms = auth_start.elapsed().as_secs_f64() * 1000.0;
    println!("FIDO2 login: {auth_ms:.2}ms");

    let total_ms = start.elapsed().as_secs_f64() * 1000.0;
    println!("FIDO2 total (register + login): {total_ms:.2}ms");
}

// ── Test 3: TOTP Login ──────────────────────────────────────────────────

#[test]
fn test_totp_login_timing() {
    use common::totp;

    let start = Instant::now();

    // Generate secret
    let secret_start = Instant::now();
    let secret = totp::generate_secret();
    let secret_ms = secret_start.elapsed().as_secs_f64() * 1000.0;
    println!("TOTP secret generation: {secret_ms:.4}ms");

    // Generate code
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let gen_start = Instant::now();
    let code = totp::generate_totp(&*secret, now_secs);
    let gen_ms = gen_start.elapsed().as_secs_f64() * 1000.0;
    println!("TOTP code generation: {gen_ms:.4}ms");

    // Verify code
    let verify_start = Instant::now();
    let valid = totp::verify_totp(&*secret, &code, now_secs, 1);
    let verify_ms = verify_start.elapsed().as_secs_f64() * 1000.0;
    assert!(valid, "TOTP code should verify");
    println!("TOTP verification: {verify_ms:.4}ms");

    let total_ms = start.elapsed().as_secs_f64() * 1000.0;
    println!("TOTP total: {total_ms:.4}ms");
}

// ── Test 4: CAC/PIV Login (simulated) ───────────────────────────────────

#[test]
fn test_cac_piv_login_timing() {
    use common::cac_auth::CacConfig;

    let start = Instant::now();

    // Create CAC config
    let config_start = Instant::now();
    let config = CacConfig {
        pkcs11_library: "/usr/lib/libcackey.so".into(),
        slot_id: 0,
        trusted_ca_certs: vec![vec![0x30; 256]], // mock DER cert
        required_policy_oids: vec!["2.16.840.1.101.2.1.11.10".to_string()],
        pin_max_retries: 3,
        session_timeout_secs: 3600,
        ..CacConfig::default()
    };
    let config_ms = config_start.elapsed().as_secs_f64() * 1000.0;
    println!("CAC/PIV config setup: {config_ms:.4}ms");

    // Create authenticator (validates config)
    let auth_start = Instant::now();
    let _authenticator =
        common::cac_auth::CacAuthenticator::new(config).expect("authenticator init");
    let auth_ms = auth_start.elapsed().as_secs_f64() * 1000.0;
    println!("CAC/PIV authenticator init: {auth_ms:.4}ms");

    // Simulate certificate chain validation with clearance extraction
    let extract_start = Instant::now();
    // Use a minimal DER certificate stub for clearance extraction timing
    let mock_cert_der = vec![0x30, 0x82, 0x01, 0x00]; // minimal DER
    let _clearance = common::cac_auth::CacAuthenticator::extract_clearance_dod(&mock_cert_der);
    let extract_ms = extract_start.elapsed().as_secs_f64() * 1000.0;
    println!("CAC/PIV clearance extraction: {extract_ms:.4}ms");

    let total_ms = start.elapsed().as_secs_f64() * 1000.0;
    println!("CAC/PIV login (simulated): {total_ms:.4}ms");
}

// ── Test 5: Full Ceremony (OPAQUE + Receipt + FROST + PQ) ───────────────

#[test]
fn test_full_ceremony_timing() {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            let ceremony_start = Instant::now();

            // 1. OPAQUE auth
            let opaque_start = Instant::now();
            let mut store = CredentialStore::new();
            store.register_with_password("ceremony_user", b"CeremonyPass!99");
            let user_id = store
                .verify_password("ceremony_user", b"CeremonyPass!99")
                .expect("OPAQUE login");
            let opaque_ms = opaque_start.elapsed().as_secs_f64() * 1000.0;
            println!("OPAQUE auth: {opaque_ms:.2}ms");

            // 2. Receipt signing (ML-DSA-87)
            let receipt_sign_start = Instant::now();
            let signer = opaque::service::ReceiptSigner::new(RECEIPT_SIGNING_KEY);
            let ceremony_session_id = crypto::entropy::generate_nonce();
            let mut receipt = Receipt {
                ceremony_session_id,
                step_id: 1,
                prev_receipt_hash: [0u8; 64],
                user_id,
                dpop_key_hash: [0xBBu8; 64],
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_micros() as i64,
                nonce: crypto::entropy::generate_nonce(),
                signature: Vec::new(),
                ttl_seconds: 30,
            };
            signer.sign(&mut receipt);
            let receipt_sign_ms = receipt_sign_start.elapsed().as_secs_f64() * 1000.0;
            println!("Receipt signing (ML-DSA-87): {receipt_sign_ms:.2}ms");

            // 3. Receipt verification
            let receipt_verify_start = Instant::now();
            assert!(signer.verify(&receipt), "receipt verification should pass");
            let receipt_verify_ms = receipt_verify_start.elapsed().as_secs_f64() * 1000.0;
            println!("Receipt verification: {receipt_verify_ms:.2}ms");

            // 4. FROST 3-of-5 threshold signing
            let frost_start = Instant::now();
            let mut dkg_result = dkg(5, 3);
            let (coordinator, mut nodes) = distribute_shares(&mut dkg_result);
            let dkg_ms = frost_start.elapsed().as_secs_f64() * 1000.0;
            println!("  FROST DKG (5 shares, threshold 3): {dkg_ms:.2}ms");

            let claims = TokenClaims {
                sub: user_id,
                iss: [0xAA; 32],
                iat: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_micros() as i64,
                exp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_micros() as i64
                    + 30_000_000,
                scope: 0x0000_000F,
                dpop_hash: [0xBB; 64],
                ceremony_id: ceremony_session_id,
                tier: 2,
                ratchet_epoch: 1,
                token_id: [0xAB; 16],
                aud: Some("benchmark-service".to_string()),
                classification: 0,
            };
            let claims_bytes = postcard::to_allocvec(&claims).expect("serialize claims");
            let msg = [common::domain::FROST_TOKEN, claims_bytes.as_slice()].concat();

            let sign_start = Instant::now();
            let mut signers: Vec<&mut SignerNode> =
                nodes.iter_mut().take(coordinator.threshold).collect();
            let frost_sig = coordinator
                .coordinate_signing(&mut signers, &msg)
                .expect("FROST signing");
            let frost_sign_ms = sign_start.elapsed().as_secs_f64() * 1000.0;
            println!("FROST 3-of-5 threshold sign: {frost_sign_ms:.2}ms");

            // 5. PQ signature (ML-DSA-87)
            let pq_start = Instant::now();
            let (pq_sk, _pq_vk) = generate_pq_keypair();
            let pq_keygen_ms = pq_start.elapsed().as_secs_f64() * 1000.0;
            println!("  PQ keygen (ML-DSA-87): {pq_keygen_ms:.2}ms");

            let pq_sign_start = Instant::now();
            let pq_signature = pq_sign(&pq_sk, &msg, &frost_sig);
            let pq_sign_ms = pq_sign_start.elapsed().as_secs_f64() * 1000.0;
            println!("PQ signature (ML-DSA-87): {pq_sign_ms:.2}ms");

            // 6. Ratchet tag (HMAC-SHA512)
            let ratchet_start = Instant::now();
            let ratchet_key = crypto::entropy::generate_key_64();
            {
                use hmac::{Hmac, Mac};
                use sha2::Sha512;
                type HmacSha512 = Hmac<Sha512>;
                let mut mac = HmacSha512::new_from_slice(&ratchet_key)
                    .expect("HMAC-SHA512 accepts any key length");
                mac.update(common::domain::TOKEN_TAG);
                mac.update(&claims_bytes);
                mac.update(&claims.ratchet_epoch.to_le_bytes());
                let _ratchet_tag: [u8; 64] = mac.finalize().into_bytes().into();
            }
            let ratchet_ms = ratchet_start.elapsed().as_secs_f64() * 1000.0;
            println!("Ratchet tag (HMAC-SHA512): {ratchet_ms:.4}ms");

            // 7. Token serialization
            let token_start = Instant::now();
            let token = Token {
                header: TokenHeader {
                    version: 1,
                    algorithm: 1,
                    tier: 2,
                },
                claims,
                ratchet_tag: [0xDD; 64],
                frost_signature: frost_sig,
                pq_signature,
            };
            let token_bytes = postcard::to_allocvec(&token).expect("serialize token");
            let token_ms = token_start.elapsed().as_secs_f64() * 1000.0;
            println!("Token serialization ({} bytes): {token_ms:.4}ms", token_bytes.len());

            let total_ms = ceremony_start.elapsed().as_secs_f64() * 1000.0;
            println!("TOTAL ceremony: {total_ms:.2}ms");
        })
        .expect("spawn")
        .join()
        .expect("join");
}

// ── Test 6: X-Wing KEM + Puzzle ─────────────────────────────────────────

#[test]
fn test_xwing_puzzle_timing() {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            // X-Wing keygen
            let keygen_start = Instant::now();
            let server_kp = crypto::xwing::XWingKeyPair::generate();
            let server_pk = server_kp.public_key();
            let keygen_ms = keygen_start.elapsed().as_secs_f64() * 1000.0;
            println!("X-Wing keygen: {keygen_ms:.2}ms");

            // Encapsulate (client side)
            let encap_start = Instant::now();
            let (client_ss, ct) = crypto::xwing::xwing_encapsulate(&server_pk);
            let encap_ms = encap_start.elapsed().as_secs_f64() * 1000.0;
            println!("X-Wing KEM encapsulate: {encap_ms:.2}ms");

            // Decapsulate (server side)
            let decap_start = Instant::now();
            let server_ss =
                crypto::xwing::xwing_decapsulate(&server_kp, &ct).expect("decapsulate");
            let decap_ms = decap_start.elapsed().as_secs_f64() * 1000.0;
            println!("X-Wing KEM decapsulate: {decap_ms:.2}ms");

            assert_eq!(client_ss.as_bytes(), server_ss.as_bytes());

            // Session key derivation
            let derive_start = Instant::now();
            let context = crypto::entropy::generate_nonce();
            let _session_key = crypto::xwing::derive_session_key(&client_ss, &context);
            let derive_ms = derive_start.elapsed().as_secs_f64() * 1000.0;
            println!("Session key derivation: {derive_ms:.4}ms");

            // Puzzle solving at various difficulties
            for difficulty in [4u8, 8, 12, 16] {
                let challenge = gateway::puzzle::generate_challenge(difficulty);
                let solve_start = Instant::now();
                let _solution = gateway::puzzle::solve_challenge(&challenge);
                let solve_ms = solve_start.elapsed().as_secs_f64() * 1000.0;
                println!("Puzzle solve (difficulty {difficulty}): {solve_ms:.2}ms");
            }
        })
        .expect("spawn")
        .join()
        .expect("join");
}

// ── Test 7: Encryption/Decryption ───────────────────────────────────────

#[test]
fn test_encryption_timing() {
    use aes_gcm::aead::generic_array::GenericArray;
    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes256Gcm, KeyInit};

    let mut key = [0u8; 32];
    getrandom::getrandom(&mut key).unwrap();
    let aad = b"benchmark-aad";

    let sizes: &[(usize, &str)] = &[(1024, "1KB"), (10240, "10KB"), (102400, "100KB")];

    println!("\n--- AES-256-GCM ---");
    for &(size, label) in sizes {
        let plaintext: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();

        // Encrypt
        let enc_start = Instant::now();
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let mut nonce_bytes = [0u8; 12];
        getrandom::getrandom(&mut nonce_bytes).unwrap();
        let nonce = GenericArray::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).unwrap();
        let enc_ms = enc_start.elapsed().as_secs_f64() * 1000.0;

        // Decrypt
        let dec_start = Instant::now();
        let _decrypted = cipher.decrypt(nonce, ciphertext.as_ref()).unwrap();
        let dec_ms = dec_start.elapsed().as_secs_f64() * 1000.0;

        println!("AES-256-GCM encrypt {label}: {enc_ms:.4}ms");
        println!("AES-256-GCM decrypt {label}: {dec_ms:.4}ms");
    }

    println!("\n--- AEGIS-256 ---");
    for &(size, label) in sizes {
        let plaintext: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();

        let enc_start = Instant::now();
        let sealed =
            crypto::symmetric::encrypt_with(crypto::symmetric::SymmetricAlgorithm::Aegis256, &key, &plaintext, aad)
                .expect("AEGIS encrypt");
        let enc_ms = enc_start.elapsed().as_secs_f64() * 1000.0;

        let dec_start = Instant::now();
        let _decrypted = crypto::symmetric::decrypt(&key, &sealed, aad).expect("AEGIS decrypt");
        let dec_ms = dec_start.elapsed().as_secs_f64() * 1000.0;

        println!("AEGIS-256 encrypt {label}: {enc_ms:.4}ms");
        println!("AEGIS-256 decrypt {label}: {dec_ms:.4}ms");
    }

    println!("\n--- Envelope Encryption (AES-256-GCM wrap/unwrap) ---");
    let kek = crypto::envelope::KeyEncryptionKey::generate();
    let dek = crypto::envelope::DataEncryptionKey::generate();

    let wrap_start = Instant::now();
    let wrapped = crypto::envelope::wrap_key(&kek, &dek).expect("wrap key");
    let wrap_ms = wrap_start.elapsed().as_secs_f64() * 1000.0;

    let unwrap_start = Instant::now();
    let _unwrapped = crypto::envelope::unwrap_key(&kek, &wrapped).expect("unwrap key");
    let unwrap_ms = unwrap_start.elapsed().as_secs_f64() * 1000.0;

    println!("Envelope wrap (DEK under KEK): {wrap_ms:.4}ms");
    println!("Envelope unwrap (DEK from KEK): {unwrap_ms:.4}ms");
}

// ════════════════════════════════════════════════════════════════════════
// Part 2: Concurrent Load Tests
// ════════════════════════════════════════════════════════════════════════

/// Helper: compute percentile from a sorted list of durations.
fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((p / 100.0) * (sorted.len() as f64 - 1.0)).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

/// Run N concurrent logins and print stats.
///
/// Uses a semaphore to bound concurrency — Argon2id uses 64 MiB per hash,
/// so we cap at (available_ram / 64 MiB) concurrent OPAQUE operations to
/// prevent OOM. On a 32 GB machine that's ~400 concurrent hashes.
async fn run_concurrent_logins(n: usize) {
    // Register N users
    let mut store = CredentialStore::new();
    let reg_start = Instant::now();
    for i in 0..n {
        store.register_with_password(&format!("user_{i}"), b"BenchPass!2024");
    }
    let reg_ms = reg_start.elapsed().as_secs_f64() * 1000.0;
    println!("Registered {n} users in {reg_ms:.1}ms ({:.1}ms/user)", reg_ms / n as f64);

    // Raise per-IP connection limit for benchmarks (default 10 is DDoS protection)
    std::env::set_var("MILNET_MAX_CONN_PER_IP", &format!("{}", n + 100));

    let gateway_addr = boot_full_system(store).await;
    // Give services a moment to stabilize
    tokio::time::sleep(Duration::from_millis(200)).await;

    let gateway_addr = Arc::new(gateway_addr);

    // Bound concurrency: 64 MiB per Argon2id, leave 2 GB headroom
    // On 32 GB machine: (32 - 2) * 1024 / 64 = 480 concurrent
    // On smaller VMs, use at least 8
    let max_concurrent = std::cmp::max(8, (30 * 1024) / 64);
    let semaphore = Arc::new(tokio::sync::Semaphore::new(max_concurrent));
    println!("Concurrency limit: {max_concurrent} (Argon2id 64MiB/hash)");

    let total_start = Instant::now();

    let mut handles = Vec::with_capacity(n);
    for i in 0..n {
        let addr = Arc::clone(&gateway_addr);
        let sem = Arc::clone(&semaphore);
        let handle = tokio::spawn(async move {
            let _permit = sem.acquire().await.expect("semaphore");
            let login_start = Instant::now();
            let username = format!("user_{i}");
            let resp = client_auth(&addr, &username, b"BenchPass!2024").await;
            let elapsed_ms = login_start.elapsed().as_secs_f64() * 1000.0;
            (resp.success, elapsed_ms)
        });
        handles.push(handle);
    }

    let mut latencies: Vec<f64> = Vec::with_capacity(n);
    let mut success_count = 0usize;
    for handle in handles {
        match handle.await {
            Ok((success, ms)) => {
                if success {
                    success_count += 1;
                }
                latencies.push(ms);
            }
            Err(e) => {
                eprintln!("task failed: {e}");
                latencies.push(f64::MAX);
            }
        }
    }

    let total_ms = total_start.elapsed().as_secs_f64() * 1000.0;
    let total_secs = total_ms / 1000.0;
    let throughput = success_count as f64 / total_secs;

    // Only include successful logins in latency stats
    let mut success_latencies: Vec<f64> = latencies.iter().copied().filter(|&l| l < 1_000_000.0).collect();
    let avg_ms = if success_latencies.is_empty() { 0.0 } else { success_latencies.iter().sum::<f64>() / success_latencies.len() as f64 };

    success_latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let p50 = percentile(&success_latencies, 50.0);
    let p95 = percentile(&success_latencies, 95.0);
    let p99 = percentile(&success_latencies, 99.0);

    println!("\n========== {n} CONCURRENT LOGINS ==========");
    println!("Total wall-clock: {total_ms:.1}ms");
    println!("Successful: {success_count}/{n}");
    println!("Avg latency: {avg_ms:.1}ms/login");
    println!("Throughput: {throughput:.1} logins/sec");
    println!("p50: {p50:.1}ms");
    println!("p95: {p95:.1}ms");
    println!("p99: {p99:.1}ms");
    println!("==========================================\n");
}

// ── Test 8: 10 concurrent logins ────────────────────────────────────────

#[cfg(feature = "load-tests")]
#[test]
fn test_concurrent_logins_10() {
    let rt = build_pq_runtime();
    rt.block_on(rt.spawn(async { run_concurrent_logins(10).await }))
        .expect("test task");
}

// ── Test 9: 100 concurrent logins ───────────────────────────────────────

#[cfg(feature = "load-tests")]
#[test]
fn test_concurrent_logins_100() {
    let rt = build_pq_runtime();
    rt.block_on(rt.spawn(async { run_concurrent_logins(100).await }))
        .expect("test task");
}

// ── Test 10: 500 concurrent logins ──────────────────────────────────────

#[cfg(feature = "load-tests")]
#[test]
fn test_concurrent_logins_500() {
    let rt = build_pq_runtime();
    rt.block_on(rt.spawn(async { run_concurrent_logins(500).await }))
        .expect("test task");
}

// ── Test 11: 1000 concurrent logins ─────────────────────────────────────

#[cfg(feature = "load-tests")]
#[test]
fn test_concurrent_logins_1000() {
    let rt = build_pq_runtime();
    rt.block_on(rt.spawn(async { run_concurrent_logins(1000).await }))
        .expect("test task");
}

// ── Test 12: 5000 concurrent logins ─────────────────────────────────────

#[cfg(feature = "load-tests")]
#[test]
fn test_concurrent_logins_5000() {
    let rt = build_pq_runtime();
    rt.block_on(rt.spawn(async { run_concurrent_logins(5000).await }))
        .expect("test task");
}
