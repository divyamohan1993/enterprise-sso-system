//! SSO Multi-Portal Proof Tests
//!
//! Proves the SSO system works as a real Single Sign-On: login once, access
//! multiple portals/services, and attacks on cross-service channels.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use frost_ristretto255::keys::PublicKeyPackage;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use uuid::Uuid;

use common::types::{ModuleId, Token, TokenClaims};
use crypto::threshold::dkg;
use gateway::puzzle::{solve_challenge, PuzzleChallenge, PuzzleSolution};
use gateway::server::{GatewayServer, OrchestratorConfig};
use gateway::wire::{AuthRequest, AuthResponse};
use opaque::messages::{OpaqueRequest, OpaqueResponse};
use opaque::store::CredentialStore;
use orchestrator::service::OrchestratorService;
use ratchet::chain::RatchetChain;
use shard::transport::ShardListener;
use tss::distributed::{distribute_shares, SignerNode, SigningCoordinator};
use tss::messages::{SigningRequest, SigningResponse};
use crypto::pq_sign::{generate_pq_keypair, PqSigningKey, PqVerifyingKey};
use tss::token_builder::build_token_distributed;
use tss::validator::validate_receipt_chain;
use verifier::verify::verify_token;

// ── Constants ────────────────────────────────────────────────────────────

const SHARD_HMAC_KEY: [u8; 64] = [0x37u8; 64];
const RECEIPT_SIGNING_KEY: [u8; 64] = [0x42u8; 64];
const TEST_DIFFICULTY: u8 = 4;

/// Shared PQ keypair for unit-level tests that build tokens directly.
static TEST_PQ_KEYPAIR: std::sync::LazyLock<(PqSigningKey, PqVerifyingKey)> =
    std::sync::LazyLock::new(generate_pq_keypair);

fn test_pq_sk() -> &'static PqSigningKey { &TEST_PQ_KEYPAIR.0 }
fn test_pq_vk() -> &'static PqVerifyingKey { &TEST_PQ_KEYPAIR.1 }

// ── Helpers ──────────────────────────────────────────────────────────────

fn now_us() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros() as i64
}

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

// ── Service boot helpers ─────────────────────────────────────────────────

async fn boot_opaque(store: CredentialStore) -> String {
    use std::sync::{Arc, Mutex};
    use opaque::messages::{OpaqueRequest, OpaqueResponse};

    let store = Arc::new(Mutex::new(store));
    let listener = ShardListener::bind("127.0.0.1:0", ModuleId::Opaque, SHARD_HMAC_KEY)
        .await
        .expect("bind OPAQUE listener");
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
                                    let response = opaque::service::handle_login_finish(server_login, &credential_finalization, &RECEIPT_SIGNING_KEY, user_id, ceremony_session_id, dpop_key_hash);
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

async fn boot_tss(coordinator: SigningCoordinator, mut nodes: Vec<SignerNode>, pq_signing_key: PqSigningKey) -> String {
    let listener = ShardListener::bind("127.0.0.1:0", ModuleId::Tss, SHARD_HMAC_KEY)
        .await
        .expect("bind TSS listener");
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
            let response =
                match validate_receipt_chain(&request.receipts, &RECEIPT_SIGNING_KEY) {
                    Ok(()) => {
                        let mut signers: Vec<&mut _> =
                            nodes.iter_mut().take(coordinator.threshold).collect();
                        match build_token_distributed(&request.claims, &coordinator, &mut signers, &request.ratchet_key, &pq_signing_key) {
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
                Err(_) => continue,
            };
            let (_sender, req_bytes) = match transport.recv().await {
                Ok(r) => r,
                Err(_) => continue,
            };
            let request: orchestrator::messages::OrchestratorRequest =
                match postcard::from_bytes(&req_bytes) {
                    Ok(r) => r,
                    Err(_) => continue,
                };
            let response = service.process_auth(&request).await;
            let resp_bytes =
                postcard::to_allocvec(&response).expect("serialize Orchestrator response");
            let _ = transport.send(&resp_bytes).await;
        }
    });

    addr
}

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

    let addr = gateway.local_addr().expect("Gateway local_addr").to_string();

    tokio::spawn(async move {
        gateway.run().await.expect("Gateway run");
    });

    addr
}

/// Boot all five services and return (gateway_addr, group_verifying_key, pq_verifying_key).
async fn boot_full_system(
    store: CredentialStore,
) -> (String, PublicKeyPackage, PqVerifyingKey) {
    let mut dkg_result = dkg(5, 3);
    let group_verifying_key = dkg_result.group.public_key_package.clone();
    let (coordinator, nodes) = distribute_shares(&mut dkg_result);

    let opaque_addr = boot_opaque(store).await;
    let tss_addr = boot_tss(coordinator, nodes, test_pq_sk().clone()).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let orchestrator_addr = boot_orchestrator(opaque_addr, tss_addr).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let gateway_addr = boot_gateway(orchestrator_addr).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    (gateway_addr, group_verifying_key, test_pq_vk().clone())
}

/// Run a full client auth flow against a gateway, returning the AuthResponse.
async fn client_auth(gateway_addr: &str, username: &str, password: &[u8]) -> AuthResponse {
    let mut stream = TcpStream::connect(gateway_addr)
        .await
        .expect("connect to gateway");

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

    let auth_req = AuthRequest {
        username: username.to_string(),
        password: password.to_vec(),
    };
    send_frame(&mut stream, &auth_req)
        .await
        .expect("send auth request");

    recv_frame(&mut stream)
        .await
        .expect("receive auth response")
}

// ── ServicePortal ────────────────────────────────────────────────────────

/// Simulated service portal that verifies tokens independently.
struct ServicePortal {
    name: String,
    required_tier: u8,
    required_scope: u32,
    verifying_key: PublicKeyPackage,
    pq_verifying_key: PqVerifyingKey,
}

impl ServicePortal {
    fn new(name: &str, required_tier: u8, required_scope: u32, key: &PublicKeyPackage, pq_vk: &PqVerifyingKey) -> Self {
        Self {
            name: name.to_string(),
            required_tier,
            required_scope,
            verifying_key: key.clone(),
            pq_verifying_key: pq_vk.clone(),
        }
    }

    /// Check access: verify signature, tier, scope, and expiry.
    fn check_access(&self, token: &Token) -> Result<String, String> {
        // 1. Verify token signature (crypto verification + expiry check)
        let claims = verify_token(token, &self.verifying_key, &self.pq_verifying_key)
            .map_err(|e| format!("{}: {e}", self.name))?;

        // 2. Check tier: lower number = higher privilege, so token tier must be <= required
        if claims.tier > self.required_tier {
            return Err(format!(
                "{}: insufficient tier: required {}, got {}",
                self.name, self.required_tier, claims.tier
            ));
        }

        // 3. Check scope bits
        if claims.scope & self.required_scope != self.required_scope {
            return Err(format!(
                "{}: insufficient scope: required 0x{:02X}, got 0x{:02X}",
                self.name, self.required_scope, claims.scope
            ));
        }

        Ok(format!("access granted to {}", self.name))
    }
}

/// Helper: build a token directly with threshold signing for unit-level tests
/// that don't need the full ceremony.
/// Fixed 64-byte ratchet key for helper token building.
const HELPER_RATCHET_KEY: [u8; 64] = [0x55u8; 64];

fn build_signed_token(
    claims: &TokenClaims,
    coordinator: &SigningCoordinator,
    signers: &mut [&mut SignerNode],
) -> Token {
    build_token_distributed(claims, coordinator, signers, &HELPER_RATCHET_KEY, test_pq_sk()).expect("build_token_distributed should succeed")
}

/// Helper: create standard claims with configurable tier and scope.
fn make_claims(user_id: Uuid, tier: u8, scope: u32, ttl_secs: u64) -> TokenClaims {
    let now = now_us();
    TokenClaims {
        sub: user_id,
        iss: [0xAA; 32],
        iat: now,
        exp: now + (ttl_secs as i64 * 1_000_000),
        scope,
        dpop_hash: [0u8; 32],
        ceremony_id: [0xCC; 32],
        tier,
        ratchet_epoch: 0,
    }
}

// ════════════════════════════════════════════════════════════════════════
// Part 1: SSO Proof — Login Once, Access Multiple Services
// ════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_sso_single_login_multiple_portals() {
    let pq_vk = test_pq_vk();
    // 1. Boot full auth system
    let mut store = CredentialStore::new();
    store.register_with_password("alice", b"password123");
    let (gateway_addr, group_key, pq_vk) = boot_full_system(store).await;

    // 2. Alice authenticates ONCE
    let resp = client_auth(&gateway_addr, "alice", b"password123").await;
    assert!(resp.success, "auth should succeed: {:?}", resp.error);

    let token_bytes = resp.token.expect("token should be present");
    let token: Token = postcard::from_bytes(&token_bytes).expect("deserialize token");

    // 3. Define 5 service portals — scopes must be within the token's
    //    granted scope bits (system grants 0x0F = bits 0..3 for tier 2).
    let portals = vec![
        ServicePortal::new("Command Dashboard", 2, 0x01, &group_key, &pq_vk),
        ServicePortal::new("Personnel Records", 2, 0x02, &group_key, &pq_vk),
        ServicePortal::new("Communications", 2, 0x04, &group_key, &pq_vk),
        ServicePortal::new("Logistics", 2, 0x08, &group_key, &pq_vk),
        ServicePortal::new("Intelligence Reports", 2, 0x03, &group_key, &pq_vk),
    ];

    // 4. Use SAME token at all 5 portals
    let mut access_count = 0;
    for portal in &portals {
        let result = portal.check_access(&token);
        assert!(
            result.is_ok(),
            "portal '{}' should grant access: {:?}",
            portal.name,
            result.err()
        );
        assert!(result.unwrap().contains("access granted"));
        access_count += 1;
    }

    // 5. Authenticated ONCE, accessed 5 services
    assert_eq!(access_count, 5, "must access all 5 portals with single token");
}

#[tokio::test]
async fn test_sso_token_works_across_independent_verifiers() {
    // 1. Run DKG, get group key, distribute shares
    let mut dkg_result = dkg(5, 3);
    let group_key = dkg_result.group.public_key_package.clone();
    let pq_vk = test_pq_vk();
    let (coordinator, mut nodes) = distribute_shares(&mut dkg_result);

    // 2. Build a token (simulating a single authentication)
    let claims = make_claims(Uuid::new_v4(), 2, 0x1F, 600);
    let mut signer_refs: Vec<&mut _> = nodes.iter_mut().take(3).collect();
    let token = build_signed_token(&claims, &coordinator, &mut signer_refs);

    // 3. Create 3 INDEPENDENT verifier instances, each only has the PUBLIC key
    let verifier_keys: Vec<PublicKeyPackage> = vec![
        group_key.clone(),
        group_key.clone(),
        group_key.clone(),
    ];

    // 4. All 3 verifiers accept the same token
    for (i, vk) in verifier_keys.iter().enumerate() {
        let result = verify_token(&token, vk, pq_vk);
        assert!(
            result.is_ok(),
            "independent verifier {} should accept token: {:?}",
            i,
            result.err()
        );
    }
}

#[tokio::test]
async fn test_sso_different_users_different_tokens_same_portals() {
    let pq_vk = test_pq_vk();
    // 1. Register alice and bob
    let mut store = CredentialStore::new();
    store.register_with_password("alice", b"alice_pass");
    store.register_with_password("bob", b"bob_pass");
    let (gateway_addr, group_key, pq_vk) = boot_full_system(store).await;

    // 2. Both authenticate (separate ceremonies)
    let resp_alice = client_auth(&gateway_addr, "alice", b"alice_pass").await;
    assert!(resp_alice.success, "alice auth failed: {:?}", resp_alice.error);
    let token_alice: Token = postcard::from_bytes(&resp_alice.token.unwrap())
        .expect("deserialize alice token");

    let resp_bob = client_auth(&gateway_addr, "bob", b"bob_pass").await;
    assert!(resp_bob.success, "bob auth failed: {:?}", resp_bob.error);
    let token_bob: Token =
        postcard::from_bytes(&resp_bob.token.unwrap()).expect("deserialize bob token");

    // 3. Both get tokens with DIFFERENT user_ids
    assert_ne!(
        token_alice.claims.sub, token_bob.claims.sub,
        "alice and bob must have different sub claims"
    );

    // 4. Both can access the same portals
    let portal = ServicePortal::new("Shared Portal", 2, 0x01, &group_key, &pq_vk);
    assert!(portal.check_access(&token_alice).is_ok(), "alice should access portal");
    assert!(portal.check_access(&token_bob).is_ok(), "bob should access portal");

    // 5. Tokens are NOT interchangeable for identity
    assert_ne!(
        token_alice.frost_signature, token_bob.frost_signature,
        "different users must have different signatures"
    );
}

// ════════════════════════════════════════════════════════════════════════
// Part 2: Scope-Based Access Control
// ════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_sso_scope_restricts_portal_access() {
    let mut dkg_result = dkg(5, 3);
    let group_key = dkg_result.group.public_key_package.clone();
    let pq_vk = test_pq_vk();
    let (coordinator, mut nodes) = distribute_shares(&mut dkg_result);

    // Token with scope=0x03 (bits 0+1)
    let claims = make_claims(Uuid::new_v4(), 2, 0x03, 600);
    let mut signer_refs: Vec<&mut _> = nodes.iter_mut().take(3).collect();
    let token = build_signed_token(&claims, &coordinator, &mut signer_refs);

    // Can access portals requiring scope 0x01 or 0x02
    let portal_01 = ServicePortal::new("Scope 0x01", 2, 0x01, &group_key, &pq_vk);
    let portal_02 = ServicePortal::new("Scope 0x02", 2, 0x02, &group_key, &pq_vk);
    assert!(portal_01.check_access(&token).is_ok(), "scope 0x01 should pass");
    assert!(portal_02.check_access(&token).is_ok(), "scope 0x02 should pass");

    // Cannot access portal requiring scope 0x04 (bit 2 not set)
    let portal_04 = ServicePortal::new("Scope 0x04", 2, 0x04, &group_key, &pq_vk);
    let result = portal_04.check_access(&token);
    assert!(result.is_err(), "scope 0x04 should be denied");
    assert!(
        result.unwrap_err().contains("insufficient scope"),
        "error should mention scope"
    );
}

#[tokio::test]
async fn test_sso_tier_restricts_portal_access() {
    let mut dkg_result = dkg(5, 3);
    let group_key = dkg_result.group.public_key_package.clone();
    let pq_vk = test_pq_vk();
    let (coordinator, mut nodes) = distribute_shares(&mut dkg_result);

    // Tier 2 token (Operational)
    let claims = make_claims(Uuid::new_v4(), 2, 0xFF, 600);
    let mut signer_refs: Vec<&mut _> = nodes.iter_mut().take(3).collect();
    let token = build_signed_token(&claims, &coordinator, &mut signer_refs);

    // Can access tier 2 portals
    let portal_t2 = ServicePortal::new("Tier 2 Portal", 2, 0x01, &group_key, &pq_vk);
    assert!(portal_t2.check_access(&token).is_ok(), "tier 2 portal should pass");

    // Can access tier 3 portals (lower privilege required)
    let portal_t3 = ServicePortal::new("Tier 3 Portal", 3, 0x01, &group_key, &pq_vk);
    assert!(portal_t3.check_access(&token).is_ok(), "tier 3 portal should pass");

    // Cannot access tier 1 (sovereign) portals
    let portal_t1 = ServicePortal::new("Sovereign Portal", 1, 0x01, &group_key, &pq_vk);
    let result = portal_t1.check_access(&token);
    assert!(result.is_err(), "sovereign portal should deny tier 2 token");
    assert!(
        result.unwrap_err().contains("insufficient tier"),
        "error should mention tier"
    );
}

// ════════════════════════════════════════════════════════════════════════
// Part 3: Cross-Portal Attack Simulation
// ════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_attack_stolen_token_used_at_different_portal() {
    let pq_vk = test_pq_vk();
    // Get token for alice via full ceremony
    let mut store = CredentialStore::new();
    store.register_with_password("alice", b"password123");
    let (gateway_addr, group_key, pq_vk) = boot_full_system(store).await;

    let resp = client_auth(&gateway_addr, "alice", b"password123").await;
    assert!(resp.success);
    let token: Token = postcard::from_bytes(&resp.token.unwrap()).expect("deserialize");

    // Token has a real DPoP hash (gateway generates per-connection DPoP key)
    assert_ne!(token.claims.dpop_hash, [0u8; 32], "DPoP hash should be bound");

    // The "stolen" token IS valid at a different portal (SSO works) because
    // portal-level check_access only verifies FROST signature, not DPoP binding.
    let portal_a = ServicePortal::new("Portal A", 2, 0x01, &group_key, &pq_vk);
    let portal_b = ServicePortal::new("Portal B", 2, 0x01, &group_key, &pq_vk);
    assert!(portal_a.check_access(&token).is_ok(), "original portal accepts");
    assert!(
        portal_b.check_access(&token).is_ok(),
        "different portal also accepts (portal does not enforce DPoP)"
    );
    // NOTE: When DPoP is enforced at portal level, channel-bound tokens will
    // restrict usage to the original client-portal binding.
}

#[tokio::test]
async fn test_attack_forged_scope_escalation() {
    let mut dkg_result = dkg(5, 3);
    let group_key = dkg_result.group.public_key_package.clone();
    let pq_vk = test_pq_vk();
    let (coordinator, mut nodes) = distribute_shares(&mut dkg_result);

    // Get valid token with scope=0x01
    let claims = make_claims(Uuid::new_v4(), 2, 0x01, 600);
    let mut signer_refs: Vec<&mut _> = nodes.iter_mut().take(3).collect();
    let token = build_signed_token(&claims, &coordinator, &mut signer_refs);

    // Modify scope to 0xFF (all permissions) — tamper with claims
    let mut tampered = token.clone();
    tampered.claims.scope = 0xFF;

    // Signature verification MUST fail at portal
    let portal = ServicePortal::new("Restricted", 2, 0xFF, &group_key, &pq_vk);
    let result = portal.check_access(&tampered);
    assert!(
        result.is_err(),
        "forged scope escalation must be rejected"
    );
    // The error comes from FROST signature mismatch
    assert!(
        {
            let err = result.unwrap_err();
            err.contains("signature") || err.contains("Crypto")
        },
        "rejection must be due to crypto verification failure"
    );
}

#[tokio::test]
async fn test_attack_forged_tier_escalation() {
    let mut dkg_result = dkg(5, 3);
    let group_key = dkg_result.group.public_key_package.clone();
    let pq_vk = test_pq_vk();
    let (coordinator, mut nodes) = distribute_shares(&mut dkg_result);

    // Get valid tier-2 token
    let claims = make_claims(Uuid::new_v4(), 2, 0x01, 600);
    let mut signer_refs: Vec<&mut _> = nodes.iter_mut().take(3).collect();
    let token = build_signed_token(&claims, &coordinator, &mut signer_refs);

    // Modify tier from 2 to 1 (sovereign)
    let mut tampered = token.clone();
    tampered.claims.tier = 1;

    // Signature verification MUST fail
    let portal = ServicePortal::new("Sovereign", 1, 0x01, &group_key, &pq_vk);
    let result = portal.check_access(&tampered);
    assert!(
        result.is_err(),
        "forged tier escalation must be rejected"
    );
}

#[tokio::test]
async fn test_attack_expired_token_at_portal() {
    let mut dkg_result = dkg(5, 3);
    let group_key = dkg_result.group.public_key_package.clone();
    let pq_vk = test_pq_vk();
    let (coordinator, mut nodes) = distribute_shares(&mut dkg_result);

    // Create token that expired 10 seconds ago
    let now = now_us();
    let claims = TokenClaims {
        sub: Uuid::new_v4(),
        iss: [0xAA; 32],
        iat: now - 20_000_000,  // 20s ago
        exp: now - 10_000_000,  // expired 10s ago
        scope: 0xFF,
        dpop_hash: [0u8; 32],
        ceremony_id: [0xCC; 32],
        tier: 2,
        ratchet_epoch: 0,
    };
    let mut signer_refs: Vec<&mut _> = nodes.iter_mut().take(3).collect();
    let token = build_signed_token(&claims, &coordinator, &mut signer_refs);

    let portal = ServicePortal::new("Portal", 2, 0x01, &group_key, &pq_vk);
    let result = portal.check_access(&token);
    assert!(result.is_err(), "expired token must be rejected");
    assert!(
        result.unwrap_err().contains("expired"),
        "error should mention expiration"
    );
}

#[tokio::test]
async fn test_attack_token_from_rogue_sso_server() {
    let pq_vk = test_pq_vk();
    // Real SSO server DKG
    let real_dkg = dkg(5, 3);
    let real_key = real_dkg.group.public_key_package.clone();

    // ROGUE SSO server: independent DKG (different group key)
    let mut rogue_dkg = dkg(5, 3);
    let (rogue_coordinator, mut rogue_nodes) = distribute_shares(&mut rogue_dkg);

    // Sign a token with the rogue server's key
    let claims = make_claims(Uuid::new_v4(), 2, 0xFF, 600);
    let mut rogue_refs: Vec<&mut _> = rogue_nodes.iter_mut().take(3).collect();
    let rogue_token = build_signed_token(&claims, &rogue_coordinator, &mut rogue_refs);

    // Portal trusts the REAL SSO server's key
    let portal = ServicePortal::new("Trusted Portal", 2, 0x01, &real_key, &pq_vk);
    let result = portal.check_access(&rogue_token);
    assert!(
        result.is_err(),
        "token from rogue SSO server must be rejected"
    );
    // Proves: portal cryptographically binds to its trusted SSO server
}

#[tokio::test]
async fn test_attack_replay_same_token_after_ratchet_advance() {
    // Create a ratchet chain and generate a tag at epoch 0
    let master_secret = [0x55u8; 64];
    let mut chain = RatchetChain::new(&master_secret);

    let claims_bytes = b"test-claims-data";
    let tag_epoch_0 = chain.generate_tag(claims_bytes);

    // Advance ratchet 5 times (well past +-3 window)
    for i in 0..5 {
        let client_ent = [i as u8; 32];
        let server_ent = [(i + 100) as u8; 32];
        chain.advance(&client_ent, &server_ent);
    }
    assert_eq!(chain.epoch(), 5);

    // Token from epoch 0 is outside +-3 window (current epoch=5, diff=5 > 3)
    let valid = chain.verify_tag(claims_bytes, &tag_epoch_0, 0);
    assert!(
        !valid,
        "ratchet must reject tag from epoch 0 when current epoch is 5"
    );

    // Tag from epoch 5 at epoch 5 should verify
    let tag_epoch_5 = chain.generate_tag(claims_bytes);
    let valid_current = chain.verify_tag(claims_bytes, &tag_epoch_5, 5);
    assert!(valid_current, "current epoch tag should verify");
}

#[tokio::test]
async fn test_attack_man_in_middle_modifies_token_in_transit() {
    let mut dkg_result = dkg(5, 3);
    let group_key = dkg_result.group.public_key_package.clone();
    let pq_vk = test_pq_vk();
    let (coordinator, mut nodes) = distribute_shares(&mut dkg_result);

    let claims = make_claims(Uuid::new_v4(), 2, 0x01, 600);
    let mut signer_refs: Vec<&mut _> = nodes.iter_mut().take(3).collect();
    let token = build_signed_token(&claims, &coordinator, &mut signer_refs);

    // Serialize, flip random bytes in the middle, try to deserialize and verify
    let mut token_bytes = postcard::to_allocvec(&token).expect("serialize");
    let mid = token_bytes.len() / 2;
    // Flip a few bytes
    for offset in 0..4 {
        if mid + offset < token_bytes.len() {
            token_bytes[mid + offset] ^= 0xFF;
        }
    }

    // Either deserialization fails or signature check fails
    let portal = ServicePortal::new("Portal", 2, 0x01, &group_key, &pq_vk);
    match postcard::from_bytes::<Token>(&token_bytes) {
        Ok(corrupted_token) => {
            let result = portal.check_access(&corrupted_token);
            assert!(
                result.is_err(),
                "corrupted token must be rejected by portal"
            );
        }
        Err(_) => {
            // Deserialization failure is also a valid rejection
        }
    }
}

#[tokio::test]
async fn test_attack_null_token_at_portal() {
    let dkg_result = dkg(5, 3);
    let group_key = dkg_result.group.public_key_package.clone();

    // Send empty bytes — must fail deserialization, not crash
    let empty: &[u8] = &[];
    let result = postcard::from_bytes::<Token>(empty);
    assert!(result.is_err(), "empty bytes must fail deserialization");

    // Also try a few bytes of zeros
    let zeros = vec![0u8; 4];
    let result2 = postcard::from_bytes::<Token>(&zeros);
    assert!(result2.is_err(), "short zero bytes must fail deserialization");

    // If somehow it deserializes, portal must still reject
    // (this is just defense-in-depth, not expected to succeed above)
    let _ = group_key; // used above conceptually
}

#[tokio::test]
async fn test_attack_oversized_token_at_portal() {
    let dkg_result = dkg(5, 3);
    let _group_key = dkg_result.group.public_key_package.clone();

    // Send 1 MB of random-ish bytes as "token" — must get error, not OOM
    let oversized = vec![0xAB; 1_000_000];
    let result = postcard::from_bytes::<Token>(&oversized);
    assert!(
        result.is_err(),
        "oversized payload must fail deserialization, not OOM"
    );
}

// ════════════════════════════════════════════════════════════════════════
// Part 4: Multi-User Session Isolation
// ════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_sso_sessions_are_isolated() {
    // alice and bob both have active ratchet sessions
    let alice_secret = [0x11u8; 64];
    let bob_secret = [0x22u8; 64];
    let mut alice_chain = RatchetChain::new(&alice_secret);
    let bob_chain = RatchetChain::new(&bob_secret);

    let claims_bytes = b"shared-claims-data";

    // Generate tags at epoch 0
    let alice_tag = alice_chain.generate_tag(claims_bytes);
    let bob_tag = bob_chain.generate_tag(claims_bytes);

    // Tags are different (different master secrets)
    assert_ne!(alice_tag, bob_tag, "different users must have different tags");

    // Advance alice's ratchet, bob stays at epoch 0
    alice_chain.advance(&[0xA1; 32], &[0xA2; 32]);
    assert_eq!(alice_chain.epoch(), 1);
    assert_eq!(bob_chain.epoch(), 0, "bob's epoch must not change");

    // alice's tag from epoch 0 does not verify against bob's chain
    let cross_verify = bob_chain.verify_tag(claims_bytes, &alice_tag, 0);
    assert!(!cross_verify, "alice's tag must not verify against bob's chain");

    // bob's tag does not verify against alice's chain (alice is now at epoch 1)
    let cross_verify2 = alice_chain.verify_tag(claims_bytes, &bob_tag, 0);
    assert!(
        !cross_verify2,
        "bob's tag must not verify against alice's chain"
    );
}

#[tokio::test]
async fn test_sso_concurrent_portal_access() {
    // Setup: DKG and 5 users
    let mut dkg_result = dkg(5, 3);
    let group_key = dkg_result.group.public_key_package.clone();
    let pq_vk = test_pq_vk();
    let (coordinator, mut nodes) = distribute_shares(&mut dkg_result);

    let user_ids: Vec<Uuid> = (0..5).map(|_| Uuid::new_v4()).collect();

    // Build tokens for 5 users
    let mut tokens = Vec::new();
    for uid in &user_ids {
        let claims = make_claims(*uid, 2, 0x1F, 600);
        let mut signer_refs: Vec<&mut _> = nodes.iter_mut().take(3).collect();
    let token = build_signed_token(&claims, &coordinator, &mut signer_refs);
        tokens.push(token);
    }

    // 3 portals
    let portals = vec![
        ServicePortal::new("Portal Alpha", 2, 0x01, &group_key, &pq_vk),
        ServicePortal::new("Portal Beta", 2, 0x02, &group_key, &pq_vk),
        ServicePortal::new("Portal Gamma", 2, 0x04, &group_key, &pq_vk),
    ];

    // 5 users x 3 portals = 15 concurrent accesses
    let mut handles = Vec::new();
    for token in &tokens {
        for portal in &portals {
            let t = token.clone();
            let p_name = portal.name.clone();
            let p_tier = portal.required_tier;
            let p_scope = portal.required_scope;
            let p_key = portal.verifying_key.clone();
            let p_pq_vk = portal.pq_verifying_key.clone();

            handles.push(tokio::spawn(async move {
                let p = ServicePortal {
                    name: p_name,
                    required_tier: p_tier,
                    required_scope: p_scope,
                    verifying_key: p_key,
                    pq_verifying_key: p_pq_vk,
                };
                p.check_access(&t)
            }));
        }
    }

    let mut success_count = 0;
    let mut verified_users = std::collections::HashSet::new();
    for (i, handle) in handles.into_iter().enumerate() {
        let result = handle.await.expect("task should not panic");
        assert!(
            result.is_ok(),
            "access #{i} should succeed: {:?}",
            result.err()
        );
        success_count += 1;
        // Track which user this was (user index = i / 3)
        verified_users.insert(tokens[i / 3].claims.sub);
    }

    assert_eq!(success_count, 15, "all 15 accesses must succeed");
    assert_eq!(verified_users.len(), 5, "all 5 unique users must be represented");

    // Verify no cross-contamination: each token's sub is unique
    let subs: Vec<Uuid> = tokens.iter().map(|t| t.claims.sub).collect();
    let unique_subs: std::collections::HashSet<Uuid> = subs.iter().copied().collect();
    assert_eq!(unique_subs.len(), 5, "all user identities must be distinct");
}
