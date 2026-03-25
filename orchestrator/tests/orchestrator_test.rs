//! Integration and unit tests for the Auth Orchestrator.

use common::types::{ModuleId, Token};
use crypto::entropy::generate_key_64;
use opaque::messages::{OpaqueRequest, OpaqueResponse};
use opaque::store::CredentialStore;
use orchestrator::ceremony::{CeremonySession, CeremonyState, CEREMONY_TIMEOUT_SECS};
use orchestrator::messages::OrchestratorRequest;
use orchestrator::service::OrchestratorService;
use shard::tls::{
    generate_ca, generate_module_cert, server_tls_config, client_tls_config, tls_connector,
};
use shard::tls_transport::TlsShardListener;
use tss::messages::{SigningRequest, SigningResponse};
use uuid::Uuid;

// ── State transition tests ──────────────────────────────────────────────

#[test]
fn ceremony_state_transitions() {
    let session_id = [0x42; 32];
    let mut session = CeremonySession::new(session_id);

    // Initial state is PendingOpaque
    assert_eq!(session.state, CeremonyState::PendingOpaque);

    // Cannot go directly to Complete from PendingOpaque
    assert!(session.tss_complete().is_err());
    // State should remain PendingOpaque after invalid transition
    assert_eq!(session.state, CeremonyState::PendingOpaque);

    // Valid: PendingOpaque -> PendingTss
    assert!(session.opaque_complete().is_ok());
    assert_eq!(session.state, CeremonyState::PendingTss);

    // Cannot go back to PendingTss from PendingTss
    assert!(session.opaque_complete().is_err());

    // Valid: PendingTss -> Complete
    assert!(session.tss_complete().is_ok());
    assert_eq!(session.state, CeremonyState::Complete);

    // Cannot transition out of Complete
    assert!(session.opaque_complete().is_err());
    assert!(session.tss_complete().is_err());
    assert!(session.fail("should not work".into()).is_err());
}

#[test]
fn ceremony_fail_from_pending_opaque() {
    let mut session = CeremonySession::new([0x01; 32]);
    assert!(session.fail("opaque issue".into()).is_ok());
    assert_eq!(session.state, CeremonyState::Failed("opaque issue".into()));
    // Cannot fail again
    assert!(session.fail("double fail".into()).is_err());
}

#[test]
fn ceremony_fail_from_pending_tss() {
    let mut session = CeremonySession::new([0x01; 32]);
    session.opaque_complete().unwrap();
    assert!(session.fail("tss issue".into()).is_ok());
    assert_eq!(session.state, CeremonyState::Failed("tss issue".into()));
}

// ── Timeout test ────────────────────────────────────────────────────────

#[test]
fn ceremony_session_timeout() {
    let session_id = [0x01; 32];
    let mut session = CeremonySession::new(session_id);

    // A freshly created session should not be expired
    assert!(!session.is_expired());

    // Manually set created_at to the past
    session.created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
        - CEREMONY_TIMEOUT_SECS
        - 1;

    assert!(session.is_expired());
}

// ── Integration test ────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn orchestrator_processes_auth() {
    let hmac_key = generate_key_64();
    let receipt_signing_key = generate_key_64();

    // Create a real OPAQUE credential store with a registered user
    let mut store = CredentialStore::new();
    let user_id = store.register_with_password("alice", b"password123");
    let _server_setup_bytes = store.server_setup().serialize().to_vec();

    // Generate shared CA and certs for mTLS — all parties trust the same CA
    let ca = generate_ca();
    let opaque_server_cert = generate_module_cert("localhost", &ca);
    let tss_server_cert = generate_module_cert("localhost", &ca);
    let orchestrator_client_cert = generate_module_cert("orchestrator", &ca);

    let opaque_server_cfg = server_tls_config(&opaque_server_cert, &ca);
    let tss_server_cfg = server_tls_config(&tss_server_cert, &ca);
    let orchestrator_client_cfg = client_tls_config(&orchestrator_client_cert, &ca);

    // Start mock OPAQUE listener with mTLS
    let opaque_listener = TlsShardListener::bind(
        "127.0.0.1:0",
        ModuleId::Opaque,
        hmac_key,
        opaque_server_cfg,
    )
    .await
    .expect("bind opaque");
    let opaque_addr = opaque_listener.local_addr().unwrap().to_string();

    // Start mock TSS listener with mTLS
    let tss_listener = TlsShardListener::bind(
        "127.0.0.1:0",
        ModuleId::Tss,
        hmac_key,
        tss_server_cfg,
    )
    .await
    .expect("bind tss");
    let tss_addr = tss_listener.local_addr().unwrap().to_string();

    let rsk = receipt_signing_key;

    // Spawn mock OPAQUE service — implements real 2-round-trip OPAQUE
    let opaque_handle = tokio::spawn(async move {
        let mut transport = opaque_listener.accept().await.expect("accept opaque");

        // Round 1: Receive LoginStart, respond with LoginChallenge
        let (_sender, req_bytes) = transport.recv().await.expect("recv opaque req");
        let req: OpaqueRequest =
            postcard::from_bytes(&req_bytes).expect("deserialize opaque req");

        let (credential_response_bytes, server_login, ceremony_session_id, dpop_key_hash) =
            match req {
                OpaqueRequest::LoginStart {
                    username,
                    credential_request,
                    ceremony_session_id,
                    dpop_key_hash,
                } => {
                    let (resp_bytes, server_login) =
                        opaque::service::handle_login_start(&store, &username, &credential_request)
                            .expect("login start");
                    (resp_bytes, server_login, ceremony_session_id, dpop_key_hash)
                }
                _ => panic!("expected LoginStart"),
            };

        let resp = OpaqueResponse::LoginChallenge {
            credential_response: credential_response_bytes,
        };
        let resp_bytes = postcard::to_allocvec(&resp).expect("serialize challenge");
        transport.send(&resp_bytes).await.expect("send challenge");

        // Round 2: Receive LoginFinish, respond with LoginSuccess
        let (_sender, req2_bytes) = transport.recv().await.expect("recv login finish");
        let req2: OpaqueRequest =
            postcard::from_bytes(&req2_bytes).expect("deserialize login finish");

        match req2 {
            OpaqueRequest::LoginFinish {
                credential_finalization,
            } => {
                let receipt_signer = opaque::service::ReceiptSigner::new(rsk);
                let response = opaque::service::handle_login_finish(
                    server_login,
                    &credential_finalization,
                    &receipt_signer,
                    user_id,
                    ceremony_session_id,
                    dpop_key_hash,
                );
                let resp_bytes = postcard::to_allocvec(&response).expect("serialize result");
                transport.send(&resp_bytes).await.expect("send result");
            }
            _ => panic!("expected LoginFinish"),
        }
    });

    // Spawn mock TSS service
    let tss_handle = tokio::spawn(async move {
        let mut transport = tss_listener.accept().await.expect("accept tss");
        let (_sender, req_bytes) = transport.recv().await.expect("recv tss req");

        let _req: SigningRequest =
            postcard::from_bytes(&req_bytes).expect("deserialize signing req");

        // Return a mock signed token
        let token = Token::test_fixture();
        let token_bytes = postcard::to_allocvec(&token).expect("serialize token");

        let resp = SigningResponse {
            success: true,
            token: Some(token_bytes),
            error: None,
        };
        let resp_bytes = postcard::to_allocvec(&resp).expect("serialize tss resp");
        transport.send(&resp_bytes).await.expect("send tss resp");
    });

    // Create orchestrator service with the SAME CA trust for mTLS.
    // The receipt verification key must match the key used by the OPAQUE
    // service's ReceiptSigner (which derives ML-DSA-65 from the first 32
    // bytes of the signing key).
    let connector = tls_connector(orchestrator_client_cfg);
    let service = OrchestratorService::new_with_tls_and_receipt_key(
        hmac_key,
        receipt_signing_key,
        opaque_addr,
        tss_addr,
        connector,
    );

    let request = OrchestratorRequest {
        username: "alice".into(),
        password: b"password123".to_vec(),
        dpop_key_hash: [0xBB; 32],
        tier: 2,
        audience: None,
        device_attestation_age_secs: None,
        geo_velocity_kmh: None,
        is_unusual_network: None,
        is_unusual_time: None,
        unusual_access_score: None,
        recent_failed_attempts: None,
    };

    let response = service.process_auth(&request).await;

    // Verify success
    assert!(
        response.success,
        "auth should succeed: {:?}",
        response.error
    );
    assert!(response.token_bytes.is_some(), "should have token bytes");
    assert!(response.error.is_none());

    // Verify the token deserializes
    let token_bytes = response.token_bytes.unwrap();
    let token: Token = postcard::from_bytes(&token_bytes).expect("token should deserialize");
    assert_eq!(token.header.version, 0x01);

    // Wait for mock services to finish
    opaque_handle.await.expect("opaque mock");
    tss_handle.await.expect("tss mock");
}

#[tokio::test]
async fn orchestrator_handles_opaque_failure() {
    let hmac_key = generate_key_64();
    let _receipt_signing_key = generate_key_64();

    // Create store with a registered user
    let mut store = CredentialStore::new();
    store.register_with_password("alice", b"password123");

    // Generate shared CA and certs for mTLS
    let ca = generate_ca();
    let opaque_server_cert = generate_module_cert("localhost", &ca);
    let tss_server_cert = generate_module_cert("localhost", &ca);
    let orchestrator_client_cert = generate_module_cert("orchestrator", &ca);

    let opaque_server_cfg = server_tls_config(&opaque_server_cert, &ca);
    let tss_server_cfg = server_tls_config(&tss_server_cert, &ca);
    let orchestrator_client_cfg = client_tls_config(&orchestrator_client_cert, &ca);

    // Start mock OPAQUE listener with mTLS
    let opaque_listener = TlsShardListener::bind(
        "127.0.0.1:0",
        ModuleId::Opaque,
        hmac_key,
        opaque_server_cfg,
    )
    .await
    .expect("bind opaque");
    let opaque_addr = opaque_listener.local_addr().unwrap().to_string();

    // TSS listener (won't be reached)
    let tss_listener = TlsShardListener::bind(
        "127.0.0.1:0",
        ModuleId::Tss,
        hmac_key,
        tss_server_cfg,
    )
    .await
    .expect("bind tss");
    let tss_addr = tss_listener.local_addr().unwrap().to_string();

    let opaque_handle = tokio::spawn(async move {
        let mut transport = opaque_listener.accept().await.expect("accept opaque");

        // Round 1: Receive LoginStart, respond with LoginChallenge
        let (_sender, req_bytes) = transport.recv().await.expect("recv opaque req");
        let req: OpaqueRequest =
            postcard::from_bytes(&req_bytes).expect("deserialize opaque req");

        match req {
            OpaqueRequest::LoginStart {
                username,
                credential_request,
                ..
            } => {
                let (resp_bytes, server_login) =
                    opaque::service::handle_login_start(&store, &username, &credential_request)
                        .expect("login start");

                let resp = OpaqueResponse::LoginChallenge {
                    credential_response: resp_bytes,
                };
                let resp_bytes = postcard::to_allocvec(&resp).expect("serialize");
                transport.send(&resp_bytes).await.expect("send");

                // Round 2: Client will fail to finish (wrong password) but
                // the orchestrator will send the finalization anyway.
                // Wait for it and respond with error.
                let result = transport.recv().await;
                if let Ok((_sender, req2_bytes)) = result {
                    let req2: OpaqueRequest =
                        postcard::from_bytes(&req2_bytes).expect("deserialize");
                    if let OpaqueRequest::LoginFinish {
                        credential_finalization,
                    } = req2
                    {
                        let receipt_signer = opaque::service::ReceiptSigner::new([0u8; 64]);
                        let response = opaque::service::handle_login_finish(
                            server_login,
                            &credential_finalization,
                            &receipt_signer,
                            Uuid::nil(),
                            [0u8; 32],
                            [0u8; 32],
                        );
                        let resp_bytes = postcard::to_allocvec(&response).expect("serialize");
                        transport.send(&resp_bytes).await.expect("send");
                    }
                }
            }
            _ => panic!("expected LoginStart"),
        }
    });

    let connector = tls_connector(orchestrator_client_cfg);
    let service = OrchestratorService::new_with_tls(
        hmac_key,
        opaque_addr,
        tss_addr,
        connector,
    );

    let request = OrchestratorRequest {
        username: "alice".into(),
        password: b"wrong_password".to_vec(),
        dpop_key_hash: [0xBB; 32],
        tier: 2,
        audience: None,
        device_attestation_age_secs: None,
        geo_velocity_kmh: None,
        is_unusual_network: None,
        is_unusual_time: None,
        unusual_access_score: None,
        recent_failed_attempts: None,
    };

    let response = service.process_auth(&request).await;

    assert!(!response.success, "auth should fail with wrong password");
    assert!(response.token_bytes.is_none());

    opaque_handle.await.expect("opaque mock");
    drop(tss_listener);
}
