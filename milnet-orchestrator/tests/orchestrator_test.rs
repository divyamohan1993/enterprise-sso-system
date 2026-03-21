//! Integration and unit tests for the Auth Orchestrator.

use milnet_common::types::{ModuleId, Receipt, Token};
use milnet_crypto::entropy::generate_key_64;
use milnet_crypto::receipts::sign_receipt;
use milnet_orchestrator::ceremony::{CeremonySession, CeremonyState, CEREMONY_TIMEOUT_SECS};
use milnet_orchestrator::messages::{OrchestratorRequest, OrchestratorResponse};
use milnet_orchestrator::service::OrchestratorService;
use milnet_opaque::messages::{OpaqueRequest, OpaqueResponse};
use milnet_shard::transport::{connect, ShardListener};
use milnet_tss::messages::{SigningRequest, SigningResponse};
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
    assert!(session.fail("opaque error".into()).is_ok());
    assert_eq!(
        session.state,
        CeremonyState::Failed("opaque error".into())
    );
    // Cannot fail again
    assert!(session.fail("double fail".into()).is_err());
}

#[test]
fn ceremony_fail_from_pending_tss() {
    let mut session = CeremonySession::new([0x01; 32]);
    session.opaque_complete().unwrap();
    assert!(session.fail("tss error".into()).is_ok());
    assert_eq!(session.state, CeremonyState::Failed("tss error".into()));
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

#[tokio::test]
async fn orchestrator_processes_auth() {
    let hmac_key = generate_key_64();
    let receipt_signing_key = generate_key_64();

    // Start mock OPAQUE listener
    let opaque_listener =
        ShardListener::bind("127.0.0.1:0", ModuleId::Opaque, hmac_key)
            .await
            .expect("bind opaque");
    let opaque_addr = opaque_listener.local_addr().unwrap().to_string();

    // Start mock TSS listener
    let tss_listener =
        ShardListener::bind("127.0.0.1:0", ModuleId::Tss, hmac_key)
            .await
            .expect("bind tss");
    let tss_addr = tss_listener.local_addr().unwrap().to_string();

    let rsk = receipt_signing_key;

    // Spawn mock OPAQUE service
    let opaque_handle = tokio::spawn(async move {
        let mut transport = opaque_listener.accept().await.expect("accept opaque");
        let (_sender, req_bytes) = transport.recv().await.expect("recv opaque req");

        let req: OpaqueRequest =
            postcard::from_bytes(&req_bytes).expect("deserialize opaque req");

        // Build a valid receipt
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros() as i64;

        let user_id = Uuid::new_v4();
        let mut receipt = Receipt {
            ceremony_session_id: req.ceremony_session_id,
            step_id: 1,
            prev_receipt_hash: [0u8; 32],
            user_id,
            dpop_key_hash: req.dpop_key_hash,
            timestamp: now,
            nonce: milnet_crypto::entropy::generate_nonce(),
            signature: vec![],
            ttl_seconds: 30,
        };
        sign_receipt(&mut receipt, &rsk);

        let resp = OpaqueResponse {
            success: true,
            receipt: Some(receipt),
            error: None,
        };
        let resp_bytes = postcard::to_allocvec(&resp).expect("serialize opaque resp");
        transport.send(&resp_bytes).await.expect("send opaque resp");
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

    // Create orchestrator service and process auth
    let service = OrchestratorService::new(
        hmac_key,
        opaque_addr,
        tss_addr,
        receipt_signing_key,
    );

    let request = OrchestratorRequest {
        username: "alice".into(),
        password_hash: [0xAA; 32],
        dpop_key_hash: [0xBB; 32],
        tier: 2,
    };

    let response = service.process_auth(&request).await;

    // Verify success
    assert!(response.success, "auth should succeed: {:?}", response.error);
    assert!(response.token_bytes.is_some(), "should have token bytes");
    assert!(response.error.is_none());

    // Verify the token deserializes
    let token_bytes = response.token_bytes.unwrap();
    let token: Token =
        postcard::from_bytes(&token_bytes).expect("token should deserialize");
    assert_eq!(token.header.version, 0x01);

    // Wait for mock services to finish
    opaque_handle.await.expect("opaque mock");
    tss_handle.await.expect("tss mock");
}

#[tokio::test]
async fn orchestrator_handles_opaque_failure() {
    let hmac_key = generate_key_64();
    let receipt_signing_key = generate_key_64();

    // Start mock OPAQUE listener that returns failure
    let opaque_listener =
        ShardListener::bind("127.0.0.1:0", ModuleId::Opaque, hmac_key)
            .await
            .expect("bind opaque");
    let opaque_addr = opaque_listener.local_addr().unwrap().to_string();

    // TSS listener (won't be reached)
    let tss_listener =
        ShardListener::bind("127.0.0.1:0", ModuleId::Tss, hmac_key)
            .await
            .expect("bind tss");
    let tss_addr = tss_listener.local_addr().unwrap().to_string();

    let opaque_handle = tokio::spawn(async move {
        let mut transport = opaque_listener.accept().await.expect("accept opaque");
        let (_sender, _req_bytes) = transport.recv().await.expect("recv opaque req");

        let resp = OpaqueResponse {
            success: false,
            receipt: None,
            error: Some("invalid credentials".into()),
        };
        let resp_bytes = postcard::to_allocvec(&resp).expect("serialize opaque resp");
        transport.send(&resp_bytes).await.expect("send opaque resp");
    });

    let service = OrchestratorService::new(
        hmac_key,
        opaque_addr,
        tss_addr,
        receipt_signing_key,
    );

    let request = OrchestratorRequest {
        username: "baduser".into(),
        password_hash: [0x00; 32],
        dpop_key_hash: [0xBB; 32],
        tier: 2,
    };

    let response = service.process_auth(&request).await;

    assert!(!response.success);
    assert!(response.token_bytes.is_none());
    assert_eq!(response.error.as_deref(), Some("invalid credentials"));

    opaque_handle.await.expect("opaque mock");
    drop(tss_listener);
}
