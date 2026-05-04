#![cfg(feature = "test-util")]

//! D-02: a code minted for client A must NOT redeem with client B's secret.
//! The constant-time `client_id`/`redirect_uri` guard rejects substitution
//! before PKCE verification.

mod common;

use authsrv::{ClientRegistration, AuthCode, now_secs};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use sha2::{Digest, Sha256};
use tower::ServiceExt;

#[tokio::test]
async fn code_minted_for_a_rejected_for_b() {
    let (app, state) = common::app();
    // Stage a second client B with its own secret.
    let secret_b = ClientRegistration::hash_secret("client-b", "secret-b")
        .expect("hash secret-b");
    {
        let mut g = state.clients.lock().unwrap();
        g.insert(
            "client-b".into(),
            ClientRegistration {
                client_id: "client-b".into(),
                client_secret_hash: secret_b,
                redirect_uris: vec!["https://b.test/cb".into()],
                allowed_scopes: vec!["openid".into()],
                origins: Vec::new(),
                post_logout_redirect_uris: Vec::new(),
            },
        );
    }
    // Mint a code directly bound to client A (test-client).
    let verifier = "v".repeat(64);
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    {
        let mut g = state.codes.lock().unwrap();
        g.insert(
            "code-a".into(),
            AuthCode {
                code: "code-a".into(),
                client_id: "test-client".into(),
                redirect_uri: "https://rp.test/cb".into(),
                user_sub: "test-subject".into(),
                scope: "openid".into(),
                code_challenge: challenge.clone(),
                created_at: now_secs(),
            },
        );
    }
    // Client B attempts to redeem A's code with B's secret.
    let body = format!(
        "grant_type=authorization_code&code=code-a&redirect_uri=https://b.test/cb\
         &client_id=client-b&client_secret=secret-b&code_verifier={verifier}"
    );
    let resp = app
        .oneshot(
            Request::post("/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["error"], "invalid_grant");
}
