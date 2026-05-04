#![cfg(feature = "test-util")]

//! D-03: refresh_token grant must REJECT requests with no client_id /
//! client_secret (RFC 6749 §10.4).  The hot-fix builds rely on
//! client_secret_post — public-client / DPoP support arrives in Phase 5.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

#[tokio::test]
async fn refresh_without_credentials_rejected() {
    let (app, _) = common::app();
    let body = "grant_type=refresh_token&refresh_token=rt_anything";
    let resp = app
        .oneshot(
            Request::post("/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let www = resp.headers().get("www-authenticate").unwrap().to_str().unwrap();
    assert!(www.starts_with("Basic"), "expected Basic challenge, got `{www}`");
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["error"], "invalid_client");
}

#[tokio::test]
async fn refresh_with_wrong_secret_rejected() {
    let (app, _) = common::app();
    let body = "grant_type=refresh_token&refresh_token=rt_anything\
                &client_id=test-client&client_secret=WRONG";
    let resp = app
        .oneshot(
            Request::post("/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
