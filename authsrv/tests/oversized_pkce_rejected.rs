#![cfg(feature = "test-util")]

//! D-15: PKCE bounds — `code_challenge` must be exactly 43 base64url chars,
//! `code_verifier` 43..=128 base64url chars.  Any deviation is rejected.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

async fn authorize_with(challenge: &str) -> StatusCode {
    let (app, _) = common::app();
    let q = format!(
        "response_type=code&client_id=test-client&redirect_uri=https://rp.test/cb\
         &code_challenge={challenge}&code_challenge_method=S256"
    );
    let resp = app
        .oneshot(
            Request::get(format!("/authorize?{q}"))
                .header("milnet-as-session", authsrv::TEST_SESSION_HEADER)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    resp.status()
}

#[tokio::test]
async fn challenge_too_short_rejected() {
    assert_eq!(
        authorize_with(&"a".repeat(42)).await,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn challenge_too_long_rejected() {
    assert_eq!(
        authorize_with(&"a".repeat(44)).await,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn challenge_wrong_charset_rejected() {
    let mut bad = "a".repeat(42);
    bad.push('!');
    assert_eq!(authorize_with(&bad).await, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn challenge_exact_43_accepted() {
    // 43 base64url bytes — passes PKCE validation.  The redirect-issuance
    // path requires session+client to succeed; we get past PKCE which is
    // all this test asserts — the response is `303 See Other` with a
    // Location pointing back at the redirect_uri.
    assert_eq!(
        authorize_with("BHSRNtMQ-zlxLdngKVe-8z42_LDdVDOeIOk4OvBvK0w").await,
        StatusCode::SEE_OTHER
    );
}
