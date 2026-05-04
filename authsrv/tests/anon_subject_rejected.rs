#![cfg(feature = "test-util")]

//! D-01: /authorize must REFUSE to mint anything for an anonymous caller.
//! The hardened build returns 401 + `WWW-Authenticate: Session realm=…`
//! and emits a CRITICAL `authorize.identity_required` audit entry.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

#[tokio::test]
async fn anon_authorize_returns_401() {
    let (app, _) = common::app();
    let q = "response_type=code&client_id=test-client&redirect_uri=https://rp.test/cb\
             &code_challenge=BHSRNtMQ-zlxLdngKVe-8z42_LDdVDOeIOk4OvBvK0w\
             &code_challenge_method=S256";
    let resp = app
        .oneshot(
            Request::get(format!("/authorize?{q}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let www = resp.headers().get("www-authenticate").unwrap().to_str().unwrap();
    assert!(www.starts_with("Session realm="), "got `{www}`");
}

#[tokio::test]
async fn empty_session_header_returns_401() {
    let (app, _) = common::app();
    let q = "response_type=code&client_id=test-client&redirect_uri=https://rp.test/cb\
             &code_challenge=BHSRNtMQ-zlxLdngKVe-8z42_LDdVDOeIOk4OvBvK0w\
             &code_challenge_method=S256";
    let resp = app
        .oneshot(
            Request::get(format!("/authorize?{q}"))
                .header("milnet-as-session", "")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
