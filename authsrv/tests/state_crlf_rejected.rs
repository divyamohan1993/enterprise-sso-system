#![cfg(feature = "test-util")]

//! D-14: `state` containing CR/LF (CWE-113) or other control characters
//! must be rejected before it can be reflected in a Location header.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

#[tokio::test]
async fn crlf_state_rejected() {
    let (app, _) = common::app();
    let q = "response_type=code&client_id=test-client&redirect_uri=https://rp.test/cb\
             &code_challenge=BHSRNtMQ-zlxLdngKVe-8z42_LDdVDOeIOk4OvBvK0w\
             &code_challenge_method=S256&state=hello%0d%0afoo";
    let resp = app
        .oneshot(
            Request::get(format!("/authorize?{q}"))
                .header("milnet-as-session", authsrv::TEST_SESSION_HEADER)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn nul_state_rejected() {
    let (app, _) = common::app();
    let q = "response_type=code&client_id=test-client&redirect_uri=https://rp.test/cb\
             &code_challenge=BHSRNtMQ-zlxLdngKVe-8z42_LDdVDOeIOk4OvBvK0w\
             &code_challenge_method=S256&state=hello%00world";
    let resp = app
        .oneshot(
            Request::get(format!("/authorize?{q}"))
                .header("milnet-as-session", authsrv::TEST_SESSION_HEADER)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}
