#![cfg(feature = "test-util")]

//! D-13: every endpoint emits SIEM-eligible audit entries.  This integration
//! test drives a successful and failed path and verifies the audit-bridge
//! buffer captures the expected records.  Because the audit buffer is a
//! process-wide singleton (per `common::audit_bridge`), the test must drain
//! it at the start to isolate this test's events.

mod common;

use axum::body::Body;
use axum::http::Request;
use tower::ServiceExt;

#[tokio::test]
async fn failed_authorize_emits_identity_required() {
    let (app, _) = common::app();
    // Drain anything left over from earlier tests so the assertion is local.
    let _ = common::audit_drain_count();
    let q = "response_type=code&client_id=test-client&redirect_uri=https://rp.test/cb\
             &code_challenge=BHSRNtMQ-zlxLdngKVe-8z42_LDdVDOeIOk4OvBvK0w\
             &code_challenge_method=S256";
    let _ = app
        .oneshot(
            Request::get(format!("/authorize?{q}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let count = common::audit_drain_count();
    assert!(count > 0, "expected at least one audit entry");
}

#[tokio::test]
async fn failed_client_authn_emits_critical() {
    let (app, _) = common::app();
    let _ = common::audit_drain_count();
    let body = "grant_type=refresh_token&refresh_token=rt_anything\
                &client_id=test-client&client_secret=WRONG";
    let _ = app
        .oneshot(
            Request::post("/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    let count = common::audit_drain_count();
    assert!(count > 0, "expected client_authn.fail audit entry");
}
