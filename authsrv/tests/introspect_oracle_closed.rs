#![cfg(feature = "test-util")]

//! D-08: anonymous /introspect must return a constant-time, length-stable
//! `inactive` body so it cannot be used as a token-existence oracle.

mod common;

use authsrv::{AccessTokenMeta, now_secs};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

#[tokio::test]
async fn anonymous_introspect_returns_padded_inactive() {
    let (app, _) = common::app();
    let resp = app
        .oneshot(
            Request::post("/introspect")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("token=anything"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    assert_eq!(bytes.len(), 512, "padded length stable");
    let v: serde_json::Value = serde_json::from_slice(bytes.split(|&b| b == b'}').next().unwrap_or(&[])).ok()
        .or_else(|| {
            // Trailing-whitespace pad — strip and re-parse.
            let trimmed = std::str::from_utf8(&bytes).ok()?;
            serde_json::from_str(trimmed.trim_end()).ok()
        })
        .unwrap();
    assert_eq!(v["active"], false);
}

#[tokio::test]
async fn cross_client_introspect_filtered_to_inactive() {
    let (app, state) = common::app();
    // Stage an access token belonging to client-A (which the test client
    // doesn't have authority to introspect).
    {
        let mut g = state.access_tokens.lock().unwrap();
        g.insert(
            "at_secret".into(),
            AccessTokenMeta {
                jti: "jti-1".into(),
                sub: "test-subject".into(),
                client_id: "client-other".into(),
                scope: "openid".into(),
                exp: now_secs() + 600,
                dpop_jkt: None,
                family_id: Some("fam-1".into()),
                revoked: false,
            },
        );
    }
    let body = "token=at_secret&client_id=test-client&client_secret=test-secret";
    let resp = app
        .oneshot(
            Request::post("/introspect")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    assert_eq!(bytes.len(), 512);
    let trimmed = std::str::from_utf8(&bytes).unwrap().trim_end();
    let v: serde_json::Value = serde_json::from_str(trimmed).unwrap();
    assert_eq!(v["active"], false);
}

#[tokio::test]
async fn same_client_introspect_returns_active_padded() {
    let (app, state) = common::app();
    {
        let mut g = state.access_tokens.lock().unwrap();
        g.insert(
            "at_legit".into(),
            AccessTokenMeta {
                jti: "jti-2".into(),
                sub: "test-subject".into(),
                client_id: "test-client".into(),
                scope: "openid".into(),
                exp: now_secs() + 600,
                dpop_jkt: None,
                family_id: Some("fam-2".into()),
                revoked: false,
            },
        );
    }
    let body = "token=at_legit&client_id=test-client&client_secret=test-secret";
    let resp = app
        .oneshot(
            Request::post("/introspect")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    assert_eq!(bytes.len(), 512);
    let trimmed = std::str::from_utf8(&bytes).unwrap().trim_end();
    let v: serde_json::Value = serde_json::from_str(trimmed).unwrap();
    assert_eq!(v["active"], true);
    assert_eq!(v["sub"], "test-subject");
}
