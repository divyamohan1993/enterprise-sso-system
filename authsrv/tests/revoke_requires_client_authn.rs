#![cfg(feature = "test-util")]

//! D-07: /revoke must require client authentication.  Anonymous callers
//! cannot mass-DoS by revoking unrelated tokens.  Only the owning client
//! may revoke, and revocation cascades family-wide.

mod common;

use authsrv::{AccessTokenMeta, RefreshToken, now_secs};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

#[tokio::test]
async fn anonymous_revoke_rejected() {
    let (app, _) = common::app();
    let resp = app
        .oneshot(
            Request::post("/revoke")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("token=at_anything"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn revoke_cascades_family_across_access_tokens() {
    let (app, state) = common::app();
    let family = "fam-cascade".to_string();
    {
        let mut at = state.access_tokens.lock().unwrap();
        at.insert(
            "at-1".into(),
            AccessTokenMeta {
                jti: "jti-1".into(),
                sub: "test-subject".into(),
                client_id: "test-client".into(),
                scope: "openid".into(),
                exp: now_secs() + 600,
                dpop_jkt: None,
                family_id: Some(family.clone()),
                revoked: false,
            },
        );
        at.insert(
            "at-2".into(),
            AccessTokenMeta {
                jti: "jti-2".into(),
                sub: "test-subject".into(),
                client_id: "test-client".into(),
                scope: "openid".into(),
                exp: now_secs() + 600,
                dpop_jkt: None,
                family_id: Some(family.clone()),
                revoked: false,
            },
        );
    }
    {
        let mut rt = state.refresh_tokens.lock().unwrap();
        rt.insert(
            "rt-cascade".into(),
            RefreshToken {
                token: "rt-cascade".into(),
                family_id: family.clone(),
                client_id: "test-client".into(),
                user_sub: "test-subject".into(),
                scope: "openid".into(),
                created_at: now_secs(),
                rotated: false,
            },
        );
    }
    let body = "token=rt-cascade&client_id=test-client&client_secret=test-secret";
    let resp = app
        .oneshot(
            Request::post("/revoke")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    // Both access tokens should now be marked revoked, and the family
    // should be in the revoked_families set.
    let at = state.access_tokens.lock().unwrap();
    assert!(at.get("at-1").unwrap().revoked, "at-1 should cascade-revoke");
    assert!(at.get("at-2").unwrap().revoked, "at-2 should cascade-revoke");
    let fams = state.revoked_families.lock().unwrap();
    assert!(fams.contains(&family));
}
