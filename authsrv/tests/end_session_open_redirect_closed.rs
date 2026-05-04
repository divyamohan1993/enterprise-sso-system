#![cfg(feature = "test-util")]

//! D-09: /end_session must require id_token_hint, validate the issuer, and
//! refuse any post_logout_redirect_uri NOT registered for the calling client.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use tower::ServiceExt;

fn make_id_token_hint(iss: &str) -> String {
    let header = URL_SAFE_NO_PAD.encode(b"{\"alg\":\"none\"}");
    let payload = serde_json::json!({"iss": iss, "sub": "test-subject"}).to_string();
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload.as_bytes());
    format!("{header}.{payload_b64}.")
}

#[tokio::test]
async fn missing_id_token_hint_rejected() {
    let (app, _) = common::app();
    let resp = app
        .oneshot(
            Request::get("/end_session?post_logout_redirect_uri=https://attacker.tld/")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn unregistered_redirect_blocked_open() {
    let (app, _) = common::app();
    let hint = make_id_token_hint(authsrv::ISSUER_DEFAULT);
    let q = format!(
        "id_token_hint={hint}&post_logout_redirect_uri=https://attacker.tld/&client_id=test-client"
    );
    let resp = app
        .oneshot(
            Request::get(format!("/end_session?{q}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn registered_redirect_accepted() {
    let (app, _) = common::app();
    let hint = make_id_token_hint(authsrv::ISSUER_DEFAULT);
    let q = format!(
        "id_token_hint={hint}&post_logout_redirect_uri=https://rp.test/post&client_id=test-client&state=abc"
    );
    let resp = app
        .oneshot(
            Request::get(format!("/end_session?{q}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp.headers().get("location").unwrap().to_str().unwrap();
    assert!(loc.contains("state=abc"));
}

#[tokio::test]
async fn issuer_mismatch_rejected() {
    let (app, _) = common::app();
    let hint = make_id_token_hint("https://hostile.example/");
    let q = format!(
        "id_token_hint={hint}&post_logout_redirect_uri=https://rp.test/post&client_id=test-client"
    );
    let resp = app
        .oneshot(
            Request::get(format!("/end_session?{q}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}
