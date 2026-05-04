#![cfg(feature = "test-util")]

//! D-11: every response must carry the full security-header set: HSTS
//! preload, X-Content-Type-Options, X-Frame-Options DENY, Referrer-Policy
//! no-referrer, COOP/COEP/CORP, Permissions-Policy lockdown, CSP, no-store.

mod common;

use axum::body::Body;
use axum::http::Request;
use tower::ServiceExt;

async fn assert_headers(path: &str) {
    let (app, _) = common::app();
    let resp = app
        .oneshot(Request::get(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let h = resp.headers();
    assert!(
        h.get("strict-transport-security")
            .map(|v| v.to_str().unwrap().contains("max-age="))
            .unwrap_or(false),
        "HSTS missing on {path}"
    );
    assert_eq!(h.get("x-content-type-options").unwrap(), "nosniff");
    assert_eq!(h.get("x-frame-options").unwrap(), "DENY");
    assert_eq!(h.get("referrer-policy").unwrap(), "no-referrer");
    assert_eq!(h.get("cross-origin-opener-policy").unwrap(), "same-origin");
    assert_eq!(h.get("cross-origin-embedder-policy").unwrap(), "require-corp");
    assert_eq!(h.get("cross-origin-resource-policy").unwrap(), "same-origin");
    assert!(h.contains_key("permissions-policy"), "Permissions-Policy missing on {path}");
    assert!(h.contains_key("content-security-policy"), "CSP missing on {path}");
    assert_eq!(h.get("cache-control").unwrap(), "no-store");
    assert_eq!(h.get("pragma").unwrap(), "no-cache");
}

#[tokio::test]
async fn discovery_carries_security_headers() {
    assert_headers("/.well-known/openid-configuration").await;
}

#[tokio::test]
async fn jwks_carries_security_headers() {
    assert_headers("/.well-known/jwks.json").await;
}

#[tokio::test]
async fn healthz_carries_security_headers() {
    assert_headers("/healthz").await;
}
