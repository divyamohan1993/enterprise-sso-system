//! Integration tests for the OIDC AS end-to-end flow.
//!
//! These tests exercise the secure flow: an authenticated login session on
//! `/authorize`, client-authenticated `/token`, and a fully-verified DPoP
//! proof on `/userinfo`. They require the `test-util` feature, which exposes
//! the gated `test_state` / `pkce_pair` fixtures:
//!
//! ```text
//! cargo test -p authsrv --features test-util
//! ```
#![cfg(feature = "test-util")]

use authsrv::*;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use sha2::{Digest, Sha256};
use tower::ServiceExt;

fn app() -> axum::Router {
    let s = test_state();
    router().with_state(s)
}

/// `Cookie:` header value carrying the test login session.
fn session_cookie() -> String {
    format!("milnet_sid={TEST_SESSION_ID}")
}

/// HTTP Basic credentials for the test client.
fn basic_auth() -> String {
    let raw = format!("{TEST_CLIENT_ID}:{TEST_CLIENT_SECRET}");
    format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(raw))
}

#[tokio::test]
async fn discovery_returns_endpoints() {
    let resp = app()
        .oneshot(
            Request::get("/.well-known/openid-configuration")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(v["token_endpoint"].as_str().unwrap().ends_with("/token"));
    assert_eq!(v["code_challenge_methods_supported"][0], "S256");
    assert_eq!(v["id_token_signing_alg_values_supported"][0], "ML-DSA-87");
}

#[tokio::test]
async fn jwks_publishes_real_key_material() {
    let resp = app()
        .oneshot(Request::get("/.well-known/jwks.json").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let pub_key = v["keys"][0]["pub"].as_str().unwrap();
    // The published key material must be non-empty real bytes, not "".
    assert!(!pub_key.is_empty(), "JWKS must publish real key material");
    assert!(URL_SAFE_NO_PAD.decode(pub_key).unwrap().len() > 1000);
}

#[tokio::test]
async fn authorize_requires_pkce_s256() {
    let q = "response_type=code&client_id=test-client&redirect_uri=https://rp.test/cb&code_challenge=abcdefghijklmnopqrstuvwxyzabcdefghijklmno1234&code_challenge_method=plain";
    let resp = app()
        .oneshot(
            Request::get(format!("/authorize?{q}"))
                .header("cookie", session_cookie())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn authorize_without_session_is_rejected() {
    let (_v, c) = pkce_pair();
    let q = format!(
        "response_type=code&client_id=test-client&redirect_uri=https://rp.test/cb&code_challenge={c}&code_challenge_method=S256"
    );
    // No cookie => no authenticated subject => login_required.
    let resp = app()
        .oneshot(Request::get(format!("/authorize?{q}")).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// An ML-DSA-87 DPoP keypair plus the proof-building helpers a client needs.
///
/// The token is DPoP-bound at issuance (RFC 9449 §5): the SAME key must sign
/// the proof on `/token` and every later proof on `/userinfo`.
struct DpopKey {
    sk: crypto::pq_sign::PqSigningKey,
    vk_b64: String,
}

impl DpopKey {
    /// Generate a keypair. ML-DSA-87 keygen needs a large stack, so it runs on
    /// a dedicated 16 MiB thread; the keys are `Send` and move back out.
    fn generate() -> Self {
        std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                let (sk, vk) = crypto::pq_sign::generate_pq_keypair();
                let vk_bytes = vk.encode();
                let vk_b64 = URL_SAFE_NO_PAD.encode(AsRef::<[u8]>::as_ref(&vk_bytes));
                DpopKey { sk, vk_b64 }
            })
            .unwrap()
            .join()
            .unwrap()
    }

    /// Build a DPoP proof JWT. `ath` is included only when `access_token` is
    /// `Some` (resource requests); the `/token` proof omits it.
    fn proof(&self, htm: &str, htu: &str, access_token: Option<&str>) -> String {
        let header = serde_json::json!({
            "typ": "dpop+jwt",
            "alg": "ML-DSA-87",
            "jwk": { "kty": "ML-DSA", "alg": "ML-DSA-87", "pub": self.vk_b64 },
        });
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let mut claims = serde_json::json!({
            "htm": htm,
            "htu": htu,
            "iat": now,
            "jti": uuid::Uuid::new_v4().to_string(),
        });
        if let Some(at) = access_token {
            claims["ath"] =
                serde_json::Value::String(URL_SAFE_NO_PAD.encode(Sha256::digest(at.as_bytes())));
        }
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        let signing_input = format!("{header_b64}.{claims_b64}");
        let sig = crypto::pq_sign::pq_sign_raw(&self.sk, signing_input.as_bytes());
        format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig))
    }
}

/// Drive `/authorize` + `/token` and return the parsed token response JSON.
///
/// The `/token` request carries a DPoP proof from `dpop` — the issued token is
/// bound to that key.
async fn obtain_tokens(app: &axum::Router, dpop: &DpopKey) -> serde_json::Value {
    let (verifier, challenge) = pkce_pair();
    let q = format!(
        "response_type=code&client_id=test-client&redirect_uri=https://rp.test/cb&code_challenge={challenge}&code_challenge_method=S256"
    );
    let resp = app
        .clone()
        .oneshot(
            Request::get(format!("/authorize?{q}"))
                .header("cookie", session_cookie())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp.headers().get("location").unwrap().to_str().unwrap().to_string();
    let code = loc.split("code=").nth(1).unwrap().split('&').next().unwrap().to_string();

    let body = format!(
        "grant_type=authorization_code&code={code}&redirect_uri=https://rp.test/cb&code_verifier={verifier}"
    );
    let token_proof = dpop.proof("POST", "https://sso.milnet.mil/token", None);
    let resp = app
        .clone()
        .oneshot(
            Request::post("/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .header("authorization", basic_auth())
                .header("DPoP", token_proof)
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn full_code_exchange_round_trip() {
    let app = app();
    let dpop = DpopKey::generate();
    let tr = obtain_tokens(&app, &dpop).await;
    // Tokens are now signed JWTs (header.claims.signature), not opaque strings.
    assert_eq!(tr["access_token"].as_str().unwrap().split('.').count(), 3);
    assert_eq!(tr["id_token"].as_str().unwrap().split('.').count(), 3);
    assert!(tr["refresh_token"].as_str().unwrap().starts_with("rt_"));
    assert_eq!(tr["token_type"], "DPoP");
}

#[tokio::test]
async fn token_endpoint_rejects_missing_dpop_proof() {
    // The /token request must carry a DPoP proof — without it the token could
    // not be DPoP-bound at issuance, so the request is refused.
    let app = app();
    let (verifier, challenge) = pkce_pair();
    let q = format!(
        "response_type=code&client_id=test-client&redirect_uri=https://rp.test/cb&code_challenge={challenge}&code_challenge_method=S256"
    );
    let resp = app
        .clone()
        .oneshot(
            Request::get(format!("/authorize?{q}"))
                .header("cookie", session_cookie())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let loc = resp.headers().get("location").unwrap().to_str().unwrap().to_string();
    let code = loc.split("code=").nth(1).unwrap().split('&').next().unwrap().to_string();

    let body = format!(
        "grant_type=authorization_code&code={code}&redirect_uri=https://rp.test/cb&code_verifier={verifier}"
    );
    // Client-authenticated, but no DPoP header.
    let resp = app
        .oneshot(
            Request::post("/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .header("authorization", basic_auth())
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn token_endpoint_rejects_unauthenticated_client() {
    let app = app();
    let (verifier, challenge) = pkce_pair();
    let q = format!(
        "response_type=code&client_id=test-client&redirect_uri=https://rp.test/cb&code_challenge={challenge}&code_challenge_method=S256"
    );
    let resp = app
        .clone()
        .oneshot(
            Request::get(format!("/authorize?{q}"))
                .header("cookie", session_cookie())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let loc = resp.headers().get("location").unwrap().to_str().unwrap().to_string();
    let code = loc.split("code=").nth(1).unwrap().split('&').next().unwrap().to_string();

    // No client authentication header and no client_secret in the body.
    let body = format!(
        "grant_type=authorization_code&code={code}&redirect_uri=https://rp.test/cb&code_verifier={verifier}"
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
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn refresh_token_reuse_revokes_family() {
    let app = app();
    let dpop = DpopKey::generate();
    let tr = obtain_tokens(&app, &dpop).await;
    let rt = tr["refresh_token"].as_str().unwrap().to_string();

    let body = format!("grant_type=refresh_token&refresh_token={rt}");
    // Each /token request needs its own fresh DPoP proof (unique jti).
    let r1 = app
        .clone()
        .oneshot(
            Request::post("/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .header("authorization", basic_auth())
                .header("DPoP", dpop.proof("POST", "https://sso.milnet.mil/token", None))
                .body(Body::from(body.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r1.status(), StatusCode::OK);

    // Reusing the now-rotated refresh token must fail and revoke the family.
    let r2 = app
        .oneshot(
            Request::post("/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .header("authorization", basic_auth())
                .header("DPoP", dpop.proof("POST", "https://sso.milnet.mil/token", None))
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r2.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn introspect_requires_client_auth() {
    // Without client authentication the endpoint must not act as an oracle.
    let resp = app()
        .oneshot(
            Request::post("/introspect")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("token=nope"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn introspect_unknown_inactive_when_authenticated() {
    let resp = app()
        .oneshot(
            Request::post("/introspect")
                .header("content-type", "application/x-www-form-urlencoded")
                .header("authorization", basic_auth())
                .body(Body::from("token=nope"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["active"], false);
}

#[tokio::test]
async fn revoke_requires_client_auth() {
    let resp = app()
        .oneshot(
            Request::post("/revoke")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("token=anything"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn end_session_rejects_unregistered_redirect() {
    // An attacker-controlled post_logout_redirect_uri must not yield a redirect.
    let resp = app()
        .oneshot(
            Request::get("/end_session?client_id=test-client&post_logout_redirect_uri=https://evil.example/phish")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn end_session_allows_registered_redirect() {
    let resp = app()
        .oneshot(
            Request::get("/end_session?client_id=test-client&post_logout_redirect_uri=https://rp.test/logout&state=abc")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn userinfo_requires_dpop_proof() {
    let app = app();
    let dpop = DpopKey::generate();
    let tr = obtain_tokens(&app, &dpop).await;
    let at = tr["access_token"].as_str().unwrap();

    // Plain Bearer scheme must be rejected — DPoP is mandatory.
    let resp = app
        .clone()
        .oneshot(
            Request::get("/userinfo")
                .header("authorization", format!("Bearer {at}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // DPoP scheme but no proof header must also be rejected.
    let resp = app
        .oneshot(
            Request::get("/userinfo")
                .header("authorization", format!("DPoP {at}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn userinfo_succeeds_with_valid_dpop_proof() {
    let app = app();
    // The SAME DPoP key signs the /token proof (binding) and the /userinfo
    // proof (presentation) — RFC 9449 §5 issuance binding.
    let dpop = DpopKey::generate();
    let tr = obtain_tokens(&app, &dpop).await;
    let at = tr["access_token"].as_str().unwrap().to_string();

    let proof = dpop.proof("GET", "https://sso.milnet.mil/userinfo", Some(&at));
    let resp = app
        .oneshot(
            Request::get("/userinfo")
                .header("authorization", format!("DPoP {at}"))
                .header("DPoP", proof)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["sub"], TEST_SUBJECT);
}

#[tokio::test]
async fn userinfo_rejects_dpop_proof_from_a_different_key() {
    // A token DPoP-bound to key A must not be usable with a proof from key B —
    // this is the stolen-token defence (no trust-on-first-use).
    let app = app();
    let bound_key = DpopKey::generate();
    let tr = obtain_tokens(&app, &bound_key).await;
    let at = tr["access_token"].as_str().unwrap().to_string();

    // A different key crafts a structurally valid proof — must be rejected.
    let attacker_key = DpopKey::generate();
    let proof = attacker_key.proof("GET", "https://sso.milnet.mil/userinfo", Some(&at));
    let resp = app
        .oneshot(
            Request::get("/userinfo")
                .header("authorization", format!("DPoP {at}"))
                .header("DPoP", proof)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
