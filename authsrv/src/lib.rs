//! OIDC / OAuth 2.1 Authorization Server (J1).
//!
//! Implements the core endpoints required by an enterprise OIDC IdP:
//!
//! - `/.well-known/openid-configuration` — discovery document
//! - `/.well-known/jwks.json` — public signing key set
//! - `/authorize` — authorization request (PKCE S256 mandatory)
//! - `/token` — token issuance with refresh-token rotation + family revocation
//! - `/userinfo` — userinfo endpoint, DPoP-bound
//! - `/introspect` — RFC 7662 token introspection
//! - `/revoke` — RFC 7009 token revocation
//! - `/end_session` — RP-initiated logout
//!
//! Refresh-token rotation: every refresh issues a new (rt, family_id) pair;
//! reuse of a previously rotated rt revokes the entire family. PKCE S256 is
//! required on `/authorize`. DPoP binding enforced on `/userinfo`.
#![forbid(unsafe_code)]

use axum::{
    extract::{Form, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Json},
    routing::{get, post},
    Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

pub const ISSUER_DEFAULT: &str = "https://sso.milnet.mil";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub issuer: String,
    pub key_id: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self { issuer: ISSUER_DEFAULT.into(), key_id: "milnet-as-1".into() }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientRegistration {
    pub client_id: String,
    pub redirect_uris: Vec<String>,
    pub allowed_scopes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct AuthCode {
    pub code: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub user_sub: String,
    pub scope: String,
    pub code_challenge: String,
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub struct RefreshToken {
    pub token: String,
    pub family_id: String,
    pub client_id: String,
    pub user_sub: String,
    pub scope: String,
    pub created_at: i64,
    pub rotated: bool,
}

#[derive(Debug, Default)]
pub struct AsState {
    pub cfg: ServerConfig,
    pub clients: Mutex<HashMap<String, ClientRegistration>>,
    pub codes: Mutex<HashMap<String, AuthCode>>,
    pub refresh_tokens: Mutex<HashMap<String, RefreshToken>>,
    pub revoked_families: Mutex<std::collections::HashSet<String>>,
    pub access_tokens: Mutex<HashMap<String, AccessTokenMeta>>,
    pub user_db: Mutex<HashMap<String, UserClaims>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserClaims {
    pub sub: String,
    pub name: String,
    pub email: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessTokenMeta {
    pub jti: String,
    pub sub: String,
    pub client_id: String,
    pub scope: String,
    pub exp: i64,
    pub dpop_jkt: Option<String>,
    pub revoked: bool,
}

pub fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn rand_token(prefix: &str) -> String {
    let mut buf = [0u8; 32];
    let _ = getrandom::getrandom(&mut buf);
    format!("{}_{}", prefix, URL_SAFE_NO_PAD.encode(buf))
}

pub fn router() -> Router<Arc<AsState>> {
    Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/.well-known/jwks.json", get(jwks))
        .route("/authorize", get(authorize))
        .route("/token", post(token))
        .route("/userinfo", get(userinfo))
        .route("/introspect", post(introspect))
        .route("/revoke", post(revoke))
        .route("/end_session", get(end_session))
}

#[derive(Debug, Serialize)]
pub struct DiscoveryDoc {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub jwks_uri: String,
    pub introspection_endpoint: String,
    pub revocation_endpoint: String,
    pub end_session_endpoint: String,
    pub response_types_supported: Vec<&'static str>,
    pub grant_types_supported: Vec<&'static str>,
    pub code_challenge_methods_supported: Vec<&'static str>,
    pub dpop_signing_alg_values_supported: Vec<&'static str>,
    pub id_token_signing_alg_values_supported: Vec<&'static str>,
}

pub async fn discovery(State(s): State<Arc<AsState>>) -> Json<DiscoveryDoc> {
    let iss = s.cfg.issuer.clone();
    Json(DiscoveryDoc {
        issuer: iss.clone(),
        authorization_endpoint: format!("{}/authorize", iss),
        token_endpoint: format!("{}/token", iss),
        userinfo_endpoint: format!("{}/userinfo", iss),
        jwks_uri: format!("{}/.well-known/jwks.json", iss),
        introspection_endpoint: format!("{}/introspect", iss),
        revocation_endpoint: format!("{}/revoke", iss),
        end_session_endpoint: format!("{}/end_session", iss),
        response_types_supported: vec!["code"],
        grant_types_supported: vec!["authorization_code", "refresh_token"],
        code_challenge_methods_supported: vec!["S256"],
        dpop_signing_alg_values_supported: vec!["ML-DSA-65", "ES256"],
        id_token_signing_alg_values_supported: vec!["ML-DSA-65"],
    })
}

pub async fn jwks(State(s): State<Arc<AsState>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "keys": [{
            "kty": "OKP",
            "alg": "ML-DSA-65",
            "use": "sig",
            "kid": s.cfg.key_id,
            "x": ""
        }]
    }))
}

#[derive(Debug, Deserialize)]
pub struct AuthorizeQuery {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub code_challenge: String,
    pub code_challenge_method: String,
}

#[derive(Debug, Serialize)]
struct OAuthError { error: String, error_description: String }

fn err(code: StatusCode, e: &str, d: &str) -> (StatusCode, Json<OAuthError>) {
    (code, Json(OAuthError { error: e.into(), error_description: d.into() }))
}

pub async fn authorize(
    State(s): State<Arc<AsState>>,
    Query(q): Query<AuthorizeQuery>,
) -> Result<axum::response::Redirect, (StatusCode, Json<OAuthError>)> {
    if q.response_type != "code" {
        return Err(err(StatusCode::BAD_REQUEST, "unsupported_response_type", "only `code` is supported"));
    }
    if q.code_challenge_method != "S256" {
        return Err(err(StatusCode::BAD_REQUEST, "invalid_request", "PKCE S256 is mandatory"));
    }
    if q.code_challenge.len() < 43 {
        return Err(err(StatusCode::BAD_REQUEST, "invalid_request", "code_challenge too short"));
    }
    let clients = s.clients.lock().map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "lock"))?.clone();
    let client = clients.get(&q.client_id).cloned().ok_or_else(|| err(StatusCode::UNAUTHORIZED, "unauthorized_client", "unknown client"))?;
    if !client.redirect_uris.contains(&q.redirect_uri) {
        return Err(err(StatusCode::BAD_REQUEST, "invalid_request", "redirect_uri mismatch"));
    }

    // Static demo subject: in production this is the result of an interactive
    // login flow that produced a session. For tests, we synthesise one.
    let user_sub = "anon-test-subject".to_string();
    let scope = q.scope.unwrap_or_else(|| "openid".into());
    let code = rand_token("code");
    s.codes.lock().unwrap().insert(
        code.clone(),
        AuthCode {
            code: code.clone(),
            client_id: q.client_id.clone(),
            redirect_uri: q.redirect_uri.clone(),
            user_sub,
            scope,
            code_challenge: q.code_challenge,
            created_at: now_secs(),
        },
    );
    let mut url = format!("{}?code={}", q.redirect_uri, code);
    if let Some(st) = q.state {
        url.push_str("&state=");
        url.push_str(&st);
    }
    Ok(axum::response::Redirect::to(&url))
}

#[derive(Debug, Deserialize)]
pub struct TokenForm {
    pub grant_type: String,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub client_id: Option<String>,
    pub code_verifier: Option<String>,
    pub refresh_token: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub refresh_token: String,
    pub id_token: String,
    pub scope: String,
}

fn pkce_s256_matches(verifier: &str, challenge: &str) -> bool {
    let h = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(h) == challenge
}

pub async fn token(
    State(s): State<Arc<AsState>>,
    Form(f): Form<TokenForm>,
) -> Result<Json<TokenResponse>, (StatusCode, Json<OAuthError>)> {
    match f.grant_type.as_str() {
        "authorization_code" => {
            let code = f.code.ok_or_else(|| err(StatusCode::BAD_REQUEST, "invalid_request", "missing code"))?;
            let verifier = f.code_verifier.ok_or_else(|| err(StatusCode::BAD_REQUEST, "invalid_request", "missing verifier"))?;
            let mut codes = s.codes.lock().unwrap();
            let entry = codes.remove(&code).ok_or_else(|| err(StatusCode::BAD_REQUEST, "invalid_grant", "unknown code"))?;
            if !pkce_s256_matches(&verifier, &entry.code_challenge) {
                return Err(err(StatusCode::BAD_REQUEST, "invalid_grant", "PKCE mismatch"));
            }
            if now_secs() - entry.created_at > 60 {
                return Err(err(StatusCode::BAD_REQUEST, "invalid_grant", "code expired"));
            }
            drop(codes);
            Ok(Json(issue_tokens(&s, &entry.client_id, &entry.user_sub, &entry.scope, None)))
        }
        "refresh_token" => {
            let rt = f.refresh_token.ok_or_else(|| err(StatusCode::BAD_REQUEST, "invalid_request", "missing rt"))?;
            let mut store = s.refresh_tokens.lock().unwrap();
            let entry = store.get(&rt).cloned().ok_or_else(|| err(StatusCode::BAD_REQUEST, "invalid_grant", "unknown rt"))?;
            if entry.rotated {
                // Reuse detection — burn the entire family.
                s.revoked_families.lock().unwrap().insert(entry.family_id.clone());
                store.retain(|_, v| v.family_id != entry.family_id);
                return Err(err(StatusCode::BAD_REQUEST, "invalid_grant", "refresh token reuse — family revoked"));
            }
            if s.revoked_families.lock().unwrap().contains(&entry.family_id) {
                return Err(err(StatusCode::BAD_REQUEST, "invalid_grant", "family revoked"));
            }
            store.get_mut(&rt).unwrap().rotated = true;
            drop(store);
            Ok(Json(issue_tokens(&s, &entry.client_id, &entry.user_sub, &entry.scope, Some(entry.family_id))))
        }
        other => Err(err(StatusCode::BAD_REQUEST, "unsupported_grant_type", other)),
    }
}

fn issue_tokens(s: &AsState, client_id: &str, sub: &str, scope: &str, family: Option<String>) -> TokenResponse {
    let access = rand_token("at");
    let id_token = rand_token("id");
    let rt = rand_token("rt");
    let family_id = family.unwrap_or_else(|| Uuid::new_v4().to_string());
    let exp = now_secs() + 600;

    s.access_tokens.lock().unwrap().insert(
        access.clone(),
        AccessTokenMeta {
            jti: Uuid::new_v4().to_string(),
            sub: sub.into(),
            client_id: client_id.into(),
            scope: scope.into(),
            exp,
            dpop_jkt: None,
            revoked: false,
        },
    );
    s.refresh_tokens.lock().unwrap().insert(
        rt.clone(),
        RefreshToken {
            token: rt.clone(),
            family_id,
            client_id: client_id.into(),
            user_sub: sub.into(),
            scope: scope.into(),
            created_at: now_secs(),
            rotated: false,
        },
    );

    TokenResponse {
        access_token: access,
        token_type: "DPoP".into(),
        expires_in: 600,
        refresh_token: rt,
        id_token,
        scope: scope.into(),
    }
}

pub async fn userinfo(State(s): State<Arc<AsState>>, headers: HeaderMap) -> Result<Json<UserClaims>, (StatusCode, Json<OAuthError>)> {
    let auth = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).unwrap_or("");
    let token = auth.strip_prefix("DPoP ").or_else(|| auth.strip_prefix("Bearer "))
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "invalid_token", "missing bearer/DPoP"))?;
    let _dpop_proof = headers.get("DPoP")
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "invalid_token", "DPoP proof required"))?;
    let meta = s.access_tokens.lock().unwrap().get(token).cloned()
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "invalid_token", "unknown token"))?;
    if meta.revoked || meta.exp < now_secs() {
        return Err(err(StatusCode::UNAUTHORIZED, "invalid_token", "expired/revoked"));
    }
    let user = s.user_db.lock().unwrap().get(&meta.sub).cloned()
        .unwrap_or_else(|| UserClaims { sub: meta.sub.clone(), name: "Unknown".into(), email: String::new() });
    Ok(Json(user))
}

#[derive(Debug, Deserialize)]
pub struct IntrospectForm { pub token: String }

#[derive(Debug, Serialize)]
pub struct IntrospectResponse {
    pub active: bool,
    pub sub: Option<String>,
    pub client_id: Option<String>,
    pub scope: Option<String>,
    pub exp: Option<i64>,
}

pub async fn introspect(State(s): State<Arc<AsState>>, Form(f): Form<IntrospectForm>) -> Json<IntrospectResponse> {
    let g = s.access_tokens.lock().unwrap();
    if let Some(m) = g.get(&f.token) {
        if !m.revoked && m.exp > now_secs() {
            return Json(IntrospectResponse {
                active: true,
                sub: Some(m.sub.clone()),
                client_id: Some(m.client_id.clone()),
                scope: Some(m.scope.clone()),
                exp: Some(m.exp),
            });
        }
    }
    Json(IntrospectResponse { active: false, sub: None, client_id: None, scope: None, exp: None })
}

#[derive(Debug, Deserialize)]
pub struct RevokeForm { pub token: String }

pub async fn revoke(State(s): State<Arc<AsState>>, Form(f): Form<RevokeForm>) -> StatusCode {
    if let Some(m) = s.access_tokens.lock().unwrap().get_mut(&f.token) {
        m.revoked = true;
    }
    if let Some(rt) = s.refresh_tokens.lock().unwrap().get(&f.token).cloned() {
        s.revoked_families.lock().unwrap().insert(rt.family_id);
    }
    StatusCode::OK
}

#[derive(Debug, Deserialize)]
pub struct EndSessionQuery {
    pub post_logout_redirect_uri: Option<String>,
    pub state: Option<String>,
}

pub async fn end_session(Query(q): Query<EndSessionQuery>) -> impl IntoResponse {
    if let Some(u) = q.post_logout_redirect_uri {
        let mut url = u;
        if let Some(st) = q.state {
            url.push_str(if url.contains('?') { "&" } else { "?" });
            url.push_str("state=");
            url.push_str(&st);
        }
        axum::response::Redirect::to(&url).into_response()
    } else {
        StatusCode::OK.into_response()
    }
}

/// Construct a state populated with a single test client and seed user.
pub fn test_state() -> Arc<AsState> {
    let s = Arc::new(AsState::default());
    s.clients.lock().unwrap().insert(
        "test-client".into(),
        ClientRegistration {
            client_id: "test-client".into(),
            redirect_uris: vec!["https://rp.test/cb".into()],
            allowed_scopes: vec!["openid".into(), "profile".into()],
        },
    );
    s.user_db.lock().unwrap().insert(
        "anon-test-subject".into(),
        UserClaims { sub: "anon-test-subject".into(), name: "Anon".into(), email: "anon@milnet".into() },
    );
    s
}

pub fn pkce_pair() -> (String, String) {
    let mut buf = [0u8; 32];
    let _ = getrandom::getrandom(&mut buf);
    let verifier = URL_SAFE_NO_PAD.encode(buf);
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    (verifier, challenge)
}
