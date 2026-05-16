//! OIDC / OAuth 2.1 Authorization Server (J1).
//!
//! Implements the core endpoints required by an enterprise OIDC IdP:
//!
//! - `/.well-known/openid-configuration` — discovery document
//! - `/.well-known/jwks.json` — public signing key set (ML-DSA-87)
//! - `/authorize` — authorization request (PKCE S256 mandatory)
//! - `/token` — token issuance with refresh-token rotation + family revocation
//! - `/userinfo` — userinfo endpoint, DPoP-bound (RFC 9449)
//! - `/introspect` — RFC 7662 token introspection (client-authenticated)
//! - `/revoke` — RFC 7009 token revocation (client-authenticated)
//! - `/end_session` — RP-initiated logout
//!
//! # Security model
//!
//! - **Tokens are signed JWTs.** Both `id_token` and `access_token` are
//!   ML-DSA-87 (FIPS 204) signed JWTs produced via `sso-protocol`. JWKS
//!   publishes the real verifying key so relying parties can validate them.
//! - **Subject comes from an authenticated session.** `/authorize` requires a
//!   server-side login session (`milnet_sid` cookie); there is no anonymous
//!   path. Sessions are established out of band by the login service.
//! - **Client authentication is mandatory** on `/token`, `/introspect` and
//!   `/revoke` via HTTP Basic or `client_secret_post`, verified against the
//!   Argon2id-hashed secret in the client registry.
//! - **Authorization-code grant binds `client_id` and `redirect_uri`** to the
//!   values from the original `/authorize` request (RFC 6749 §4.1.3).
//! - **DPoP is enforced** on `/userinfo`: the proof JWT is fully parsed, its
//!   ML-DSA-87 signature verified, `htm`/`htu`/`iat`/`jti`/`ath` checked, and
//!   the JWK thumbprint matched against the token's `cnf.jkt` binding.
//! - **CSPRNG failures are fatal**, never silently degraded to zero buffers.
#![forbid(unsafe_code)]

use axum::{
    extract::{Form, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use crypto::pq_sign::{PqSigningKey, PqVerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

pub const ISSUER_DEFAULT: &str = "https://sso.milnet.mil";

/// Maximum form/proof body sizes accepted by the router (defense against
/// memory-exhaustion via oversized requests).
const MAX_BODY_BYTES: usize = 16 * 1024;

/// Authorization-code lifetime in seconds (RFC 6749 recommends a short TTL).
const AUTH_CODE_TTL_SECS: i64 = 60;

/// Access-token lifetime in seconds.
const ACCESS_TOKEN_TTL_SECS: i64 = 600;

/// Maximum age (seconds) accepted for a DPoP proof `iat` (RFC 9449 §11.1).
const DPOP_PROOF_MAX_AGE_SECS: i64 = 30;

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

impl ServerConfig {
    /// Issuer with any trailing slash removed, so endpoint URLs never contain
    /// a `//` path segment (P2: strict-validator compatibility).
    fn issuer_base(&self) -> &str {
        self.issuer.trim_end_matches('/')
    }
}

/// A registered OAuth client. The `client_secret_hash` is the Argon2id hash of
/// the secret (see `sso-protocol::clients`); the plaintext is never stored.
#[derive(Debug, Clone)]
pub struct ClientRegistration {
    pub client_id: String,
    /// Argon2id hash of the client secret, hex-encoded.
    pub client_secret_hash: String,
    pub redirect_uris: Vec<String>,
    /// Exact-match allowlist of `post_logout_redirect_uri` values.
    pub post_logout_redirect_uris: Vec<String>,
    pub allowed_scopes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct AuthCode {
    pub client_id: String,
    pub redirect_uri: String,
    pub user_sub: String,
    pub scope: String,
    pub nonce: Option<String>,
    pub code_challenge: String,
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub struct RefreshToken {
    pub family_id: String,
    pub client_id: String,
    pub user_sub: String,
    pub scope: String,
    pub created_at: i64,
    pub rotated: bool,
}

/// A server-side login session. Established by the login service out of band;
/// `/authorize` consumes it to determine the authenticated subject.
#[derive(Debug, Clone)]
pub struct LoginSession {
    pub user_sub: String,
    /// Absolute expiry (UNIX seconds).
    pub expires_at: i64,
}

/// The AS's ML-DSA-87 (FIPS 204) OIDC signing keypair.
///
/// SECURITY (P0): id_token and access_token are signed with this key, and the
/// verifying key is published verbatim in JWKS so relying parties can validate
/// tokens. ML-DSA-87 meets CNSA 2.0 Level 5.
pub struct OidcKeypair {
    signing_key: PqSigningKey,
    verifying_key: PqVerifyingKey,
    kid: String,
}

impl OidcKeypair {
    /// Generate a fresh ML-DSA-87 OIDC keypair.
    ///
    /// SECURITY (P0): uses the checked CSPRNG path; an entropy failure returns
    /// `Err` so the caller fails closed instead of starting with a weak key.
    pub fn generate(kid: impl Into<String>) -> Result<Self, String> {
        let (signing_key, verifying_key) = crypto::pq_sign::generate_pq_keypair_checked()?;
        Ok(Self { signing_key, verifying_key, kid: kid.into() })
    }

    /// JWK `kid` for this key.
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// JWKS document publishing the real ML-DSA-87 verifying key material.
    ///
    /// NOTE — non-IETF-standard JWK shape: the key uses `"kty": "ML-DSA"` with
    /// the encoded verifying key in a `"pub"` member. At the time of writing
    /// no RFC assigns a JWK representation for ML-DSA (FIPS 204), so this is a
    /// MILNET-internal convention. It is used consistently by this JWKS
    /// endpoint and by `verify_dpop_proof`'s embedded-JWK parsing. Relying
    /// parties outside the MILNET ecosystem must be configured to expect this
    /// shape; a standard JOSE library will not recognise `kty=ML-DSA`.
    pub fn jwks_json(&self) -> serde_json::Value {
        let vk_bytes = self.verifying_key.encode();
        let vk_b64 = URL_SAFE_NO_PAD.encode(AsRef::<[u8]>::as_ref(&vk_bytes));
        serde_json::json!({
            "keys": [{
                "kty": "ML-DSA",
                "alg": "ML-DSA-87",
                "use": "sig",
                "kid": self.kid,
                "pub": vk_b64,
            }]
        })
    }
}

pub struct AsState {
    pub cfg: ServerConfig,
    /// ML-DSA-87 signing key for id_token / access_token JWTs and JWKS.
    pub signing_key: OidcKeypair,
    pub clients: Mutex<HashMap<String, ClientRegistration>>,
    pub codes: Mutex<HashMap<String, AuthCode>>,
    pub refresh_tokens: Mutex<HashMap<String, RefreshToken>>,
    pub revoked_families: Mutex<HashSet<String>>,
    pub access_tokens: Mutex<HashMap<String, AccessTokenMeta>>,
    pub user_db: Mutex<HashMap<String, UserClaims>>,
    /// Active login sessions keyed by opaque session id.
    pub sessions: Mutex<HashMap<String, LoginSession>>,
    /// DPoP proof JTIs already seen, with their expiry, for replay rejection.
    pub dpop_jti_seen: Mutex<HashMap<String, i64>>,
}

impl AsState {
    /// Construct fresh server state with a newly generated signing key.
    ///
    /// SECURITY (P0): returns `Err` if the OS CSPRNG is unavailable rather than
    /// starting with a degraded key.
    pub fn new(cfg: ServerConfig) -> Result<Self, String> {
        let signing_key = OidcKeypair::generate(format!("{}-mldsa87-v1", cfg.key_id))?;
        Ok(Self {
            cfg,
            signing_key,
            clients: Mutex::new(HashMap::new()),
            codes: Mutex::new(HashMap::new()),
            refresh_tokens: Mutex::new(HashMap::new()),
            revoked_families: Mutex::new(HashSet::new()),
            access_tokens: Mutex::new(HashMap::new()),
            user_db: Mutex::new(HashMap::new()),
            sessions: Mutex::new(HashMap::new()),
            dpop_jti_seen: Mutex::new(HashMap::new()),
        })
    }
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
    /// JWK SHA-256 thumbprint (RFC 9449 `jkt`) the token is DPoP-bound to.
    pub dpop_jkt: String,
    pub revoked: bool,
}

pub fn now_secs() -> i64 {
    common::secure_time::secure_now_secs_i64()
}

/// Fill `buf` with cryptographically secure random bytes.
///
/// SECURITY (P0): a CSPRNG failure is unrecoverable — continuing would emit a
/// deterministic, all-zero token. The return value is propagated, never
/// dropped with `let _ = …`.
fn fill_random(buf: &mut [u8]) -> Result<(), getrandom::Error> {
    getrandom::getrandom(buf)
}

/// Generate an opaque random token string with the given prefix.
///
/// Returns `Err` if the OS CSPRNG is unavailable so callers fail closed
/// instead of issuing a predictable token.
fn rand_token(prefix: &str) -> Result<String, getrandom::Error> {
    let mut buf = [0u8; 32];
    fill_random(&mut buf)?;
    Ok(format!("{}_{}", prefix, URL_SAFE_NO_PAD.encode(buf)))
}

/// Mutex-lock helper that converts poisoning into a 500 instead of a panic
/// (P1: a single poisoned lock must not turn the service into a 500-machine —
/// a poisoned lock is reported once and recovered).
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| {
        common::siem::SecurityEvent::mutex_poisoning("authsrv state mutex poisoned — recovered");
        poisoned.into_inner()
    })
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
        // P1: global body-size cap so /token, /introspect, /revoke cannot be
        // used for memory exhaustion via oversized form bodies.
        .layer(axum::extract::DefaultBodyLimit::max(MAX_BODY_BYTES))
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
    pub token_endpoint_auth_methods_supported: Vec<&'static str>,
    pub dpop_signing_alg_values_supported: Vec<&'static str>,
    pub id_token_signing_alg_values_supported: Vec<&'static str>,
}

pub async fn discovery(State(s): State<Arc<AsState>>) -> Json<DiscoveryDoc> {
    let iss = s.cfg.issuer_base().to_string();
    Json(DiscoveryDoc {
        authorization_endpoint: format!("{iss}/authorize"),
        token_endpoint: format!("{iss}/token"),
        userinfo_endpoint: format!("{iss}/userinfo"),
        jwks_uri: format!("{iss}/.well-known/jwks.json"),
        introspection_endpoint: format!("{iss}/introspect"),
        revocation_endpoint: format!("{iss}/revoke"),
        end_session_endpoint: format!("{iss}/end_session"),
        issuer: iss,
        response_types_supported: vec!["code"],
        grant_types_supported: vec!["authorization_code", "refresh_token"],
        code_challenge_methods_supported: vec!["S256"],
        token_endpoint_auth_methods_supported: vec!["client_secret_basic", "client_secret_post"],
        // The AS signs id_token / access_token with ML-DSA-87 and accepts
        // ML-DSA-87 DPoP proofs. The advertised algorithm matches what JWKS
        // actually publishes (P0/P1: discovery must not over-claim).
        dpop_signing_alg_values_supported: vec!["ML-DSA-87"],
        id_token_signing_alg_values_supported: vec!["ML-DSA-87"],
    })
}

/// JWKS — publishes the real ML-DSA-87 verifying key material (P0/P1: the
/// previous implementation published `"x": ""`, making every RP either reject
/// all tokens or accept forgeries).
pub async fn jwks(State(s): State<Arc<AsState>>) -> Json<serde_json::Value> {
    Json(s.signing_key.jwks_json())
}

#[derive(Debug, Deserialize)]
pub struct AuthorizeQuery {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub code_challenge: String,
    pub code_challenge_method: String,
}

#[derive(Debug, Serialize)]
struct OAuthError {
    error: String,
    error_description: String,
}

fn err(code: StatusCode, e: &str, d: &str) -> (StatusCode, Json<OAuthError>) {
    (code, Json(OAuthError { error: e.into(), error_description: d.into() }))
}

/// RFC 6749 §4.1.2 requires response parameters to be `application/x-www-form-
/// urlencoded`. Encoding `state`/`code` prevents response-splitting (`\r\n`)
/// and query corruption (`&`, `#`) — P1.
fn pct_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for &b in value.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Validate a PKCE `code_challenge`: 43-128 chars, Base64URL charset only
/// (RFC 7636 §4.2). P1: the previous code only checked a lower bound.
fn valid_code_challenge(c: &str) -> bool {
    (43..=128).contains(&c.len())
        && c.bytes().all(|b| {
            b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
        })
}

/// Extract the authenticated subject from the request's login session cookie.
///
/// SECURITY (P0): there is no anonymous path. The subject is the user proven
/// to be logged in by the login service, looked up from a non-expired session.
/// A missing, unknown, or expired session is rejected.
fn authenticated_subject(
    s: &AsState,
    headers: &HeaderMap,
) -> Result<String, (StatusCode, Json<OAuthError>)> {
    let sid = headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(parse_session_cookie)
        .ok_or_else(|| {
            err(
                StatusCode::UNAUTHORIZED,
                "login_required",
                "no authenticated session — complete interactive login first",
            )
        })?;

    let session = lock(&s.sessions).get(&sid).cloned().ok_or_else(|| {
        err(StatusCode::UNAUTHORIZED, "login_required", "session not found")
    })?;

    if session.expires_at <= now_secs() {
        lock(&s.sessions).remove(&sid);
        return Err(err(StatusCode::UNAUTHORIZED, "login_required", "session expired"));
    }
    Ok(session.user_sub)
}

/// Pull the `milnet_sid` value out of a `Cookie:` header.
fn parse_session_cookie(cookie_header: &str) -> Option<String> {
    cookie_header
        .split(';')
        .map(str::trim)
        .find_map(|pair| pair.strip_prefix("milnet_sid="))
        .filter(|v| !v.is_empty())
        .map(str::to_string)
}

pub async fn authorize(
    State(s): State<Arc<AsState>>,
    headers: HeaderMap,
    Query(q): Query<AuthorizeQuery>,
) -> Result<axum::response::Redirect, (StatusCode, Json<OAuthError>)> {
    if q.response_type != "code" {
        return Err(err(StatusCode::BAD_REQUEST, "unsupported_response_type", "only `code` is supported"));
    }
    if q.code_challenge_method != "S256" {
        return Err(err(StatusCode::BAD_REQUEST, "invalid_request", "PKCE S256 is mandatory"));
    }
    if !valid_code_challenge(&q.code_challenge) {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "code_challenge must be 43-128 Base64URL characters",
        ));
    }

    let client = lock(&s.clients)
        .get(&q.client_id)
        .cloned()
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "unauthorized_client", "unknown client"))?;
    if !client.redirect_uris.iter().any(|u| u == &q.redirect_uri) {
        return Err(err(StatusCode::BAD_REQUEST, "invalid_request", "redirect_uri mismatch"));
    }

    // SECURITY (P0): subject is the authenticated session user — no anon stub.
    let user_sub = authenticated_subject(&s, &headers)?;

    // SECURITY: every requested scope must be on the client's registered
    // allowlist (RFC 6749 §3.3) — a client may not obtain a token for a scope
    // it was never granted. `openid` is the implicit default for OIDC.
    let scope = q.scope.unwrap_or_else(|| "openid".into());
    for requested in scope.split_whitespace() {
        if !client.allowed_scopes.iter().any(|s| s == requested) {
            return Err(err(
                StatusCode::BAD_REQUEST,
                "invalid_scope",
                "requested scope is not allowed for this client",
            ));
        }
    }

    let code = rand_token("code").map_err(|e| {
        common::siem::SecurityEvent::crypto_failure(&format!("CSPRNG failure issuing auth code: {e}"));
        err(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "entropy unavailable")
    })?;

    lock(&s.codes).insert(
        code.clone(),
        AuthCode {
            client_id: q.client_id.clone(),
            redirect_uri: q.redirect_uri.clone(),
            user_sub,
            scope,
            nonce: q.nonce,
            code_challenge: q.code_challenge,
            created_at: now_secs(),
        },
    );

    // P1: percent-encode the response parameters so a malicious `state`
    // cannot inject headers or corrupt the redirect URL.
    let mut url = format!("{}?code={}", q.redirect_uri, pct_encode(&code));
    if let Some(st) = q.state {
        url.push_str("&state=");
        url.push_str(&pct_encode(&st));
    }
    common::siem::SecurityEvent::session_created(&q.client_id, "authorize");
    Ok(axum::response::Redirect::to(&url))
}

#[derive(Debug, Deserialize)]
pub struct TokenForm {
    pub grant_type: String,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
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
    let computed = URL_SAFE_NO_PAD.encode(h);
    // Constant-time comparison of the PKCE challenge (defense-in-depth).
    crypto::ct::ct_eq(computed.as_bytes(), challenge.as_bytes())
}

/// Authenticate the calling client from HTTP Basic or `client_secret_post`.
///
/// SECURITY (P0): mandatory on `/token`, `/introspect`, `/revoke`. The secret
/// is verified against the Argon2id hash; the comparison inside
/// `verify_client_secret` is constant-time. Returns the client_id on success.
fn authenticate_client(
    s: &AsState,
    headers: &HeaderMap,
    form_client_id: Option<&str>,
    form_client_secret: Option<&str>,
) -> Result<String, (StatusCode, Json<OAuthError>)> {
    let (client_id, client_secret) = match basic_auth_credentials(headers) {
        Some(creds) => creds,
        None => {
            let id = form_client_id
                .ok_or_else(|| {
                    err(StatusCode::UNAUTHORIZED, "invalid_client", "client authentication required")
                })?
                .to_string();
            let secret = form_client_secret
                .ok_or_else(|| {
                    err(StatusCode::UNAUTHORIZED, "invalid_client", "client_secret required")
                })?
                .to_string();
            (id, secret)
        }
    };

    let client = lock(&s.clients)
        .get(&client_id)
        .cloned()
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "invalid_client", "unknown client"))?;

    if verify_client_secret(&client_id, &client_secret, &client.client_secret_hash) {
        Ok(client_id)
    } else {
        common::siem::SecurityEvent::auth_failure(None, None, "invalid client_secret on /token");
        Err(err(StatusCode::UNAUTHORIZED, "invalid_client", "client authentication failed"))
    }
}

/// Hash a client secret with Argon2id (CNSA 2.0 KSF), domain-separated by the
/// `client_id` so identical secrets across clients produce distinct hashes.
///
/// SECURITY: Argon2id is the project-mandated password hash — no bcrypt,
/// no scrypt, no plaintext storage of client secrets.
pub fn hash_client_secret(client_id: &str, plaintext_secret: &str) -> Result<String, String> {
    // Domain-separated 16-byte salt: SHA-256("authsrv-client-secret:" || client_id).
    let mut salt_hasher = Sha256::new();
    salt_hasher.update(b"authsrv-client-secret:");
    salt_hasher.update(client_id.as_bytes());
    let salt = salt_hasher.finalize();
    let derived = crypto::kdf::stretch_password(plaintext_secret.as_bytes(), &salt[..16])?;
    Ok(hex::encode(&*derived))
}

/// Verify a plaintext client secret against its stored Argon2id hash.
///
/// SECURITY: recomputes the hash and compares it in constant time; fails
/// closed on any hashing error.
fn verify_client_secret(client_id: &str, plaintext_secret: &str, stored_hash: &str) -> bool {
    match hash_client_secret(client_id, plaintext_secret) {
        Ok(candidate) => crypto::ct::ct_eq(candidate.as_bytes(), stored_hash.as_bytes()),
        Err(e) => {
            tracing::error!("client secret verification failed (argon2id error): {e}");
            false
        }
    }
}

/// Decode `Authorization: Basic <base64(client_id:client_secret)>`.
fn basic_auth_credentials(headers: &HeaderMap) -> Option<(String, String)> {
    let raw = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let b64 = raw.strip_prefix("Basic ").or_else(|| raw.strip_prefix("basic "))?;
    let decoded = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
    let text = String::from_utf8(decoded).ok()?;
    let (id, secret) = text.split_once(':')?;
    Some((id.to_string(), secret.to_string()))
}

pub async fn token(
    State(s): State<Arc<AsState>>,
    headers: HeaderMap,
    Form(f): Form<TokenForm>,
) -> Result<Json<TokenResponse>, (StatusCode, Json<OAuthError>)> {
    // SECURITY (P0): every grant type is client-authenticated. This closes the
    // unauthenticated /refresh hole and prevents anonymous token minting.
    let authed_client = authenticate_client(&s, &headers, f.client_id.as_deref(), f.client_secret.as_deref())?;

    // SECURITY (RFC 9449 §5): the access token is DPoP-bound at ISSUANCE. The
    // client MUST present a DPoP proof on `/token`; its JWK thumbprint becomes
    // the token's `cnf.jkt`. This is not trust-on-first-use — a token stolen
    // later cannot be used at `/userinfo` because the thief cannot produce a
    // proof under the client's key. The `/token` proof carries no `ath` (no
    // access token exists yet).
    let proof = headers
        .get("DPoP")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "invalid_dpop_proof", "DPoP proof header required on /token"))?;
    let token_htu = format!("{}/token", s.cfg.issuer_base());
    let dpop_jkt = verify_dpop_proof(&s, proof, "POST", &token_htu, None)?;

    match f.grant_type.as_str() {
        "authorization_code" => {
            let code = f
                .code
                .ok_or_else(|| err(StatusCode::BAD_REQUEST, "invalid_request", "missing code"))?;
            let verifier = f
                .code_verifier
                .ok_or_else(|| err(StatusCode::BAD_REQUEST, "invalid_request", "missing verifier"))?;
            // P1: PKCE verifier length must be RFC 7636-compliant (43-128).
            if sso_protocol::pkce::validate_verifier_length(&verifier).is_err() {
                return Err(err(StatusCode::BAD_REQUEST, "invalid_grant", "code_verifier length invalid"));
            }

            let entry = lock(&s.codes)
                .remove(&code)
                .ok_or_else(|| err(StatusCode::BAD_REQUEST, "invalid_grant", "unknown code"))?;

            // SECURITY (P0): bind the code to the original client_id and
            // redirect_uri (RFC 6749 §4.1.3) — prevents cross-client code
            // substitution. PKCE alone does not close this.
            if !crypto::ct::ct_eq(entry.client_id.as_bytes(), authed_client.as_bytes()) {
                common::siem::SecurityEvent::auth_failure(
                    None,
                    None,
                    "authorization code redeemed by a different client",
                );
                return Err(err(StatusCode::BAD_REQUEST, "invalid_grant", "code was not issued to this client"));
            }
            match &f.redirect_uri {
                Some(ru) if ru == &entry.redirect_uri => {}
                _ => {
                    return Err(err(
                        StatusCode::BAD_REQUEST,
                        "invalid_grant",
                        "redirect_uri does not match the authorization request",
                    ));
                }
            }

            if !pkce_s256_matches(&verifier, &entry.code_challenge) {
                return Err(err(StatusCode::BAD_REQUEST, "invalid_grant", "PKCE mismatch"));
            }
            // P2: `<=` so a code expiring exactly now is treated as expired.
            if now_secs() - entry.created_at >= AUTH_CODE_TTL_SECS {
                return Err(err(StatusCode::BAD_REQUEST, "invalid_grant", "code expired"));
            }

            issue_tokens(
                &s,
                &entry.client_id,
                &entry.user_sub,
                &entry.scope,
                entry.nonce.clone(),
                None,
                dpop_jkt,
            )
            .map(Json)
        }
        "refresh_token" => {
            let rt = f
                .refresh_token
                .ok_or_else(|| err(StatusCode::BAD_REQUEST, "invalid_request", "missing rt"))?;

            // Single critical section: look up, validate, and rotate atomically
            // so a concurrent writer cannot invalidate the entry mid-flight
            // (P1: removes the `.unwrap()`-after-`.cloned()` panic window).
            let (family_id, user_sub, scope) = {
                let mut store = lock(&s.refresh_tokens);
                let entry = store
                    .get(&rt)
                    .cloned()
                    .ok_or_else(|| err(StatusCode::BAD_REQUEST, "invalid_grant", "unknown rt"))?;

                // SECURITY (P0): the refresh token must belong to the
                // authenticated client — no cross-client refresh.
                if !crypto::ct::ct_eq(entry.client_id.as_bytes(), authed_client.as_bytes()) {
                    common::siem::SecurityEvent::auth_failure(
                        None,
                        None,
                        "refresh token presented by a different client",
                    );
                    return Err(err(StatusCode::BAD_REQUEST, "invalid_grant", "refresh token client mismatch"));
                }

                if entry.rotated {
                    // Reuse detection — burn the entire family.
                    lock(&s.revoked_families).insert(entry.family_id.clone());
                    store.retain(|_, v| v.family_id != entry.family_id);
                    common::siem::SecurityEvent::token_revoked(&entry.family_id, "refresh token reuse");
                    return Err(err(
                        StatusCode::BAD_REQUEST,
                        "invalid_grant",
                        "refresh token reuse — family revoked",
                    ));
                }
                if lock(&s.revoked_families).contains(&entry.family_id) {
                    return Err(err(StatusCode::BAD_REQUEST, "invalid_grant", "family revoked"));
                }
                if let Some(v) = store.get_mut(&rt) {
                    v.rotated = true;
                }
                (entry.family_id, entry.user_sub, entry.scope)
            };

            issue_tokens(&s, &authed_client, &user_sub, &scope, None, Some(family_id), dpop_jkt).map(Json)
        }
        other => Err(err(StatusCode::BAD_REQUEST, "unsupported_grant_type", other)),
    }
}

/// Issue an access_token + id_token (both ML-DSA-87 signed JWTs) and a fresh
/// refresh token.
///
/// SECURITY (P0): tokens are signed JWTs, not opaque random strings. The
/// id_token carries `iss`/`sub`/`aud`/`exp`/`iat`/`nonce`/`at_hash`; the
/// access_token is an ML-DSA-87-signed JWT. `dpop_jkt` is the client's JWK
/// thumbprint from the DPoP proof presented on `/token` — the token is bound
/// to that key at issuance (RFC 9449 §5), so it is unusable if stolen.
fn issue_tokens(
    s: &AsState,
    client_id: &str,
    sub: &str,
    scope: &str,
    nonce: Option<String>,
    family: Option<String>,
    dpop_jkt: String,
) -> Result<TokenResponse, (StatusCode, Json<OAuthError>)> {
    let jti = Uuid::new_v4().to_string();
    let exp = now_secs() + ACCESS_TOKEN_TTL_SECS;
    let access = sign_access_token(s, &jti, sub, client_id, scope, exp)?;

    let id_token = sign_id_token(s, sub, client_id, nonce, &access)?;

    let rt = rand_token("rt").map_err(|e| {
        common::siem::SecurityEvent::crypto_failure(&format!("CSPRNG failure issuing refresh token: {e}"));
        err(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "entropy unavailable")
    })?;
    let family_id = family.unwrap_or_else(|| Uuid::new_v4().to_string());

    lock(&s.access_tokens).insert(
        access.clone(),
        AccessTokenMeta {
            jti,
            sub: sub.into(),
            client_id: client_id.into(),
            scope: scope.into(),
            exp,
            // Bound at issuance to the client's DPoP key (RFC 9449 §5).
            dpop_jkt,
            revoked: false,
        },
    );
    lock(&s.refresh_tokens).insert(
        rt.clone(),
        RefreshToken {
            family_id,
            client_id: client_id.into(),
            user_sub: sub.into(),
            scope: scope.into(),
            created_at: now_secs(),
            rotated: false,
        },
    );

    Ok(TokenResponse {
        access_token: access,
        token_type: "DPoP".into(),
        expires_in: ACCESS_TOKEN_TTL_SECS,
        refresh_token: rt,
        id_token,
        scope: scope.into(),
    })
}

/// Sign an ML-DSA-87 JWT from a header `typ` and an arbitrary claims value.
///
/// Produces the compact JWS `base64url(header).base64url(claims).base64url(sig)`
/// where the signature covers `header.claims` (RFC 7515).
fn sign_jwt(
    s: &AsState,
    typ: &str,
    claims: &serde_json::Value,
) -> Result<String, (StatusCode, Json<OAuthError>)> {
    let header = serde_json::json!({
        "alg": "ML-DSA-87",
        "typ": typ,
        "kid": s.signing_key.kid(),
    });
    let header_b64 = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&header)
            .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "jwt header"))?,
    );
    let claims_b64 = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(claims)
            .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "jwt claims"))?,
    );
    let signing_input = format!("{header_b64}.{claims_b64}");
    let sig = crypto::pq_sign::pq_sign_raw(&s.signing_key.signing_key, signing_input.as_bytes());
    Ok(format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig)))
}

/// Produce an ML-DSA-87-signed JWT access token.
///
/// SECURITY (P0): the access token is a signed JWT, not a random string, so a
/// resource server can verify it offline against JWKS. Mirrors the OAuth 2.0
/// JWT access-token profile (RFC 9068).
fn sign_access_token(
    s: &AsState,
    jti: &str,
    sub: &str,
    client_id: &str,
    scope: &str,
    exp: i64,
) -> Result<String, (StatusCode, Json<OAuthError>)> {
    let claims = serde_json::json!({
        "iss": s.cfg.issuer_base(),
        "sub": sub,
        "aud": client_id,
        "exp": exp,
        "iat": now_secs(),
        "jti": jti,
        "scope": scope,
    });
    sign_jwt(s, "at+jwt", &claims)
}

/// Produce an ML-DSA-87-signed OIDC id_token.
///
/// SECURITY (P0): carries `iss`, `sub`, `aud`, `exp`, `iat`, `nonce` and
/// `at_hash` (OIDC §3.1.3.6 — the left-half SHA-256 of the access token), so
/// relying parties can validate the token and bind it to the access token.
fn sign_id_token(
    s: &AsState,
    sub: &str,
    client_id: &str,
    nonce: Option<String>,
    access_token: &str,
) -> Result<String, (StatusCode, Json<OAuthError>)> {
    let now = now_secs();
    // at_hash: base64url of the left-most half of SHA-256(access_token).
    let at_digest = Sha256::digest(access_token.as_bytes());
    let at_hash = URL_SAFE_NO_PAD.encode(&at_digest[..16]);

    let mut claims = serde_json::json!({
        "iss": s.cfg.issuer_base(),
        "sub": sub,
        "aud": client_id,
        "exp": now + ACCESS_TOKEN_TTL_SECS,
        "iat": now,
        "auth_time": now,
        "jti": Uuid::new_v4().to_string(),
        "at_hash": at_hash,
    });
    if let Some(n) = nonce {
        claims["nonce"] = serde_json::Value::String(n);
    }
    sign_jwt(s, "JWT", &claims)
}

// ── DPoP proof verification (RFC 9449) ─────────────────────────────────────

/// Decoded DPoP proof header — must carry an embedded ML-DSA-87 public JWK.
#[derive(Debug, Deserialize)]
struct DpopHeader {
    typ: String,
    alg: String,
    jwk: serde_json::Value,
}

/// Decoded DPoP proof claims.
#[derive(Debug, Deserialize)]
struct DpopClaims {
    htm: String,
    htu: String,
    iat: i64,
    jti: String,
    /// Access-token hash (RFC 9449 §4.3) — present when a token is presented.
    ath: Option<String>,
}

/// Verify a DPoP proof JWT presented in the `DPoP:` header.
///
/// SECURITY (P0): the previous implementation only checked header *presence*.
/// This fully verifies the proof per RFC 9449: it parses the JWT, requires
/// `typ=dpop+jwt` and `alg=ML-DSA-87`, verifies the ML-DSA-87 signature with
/// the embedded JWK, checks `htm`/`htu` against the actual request, enforces
/// `iat` freshness, and rejects replayed `jti`s. Returns the JWK SHA-256
/// thumbprint (`jkt`).
///
/// `bound_access_token` controls `ath` (RFC 9449 §4.3 access-token hash):
/// - `Some(token)` — a proof accompanying a token at a protected resource;
///   the proof MUST carry an `ath` equal to `base64url(SHA-256(token))`.
/// - `None` — a proof on the `/token` request itself, where no access token
///   exists yet; `ath` MUST be absent.
fn verify_dpop_proof(
    s: &AsState,
    proof: &str,
    expected_htm: &str,
    expected_htu: &str,
    bound_access_token: Option<&str>,
) -> Result<String, (StatusCode, Json<OAuthError>)> {
    let invalid = |d: &str| err(StatusCode::UNAUTHORIZED, "invalid_dpop_proof", d);

    let parts: Vec<&str> = proof.split('.').collect();
    if parts.len() != 3 {
        return Err(invalid("DPoP proof must be a 3-part JWT"));
    }

    let header_bytes = URL_SAFE_NO_PAD.decode(parts[0]).map_err(|_| invalid("bad proof header"))?;
    let header: DpopHeader =
        serde_json::from_slice(&header_bytes).map_err(|_| invalid("malformed proof header"))?;
    if header.typ != "dpop+jwt" {
        return Err(invalid("proof typ must be dpop+jwt"));
    }
    // SECURITY: pin the algorithm — prevents algorithm-confusion downgrade.
    if header.alg != "ML-DSA-87" {
        return Err(invalid("proof alg must be ML-DSA-87"));
    }

    // Parse the embedded ML-DSA-87 public JWK and decode the verifying key.
    let jwk_kty = header.jwk.get("kty").and_then(|v| v.as_str()).unwrap_or("");
    let jwk_alg = header.jwk.get("alg").and_then(|v| v.as_str()).unwrap_or("");
    if jwk_kty != "ML-DSA" || jwk_alg != "ML-DSA-87" {
        return Err(invalid("embedded JWK must be an ML-DSA-87 key"));
    }
    let pub_b64 = header
        .jwk
        .get("pub")
        .and_then(|v| v.as_str())
        .ok_or_else(|| invalid("JWK missing pub key material"))?;
    let pub_bytes = URL_SAFE_NO_PAD
        .decode(pub_b64)
        .map_err(|_| invalid("JWK pub is not Base64URL"))?;

    // Verify the proof signature over `header.claims`.
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig_bytes = URL_SAFE_NO_PAD.decode(parts[2]).map_err(|_| invalid("bad proof signature"))?;
    if !crypto::pq_sign::pq_verify_raw_from_bytes(&pub_bytes, signing_input.as_bytes(), &sig_bytes) {
        common::siem::SecurityEvent::auth_failure(None, None, "DPoP proof signature invalid");
        return Err(invalid("DPoP proof signature verification failed"));
    }

    // Validate the claims.
    let claims_bytes = URL_SAFE_NO_PAD.decode(parts[1]).map_err(|_| invalid("bad proof claims"))?;
    let claims: DpopClaims =
        serde_json::from_slice(&claims_bytes).map_err(|_| invalid("malformed proof claims"))?;

    if !crypto::ct::ct_eq(claims.htm.as_bytes(), expected_htm.as_bytes()) {
        return Err(invalid("DPoP htm does not match the request method"));
    }
    if !crypto::ct::ct_eq(claims.htu.as_bytes(), expected_htu.as_bytes()) {
        return Err(invalid("DPoP htu does not match the request URI"));
    }
    let now = now_secs();
    if (now - claims.iat).abs() > DPOP_PROOF_MAX_AGE_SECS {
        return Err(invalid("DPoP proof iat is stale or future-dated"));
    }

    // Replay rejection: a DPoP jti may be used only once within its window.
    {
        let mut seen = lock(&s.dpop_jti_seen);
        seen.retain(|_, exp| *exp > now);
        if seen.contains_key(&claims.jti) {
            common::siem::SecurityEvent::auth_failure(None, None, "DPoP proof jti replay");
            return Err(invalid("DPoP proof jti has already been used"));
        }
        seen.insert(claims.jti.clone(), now + DPOP_PROOF_MAX_AGE_SECS);
    }

    // `ath` binds the proof to a specific access token (RFC 9449 §4.3).
    match bound_access_token {
        Some(token) => {
            let expected_ath = URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()));
            match claims.ath {
                Some(ath) if crypto::ct::ct_eq(ath.as_bytes(), expected_ath.as_bytes()) => {}
                _ => return Err(invalid("DPoP ath does not match the access token")),
            }
        }
        None => {
            // A proof on the /token request must NOT carry an ath — there is
            // no access token yet. Rejecting a stray ath keeps the two proof
            // shapes unambiguous.
            if claims.ath.is_some() {
                return Err(invalid("DPoP proof on /token must not carry ath"));
            }
        }
    }

    // The jkt is the SHA-256 thumbprint of the public key material.
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(&pub_bytes)))
}

pub async fn userinfo(
    State(s): State<Arc<AsState>>,
    headers: HeaderMap,
) -> Result<Json<UserClaims>, (StatusCode, Json<OAuthError>)> {
    // P2: require the DPoP scheme; reject plain Bearer. DPoP is the advertised
    // proof-of-possession mechanism, so a bare bearer token is not accepted.
    let auth = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let token = auth
        .strip_prefix("DPoP ")
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "invalid_token", "DPoP-scheme authorization required"))?;

    // SECURITY (P0): the DPoP proof JWT is fully verified, not merely present.
    let proof = headers
        .get("DPoP")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "invalid_dpop_proof", "DPoP proof header required"))?;
    let htu = format!("{}/userinfo", s.cfg.issuer_base());
    let jkt = verify_dpop_proof(&s, proof, "GET", &htu, Some(token))?;

    let meta = lock(&s.access_tokens)
        .get(token)
        .cloned()
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "invalid_token", "unknown token"))?;
    // P2: `<=` so a token expiring exactly now is treated as expired.
    if meta.revoked || meta.exp <= now_secs() {
        return Err(err(StatusCode::UNAUTHORIZED, "invalid_token", "expired/revoked"));
    }

    // SECURITY (P0): the token was DPoP-bound at issuance (`/token` recorded
    // the client's JWK thumbprint as `dpop_jkt`). The proof on this request
    // must come from that exact key — a stolen token cannot be used because
    // the attacker cannot produce a proof under the legitimate client's key.
    // No trust-on-first-use: an empty `dpop_jkt` means the token was issued
    // without a DPoP proof and is rejected outright.
    if meta.dpop_jkt.is_empty() || !crypto::ct::ct_eq(meta.dpop_jkt.as_bytes(), jkt.as_bytes()) {
        common::siem::SecurityEvent::auth_failure(None, None, "DPoP key mismatch on /userinfo");
        return Err(err(StatusCode::UNAUTHORIZED, "invalid_token", "DPoP key does not match token binding"));
    }

    // P2: an unknown subject means a referential-integrity violation — fail
    // closed rather than returning a synthetic "Unknown" user.
    let user = lock(&s.user_db)
        .get(&meta.sub)
        .cloned()
        .ok_or_else(|| err(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "subject not found"))?;
    Ok(Json(user))
}

#[derive(Debug, Deserialize)]
pub struct IntrospectForm {
    pub token: String,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct IntrospectResponse {
    pub active: bool,
    pub sub: Option<String>,
    pub client_id: Option<String>,
    pub scope: Option<String>,
    pub exp: Option<i64>,
}

/// RFC 7662 token introspection.
///
/// SECURITY (P0): RFC 7662 §2.1 mandates caller authentication. Without it the
/// endpoint is a token-validity oracle. The caller must authenticate as a
/// registered client.
pub async fn introspect(
    State(s): State<Arc<AsState>>,
    headers: HeaderMap,
    Form(f): Form<IntrospectForm>,
) -> Result<Json<IntrospectResponse>, (StatusCode, Json<OAuthError>)> {
    authenticate_client(&s, &headers, f.client_id.as_deref(), f.client_secret.as_deref())?;

    let inactive = IntrospectResponse {
        active: false,
        sub: None,
        client_id: None,
        scope: None,
        exp: None,
    };
    let g = lock(&s.access_tokens);
    if let Some(m) = g.get(&f.token) {
        if !m.revoked && m.exp > now_secs() {
            return Ok(Json(IntrospectResponse {
                active: true,
                sub: Some(m.sub.clone()),
                client_id: Some(m.client_id.clone()),
                scope: Some(m.scope.clone()),
                exp: Some(m.exp),
            }));
        }
    }
    Ok(Json(inactive))
}

#[derive(Debug, Deserialize)]
pub struct RevokeForm {
    pub token: String,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
}

/// RFC 7009 token revocation.
///
/// SECURITY (P0): the caller must authenticate as a registered client and may
/// only revoke tokens that belong to it — this closes the anonymous mass-revoke
/// denial-of-service.
pub async fn revoke(
    State(s): State<Arc<AsState>>,
    headers: HeaderMap,
    Form(f): Form<RevokeForm>,
) -> Result<StatusCode, (StatusCode, Json<OAuthError>)> {
    let client_id = authenticate_client(&s, &headers, f.client_id.as_deref(), f.client_secret.as_deref())?;

    let mut revoked_something = false;
    if let Some(m) = lock(&s.access_tokens).get_mut(&f.token) {
        if crypto::ct::ct_eq(m.client_id.as_bytes(), client_id.as_bytes()) {
            m.revoked = true;
            revoked_something = true;
        }
    }
    if let Some(rt) = lock(&s.refresh_tokens).get(&f.token).cloned() {
        if crypto::ct::ct_eq(rt.client_id.as_bytes(), client_id.as_bytes()) {
            lock(&s.revoked_families).insert(rt.family_id);
            revoked_something = true;
        }
    }
    if revoked_something {
        common::siem::SecurityEvent::token_revoked(&client_id, "RFC 7009 revocation");
    }
    // RFC 7009 §2.2: respond 200 regardless of whether the token was known, so
    // the endpoint is not a token-existence oracle.
    Ok(StatusCode::OK)
}

#[derive(Debug, Deserialize)]
pub struct EndSessionQuery {
    pub post_logout_redirect_uri: Option<String>,
    pub client_id: Option<String>,
    pub state: Option<String>,
}

/// RP-initiated logout.
///
/// SECURITY (P0): `post_logout_redirect_uri` is validated against the named
/// client's registered allowlist before any redirect — this closes the open
/// redirect. An unregistered URI yields a plain 200, never a redirect.
pub async fn end_session(
    State(s): State<Arc<AsState>>,
    Query(q): Query<EndSessionQuery>,
) -> Response {
    let Some(target) = q.post_logout_redirect_uri else {
        return StatusCode::OK.into_response();
    };

    // The redirect target MUST be on a registered client's allowlist.
    let allowed = q
        .client_id
        .as_deref()
        .and_then(|cid| lock(&s.clients).get(cid).cloned())
        .map(|c| c.post_logout_redirect_uris.iter().any(|u| u == &target))
        .unwrap_or(false);

    if !allowed {
        common::siem::SecurityEvent::auth_failure(
            None,
            None,
            "end_session post_logout_redirect_uri not registered",
        );
        return (
            StatusCode::BAD_REQUEST,
            Json(OAuthError {
                error: "invalid_request".into(),
                error_description: "post_logout_redirect_uri is not registered for this client".into(),
            }),
        )
            .into_response();
    }

    // P1: percent-encode `state` so it cannot inject headers or corrupt the URL.
    let mut url = target;
    if let Some(st) = q.state {
        url.push_str(if url.contains('?') { "&" } else { "?" });
        url.push_str("state=");
        url.push_str(&pct_encode(&st));
    }
    axum::response::Redirect::to(&url).into_response()
}

// ── Test-only helpers ──────────────────────────────────────────────────────
//
// SECURITY (P0/P2): these constructors embed test fixtures (a fixed client and
// seed user) and MUST NOT be reachable in a release binary. They are gated
// behind `cfg(test)` and the non-default `test-util` feature so they are
// compiled out of the production build.

/// A test client id used only by the gated test helpers.
#[cfg(any(test, feature = "test-util"))]
pub const TEST_CLIENT_ID: &str = "test-client";

/// A test client secret used only by the gated test helpers.
#[cfg(any(test, feature = "test-util"))]
pub const TEST_CLIENT_SECRET: &str = "test-client-secret-value-0123456789";

/// A test subject used only by the gated test helpers.
#[cfg(any(test, feature = "test-util"))]
pub const TEST_SUBJECT: &str = "test-subject";

/// A test login-session id used only by the gated test helpers.
#[cfg(any(test, feature = "test-util"))]
pub const TEST_SESSION_ID: &str = "test-session-id";

/// Construct a state populated with a single test client, a seed user, and a
/// valid login session — for tests and local development only.
#[cfg(any(test, feature = "test-util"))]
pub fn test_state() -> Arc<AsState> {
    let s = Arc::new(AsState::new(ServerConfig::default()).expect("OS CSPRNG unavailable in test"));
    let secret_hash =
        hash_client_secret(TEST_CLIENT_ID, TEST_CLIENT_SECRET).expect("test client secret hashing");
    lock(&s.clients).insert(
        TEST_CLIENT_ID.into(),
        ClientRegistration {
            client_id: TEST_CLIENT_ID.into(),
            client_secret_hash: secret_hash,
            redirect_uris: vec!["https://rp.test/cb".into()],
            post_logout_redirect_uris: vec!["https://rp.test/logout".into()],
            allowed_scopes: vec!["openid".into(), "profile".into()],
        },
    );
    lock(&s.user_db).insert(
        TEST_SUBJECT.into(),
        UserClaims {
            sub: TEST_SUBJECT.into(),
            name: "Test User".into(),
            email: "test@milnet".into(),
        },
    );
    lock(&s.sessions).insert(
        TEST_SESSION_ID.into(),
        LoginSession {
            user_sub: TEST_SUBJECT.into(),
            expires_at: now_secs() + 3600,
        },
    );
    s
}

/// Generate a PKCE (verifier, challenge) pair — test/dev helper only.
///
/// The verifier is 43 Base64URL characters (32 random bytes), satisfying the
/// RFC 7636 §4.1 length requirement.
#[cfg(any(test, feature = "test-util"))]
pub fn pkce_pair() -> (String, String) {
    let mut buf = [0u8; 32];
    fill_random(&mut buf).expect("OS CSPRNG unavailable in test");
    let verifier = URL_SAFE_NO_PAD.encode(buf);
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    (verifier, challenge)
}
