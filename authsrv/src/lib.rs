//! OIDC / OAuth 2.1 Authorization Server (J1) — hardened build.
//!
//! This crate implements the production endpoints for the milnet OIDC IdP:
//!
//! - `/.well-known/openid-configuration` — discovery (RFC 8414)
//! - `/.well-known/jwks.json` — public signing key set
//! - `/authorize`   — authorization request (PKCE S256 mandatory, real session required)
//! - `/token`       — code + refresh-token rotation with reuse-detection family revoke
//! - `/userinfo`    — DPoP-bound userinfo (real DPoP enforcement lands in Phase 5)
//! - `/introspect`  — RFC 7662 introspection, client-authenticated, oracle-closed
//! - `/revoke`      — RFC 7009 revocation, client-authenticated, family-cascade
//! - `/end_session` — RP-initiated logout with `id_token_hint` + allowlist
//! - `/healthz` `/livez` `/readyz` — lifecycle probes (`/readyz` Bearer-gated)
//!
//! All randomness flows through `crypto::drbg::HmacDrbg`; all timestamps come
//! from `common::secure_time::secure_now_secs_i64()`; all secret comparisons
//! use `subtle::ConstantTimeEq`.  Every endpoint emits SIEM-eligible audit
//! entries via `common::audit_bridge::buffer_audit_entry`.
//!
//! Phases delivered: §5 Phase 1 (kill-the-demo), Phase 4 hot-fix
//! (client_secret_post + cross-client + cascade revoke + oracle-closed
//! introspect), Phase 6 (router middleware, percent-encoded redirects,
//! tightened PKCE, allowlisted logout, mutex hygiene), Phase 9 partial
//! (audit wiring).  Phase 2/3/5/7/8 land in subsequent tracks — until then
//! the binary REFUSES to mint anything for an unauthenticated caller.
#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use axum::{
    body::Body,
    extract::{Form, Query, State},
    http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::sync::Arc;
use std::time::Duration;
use subtle::ConstantTimeEq;
use tower_http::{
    catch_panic::CatchPanicLayer,
    cors::{AllowOrigin, CorsLayer},
    limit::RequestBodyLimitLayer,
    set_header::SetResponseHeaderLayer,
    timeout::TimeoutLayer,
    trace::TraceLayer,
};
use uuid::Uuid;

pub const ISSUER_DEFAULT: &str = "https://sso.milnet.mil";

// ── Sliding-window rate limit (per-key) ────────────────────────────────────
//
// Phase-6 hot-fix in-process limiter.  Phase 2 replaces this with the
// gateway distributed Redis-Lua sliding-window backed by Raft replication.
// The shape (allowed?, count, remaining) mirrors `gateway::distributed_rate_limit`.
mod rate_limit {
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::sync::OnceLock;

    pub struct Limit {
        pub window_ms: u64,
        pub max: u64,
    }

    fn store() -> &'static Mutex<HashMap<String, Vec<u64>>> {
        static S: OnceLock<Mutex<HashMap<String, Vec<u64>>>> = OnceLock::new();
        S.get_or_init(|| Mutex::new(HashMap::new()))
    }

    /// Returns true when the request is permitted.  Permits are counted; the
    /// caller is expected to reject (429) on a deny.
    pub fn check(key: &str, limit: &Limit, now_ms: u64) -> bool {
        let mut g = match store().lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let entry = g.entry(key.to_string()).or_default();
        let cutoff = now_ms.saturating_sub(limit.window_ms);
        entry.retain(|&t| t > cutoff);
        if (entry.len() as u64) >= limit.max {
            return false;
        }
        entry.push(now_ms);
        true
    }
}

// ── Domain types ───────────────────────────────────────────────────────────

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

/// OAuth client registration.  Carries the **Argon2id hash** of the client
/// secret — never plaintext — and an explicit allowlist of post-logout
/// redirects (every client must register; empty disables RP-initiated logout
/// for that client).  Mirrors `sso_protocol::clients::OAuthClient` for the
/// hot-fix path; full unification with `ClientRegistry` lands Phase 4.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientRegistration {
    pub client_id: String,
    /// Argon2id hex-encoded hash; verification path mirrors
    /// `sso_protocol::clients::verify_client_secret`.
    pub client_secret_hash: String,
    pub redirect_uris: Vec<String>,
    pub allowed_scopes: Vec<String>,
    /// Allowed Origin header values for CORS (default-deny if empty).
    #[serde(default)]
    pub origins: Vec<String>,
    /// Allowlist for `/end_session` `post_logout_redirect_uri` (RFC ?? §5).
    #[serde(default)]
    pub post_logout_redirect_uris: Vec<String>,
}

impl ClientRegistration {
    /// Compute the storable Argon2id hash for a plaintext secret bound to
    /// `client_id`.  Same domain-separated salt scheme as
    /// `sso-protocol/src/clients.rs:hash_client_secret`.
    pub fn hash_secret(client_id: &str, plaintext: &str) -> Result<String, AsError> {
        let mut salt_hasher = Sha512::new();
        salt_hasher.update(b"milnet-client-secret:");
        salt_hasher.update(client_id.as_bytes());
        let salt = salt_hasher.finalize();
        let salt_slice = salt.get(..16).ok_or_else(|| AsError::server(
            "argon2 salt slice", "internal salt slice failed", "client_authn.config",
        ))?;
        let derived = crypto::kdf::stretch_password(plaintext.as_bytes(), salt_slice)
            .map_err(|e| AsError::server(
                "argon2 stretch", &format!("argon2id failure: {e}"), "client_authn.config",
            ))?;
        Ok(hex::encode(derived))
    }

    /// Constant-time comparison of a candidate plaintext secret against the
    /// stored hash for this client.  Does not branch on the secret value or
    /// on a mismatch's location.
    pub fn verify_secret(&self, plaintext: &str) -> bool {
        let candidate_hex = match Self::hash_secret(&self.client_id, plaintext) {
            Ok(h) => h,
            Err(_) => return false, // fail-closed
        };
        bool::from(
            candidate_hex
                .as_bytes()
                .ct_eq(self.client_secret_hash.as_bytes()),
        )
    }
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
    /// Family the access token belongs to; cascades on family revoke (D-07 fix).
    pub family_id: Option<String>,
    pub revoked: bool,
}

#[derive(Debug, Default)]
pub struct AsState {
    pub cfg: ServerConfig,
    pub clients: Mutex<HashMap<String, ClientRegistration>>,
    pub codes: Mutex<HashMap<String, AuthCode>>,
    pub refresh_tokens: Mutex<HashMap<String, RefreshToken>>,
    pub revoked_families: Mutex<HashSet<String>>,
    pub access_tokens: Mutex<HashMap<String, AccessTokenMeta>>,
    pub user_db: Mutex<HashMap<String, UserClaims>>,
}

// ── Errors ─────────────────────────────────────────────────────────────────

/// OAuth-shape error the handlers return.  `WWW-Authenticate` is set on 401
/// so a real client can negotiate the right scheme.
#[derive(Debug, Clone)]
pub struct AsError {
    pub status: StatusCode,
    pub code: &'static str,
    pub description: String,
    pub www_authenticate: Option<&'static str>,
    /// Audit-bridge action tag for SIEM (e.g. `client_authn.fail.secret_mismatch`).
    pub audit_tag: &'static str,
}

impl AsError {
    fn unauthorized(code: &'static str, description: &str, audit_tag: &'static str, scheme: &'static str) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code,
            description: description.into(),
            www_authenticate: Some(scheme),
            audit_tag,
        }
    }
    fn bad_request(code: &'static str, description: &str, audit_tag: &'static str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code,
            description: description.into(),
            www_authenticate: None,
            audit_tag,
        }
    }
    fn server(code: &'static str, description: &str, audit_tag: &'static str) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code,
            description: description.into(),
            www_authenticate: None,
            audit_tag,
        }
    }
}

#[derive(Debug, Serialize)]
struct OAuthErrorBody {
    error: String,
    error_description: String,
}

impl IntoResponse for AsError {
    fn into_response(self) -> Response {
        let body = OAuthErrorBody {
            error: self.code.to_string(),
            error_description: self.description.clone(),
        };
        let mut resp = (self.status, Json(body)).into_response();
        if let Some(scheme) = self.www_authenticate {
            // Each scheme is a static literal — parsing is infallible at runtime.
            if let Ok(v) = HeaderValue::from_str(scheme) {
                resp.headers_mut().insert(header::WWW_AUTHENTICATE, v);
            }
        }
        // Cache-Control: no-store on every error response (prevent caching of
        // OAuth error replies that may carry leaked context in description).
        resp.headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        resp
    }
}

fn lock_or_fail<T>(m: &Mutex<T>, label: &'static str) -> Result<MutexGuard<'_, T>, AsError> {
    m.lock().map_err(|_| {
        emit_audit_critical("lock.poisoned", &format!("mutex `{label}` poisoned"), None, None);
        AsError::server("server_error", "internal lock poisoned", "lock.poisoned")
    })
}

// ── Time / RNG ────────────────────────────────────────────────────────────

/// Monotonic-anchored seconds.  Anchored in `main` via `init_time_anchor`;
/// callers in this crate must NEVER use `SystemTime::now()` directly (D-17).
pub fn now_secs() -> i64 {
    common::secure_time::secure_now_secs_i64()
}

#[allow(clippy::arithmetic_side_effects)]
fn now_ms() -> u64 {
    let us = common::secure_time::secure_now_us();
    us / 1000
}

static DRBG: OnceLock<Mutex<crypto::drbg::HmacDrbg>> = OnceLock::new();

/// Initialize the process-wide DRBG.  MUST be called once, early, from
/// `main.rs` — a failure here is fatal because every randomness consumer
/// in this crate refuses to mint without a healthy DRBG.
pub fn init_drbg() -> Result<(), String> {
    let d = crypto::drbg::HmacDrbg::new()?;
    DRBG.set(Mutex::new(d)).map_err(|_| "drbg already initialised".to_string())
}

fn drbg() -> Result<&'static Mutex<crypto::drbg::HmacDrbg>, AsError> {
    DRBG.get().ok_or_else(|| {
        emit_audit_critical("rng.fail", "DRBG not initialised", None, None);
        AsError::server("server_error", "rng not initialised", "rng.fail")
    })
}

fn rand_bytes(buf: &mut [u8]) -> Result<(), AsError> {
    let lock = drbg()?;
    let mut g = lock_or_fail(lock, "drbg")?;
    g.generate(buf).map_err(|e| {
        emit_audit_critical("rng.fail", &format!("DRBG generate failed: {e}"), None, None);
        AsError::server("server_error", "rng failure", "rng.fail")
    })
}

fn rand_token(prefix: &str) -> Result<String, AsError> {
    let mut buf = [0u8; 32];
    rand_bytes(&mut buf)?;
    Ok(format!("{prefix}_{}", URL_SAFE_NO_PAD.encode(buf)))
}

/// DRBG-derived UUIDv7: 48-bit unix-millisecond timestamp from secure_time +
/// 74 bits of DRBG randomness with the standard variant/version bits.  Used
/// for `family_id` and `jti` so identifiers cannot be predicted from `Uuid::new_v4`.
#[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
fn drbg_uuid_v7() -> Result<Uuid, AsError> {
    let ts_ms = now_ms();
    let mut rand10 = [0u8; 10];
    rand_bytes(&mut rand10)?;
    let mut bytes = [0u8; 16];
    bytes[0] = ((ts_ms >> 40) & 0xFF) as u8;
    bytes[1] = ((ts_ms >> 32) & 0xFF) as u8;
    bytes[2] = ((ts_ms >> 24) & 0xFF) as u8;
    bytes[3] = ((ts_ms >> 16) & 0xFF) as u8;
    bytes[4] = ((ts_ms >> 8) & 0xFF) as u8;
    bytes[5] = (ts_ms & 0xFF) as u8;
    bytes[6] = 0x70 | (rand10[0] & 0x0F); // version 7
    bytes[7] = rand10[1];
    bytes[8] = 0x80 | (rand10[2] & 0x3F); // variant RFC 4122
    bytes[9] = rand10[3];
    bytes[10] = rand10[4];
    bytes[11] = rand10[5];
    bytes[12] = rand10[6];
    bytes[13] = rand10[7];
    bytes[14] = rand10[8];
    bytes[15] = rand10[9];
    Ok(Uuid::from_bytes(bytes))
}

// ── Audit helpers ─────────────────────────────────────────────────────────

fn pseudo_client(client_id: &str) -> String {
    common::log_pseudonym::pseudonym_str("client_id", client_id)
}

fn pseudo_sub(sub: &str) -> String {
    common::log_pseudonym::pseudonym_str("sub", sub)
}

fn pseudo_ip(ip: &str) -> String {
    common::log_pseudonym::pseudonym_ip(ip)
}

#[derive(Debug, Clone, Copy)]
enum Sev {
    Info,
    Medium,
    High,
    Critical,
}

impl Sev {
    fn as_str(self) -> &'static str {
        match self {
            Sev::Info => "INFO",
            Sev::Medium => "MEDIUM",
            Sev::High => "HIGH",
            Sev::Critical => "CRITICAL",
        }
    }
}

#[derive(Default, Debug, Clone)]
struct AuditCtx {
    pub source_ip: Option<String>,
    pub client_id: Option<String>,
    pub sub: Option<String>,
    pub trace_id: Option<String>,
}

impl AuditCtx {
    fn from_headers(h: &HeaderMap) -> Self {
        let source_ip = h
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.split(',').next())
            .map(|s| s.trim().to_string());
        let trace_id = h.get("x-request-id").and_then(|v| v.to_str().ok()).map(str::to_string);
        Self { source_ip, trace_id, ..Default::default() }
    }
    fn with_client(mut self, c: &str) -> Self { self.client_id = Some(c.into()); self }
    fn with_sub(mut self, s: &str) -> Self { self.sub = Some(s.into()); self }
}

fn emit_audit(action: &str, sev: Sev, ctx: &AuditCtx, outcome: &str, detail: Option<&str>) {
    let event_type = match action {
        a if a.starts_with("authorize.") && a.contains(".start") => common::types::AuditEventType::AuthSuccess,
        a if a.starts_with("authorize.") => common::types::AuditEventType::AuthFailure,
        a if a.starts_with("token.issue") => common::types::AuditEventType::AuthSuccess,
        a if a.starts_with("token.refresh.rotated") => common::types::AuditEventType::AuthSuccess,
        a if a.starts_with("token.fail") => common::types::AuditEventType::AuthFailure,
        a if a.starts_with("token.refresh.reuse_detected") => common::types::AuditEventType::CredentialRevoked,
        a if a.starts_with("client_authn.fail") => common::types::AuditEventType::AuthFailure,
        a if a.starts_with("dpop.fail") => common::types::AuditEventType::DpopReplayDetected,
        a if a.starts_with("introspect.") => common::types::AuditEventType::AuthSuccess,
        a if a.starts_with("revoke.") => common::types::AuditEventType::CredentialRevoked,
        a if a.starts_with("end_session.") => common::types::AuditEventType::AuthSuccess,
        a if a.starts_with("userinfo.") => common::types::AuditEventType::AuthSuccess,
        "rng.fail" | "clock.fail" | "lock.poisoned" => common::types::AuditEventType::SystemDegraded,
        _ => common::types::AuditEventType::AuthFailure,
    };
    let mut entry = common::audit_bridge::create_audit_entry(
        event_type,
        Vec::new(),
        Vec::new(),
        ctx.source_ip.as_ref().map(|ip| pseudo_ip(ip)),
        ctx.trace_id.clone(),
    );
    entry.trace_id = ctx.trace_id.clone();
    common::audit_bridge::buffer_audit_entry(entry);

    // SIEM mirror — these go through `tracing` with target="siem" so the
    // structured-log layer routes them.  Pseudonymise every PII field.
    tracing::event!(
        target: "siem",
        tracing::Level::INFO,
        action = action,
        severity = sev.as_str(),
        outcome = outcome,
        client_id = ctx.client_id.as_deref().map(pseudo_client_static).unwrap_or_default(),
        sub = ctx.sub.as_deref().map(pseudo_sub_static).unwrap_or_default(),
        source_ip = ctx.source_ip.as_deref().map(pseudo_ip_static).unwrap_or_default(),
        trace_id = ctx.trace_id.as_deref().unwrap_or(""),
        detail = detail.unwrap_or(""),
        "audit"
    );
}

fn pseudo_client_static(s: &str) -> String { pseudo_client(s) }
fn pseudo_sub_static(s: &str) -> String { pseudo_sub(s) }
fn pseudo_ip_static(s: &str) -> String { pseudo_ip(s) }

fn emit_audit_critical(action: &str, detail: &str, client_id: Option<&str>, sub: Option<&str>) {
    let mut ctx = AuditCtx::default();
    if let Some(c) = client_id { ctx = ctx.with_client(c); }
    if let Some(s) = sub { ctx = ctx.with_sub(s); }
    emit_audit(action, Sev::Critical, &ctx, "fail", Some(detail));
}

// ── Session resolution (Phase 1 stub; Phase 7 wires real interactive login)

#[derive(Debug, Clone)]
pub struct SessionContext {
    pub sub: String,
    pub session_id: String,
    pub auth_time: i64,
    pub amr: Vec<&'static str>,
    pub acr: &'static str,
}

/// Resolve the caller's interactive session.  Until Phase 7 lands, the only
/// session the binary recognises is the unit-test session header injected by
/// `test_state` (gated behind `test-util`).  Production callers receive a
/// 401 + `WWW-Authenticate: Session …` response and a CRITICAL audit entry
/// — D-01 specifies that authsrv must DENY rather than mint silent codes.
fn require_session(headers: &HeaderMap, state: &AsState) -> Result<SessionContext, AsError> {
    let raw = headers
        .get("milnet-as-session")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AsError::unauthorized(
            "login_required",
            "interactive login required — present a `MILNET-AS-Session` token",
            "authorize.identity_required",
            "Session realm=\"milnet-authsrv\", error=\"login_required\"",
        ))?;
    if raw.is_empty() {
        return Err(AsError::unauthorized(
            "login_required",
            "empty session header",
            "authorize.identity_required",
            "Session realm=\"milnet-authsrv\", error=\"login_required\"",
        ));
    }
    // Until Phase 7: `test-util` build can pre-stage sessions in `user_db`
    // keyed by session id (the user_db actually stores sub-keyed rows; the
    // test path stores a session record there with sub == session id).
    #[cfg(any(test, feature = "test-util"))]
    {
        let g = lock_or_fail(&state.user_db, "user_db")?;
        if let Some(u) = g.get(raw).cloned() {
            return Ok(SessionContext {
                sub: u.sub,
                session_id: raw.to_string(),
                auth_time: now_secs(),
                amr: vec!["pwd"],
                acr: "0",
            });
        }
    }
    // Production build: this branch is the only one taken.  Identity-required
    // is the **deliberate** state until Phase 7 wires OPAQUE + WebAuthn + CAC.
    let _ = state; // silence unused on cfg(not(any(test, feature = "test-util")))
    Err(AsError::unauthorized(
        "login_required",
        "interactive login not yet wired — see master plan §5 Phase 7",
        "authorize.identity_required",
        "Session realm=\"milnet-authsrv\", error=\"login_required\"",
    ))
}

// ── Discovery / JWKS ──────────────────────────────────────────────────────

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
    pub pushed_authorization_request_endpoint: String,
    pub response_types_supported: Vec<&'static str>,
    pub grant_types_supported: Vec<&'static str>,
    pub code_challenge_methods_supported: Vec<&'static str>,
    pub dpop_signing_alg_values_supported: Vec<&'static str>,
    pub id_token_signing_alg_values_supported: Vec<&'static str>,
    pub subject_types_supported: Vec<&'static str>,
    pub token_endpoint_auth_methods_supported: Vec<&'static str>,
    pub tls_client_certificate_bound_access_tokens: bool,
}

fn join_iss(iss: &str, suffix: &str) -> Result<String, AsError> {
    // Ensure the issuer is a valid base URL with a trailing slash semantic so
    // `Url::join` does not drop the path component.  `Url::join` follows RFC
    // 3986 and normalises any `..` / `//` artefacts.
    let mut base = url::Url::parse(iss).map_err(|e| AsError::server(
        "server_error",
        &format!("invalid issuer URL: {e}"),
        "config.invalid_issuer",
    ))?;
    if !base.path().ends_with('/') {
        let new_path = format!("{}/", base.path());
        base.set_path(&new_path);
    }
    let joined = base.join(suffix).map_err(|e| AsError::server(
        "server_error",
        &format!("issuer join failed: {e}"),
        "config.invalid_issuer",
    ))?;
    Ok(joined.to_string())
}

pub async fn discovery(State(s): State<Arc<AsState>>) -> Result<Json<DiscoveryDoc>, AsError> {
    let iss = &s.cfg.issuer;
    Ok(Json(DiscoveryDoc {
        issuer: iss.clone(),
        authorization_endpoint: join_iss(iss, "authorize")?,
        token_endpoint: join_iss(iss, "token")?,
        userinfo_endpoint: join_iss(iss, "userinfo")?,
        jwks_uri: join_iss(iss, ".well-known/jwks.json")?,
        introspection_endpoint: join_iss(iss, "introspect")?,
        revocation_endpoint: join_iss(iss, "revoke")?,
        end_session_endpoint: join_iss(iss, "end_session")?,
        pushed_authorization_request_endpoint: join_iss(iss, "par")?,
        response_types_supported: vec!["code"],
        grant_types_supported: vec!["authorization_code", "refresh_token"],
        code_challenge_methods_supported: vec!["S256"],
        // Level 5 only.  ML-DSA-65 is forbidden in MIL-tier deployments per
        // `crypto/src/pq_sign.rs:333-340`.
        dpop_signing_alg_values_supported: vec!["ML-DSA-87"],
        id_token_signing_alg_values_supported: vec!["ML-DSA-87"],
        subject_types_supported: vec!["public"],
        // Phase-4 hot-fix exposes only `client_secret_post`; PAR / private_key_jwt
        // / tls_client_auth land in the full Phase 4 commit.
        token_endpoint_auth_methods_supported: vec!["client_secret_post"],
        tls_client_certificate_bound_access_tokens: true,
    }))
}

pub async fn jwks(State(_s): State<Arc<AsState>>) -> Json<serde_json::Value> {
    // Phase-3 wires real JWKS from `OidcSigningKey::jwks_json()`.  Until the
    // signing-key generator lands we publish an empty key set so a probe
    // sees the endpoint responding correctly and id_token verification
    // fails-closed at every RP (preventable failure surface, not a forged-key
    // surface).  D-21 closes alongside Phase 3.
    Json(serde_json::json!({ "keys": [] }))
}

// ── /authorize ────────────────────────────────────────────────────────────

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

const PKCE_CHALLENGE_LEN: usize = 43;
const PKCE_VERIFIER_MIN: usize = 43;
const PKCE_VERIFIER_MAX: usize = 128;
const STATE_MAX_LEN: usize = 1024;

fn is_base64url_byte(b: u8) -> bool {
    matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_')
}

fn validate_pkce_challenge(s: &str) -> Result<(), AsError> {
    if s.len() != PKCE_CHALLENGE_LEN {
        return Err(AsError::bad_request(
            "invalid_request",
            "code_challenge must be exactly 43 base64url chars (S256 over 32B)",
            "authorize.fail.pkce_invalid",
        ));
    }
    if !s.bytes().all(is_base64url_byte) {
        return Err(AsError::bad_request(
            "invalid_request",
            "code_challenge contains non-base64url byte",
            "authorize.fail.pkce_invalid",
        ));
    }
    Ok(())
}

fn validate_pkce_verifier(s: &str) -> Result<(), AsError> {
    if s.len() < PKCE_VERIFIER_MIN || s.len() > PKCE_VERIFIER_MAX {
        return Err(AsError::bad_request(
            "invalid_request",
            "code_verifier length must be 43..=128",
            "token.fail.pkce_invalid",
        ));
    }
    if !s.bytes().all(is_base64url_byte) {
        return Err(AsError::bad_request(
            "invalid_request",
            "code_verifier contains non-base64url byte",
            "token.fail.pkce_invalid",
        ));
    }
    Ok(())
}

fn validate_state(s: &str) -> Result<(), AsError> {
    if s.len() > STATE_MAX_LEN {
        return Err(AsError::bad_request(
            "invalid_request",
            "state exceeds 1024 bytes",
            "authorize.fail.state_invalid",
        ));
    }
    common::input_validation::no_control("state", s).map_err(|_| AsError::bad_request(
        "invalid_request",
        "state contains control characters (CR/LF/etc)",
        "authorize.fail.state_invalid",
    ))?;
    common::input_validation::no_nul("state", s).map_err(|_| AsError::bad_request(
        "invalid_request",
        "state contains NUL byte",
        "authorize.fail.state_invalid",
    ))?;
    Ok(())
}

fn pkce_s256_matches(verifier: &str, challenge: &str) -> bool {
    // Decode the challenge once into raw bytes; compare digest bytes directly
    // via `subtle::ConstantTimeEq`.  No String comparison, no early exits.
    let h = Sha256::digest(verifier.as_bytes());
    let challenge_bytes = match URL_SAFE_NO_PAD.decode(challenge) {
        Ok(b) => b,
        Err(_) => return false,
    };
    if challenge_bytes.len() != h.len() {
        return false;
    }
    bool::from(h.as_slice().ct_eq(&challenge_bytes))
}

pub async fn authorize(
    State(s): State<Arc<AsState>>,
    headers: HeaderMap,
    Query(q): Query<AuthorizeQuery>,
) -> Result<axum::response::Response, AsError> {
    let mut ctx = AuditCtx::from_headers(&headers).with_client(&q.client_id);

    // Identity gate FIRST — before anything else can consume server cycles.
    let session = require_session(&headers, &s).map_err(|e| {
        emit_audit(e.audit_tag, Sev::Critical, &ctx, "fail", Some(&e.description));
        e
    })?;
    ctx = ctx.with_sub(&session.sub);
    emit_audit("authorize.start", Sev::Info, &ctx, "ok", None);

    if q.response_type != "code" {
        let e = AsError::bad_request(
            "unsupported_response_type",
            "only `code` is supported",
            "authorize.fail.response_type",
        );
        emit_audit(e.audit_tag, Sev::Medium, &ctx, "fail", None);
        return Err(e);
    }
    if q.code_challenge_method != "S256" {
        let e = AsError::bad_request(
            "invalid_request",
            "PKCE S256 is mandatory",
            "authorize.fail.pkce_method",
        );
        emit_audit(e.audit_tag, Sev::Medium, &ctx, "fail", None);
        return Err(e);
    }
    validate_pkce_challenge(&q.code_challenge).map_err(|e| {
        emit_audit(e.audit_tag, Sev::Medium, &ctx, "fail", None);
        e
    })?;
    if let Some(ref st) = q.state {
        validate_state(st).map_err(|e| {
            emit_audit(e.audit_tag, Sev::Medium, &ctx, "fail", None);
            e
        })?;
    }

    let client = {
        let g = lock_or_fail(&s.clients, "clients")?;
        g.get(&q.client_id).cloned()
    };
    let client = client.ok_or_else(|| {
        let e = AsError::unauthorized(
            "unauthorized_client",
            "unknown client",
            "authorize.fail.client_unknown",
            "Bearer realm=\"milnet-authsrv\"",
        );
        emit_audit(e.audit_tag, Sev::High, &ctx, "fail", None);
        e
    })?;

    // Constant-time membership check on the redirect_uris allowlist.
    let mut redirect_ok = false;
    for ru in &client.redirect_uris {
        if bool::from(ru.as_bytes().ct_eq(q.redirect_uri.as_bytes())) {
            redirect_ok = true;
        }
    }
    if !redirect_ok {
        let e = AsError::bad_request(
            "invalid_request",
            "redirect_uri mismatch",
            "authorize.fail.redirect_mismatch",
        );
        emit_audit(e.audit_tag, Sev::High, &ctx, "fail", None);
        return Err(e);
    }

    let scope = q.scope.unwrap_or_else(|| "openid".into());
    let code = rand_token("code")?;
    {
        let mut codes = lock_or_fail(&s.codes, "codes")?;
        codes.insert(
            code.clone(),
            AuthCode {
                code: code.clone(),
                client_id: q.client_id.clone(),
                redirect_uri: q.redirect_uri.clone(),
                user_sub: session.sub.clone(),
                scope: scope.clone(),
                code_challenge: q.code_challenge,
                created_at: now_secs(),
            },
        );
    }

    // RFC 3986-conformant URL construction with `iss` (RFC 9207) included.
    let mut url = url::Url::parse(&q.redirect_uri).map_err(|e| AsError::bad_request(
        "invalid_request",
        &format!("redirect_uri is not a valid URL: {e}"),
        "authorize.fail.redirect_mismatch",
    ))?;
    {
        let mut q_pairs = url.query_pairs_mut();
        q_pairs.append_pair("code", &code);
        q_pairs.append_pair("iss", &s.cfg.issuer);
        if let Some(st) = &q.state {
            q_pairs.append_pair("state", st);
        }
    }

    emit_audit("authorize.code_issued", Sev::Info, &ctx, "ok", None);
    let location = HeaderValue::from_str(url.as_str()).map_err(|e| AsError::server(
        "server_error",
        &format!("invalid Location header: {e}"),
        "authorize.fail.location_encoding",
    ))?;
    Ok((StatusCode::SEE_OTHER, [(header::LOCATION, location)]).into_response())
}

// ── /token ────────────────────────────────────────────────────────────────

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

fn authenticate_client_post(
    state: &AsState,
    client_id_form: &Option<String>,
    client_secret_form: &Option<String>,
    ctx: &AuditCtx,
) -> Result<ClientRegistration, AsError> {
    let cid = client_id_form.as_deref().ok_or_else(|| {
        let e = AsError::unauthorized(
            "invalid_client",
            "client_id required",
            "client_authn.fail.client_id_missing",
            "Basic realm=\"milnet-authsrv\"",
        );
        emit_audit(e.audit_tag, Sev::High, ctx, "fail", None);
        e
    })?;
    let secret = client_secret_form.as_deref().ok_or_else(|| {
        let e = AsError::unauthorized(
            "invalid_client",
            "client_secret required (client_secret_post)",
            "client_authn.fail.secret_missing",
            "Basic realm=\"milnet-authsrv\"",
        );
        emit_audit(e.audit_tag, Sev::High, &ctx.clone().with_client(cid), "fail", None);
        e
    })?;

    let registration = {
        let g = lock_or_fail(&state.clients, "clients")?;
        g.get(cid).cloned()
    };
    // Run Argon2id verify regardless of whether the client exists, so the
    // attacker cannot distinguish unknown vs wrong-secret by timing.
    let dummy = ClientRegistration {
        client_id: cid.to_string(),
        client_secret_hash: ClientRegistration::hash_secret(cid, "")
            .unwrap_or_else(|_| "0".repeat(64)),
        redirect_uris: Vec::new(),
        allowed_scopes: Vec::new(),
        origins: Vec::new(),
        post_logout_redirect_uris: Vec::new(),
    };
    let target = registration.as_ref().unwrap_or(&dummy);
    let ok = target.verify_secret(secret);

    let ip = ctx.source_ip.as_deref().unwrap_or("unknown");
    let _ = common::login_lockout::record_attempt(cid, ip, ok && registration.is_some());

    let registration = match (registration, ok) {
        (Some(c), true) => c,
        _ => {
            let e = AsError::unauthorized(
                "invalid_client",
                "client authentication failed",
                "client_authn.fail.secret_mismatch",
                "Basic realm=\"milnet-authsrv\"",
            );
            emit_audit(e.audit_tag, Sev::Critical, &ctx.clone().with_client(cid), "fail", None);
            return Err(e);
        }
    };
    Ok(registration)
}

pub async fn token(
    State(s): State<Arc<AsState>>,
    headers: HeaderMap,
    Form(f): Form<TokenForm>,
) -> Result<Json<TokenResponse>, AsError> {
    let mut ctx = AuditCtx::from_headers(&headers);
    if let Some(c) = &f.client_id { ctx = ctx.with_client(c); }
    match f.grant_type.as_str() {
        "authorization_code" => token_authorization_code(s, f, ctx).await,
        "refresh_token" => token_refresh(s, f, headers, ctx).await,
        other => {
            let e = AsError::bad_request(
                "unsupported_grant_type",
                &format!("`{other}` is not supported"),
                "token.fail.unsupported_grant",
            );
            emit_audit(e.audit_tag, Sev::Medium, &ctx, "fail", Some(other));
            Err(e)
        }
    }
}

async fn token_authorization_code(
    s: Arc<AsState>,
    f: TokenForm,
    ctx: AuditCtx,
) -> Result<Json<TokenResponse>, AsError> {
    let code = f.code.clone().ok_or_else(|| {
        let e = AsError::bad_request("invalid_request", "missing code", "token.fail.code_missing");
        emit_audit(e.audit_tag, Sev::Medium, &ctx, "fail", None);
        e
    })?;
    let verifier = f.code_verifier.clone().ok_or_else(|| {
        let e = AsError::bad_request("invalid_request", "missing code_verifier", "token.fail.verifier_missing");
        emit_audit(e.audit_tag, Sev::Medium, &ctx, "fail", None);
        e
    })?;
    validate_pkce_verifier(&verifier).map_err(|e| {
        emit_audit(e.audit_tag, Sev::Medium, &ctx, "fail", None);
        e
    })?;
    let redirect_uri = f.redirect_uri.clone().ok_or_else(|| {
        let e = AsError::bad_request("invalid_request", "missing redirect_uri", "token.fail.redirect_missing");
        emit_audit(e.audit_tag, Sev::Medium, &ctx, "fail", None);
        e
    })?;

    // Public-client compatibility: `client_id` is required, but the secret
    // is optional only if the registration's hash field is the well-known
    // "no secret" sentinel.  For Phase 4 hot-fix we always require
    // client_secret_post on confidential clients; public clients are not
    // supported in the hot-fix path (they require DPoP, which lands Phase 5).
    let client = authenticate_client_post(&s, &f.client_id, &f.client_secret, &ctx)?;
    let ctx = ctx.with_client(&client.client_id);

    let entry = {
        let mut codes = lock_or_fail(&s.codes, "codes")?;
        codes.remove(&code).ok_or_else(|| {
            let e = AsError::bad_request("invalid_grant", "unknown code", "token.fail.code_unknown");
            emit_audit(e.audit_tag, Sev::High, &ctx, "fail", None);
            e
        })?
    };

    // Cross-client substitution guard (D-02).  Constant-time on both fields.
    let cid_eq = entry.client_id.as_bytes().ct_eq(client.client_id.as_bytes());
    let ru_eq = entry.redirect_uri.as_bytes().ct_eq(redirect_uri.as_bytes());
    if !bool::from(cid_eq & ru_eq) {
        let e = AsError::bad_request(
            "invalid_grant",
            "client/redirect mismatch on code redemption",
            "token.fail.redirect_uri_mismatch",
        );
        emit_audit(e.audit_tag, Sev::Critical, &ctx, "fail", None);
        return Err(e);
    }

    if !pkce_s256_matches(&verifier, &entry.code_challenge) {
        let e = AsError::bad_request("invalid_grant", "PKCE mismatch", "token.fail.pkce_mismatch");
        emit_audit(e.audit_tag, Sev::Critical, &ctx, "fail", None);
        return Err(e);
    }

    let now = now_secs();
    let age = now.saturating_sub(entry.created_at);
    if age > 60 {
        let e = AsError::bad_request("invalid_grant", "code expired", "token.fail.code_expired");
        emit_audit(e.audit_tag, Sev::Medium, &ctx, "fail", None);
        return Err(e);
    }

    let resp = issue_tokens(&s, &client.client_id, &entry.user_sub, &entry.scope, None)?;
    emit_audit("token.issue.authorization_code", Sev::Info, &ctx.clone().with_sub(&entry.user_sub), "ok", None);
    Ok(Json(resp))
}

async fn token_refresh(
    s: Arc<AsState>,
    f: TokenForm,
    _headers: HeaderMap,
    ctx: AuditCtx,
) -> Result<Json<TokenResponse>, AsError> {
    let rt = f.refresh_token.clone().ok_or_else(|| {
        let e = AsError::bad_request("invalid_request", "missing refresh_token", "token.fail.rt_missing");
        emit_audit(e.audit_tag, Sev::Medium, &ctx, "fail", None);
        e
    })?;

    let client = authenticate_client_post(&s, &f.client_id, &f.client_secret, &ctx)?;
    let ctx = ctx.with_client(&client.client_id);

    let entry = {
        let store = lock_or_fail(&s.refresh_tokens, "refresh_tokens")?;
        store.get(&rt).cloned()
    };
    let entry = entry.ok_or_else(|| {
        let e = AsError::bad_request("invalid_grant", "unknown refresh_token", "token.fail.rt_unknown");
        emit_audit(e.audit_tag, Sev::High, &ctx, "fail", None);
        e
    })?;

    // Bind the refresh token to the calling client (RFC 6749 §10.4).
    let cid_eq = entry.client_id.as_bytes().ct_eq(client.client_id.as_bytes());
    if !bool::from(cid_eq) {
        let e = AsError::bad_request(
            "invalid_grant",
            "refresh_token bound to a different client",
            "token.fail.rt_client_mismatch",
        );
        emit_audit(e.audit_tag, Sev::Critical, &ctx, "fail", None);
        return Err(e);
    }

    if entry.rotated {
        // Reuse detection — burn the entire family AND every live access
        // token bound to that family (D-07 cascade fix).
        {
            let mut fams = lock_or_fail(&s.revoked_families, "revoked_families")?;
            fams.insert(entry.family_id.clone());
        }
        {
            let mut store = lock_or_fail(&s.refresh_tokens, "refresh_tokens")?;
            store.retain(|_, v| v.family_id != entry.family_id);
        }
        {
            let mut ats = lock_or_fail(&s.access_tokens, "access_tokens")?;
            for (_, m) in ats.iter_mut() {
                if m.family_id.as_deref() == Some(&entry.family_id) {
                    m.revoked = true;
                }
            }
        }
        let e = AsError::bad_request(
            "invalid_grant",
            "refresh_token reuse detected — family revoked",
            "token.refresh.reuse_detected_family_revoked",
        );
        emit_audit(e.audit_tag, Sev::Critical, &ctx.clone().with_sub(&entry.user_sub), "fail", None);
        return Err(e);
    }
    if lock_or_fail(&s.revoked_families, "revoked_families")?.contains(&entry.family_id) {
        let e = AsError::bad_request("invalid_grant", "family revoked", "token.fail.family_revoked");
        emit_audit(e.audit_tag, Sev::High, &ctx, "fail", None);
        return Err(e);
    }
    {
        let mut store = lock_or_fail(&s.refresh_tokens, "refresh_tokens")?;
        if let Some(v) = store.get_mut(&rt) {
            v.rotated = true;
        }
    }

    let resp = issue_tokens(&s, &client.client_id, &entry.user_sub, &entry.scope, Some(entry.family_id))?;
    emit_audit("token.refresh.rotated", Sev::Info, &ctx.clone().with_sub(&entry.user_sub), "ok", None);
    Ok(Json(resp))
}

fn issue_tokens(
    s: &AsState,
    client_id: &str,
    sub: &str,
    scope: &str,
    family: Option<String>,
) -> Result<TokenResponse, AsError> {
    let access = rand_token("at")?;
    let id_token = rand_token("id")?;
    let rt = rand_token("rt")?;
    let family_id = match family {
        Some(f) => f,
        None => drbg_uuid_v7()?.to_string(),
    };
    let exp = now_secs().saturating_add(600);
    let jti = drbg_uuid_v7()?.to_string();

    {
        let mut g = lock_or_fail(&s.access_tokens, "access_tokens")?;
        g.insert(
            access.clone(),
            AccessTokenMeta {
                jti,
                sub: sub.into(),
                client_id: client_id.into(),
                scope: scope.into(),
                exp,
                dpop_jkt: None,
                family_id: Some(family_id.clone()),
                revoked: false,
            },
        );
    }
    {
        let mut g = lock_or_fail(&s.refresh_tokens, "refresh_tokens")?;
        g.insert(
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
    }

    Ok(TokenResponse {
        access_token: access,
        token_type: "DPoP".into(),
        expires_in: 600,
        refresh_token: rt,
        id_token,
        scope: scope.into(),
    })
}

// ── /userinfo ─────────────────────────────────────────────────────────────

pub async fn userinfo(
    State(s): State<Arc<AsState>>,
    headers: HeaderMap,
) -> Result<Json<UserClaims>, AsError> {
    let ctx = AuditCtx::from_headers(&headers);
    let auth = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    // Phase 5 wires real DPoP enforcement.  Until then we still REJECT
    // bareword Bearer (which the demo accepted) — D-04 hot-fix per master
    // plan §6 row 4.  Real DPoP proof verification lands Phase 5.
    let token = auth
        .strip_prefix("DPoP ")
        .ok_or_else(|| {
            let e = AsError::unauthorized(
                "invalid_token",
                "DPoP scheme required (Bearer not accepted)",
                "userinfo.scheme_bearer_blocked",
                "DPoP realm=\"milnet-authsrv\"",
            );
            emit_audit(e.audit_tag, Sev::High, &ctx, "fail", None);
            e
        })?
        .trim();

    let _dpop_proof = headers.get("DPoP").ok_or_else(|| {
        let e = AsError::unauthorized(
            "invalid_token",
            "DPoP proof header required",
            "dpop.fail.proof_missing",
            "DPoP realm=\"milnet-authsrv\"",
        );
        emit_audit(e.audit_tag, Sev::High, &ctx, "fail", None);
        e
    })?;

    let meta = {
        let g = lock_or_fail(&s.access_tokens, "access_tokens")?;
        g.get(token).cloned()
    };
    let meta = meta.ok_or_else(|| {
        let e = AsError::unauthorized(
            "invalid_token",
            "unknown access token",
            "userinfo.token_unknown",
            "DPoP realm=\"milnet-authsrv\"",
        );
        emit_audit(e.audit_tag, Sev::High, &ctx, "fail", None);
        e
    })?;
    if meta.revoked {
        let e = AsError::unauthorized(
            "invalid_token",
            "token revoked",
            "userinfo.token_revoked",
            "DPoP realm=\"milnet-authsrv\"",
        );
        emit_audit(e.audit_tag, Sev::High, &ctx.clone().with_sub(&meta.sub), "fail", None);
        return Err(e);
    }
    // Strict `<=` so a token expiring at exactly `now` is treated as expired (D-17).
    if meta.exp <= now_secs() {
        let e = AsError::unauthorized(
            "invalid_token",
            "token expired",
            "userinfo.token_expired",
            "DPoP realm=\"milnet-authsrv\"",
        );
        emit_audit(e.audit_tag, Sev::Medium, &ctx.clone().with_sub(&meta.sub), "fail", None);
        return Err(e);
    }
    let user = {
        let g = lock_or_fail(&s.user_db, "user_db")?;
        g.get(&meta.sub).cloned()
    };
    let user = user.ok_or_else(|| {
        let e = AsError::unauthorized(
            "invalid_token",
            "subject record not found",
            "userinfo.sub_not_found",
            "DPoP realm=\"milnet-authsrv\"",
        );
        emit_audit(e.audit_tag, Sev::Critical, &ctx.clone().with_sub(&meta.sub), "fail", None);
        e
    })?;
    emit_audit("userinfo.ok", Sev::Info, &ctx.clone().with_sub(&meta.sub), "ok", None);
    Ok(Json(user))
}

// ── /introspect ───────────────────────────────────────────────────────────

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

const INTROSPECT_PADDED_LEN: usize = 512;

fn pad_json(mut bytes: Vec<u8>, target_len: usize) -> Vec<u8> {
    while bytes.len() < target_len {
        bytes.push(b' ');
    }
    bytes
}

fn introspect_inactive_body() -> Vec<u8> {
    // `{"active":false,"sub":null,"client_id":null,"scope":null,"exp":null}`
    // padded to a fixed length so the response is byte-length-stable.  RFC
    // 7159 allows trailing whitespace after a JSON value.
    let body = serde_json::to_vec(&IntrospectResponse {
        active: false,
        sub: None,
        client_id: None,
        scope: None,
        exp: None,
    })
    .unwrap_or_else(|_| b"{\"active\":false}".to_vec());
    pad_json(body, INTROSPECT_PADDED_LEN)
}

pub async fn introspect(
    State(s): State<Arc<AsState>>,
    headers: HeaderMap,
    Form(f): Form<IntrospectForm>,
) -> Response {
    let ctx = AuditCtx::from_headers(&headers);
    let inactive = introspect_inactive_body();
    let make_response = |bytes: Vec<u8>| -> Response {
        let mut resp = Response::new(Body::from(bytes));
        resp.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        resp.headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        resp
    };

    // Always run client authn — anonymous callers cannot use this as an
    // oracle for live tokens (D-08).  Failure → constant-time padded inactive.
    let client = match authenticate_client_post(&s, &f.client_id, &f.client_secret, &ctx) {
        Ok(c) => c,
        Err(_) => {
            emit_audit("introspect.unauthorized_caller", Sev::High, &ctx, "fail", None);
            return make_response(inactive);
        }
    };
    let ctx = ctx.with_client(&client.client_id);

    let meta_opt = {
        let g = match lock_or_fail(&s.access_tokens, "access_tokens") {
            Ok(g) => g,
            Err(e) => return e.into_response(),
        };
        g.get(&f.token).cloned()
    };

    if let Some(meta) = meta_opt {
        let same_client = bool::from(meta.client_id.as_bytes().ct_eq(client.client_id.as_bytes()));
        let live = !meta.revoked && meta.exp > now_secs();
        if same_client && live {
            let real = IntrospectResponse {
                active: true,
                sub: Some(meta.sub.clone()),
                client_id: Some(meta.client_id.clone()),
                scope: Some(meta.scope.clone()),
                exp: Some(meta.exp),
            };
            let real_bytes = match serde_json::to_vec(&real) {
                Ok(b) => pad_json(b, INTROSPECT_PADDED_LEN),
                Err(_) => inactive.clone(),
            };
            emit_audit("introspect.ok", Sev::Info, &ctx.clone().with_sub(&meta.sub), "ok", None);
            return make_response(real_bytes);
        }
    }
    emit_audit("introspect.inactive", Sev::Info, &ctx, "ok", None);
    make_response(inactive)
}

// ── /revoke ───────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct RevokeForm {
    pub token: String,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
}

pub async fn revoke(
    State(s): State<Arc<AsState>>,
    headers: HeaderMap,
    Form(f): Form<RevokeForm>,
) -> Result<StatusCode, AsError> {
    let ctx = AuditCtx::from_headers(&headers);
    let client = authenticate_client_post(&s, &f.client_id, &f.client_secret, &ctx)?;
    let ctx = ctx.with_client(&client.client_id);

    let mut hit = false;

    // Access-token leg.
    {
        let mut g = lock_or_fail(&s.access_tokens, "access_tokens")?;
        if let Some(m) = g.get_mut(&f.token) {
            // Only the owning client may revoke its own access tokens.
            if bool::from(m.client_id.as_bytes().ct_eq(client.client_id.as_bytes())) {
                m.revoked = true;
                hit = true;
            } else {
                emit_audit("revoke.unauthorized_caller", Sev::Critical, &ctx, "fail", None);
            }
        }
    }

    // Refresh-token leg with family cascade (D-07).
    let family = {
        let g = lock_or_fail(&s.refresh_tokens, "refresh_tokens")?;
        g.get(&f.token).cloned()
    };
    if let Some(rt) = family {
        if bool::from(rt.client_id.as_bytes().ct_eq(client.client_id.as_bytes())) {
            {
                let mut fams = lock_or_fail(&s.revoked_families, "revoked_families")?;
                fams.insert(rt.family_id.clone());
            }
            {
                let mut store = lock_or_fail(&s.refresh_tokens, "refresh_tokens")?;
                store.retain(|_, v| v.family_id != rt.family_id);
            }
            {
                let mut ats = lock_or_fail(&s.access_tokens, "access_tokens")?;
                for (_, m) in ats.iter_mut() {
                    if m.family_id.as_deref() == Some(&rt.family_id) {
                        m.revoked = true;
                    }
                }
            }
            emit_audit("revoke.family_revoked", Sev::High, &ctx.clone().with_sub(&rt.user_sub), "ok", None);
            hit = true;
        } else {
            emit_audit("revoke.unauthorized_caller", Sev::Critical, &ctx, "fail", None);
        }
    }

    if hit {
        emit_audit("revoke.ok", Sev::Info, &ctx, "ok", None);
    } else {
        emit_audit("revoke.unknown", Sev::Info, &ctx, "ok", None);
    }
    // RFC 7009 §2.2 — return 200 regardless, so a caller cannot distinguish
    // "token did not exist" from "token revoked" via the status code.
    Ok(StatusCode::OK)
}

// ── /end_session ──────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct EndSessionQuery {
    pub id_token_hint: Option<String>,
    pub post_logout_redirect_uri: Option<String>,
    pub state: Option<String>,
    pub client_id: Option<String>,
}

fn parse_jws_iss(jws: &str) -> Option<String> {
    let mut parts = jws.split('.');
    let _ = parts.next()?;
    let payload_b64 = parts.next()?;
    let payload = URL_SAFE_NO_PAD.decode(payload_b64).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&payload).ok()?;
    v.get("iss").and_then(|i| i.as_str()).map(str::to_string)
}

pub async fn end_session(
    State(s): State<Arc<AsState>>,
    headers: HeaderMap,
    Query(q): Query<EndSessionQuery>,
) -> Result<Response, AsError> {
    let ctx = AuditCtx::from_headers(&headers);
    let id_token_hint = q.id_token_hint.as_deref().ok_or_else(|| {
        let e = AsError::bad_request(
            "invalid_request",
            "id_token_hint required",
            "end_session.id_token_hint_missing",
        );
        emit_audit(e.audit_tag, Sev::Medium, &ctx, "fail", None);
        e
    })?;
    let issuer = parse_jws_iss(id_token_hint).ok_or_else(|| {
        let e = AsError::bad_request(
            "invalid_request",
            "id_token_hint not a parseable JWS",
            "end_session.id_token_hint_invalid",
        );
        emit_audit(e.audit_tag, Sev::Medium, &ctx, "fail", None);
        e
    })?;
    if !bool::from(issuer.as_bytes().ct_eq(s.cfg.issuer.as_bytes())) {
        let e = AsError::bad_request(
            "invalid_request",
            "id_token_hint issuer mismatch",
            "end_session.id_token_hint_iss_mismatch",
        );
        emit_audit(e.audit_tag, Sev::High, &ctx, "fail", None);
        return Err(e);
    }
    // Phase 3 wires real signature verification; until then we audit MEDIUM.
    emit_audit(
        "end_session.idtokenhint_unverified",
        Sev::Medium,
        &ctx,
        "ok",
        Some("id_token_hint signature verification deferred to Phase 3"),
    );

    if let Some(ref st) = q.state {
        validate_state(st).map_err(|e| {
            emit_audit(e.audit_tag, Sev::Medium, &ctx, "fail", None);
            e
        })?;
    }

    let post_logout = match q.post_logout_redirect_uri.as_deref() {
        Some(p) => p,
        None => {
            emit_audit("end_session.ok", Sev::Info, &ctx, "ok", None);
            return Ok(StatusCode::OK.into_response());
        }
    };

    // Allowlist check (D-09).  Without a registered `client_id` we cannot
    // verify the redirect — refuse outright.
    let client_id = q.client_id.as_deref().ok_or_else(|| {
        let e = AsError::bad_request(
            "invalid_request",
            "client_id required when post_logout_redirect_uri is present",
            "end_session.client_id_missing",
        );
        emit_audit(e.audit_tag, Sev::High, &ctx, "fail", None);
        e
    })?;
    let client = {
        let g = lock_or_fail(&s.clients, "clients")?;
        g.get(client_id).cloned()
    };
    let client = client.ok_or_else(|| {
        let e = AsError::bad_request(
            "invalid_request",
            "unknown client",
            "end_session.client_unknown",
        );
        emit_audit(e.audit_tag, Sev::High, &ctx, "fail", None);
        e
    })?;

    let mut allowed = false;
    for u in &client.post_logout_redirect_uris {
        if bool::from(u.as_bytes().ct_eq(post_logout.as_bytes())) {
            allowed = true;
        }
    }
    if !allowed {
        let e = AsError::bad_request(
            "invalid_request",
            "post_logout_redirect_uri not registered for this client",
            "end_session.redirect_blocked_open",
        );
        emit_audit(e.audit_tag, Sev::Critical, &ctx, "fail", None);
        return Err(e);
    }

    let mut url = url::Url::parse(post_logout).map_err(|e| AsError::bad_request(
        "invalid_request",
        &format!("post_logout_redirect_uri is not a valid URL: {e}"),
        "end_session.redirect_invalid",
    ))?;
    if let Some(st) = q.state {
        url.query_pairs_mut().append_pair("state", &st);
    }
    let location = HeaderValue::from_str(url.as_str()).map_err(|e| AsError::server(
        "server_error",
        &format!("invalid Location header: {e}"),
        "end_session.location_encoding",
    ))?;
    emit_audit("end_session.ok", Sev::Info, &ctx, "ok", None);
    Ok((StatusCode::SEE_OTHER, [(header::LOCATION, location)]).into_response())
}

// ── Health ────────────────────────────────────────────────────────────────

async fn healthz() -> Response {
    let mut r = Response::new(Body::from("ok"));
    r.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

async fn livez() -> Response { healthz().await }

async fn readyz(headers: HeaderMap) -> Response {
    let required = std::env::var("MILNET_HEALTH_TOKEN").ok().filter(|t| !t.is_empty());
    if let Some(token) = required {
        let presented = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .map(str::trim)
            .unwrap_or("");
        let len_eq = (presented.len() as u64).ct_eq(&(token.len() as u64));
        let bytes_a = presented.as_bytes();
        let bytes_b = token.as_bytes();
        let min = bytes_a.len().min(bytes_b.len());
        let body_eq = if min == 0 {
            subtle::Choice::from(0)
        } else {
            #[allow(clippy::indexing_slicing)]
            bytes_a[..min].ct_eq(&bytes_b[..min])
        };
        if !bool::from(len_eq & body_eq) {
            return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
        }
    }
    let mut r = Response::new(Body::from("ready"));
    r.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

// ── Router ────────────────────────────────────────────────────────────────

const RATE_LIMIT_WINDOW_MS: u64 = 60_000;
const RATE_LIMIT_PER_IP: u64 = 600;

fn rate_limit_layer<B>(req: axum::http::Request<B>) -> Result<axum::http::Request<B>, Response> {
    let ip = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .unwrap_or("local")
        .trim()
        .to_string();
    let key = format!("ip:{ip}:{}", req.uri().path());
    let allowed = rate_limit::check(
        &key,
        &rate_limit::Limit { window_ms: RATE_LIMIT_WINDOW_MS, max: RATE_LIMIT_PER_IP },
        now_ms(),
    );
    if !allowed {
        let mut r = (StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded").into_response();
        r.headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("60"));
        return Err(r);
    }
    Ok(req)
}

async fn rate_limit_middleware(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    match rate_limit_layer(req) {
        Ok(req) => next.run(req).await,
        Err(resp) => resp,
    }
}

fn h(v: &'static str) -> HeaderValue { HeaderValue::from_static(v) }
fn hname(s: &'static str) -> HeaderName { HeaderName::from_static(s) }

pub fn router() -> Router<Arc<AsState>> {
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::predicate(|_origin: &HeaderValue, _parts: &axum::http::request::Parts| {
            // Default-deny: discovery / JWKS / etc. are intentionally
            // same-origin only.  Per-client origin allowlist lands when CORS
            // is wired against the registry in Phase 6 follow-up.
            false
        }))
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            HeaderName::from_static("dpop"),
        ])
        .max_age(Duration::from_secs(3600));

    let token_route = post(token).layer(RequestBodyLimitLayer::new(32 * 1024));
    let authorize_route = get(authorize); // GET, body limit not applicable
    let introspect_route = post(introspect).layer(RequestBodyLimitLayer::new(8 * 1024));
    let revoke_route = post(revoke).layer(RequestBodyLimitLayer::new(8 * 1024));
    let end_session_route = get(end_session); // GET, no body
    let userinfo_route = get(userinfo);

    // tower / axum semantics: each `.layer()` wraps the prior service in the
    // new layer.  The LAST `.layer()` call is the OUTERMOST.  Order below
    // (top to bottom) places security headers innermost (so they decorate
    // every response), then CORS, then per-request resource limits, then
    // the rate limit (outermost, rejecting before any work runs), and the
    // panic catcher + trace at the very top of the stack.
    Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/.well-known/jwks.json", get(jwks))
        .route("/authorize", authorize_route)
        .route("/token", token_route)
        .route("/userinfo", userinfo_route)
        .route("/introspect", introspect_route)
        .route("/revoke", revoke_route)
        .route("/end_session", end_session_route)
        .route("/healthz", get(healthz))
        .route("/livez", get(livez))
        .route("/readyz", get(readyz))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::STRICT_TRANSPORT_SECURITY,
            h("max-age=63072000; includeSubDomains; preload"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::X_CONTENT_TYPE_OPTIONS,
            h("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::X_FRAME_OPTIONS,
            h("DENY"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::REFERRER_POLICY,
            h("no-referrer"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            hname("cross-origin-opener-policy"),
            h("same-origin"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            hname("cross-origin-embedder-policy"),
            h("require-corp"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            hname("cross-origin-resource-policy"),
            h("same-origin"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            hname("permissions-policy"),
            h("accelerometer=(), camera=(), geolocation=(), gyroscope=(), microphone=(), payment=()"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::CONTENT_SECURITY_POLICY,
            h("default-src 'none'; frame-ancestors 'none'"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::CACHE_CONTROL,
            h("no-store"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::PRAGMA,
            h("no-cache"),
        ))
        .layer(cors)
        .layer(TimeoutLayer::new(Duration::from_secs(5)))
        .layer(axum::middleware::from_fn(rate_limit_middleware))
        .layer(CatchPanicLayer::new())
        .layer(TraceLayer::new_for_http())
}

// ── Test fixtures (gated) ─────────────────────────────────────────────────

#[cfg(any(test, feature = "test-util"))]
pub fn test_state() -> Arc<AsState> {
    let s = Arc::new(AsState::default());
    let secret_hash = ClientRegistration::hash_secret("test-client", "test-secret")
        .unwrap_or_else(|_| "0".repeat(64));
    if let Ok(mut g) = s.clients.lock() {
        g.insert(
            "test-client".into(),
            ClientRegistration {
                client_id: "test-client".into(),
                client_secret_hash: secret_hash,
                redirect_uris: vec!["https://rp.test/cb".into()],
                allowed_scopes: vec!["openid".into(), "profile".into()],
                origins: vec!["https://rp.test".into()],
                post_logout_redirect_uris: vec!["https://rp.test/post".into()],
            },
        );
    }
    if let Ok(mut g) = s.user_db.lock() {
        // The bypass-session header below directs `require_session` to look
        // up the row keyed by the session id == "session-test-1".  The
        // resolved subject is the test user.
        g.insert(
            "session-test-1".into(),
            UserClaims {
                sub: "test-subject".into(),
                name: "Test".into(),
                email: "test@milnet".into(),
            },
        );
        g.insert(
            "test-subject".into(),
            UserClaims {
                sub: "test-subject".into(),
                name: "Test".into(),
                email: "test@milnet".into(),
            },
        );
    }
    s
}

#[cfg(any(test, feature = "test-util"))]
pub const TEST_SESSION_HEADER: &str = "session-test-1";

#[cfg(any(test, feature = "test-util"))]
pub const TEST_CLIENT_ID: &str = "test-client";

#[cfg(any(test, feature = "test-util"))]
pub const TEST_CLIENT_SECRET: &str = "test-secret";

/// Idempotent DRBG bootstrap for test harnesses.  Returns Ok on first call;
/// subsequent calls are silently ignored (the OnceLock has already been set).
#[cfg(any(test, feature = "test-util"))]
pub fn ensure_drbg_init() {
    let _ = init_drbg();
    common::secure_time::init_time_anchor();
}

/// Drain and return the buffered audit entries — a thin wrapper for tests so
/// integration test crates do not need a direct `common` dev-dep.
#[cfg(any(test, feature = "test-util"))]
pub fn drain_audit_count() -> usize {
    common::audit_bridge::drain_audit_buffer().len()
}

#[cfg(any(test, feature = "test-util"))]
pub fn pkce_pair() -> (String, String) {
    let mut buf = [0u8; 32];
    let _ = rand_bytes(&mut buf);
    let verifier = URL_SAFE_NO_PAD.encode(buf);
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    (verifier, challenge)
}

#[cfg(test)]
mod unit {
    use super::*;

    #[test]
    fn pkce_challenge_charset_rejected() {
        assert!(validate_pkce_challenge(&"a".repeat(43)).is_ok());
        let mut bad = "a".repeat(42);
        bad.push('!');
        assert!(validate_pkce_challenge(&bad).is_err());
    }

    #[test]
    fn pkce_challenge_length_strict() {
        assert!(validate_pkce_challenge(&"a".repeat(42)).is_err());
        assert!(validate_pkce_challenge(&"a".repeat(44)).is_err());
        assert!(validate_pkce_challenge(&"a".repeat(43)).is_ok());
    }

    #[test]
    fn state_crlf_rejected() {
        assert!(validate_state("hello\r\nfoo").is_err());
        assert!(validate_state("hello").is_ok());
    }

    #[test]
    fn pkce_match_constant_time() {
        let v = "abcd".repeat(16);
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(v.as_bytes()));
        assert!(pkce_s256_matches(&v, &challenge));
        assert!(!pkce_s256_matches(&v, &"a".repeat(43)));
    }

    #[test]
    fn introspect_inactive_padded() {
        let body = introspect_inactive_body();
        assert_eq!(body.len(), INTROSPECT_PADDED_LEN);
    }
}
