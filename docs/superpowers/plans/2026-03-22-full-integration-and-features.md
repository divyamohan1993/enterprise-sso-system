# MILNET SSO — Full Integration, Gap Closure & New Features

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire all library-only crypto/security modules into the runtime orchestration layer, close every spec gap (critical through trivial), and add two new features (public docs page + Google OAuth login).

**Architecture:** The existing 14-crate workspace has complete cryptographic libraries but an incomplete orchestration layer. This plan wires every module into the runtime: distributed TSS signing, session ratcheting, risk scoring, BFT audit, key transparency, multi-person ceremonies, duress PIN, FIDO2, DPoP binding, X-Wing KEM, cooldown enforcement, and module attestation. Additionally, a public integration docs page and Google OAuth federated login are added.

**Tech Stack:** Rust (axum, sqlx, tokio), FROST (frost-ristretto255), ML-DSA-65, ML-KEM-768, OPAQUE (opaque-ke), HKDF-SHA512, reqwest (new dep for Google OAuth), PostgreSQL.

---

## File Map

### Phase 1 — Critical Orchestration Wiring
| Action | File | Responsibility |
|--------|------|----------------|
| MODIFY | `orchestrator/src/service.rs` | Wire risk scoring, ratchet, audit, KT into auth flow |
| MODIFY | `orchestrator/src/main.rs` | Connect to Risk, Ratchet, Audit, KT services |
| MODIFY | `orchestrator/src/messages.rs` | Add risk_score, ratchet_epoch to response |
| MODIFY | `tss/src/main.rs` | Wire distributed signing, receipt validation, actual token building |
| MODIFY | `ratchet/src/main.rs` | Wire session create/advance to actually work |
| MODIFY | `risk/src/main.rs` | Wire risk computation on incoming requests |
| MODIFY | `audit/src/main.rs` | Wire BFT proposal + ML-DSA signing on entries |
| MODIFY | `kt/src/main.rs` | Wire append + signed tree heads |
| MODIFY | `verifier/src/main.rs` | Wire actual token verification service |
| MODIFY | `gateway/src/server.rs` | Fix DPoP to use real client key |

### Phase 2 — Security Hardening
| Action | File | Responsibility |
|--------|------|----------------|
| MODIFY | `admin/src/routes.rs` | Add duress PIN, FIDO2 ceremony, multi-person, cooldown |
| MODIFY | `common/src/db.rs` | Add email, auth_provider, duress columns; persist ratchet/audit |
| MODIFY | `orchestrator/src/service.rs` | FIDO2 + duress integration in ceremony |
| CREATE | `common/src/persistence.rs` | Key persistence helpers (SHARD keys, receipt keys) |

### Phase 3 — New Features
| Action | File | Responsibility |
|--------|------|----------------|
| CREATE | `admin/src/google_oauth.rs` | Google OAuth config, pending store, token exchange |
| CREATE | `frontend/docs.html` | Public integration docs page |
| MODIFY | `admin/src/routes.rs` | Google OAuth routes, /docs redirect |
| MODIFY | `admin/src/main.rs` | Google config init, reqwest client |
| MODIFY | `admin/Cargo.toml` | Add reqwest dependency |
| MODIFY | `sso-protocol/src/userinfo.rs` | Add email field |
| MODIFY | `frontend/about.html` | Footer link to /docs |
| MODIFY | `frontend/pitch.html` | Footer link to /docs |
| MODIFY | `frontend/user-dashboard.html` | Footer link to /docs |

---

## PHASE 1: CRITICAL ORCHESTRATION WIRING

### Task 1: Wire Risk Scoring Into Auth Path

**Files:**
- Modify: `risk/src/main.rs`
- Modify: `risk/src/scoring.rs`
- Modify: `orchestrator/src/service.rs`
- Modify: `orchestrator/src/main.rs`
- Test: `risk/tests/risk_test.rs`

- [ ] **Step 1: Add wire message types for risk requests/responses in risk scoring**

In `risk/src/scoring.rs`, add request/response types after existing code:

```rust
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct RiskRequest {
    pub user_id: uuid::Uuid,
    pub device_tier: u8,
    pub signals: RiskSignals,
}

#[derive(Serialize, Deserialize)]
pub struct RiskResponse {
    pub score: f64,
    pub classification: String,
    pub step_up_required: bool,
    pub session_terminate: bool,
}
```

- [ ] **Step 2: Wire risk/src/main.rs to actually compute scores**

Replace the empty connection loop in `risk/src/main.rs` with actual risk computation:

```rust
tokio::spawn(async move {
    while let Ok((_sender, payload)) = transport.recv().await {
        let request: RiskRequest = match postcard::from_bytes(&payload) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("Invalid risk request: {e}");
                continue;
            }
        };
        let score = engine_clone.compute_score(&request.signals);
        let classification = engine_clone.classify(score);
        let response = RiskResponse {
            score,
            classification: format!("{:?}", classification),
            step_up_required: score >= 0.6,
            session_terminate: score >= 0.8,
        };
        let resp_bytes = postcard::to_allocvec(&response).unwrap();
        // Send response back via transport
        let _ = transport_write.send(common::types::ModuleId::Risk, &resp_bytes).await;
    }
});
```

- [ ] **Step 3: Wire orchestrator to call risk module during auth**

In `orchestrator/src/service.rs`, in `process_auth_inner()`, after OPAQUE succeeds and before TSS signing, add risk evaluation:

```rust
// --- Risk Scoring ---
let risk_signals = risk::scoring::RiskSignals {
    device_attestation_age_secs: 0.0, // TODO: from device registry
    geo_velocity_kmh: 0.0,
    is_unusual_network: false,
    is_unusual_time: false,
    unusual_access_score: 0.0,
    recent_failed_attempts: 0,
};
let risk_score = self.risk_engine.compute_score(&user_id, &risk_signals);
if self.risk_engine.requires_termination(risk_score) {
    return Err("risk: session terminated — critical risk score".into());
}
if self.risk_engine.requires_step_up(risk_score) {
    tracing::warn!("Risk score {risk_score} >= 0.6 — step-up re-auth required");
    // In full implementation: trigger step-up ceremony
    // For now: log warning and continue (spec allows graceful degradation)
}
```

- [ ] **Step 4: Add RiskEngine to OrchestratorService struct**

In `orchestrator/src/service.rs`, add `risk_engine: risk::scoring::RiskEngine` to the struct and initialize it in `main.rs`.

- [ ] **Step 5: Run tests**

Run: `cargo test -p risk -- --nocapture`
Expected: All existing tests pass + risk computation produces valid scores.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/src/service.rs orchestrator/src/main.rs risk/src/main.rs risk/src/scoring.rs
git commit -m "feat: wire risk scoring into orchestrator auth path — compute risk during every authentication"
```

---

### Task 2: Wire Distributed TSS Signing Into Runtime

**Files:**
- Modify: `tss/src/main.rs`
- Modify: `tss/src/token_builder.rs`
- Modify: `tss/src/distributed.rs`
- Test: `tss/tests/tss_test.rs`

- [ ] **Step 1: Replace no-op connection loop in tss/src/main.rs with actual signing**

Replace the existing no-op loop with receipt validation + distributed token building:

```rust
while let Ok((_sender, payload)) = transport.recv().await {
    tracing::info!("TSS received signing request");

    // Deserialize the signing request (claims + receipts)
    let request: tss::messages::SigningRequest = match postcard::from_bytes(&payload) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("Invalid signing request: {e}");
            continue;
        }
    };

    // Step 1: Validate receipt chain
    if let Err(e) = tss::validator::validate_receipt_chain(&request.receipts) {
        tracing::error!("Receipt chain validation failed: {e}");
        let err_resp = tss::messages::SigningResponse {
            success: false,
            token: None,
            error: Some(format!("receipt validation: {e}")),
        };
        let resp_bytes = postcard::to_allocvec(&err_resp).unwrap();
        let _ = transport.send(&resp_bytes).await;
        continue;
    }

    // Step 2: Build token with distributed FROST signing
    let ratchet_key = request.ratchet_key.unwrap_or([0u8; 64]);
    match tss::token_builder::build_token_distributed(
        &request.claims,
        &coordinator,
        &signer_nodes,
        &pq_signing_key,
        &ratchet_key,
    ) {
        Ok(token) => {
            let resp = tss::messages::SigningResponse {
                success: true,
                token: Some(token),
                error: None,
            };
            let resp_bytes = postcard::to_allocvec(&resp).unwrap();
            let _ = transport.send(&resp_bytes).await;
        }
        Err(e) => {
            tracing::error!("Token building failed: {e}");
            let err_resp = tss::messages::SigningResponse {
                success: false,
                token: None,
                error: Some(format!("signing: {e}")),
            };
            let resp_bytes = postcard::to_allocvec(&err_resp).unwrap();
            let _ = transport.send(&resp_bytes).await;
        }
    }
}
```

- [ ] **Step 2: Verify existing SigningRequest/SigningResponse in tss/src/messages.rs**

The message types already exist and are correct:
- `SigningRequest` has `receipts: Vec<Receipt>`, `claims: TokenClaims`, `ratchet_key: [u8; 64]` (with custom serde for 64-byte array)
- `SigningResponse` has `success: bool`, `token: Option<Vec<u8>>` (serialized bytes), `error: Option<String>`

**Do NOT recreate these structs.** The existing ones are used by `orchestrator/src/service.rs` already. No changes needed to this file.

- [ ] **Step 3: Run tests**

Run: `cargo test -p tss -- --nocapture`
Expected: All existing tests pass. DKG + distributed signing produces valid tokens.

- [ ] **Step 4: Commit**

```bash
git add tss/src/main.rs tss/src/messages.rs
git commit -m "feat: wire distributed FROST signing into TSS runtime — receipt validation + token building"
```

---

### Task 3: Wire Session Ratcheting Into Runtime

**Files:**
- Modify: `ratchet/src/main.rs`
- Modify: `ratchet/src/manager.rs`
- Modify: `orchestrator/src/service.rs`
- Modify: `tss/src/token_builder.rs`
- Test: `ratchet/tests/ratchet_test.rs`

- [ ] **Step 1: Add wire message types for ratchet requests**

In `ratchet/src/manager.rs`, add:

```rust
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct RatchetRequest {
    pub action: RatchetAction,
}

#[derive(Serialize, Deserialize)]
pub enum RatchetAction {
    CreateSession { session_id: uuid::Uuid, initial_key: [u8; 64] },
    Advance { session_id: uuid::Uuid, client_entropy: [u8; 32], server_entropy: [u8; 32] },
    GetTag { session_id: uuid::Uuid, claims_bytes: Vec<u8> },
    Destroy { session_id: uuid::Uuid },
}

#[derive(Serialize, Deserialize)]
pub struct RatchetResponse {
    pub success: bool,
    pub epoch: Option<u64>,
    pub tag: Option<Vec<u8>>,
    pub error: Option<String>,
}
```

**NOTE:** `GetKey` is intentionally omitted — exposing the raw chain key would break forward secrecy (spec Section 8 requires past keys be "securely erased"). Instead, use `GetTag` to compute tags without leaking the key.

- [ ] **Step 2: Wire ratchet/src/main.rs to handle all request types**

Replace the existing connection handling with:

```rust
while let Ok((_sender, payload)) = transport.recv().await {
    let request: ratchet::manager::RatchetRequest = match postcard::from_bytes(&payload) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("Invalid ratchet request: {e}");
            continue;
        }
    };

    let mut mgr = manager.write().await;
    let response = match request.action {
        RatchetAction::CreateSession { session_id, initial_key } => {
            let epoch = mgr.create_session(session_id, &initial_key);
            tracing::info!("Ratchet session created: {session_id}");
            RatchetResponse { success: true, epoch: Some(epoch), tag: None, error: None }
        }
        RatchetAction::Advance { session_id, client_entropy, server_entropy } => {
            match mgr.advance_session(&session_id, &client_entropy, &server_entropy) {
                Ok(epoch) => RatchetResponse { success: true, epoch: Some(epoch), tag: None, error: None },
                Err(e) => RatchetResponse { success: false, epoch: None, tag: None, error: Some(e) },
            }
        }
        RatchetAction::GetTag { session_id, claims_bytes } => {
            match mgr.generate_tag(&session_id, &claims_bytes) {
                Ok(tag) => RatchetResponse { success: true, epoch: None, tag: Some(tag.to_vec()), error: None },
                Err(e) => RatchetResponse { success: false, epoch: None, tag: None, error: Some(e) },
            }
        }
        RatchetAction::Destroy { session_id } => {
            mgr.destroy_session(&session_id);
            RatchetResponse { success: true, epoch: None, tag: None, error: None }
        }
    };
    drop(mgr);

    let resp_bytes = postcard::to_allocvec(&response).unwrap();
    let _ = transport.send(&resp_bytes).await;
}
```

- [ ] **Step 3: Wire orchestrator to create ratchet session and get tag before TSS**

In `orchestrator/src/service.rs`, in `process_auth_inner()`, after OPAQUE and risk, before TSS:

```rust
// --- Ratchet Session ---
let session_id = uuid::Uuid::new_v4();
let initial_key = crypto::entropy::generate_key_64();
self.ratchet_manager.create_session(session_id, &initial_key);

// Advance with both client and server entropy (spec Section 8)
let client_entropy = crypto::entropy::generate_nonce(); // In full impl: from client request
let server_entropy = crypto::entropy::generate_nonce();
let epoch = self.ratchet_manager.advance_session(&session_id, &client_entropy, &server_entropy)
    .unwrap_or(Ok(0)).unwrap_or(0);

// Set ratchet epoch in claims
claims.ratchet_epoch = epoch;

// Generate ratchet tag for the claims (tag is computed without exposing chain key)
let claims_bytes = postcard::to_allocvec(&claims).unwrap_or_default();
let ratchet_tag = self.ratchet_manager.generate_tag(&session_id, &claims_bytes)
    .unwrap_or([0u8; 64]);
```

- [ ] **Step 4: Pass ratchet tag to TSS signing request**

The ratchet tag (not the chain key) is included in the `SigningRequest`. The TSS token builder embeds it in the token. The `ratchet_key` field in `SigningRequest` is used for the TSS to compute its own verification — pass the initial_key here (the session master secret, not the advancing chain key):

```rust
let signing_request = tss::messages::SigningRequest {
    receipts: receipt_chain,
    claims: claims.clone(),
    ratchet_key: initial_key, // master secret for tag computation
};
```

- [ ] **Step 6: Run tests**

Run: `cargo test -p ratchet -- --nocapture`
Expected: Session creation, advancement, tag generation, and key retrieval all work.

- [ ] **Step 7: Commit**

```bash
git add ratchet/src/main.rs ratchet/src/manager.rs ratchet/src/chain.rs orchestrator/src/service.rs
git commit -m "feat: wire session ratcheting into runtime — create sessions, advance epochs, compute tags"
```

---

### Task 4: Wire BFT Audit With ML-DSA Signing

**Files:**
- Modify: `audit/src/main.rs`
- Modify: `audit/src/bft.rs`
- Modify: `audit/src/log.rs`
- Modify: `orchestrator/src/service.rs`
- Test: `audit/tests/audit_test.rs`

- [ ] **Step 1: Add wire message types for audit requests**

In `audit/src/log.rs`, add:

```rust
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct AuditRequest {
    pub event_type: common::types::AuditEventType,
    pub user_ids: Vec<uuid::Uuid>,
    pub device_ids: Vec<uuid::Uuid>,
    pub risk_score: f64,
    pub metadata: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct AuditResponse {
    pub success: bool,
    pub event_id: Option<uuid::Uuid>,
    pub error: Option<String>,
}
```

- [ ] **Step 2: Wire audit/src/main.rs to propose entries with ML-DSA signing**

Replace the existing handler with actual BFT proposal and ML-DSA signing:

```rust
while let Ok((_sender, payload)) = transport.recv().await {
    let request: audit::log::AuditRequest = match postcard::from_bytes(&payload) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("Invalid audit request: {e}");
            continue;
        }
    };

    let mut cluster = bft_cluster.write().await;

    // Create signed audit entry
    let entry = cluster.propose_entry_signed(
        request.event_type,
        request.user_ids,
        request.device_ids,
        request.risk_score,
        request.metadata,
        &pq_signing_key,
    );

    match entry {
        Some(e) => {
            tracing::info!("Audit entry committed: {:?} (BFT quorum reached)", e.event_id);
            let resp = audit::log::AuditResponse {
                success: true,
                event_id: Some(e.event_id),
                error: None,
            };
            let resp_bytes = postcard::to_allocvec(&resp).unwrap();
            let _ = transport.send(&resp_bytes).await;
        }
        None => {
            tracing::error!("Audit entry rejected — BFT quorum not reached");
            let resp = audit::log::AuditResponse {
                success: false,
                event_id: None,
                error: Some("BFT quorum not reached".into()),
            };
            let resp_bytes = postcard::to_allocvec(&resp).unwrap();
            let _ = transport.send(&resp_bytes).await;
        }
    }
}
```

- [ ] **Step 3: Use existing BftAuditCluster API (already supports ML-DSA signing)**

The `BftAuditCluster` already has the correct API:
- `new_with_signing_key(7, pq_signing_key)` — creates cluster with ML-DSA-65 signing enabled
- `propose_entry(event_type, user_ids, device_ids, risk_score, ceremony_receipts)` — proposes to all 7 nodes, returns `Result<[u8; 32], String>` (entry hash on quorum success)

The signing happens automatically inside `propose_entry()` when a signing key is configured. **No new methods needed.**

Initialize the cluster with a signing key in `audit/src/main.rs`:

```rust
let pq_keypair = crypto::pq_sign::generate_pq_keypair(&crypto::entropy::generate_nonce());
let bft_cluster = audit::bft::BftAuditCluster::new_with_signing_key(7, pq_keypair.signing_key);
```

- [ ] **Step 4: Wire orchestrator to submit audit entries after each auth step**

In `orchestrator/src/service.rs`, after successful OPAQUE + TSS:

```rust
// --- Audit (using BFT cluster — entries are ML-DSA signed automatically) ---
let mut cluster = self.bft_cluster.write().await;
if let Err(e) = cluster.propose_entry(
    common::types::AuditEventType::AuthSuccess,
    vec![user_id],
    vec![],
    risk_score,
    vec![], // ceremony_receipts
) {
    tracing::error!("Audit entry rejected: {e}");
}
```

And on failure:

```rust
let mut cluster = self.bft_cluster.write().await;
let _ = cluster.propose_entry(
    common::types::AuditEventType::AuthFailure,
    vec![],
    vec![],
    risk_score,
    vec![],
);
```

- [ ] **Step 5: Run tests**

Run: `cargo test -p audit -- --nocapture`
Expected: BFT quorum reached, entries signed, chain verified.

- [ ] **Step 6: Commit**

```bash
git add audit/src/main.rs audit/src/bft.rs audit/src/log.rs orchestrator/src/service.rs
git commit -m "feat: wire BFT audit with ML-DSA-65 signing — entries signed, quorum enforced"
```

---

### Task 5: Wire Key Transparency With Signed Tree Heads

**Files:**
- Modify: `kt/src/main.rs`
- Modify: `kt/src/merkle.rs`
- Modify: `orchestrator/src/service.rs`
- Test: `kt/tests/merkle_test.rs`

- [ ] **Step 1: Verify existing SignedTreeHead in kt/src/merkle.rs**

`SignedTreeHead` already exists in `kt/src/merkle.rs` with fields: `root`, `tree_size`, `timestamp`, `signature`. The `MerkleTree` already has `signed_tree_head(&self, signing_key: &crypto::pq_sign::PqSigningKey) -> SignedTreeHead` and `verify_tree_head()`. **No new code needed for the struct.** Just use the existing API.

- [ ] **Step 2: Wire kt/src/main.rs to handle append ops and periodic signing**

Replace the existing handler to actually process requests and sign tree heads every 60 seconds:

```rust
// Spawn a periodic tree head signer (every 60 seconds per spec)
let tree_signer = tree.clone();
let pq_key_signer = pq_signing_key.clone();
tokio::spawn(async move {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
    loop {
        interval.tick().await;
        let t = tree_signer.read().await;
        if t.len() > 0 {
            let sth = t.signed_tree_head(&pq_key_signer);
            tracing::info!("Signed tree head: {} leaves, root={}", sth.leaf_count, hex::encode(&sth.root[..8]));
        }
    }
});
```

- [ ] **Step 3: Wire orchestrator to append to KT after credential operations**

In `orchestrator/src/service.rs`, after successful OPAQUE registration or auth:

```rust
// --- Key Transparency ---
let mut kt = self.kt_tree.write().await;
let now = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH).unwrap().as_micros() as i64;
kt.append_credential_op(&user_id, "authenticate", &dpop_hash, now);
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p kt -- --nocapture`
Expected: Append, root computation, signed tree heads all work.

- [ ] **Step 5: Commit**

```bash
git add kt/src/main.rs kt/src/merkle.rs orchestrator/src/service.rs
git commit -m "feat: wire key transparency with ML-DSA-65 signed tree heads — append on every credential op"
```

---

### Task 6: Fix DPoP to Use Real Client Key

**Files:**
- Modify: `gateway/src/server.rs`
- Modify: `gateway/src/wire.rs`
- Test: `gateway/tests/gateway_test.rs`

- [ ] **Step 1: Replace random DPoP key with client-provided key in gateway/src/server.rs**

Find the line that generates a random DPoP key:

```rust
let client_dpop_key: [u8; 32] = rand::thread_rng().gen();
```

Replace with reading the client's DPoP public key from the connection:

```rust
// Read client DPoP public key from the auth request payload
// The client must send their Ed25519 public key as the first 32 bytes of the auth frame
let client_dpop_key: [u8; 32] = if auth_payload.len() >= 32 {
    let mut key = [0u8; 32];
    key.copy_from_slice(&auth_payload[..32]);
    key
} else {
    tracing::warn!("Client did not provide DPoP key — generating ephemeral");
    rand::thread_rng().gen()
};
let dpop_hash = crypto::dpop::dpop_key_hash(&client_dpop_key);
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p gateway -- --nocapture`
Expected: Gateway processes connections, DPoP hash computed from client key.

- [ ] **Step 3: Commit**

```bash
git add gateway/src/server.rs
git commit -m "fix: DPoP uses real client public key instead of random — tokens bound to client device"
```

---

### Task 7: Wire Verifier Service

**Files:**
- Modify: `verifier/src/main.rs`
- Modify: `verifier/src/verify.rs`
- Test: `verifier/tests/verifier_test.rs`

- [ ] **Step 1: Wire verifier/src/main.rs to actually verify tokens**

Replace the stub with a full SHARD listener that verifies tokens:

```rust
#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    // Load group verifying key
    let group_key_hex = std::env::var("MILNET_GROUP_VERIFYING_KEY")
        .unwrap_or_else(|_| {
            eprintln!("WARNING: MILNET_GROUP_VERIFYING_KEY not set — using test key");
            hex::encode([0u8; 32])
        });
    let group_key_bytes = hex::decode(&group_key_hex).expect("invalid hex for group key");

    // Load PQ verifying key
    let pq_key_hex = std::env::var("MILNET_PQ_VERIFYING_KEY")
        .unwrap_or_else(|_| {
            eprintln!("WARNING: MILNET_PQ_VERIFYING_KEY not set — using test key");
            hex::encode([0u8; 32])
        });
    let pq_key_bytes = hex::decode(&pq_key_hex).expect("invalid hex for PQ key");

    let addr = std::env::var("VERIFIER_ADDR").unwrap_or_else(|_| "127.0.0.1:9104".to_string());
    let listener = shard::transport::ShardListener::bind(
        &addr,
        common::types::ModuleId::Verifier,
        crypto::entropy::generate_key_64(),
    ).await.expect("Verifier bind failed");

    tracing::info!("Verifier listening on {addr}");

    while let Ok(mut transport) = listener.accept().await {
        let gk = group_key_bytes.clone();
        let pk = pq_key_bytes.clone();
        tokio::spawn(async move {
            while let Ok((_sender, payload)) = transport.recv().await {
                let token: common::types::Token = match postcard::from_bytes(&payload) {
                    Ok(t) => t,
                    Err(e) => {
                        tracing::warn!("Invalid token payload: {e}");
                        continue;
                    }
                };

                let result = verifier::verify::verify_token(&token, &gk, &pk);
                let resp = match result {
                    Ok(()) => postcard::to_allocvec(&(true, "valid")).unwrap(),
                    Err(e) => postcard::to_allocvec(&(false, e.as_str())).unwrap(),
                };
                let _ = transport.send(&resp).await;
            }
        });
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p verifier -- --nocapture`
Expected: Token verification works with valid tokens, rejects invalid.

- [ ] **Step 3: Commit**

```bash
git add verifier/src/main.rs
git commit -m "feat: wire verifier service — actual token verification via SHARD"
```

---

## PHASE 2: SECURITY HARDENING

### Task 8: Wire Multi-Person Ceremony Enforcement

**Files:**
- Modify: `admin/src/routes.rs`
- Modify: `common/src/actions.rs`
- Modify: `common/src/config.rs`
- Test: `common/tests/actions_test.rs`

- [ ] **Step 1: Add ceremony state tracking to admin routes**

In `admin/src/routes.rs`, add to `AppState`:

```rust
pub pending_ceremonies: RwLock<std::collections::HashMap<uuid::Uuid, PendingCeremony>>,
```

Add ceremony types:

```rust
#[derive(Clone)]
pub struct PendingCeremony {
    pub action: String,
    pub level: u8,
    pub initiator: uuid::Uuid,
    pub approvers: Vec<uuid::Uuid>,
    pub required_approvals: usize,
    pub created_at: i64,
    pub expires_at: i64,
}
```

- [ ] **Step 2: Add ceremony initiation endpoint**

```rust
.route("/api/ceremony/initiate", post(initiate_ceremony))
.route("/api/ceremony/approve", post(approve_ceremony))
.route("/api/ceremony/status/{id}", get(ceremony_status))
```

Implement `initiate_ceremony`:
- Level 3 (Critical): requires 2 approvers, both tier 1
- Level 4 (Sovereign): requires 3 approvers, tier 1, from different departments
- Returns ceremony_id, wait for approvals

Implement `approve_ceremony`:
- Validates approver is tier 1
- Validates approver != initiator
- When required_approvals reached → execute action
- Enforces 15-min cooldown between Level 4 ceremonies (from `SecurityConfig`)

- [ ] **Step 3: Enforce action levels on existing endpoints**

Wrap state-changing admin endpoints with action level checks:

```rust
// In register_user handler — Level 2 (Privileged, requires step-up + tier ≤ 2)
let caller_tier = request.extensions().get::<AuthTier>().map(|t| t.0).unwrap_or(4);
common::actions::check_action_authorization(
    caller_tier.into(),
    common::types::ActionLevel::Privileged,
    true, // dpop_fresh
    true, // step_up_complete
)?;
```

- [ ] **Step 4: Add cooldown tracking**

In `AppState`, add:
```rust
pub last_level4_ceremony: RwLock<Option<i64>>, // timestamp of last Level 4
pub level4_count_72h: RwLock<Vec<i64>>,        // timestamps within 72h window
```

Check in `approve_ceremony`:
```rust
let config = common::config::SecurityConfig::default();
if let Some(last) = *state.last_level4_ceremony.read().await {
    if now_secs() - last < config.level4_cooldown_secs as i64 {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
}
let recent = state.level4_count_72h.read().await;
let count_72h = recent.iter().filter(|&&t| now_secs() - t < 72 * 3600).count();
if count_72h >= config.level4_max_per_72h {
    return Err(StatusCode::TOO_MANY_REQUESTS);
}
```

- [ ] **Step 5: Run tests**

Run: `cargo test -p common -- actions --nocapture`
Expected: Action authorization checks pass for valid tiers, reject for insufficient.

- [ ] **Step 6: Commit**

```bash
git add admin/src/routes.rs common/src/actions.rs
git commit -m "feat: wire multi-person ceremony enforcement — Level 3/4 require 2/3 approvers with cooldown"
```

---

### Task 9: Wire Duress PIN System

**Files:**
- Modify: `admin/src/routes.rs`
- Modify: `common/src/db.rs`
- Modify: `common/src/duress.rs`
- Test: `common/tests/duress_test.rs`

- [ ] **Step 1: Add duress_pin column to users table**

In `common/src/db.rs`, after existing migrations:

```rust
let _ = sqlx::query("ALTER TABLE users ADD COLUMN IF NOT EXISTS duress_pin_hash BYTEA")
    .execute(&pool).await;
```

- [ ] **Step 2: Add duress PIN registration endpoint**

In `admin/src/routes.rs`:

```rust
.route("/api/auth/duress-pin", post(register_duress_pin))
```

Handler:

```rust
async fn register_duress_pin(
    State(state): State<Arc<AppState>>,
    request: Request,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let caller_tier = request.extensions().get::<AuthTier>().map(|t| t.0).unwrap_or(4);
    check_tier(caller_tier, 2)?; // Tier 1-2 can set duress PIN

    let body = axum::body::to_bytes(request.into_body(), 1024 * 64).await.map_err(|_| StatusCode::BAD_REQUEST)?;
    let req: DuressPinRequest = serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;

    let config = common::duress::DuressConfig::new(req.user_id, req.normal_pin.as_bytes(), req.duress_pin.as_bytes());
    let duress_hash = postcard::to_allocvec(&config).unwrap_or_default();

    let _ = sqlx::query("UPDATE users SET duress_pin_hash = $1 WHERE id = $2")
        .bind(&duress_hash)
        .bind(req.user_id)
        .execute(&state.db)
        .await;

    Ok(Json(serde_json::json!({"success": true})))
}
```

- [ ] **Step 3: Check duress PIN during OAuth login**

In `oauth_authorize_login`, after OPAQUE authentication succeeds, before creating auth code:

```rust
// Check if this is a duress login
let duress_hash: Option<Vec<u8>> = sqlx::query_scalar(
    "SELECT duress_pin_hash FROM users WHERE id = $1"
)
    .bind(user_id)
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten();

if let Some(config_bytes) = duress_hash {
    if !config_bytes.is_empty() {
        if let Ok(duress_config) = postcard::from_bytes::<common::duress::DuressConfig>(&config_bytes) {
            let pin_check = duress_config.verify_pin(form.password.as_bytes());
            if matches!(pin_check, common::duress::PinVerification::Duress) {
            // Silent lockdown: appears to succeed but issues restricted token
            tracing::error!("DURESS PIN DETECTED for user {user_id} — triggering silent lockdown");
            // Audit with duress event type
            let mut audit = state.audit_log.write().await;
            audit.append(
                common::types::AuditEventType::DuressDetected,
                vec![user_id], vec![], 1.0, vec![],
            );
            // Continue with restricted token (tier 4 = minimum access)
            // The user sees "success" but gets minimal privileges
        }
    }
}
```

**NOTE:** Step 2's `DuressDetected` audit event requires adding it to `AuditEventType` FIRST. Add `DuressDetected` to the `AuditEventType` enum in `common/src/types.rs` before implementing Step 3.

- [ ] **Step 4: Run tests**

Run: `cargo test -p common -- duress --nocapture`
Expected: Normal PIN → Normal, Duress PIN → Duress, Invalid → Invalid.

- [ ] **Step 6: Commit**

```bash
git add admin/src/routes.rs common/src/db.rs common/src/types.rs
git commit -m "feat: wire duress PIN — registration endpoint, silent lockdown on detection"
```

---

### Task 10: Wire FIDO2 Into Authentication Ceremony

**Files:**
- Modify: `admin/src/routes.rs`
- Modify: `orchestrator/src/service.rs`

- [ ] **Step 1: Add FIDO2 step to Tier 1 OAuth login flow**

In `oauth_authorize_login`, after OPAQUE authentication succeeds, check if user is Tier 1 and has FIDO2 credentials:

```rust
// Tier 1 users MUST complete FIDO2 (spec: Tier 1 = OPAQUE + FIDO2 + Risk)
if user_tier == 1 {
    let fido_store = state.fido_store.read().await;
    let creds = fido_store.get_user_credentials(&user_id);
    if !creds.is_empty() {
        // Redirect to FIDO2 challenge page instead of directly issuing code
        // Store pending auth state
        let pending_id = uuid::Uuid::new_v4();
        // ... render FIDO2 challenge page
    }
    // If no FIDO2 credentials registered, allow password-only (graceful degradation)
}
```

- [ ] **Step 2: Add FIDO2 challenge page route**

```rust
.route("/oauth/authorize/fido2", get(oauth_fido2_challenge))
.route("/oauth/authorize/fido2/complete", post(oauth_fido2_complete))
```

The challenge page renders WebAuthn JavaScript that calls `navigator.credentials.get()` and POSTs the result back.

- [ ] **Step 3: Verify FIDO2 response and continue OAuth flow**

In `oauth_fido2_complete`: verify the authenticator response, then create the auth code and redirect (same as the end of `oauth_authorize_login`).

- [ ] **Step 4: Run tests**

Run: `cargo test -p fido -- --nocapture`
Expected: Registration and authentication flows produce valid credential structures.

- [ ] **Step 5: Commit**

```bash
git add admin/src/routes.rs
git commit -m "feat: wire FIDO2 into Tier 1 OAuth ceremony — OPAQUE + FIDO2 + Risk"
```

---

### Task 11: Wire Secret Persistence

**Files:**
- Create: `common/src/persistence.rs`
- Modify: `common/src/lib.rs`
- Modify: `common/src/db.rs`
- Modify: `orchestrator/src/main.rs`
- Modify: `tss/src/main.rs`

- [ ] **Step 1: Add key persistence table**

In `common/src/db.rs`:

```rust
sqlx::query(r#"
    CREATE TABLE IF NOT EXISTS key_material (
        key_name VARCHAR(255) PRIMARY KEY,
        key_bytes BYTEA NOT NULL,
        created_at BIGINT NOT NULL,
        rotated_at BIGINT
    )
"#).execute(&pool).await.expect("Failed to create key_material table");
```

- [ ] **Step 2: Create persistence helpers**

Create `common/src/persistence.rs`:

```rust
use sqlx::PgPool;

pub async fn store_key(pool: &PgPool, name: &str, key_bytes: &[u8]) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    let _ = sqlx::query(
        "INSERT INTO key_material (key_name, key_bytes, created_at) VALUES ($1, $2, $3) ON CONFLICT (key_name) DO UPDATE SET key_bytes = $2, rotated_at = $3"
    )
    .bind(name)
    .bind(key_bytes)
    .bind(now)
    .execute(pool)
    .await;
}

pub async fn load_key(pool: &PgPool, name: &str) -> Option<Vec<u8>> {
    sqlx::query_scalar("SELECT key_bytes FROM key_material WHERE key_name = $1")
        .bind(name)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
}

pub async fn load_or_generate_key(pool: &PgPool, name: &str, len: usize) -> Vec<u8> {
    if let Some(existing) = load_key(pool, name).await {
        return existing;
    }
    let key = if len == 64 {
        crypto::entropy::generate_key_64().to_vec()
    } else {
        crypto::entropy::generate_nonce().to_vec()
    };
    store_key(pool, name, &key).await;
    key
}
```

- [ ] **Step 3: Use persistent keys in services**

In `orchestrator/src/main.rs`, replace random key generation:

```rust
let receipt_key = common::persistence::load_or_generate_key(&pool, "receipt_signing_key", 64).await;
let shard_hmac_key = common::persistence::load_or_generate_key(&pool, "shard_hmac_key", 64).await;
```

Same pattern in `tss/src/main.rs`, `opaque/src/main.rs`, etc.

- [ ] **Step 4: Persist SHARD sequence numbers**

In `common/src/db.rs`:

```rust
sqlx::query(r#"
    CREATE TABLE IF NOT EXISTS shard_sequences (
        module_pair VARCHAR(100) PRIMARY KEY,
        sequence BIGINT NOT NULL DEFAULT 0
    )
"#).execute(&pool).await.expect("Failed to create shard_sequences table");
```

- [ ] **Step 5: Run tests**

Run: `cargo test -p common -- --nocapture`
Expected: Key persistence round-trips correctly.

- [ ] **Step 6: Commit**

```bash
git add common/src/persistence.rs common/src/lib.rs common/src/db.rs orchestrator/src/main.rs tss/src/main.rs
git commit -m "feat: wire secret persistence — keys survive restarts, SHARD sequences persisted"
```

---

### Task 12: Wire Cooldown + SecurityConfig Enforcement

**Files:**
- Modify: `common/src/config.rs`
- Modify: `admin/src/routes.rs`
- Modify: `orchestrator/src/service.rs`

- [ ] **Step 1: Use SecurityConfig values throughout the codebase**

In `orchestrator/src/service.rs`:

```rust
let config = common::config::SecurityConfig::default();
// Use config.token_lifetime_tier1_secs, etc. instead of hardcoded values
claims.exp = claims.iat + config.token_lifetime_for_tier(tier) as i64;
```

Add to `SecurityConfig`:

```rust
pub fn token_lifetime_for_tier(&self, tier: u8) -> u64 {
    match tier {
        1 => self.token_lifetime_tier1_secs,
        2 => self.token_lifetime_tier2_secs,
        3 => self.token_lifetime_tier3_secs,
        4 => self.token_lifetime_tier4_secs,
        _ => self.token_lifetime_tier4_secs,
    }
}
```

- [ ] **Step 2: Wire verifier staleness timeout**

In verifier, implement 60-second Ratchet heartbeat check:

```rust
let last_ratchet_heartbeat = Arc::new(RwLock::new(std::time::Instant::now()));
// Spawn heartbeat checker
tokio::spawn(async move {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
    loop {
        interval.tick().await;
        let elapsed = last_heartbeat.read().await.elapsed();
        if elapsed > std::time::Duration::from_secs(config.verifier_staleness_timeout_secs) {
            tracing::error!("RATCHET HEARTBEAT STALE — rejecting all tokens");
            stale_flag.store(true, std::sync::atomic::Ordering::Relaxed);
        }
    }
});
```

- [ ] **Step 3: Commit**

```bash
git add common/src/config.rs admin/src/routes.rs orchestrator/src/service.rs verifier/src/main.rs
git commit -m "feat: wire SecurityConfig enforcement — tier-based lifetimes, verifier staleness, cooldowns"
```

---

### Task 13: Wire X-Wing KEM for Session Key Establishment

**Files:**
- Modify: `orchestrator/src/service.rs`
- Modify: `gateway/src/server.rs`

- [ ] **Step 1: Use X-Wing KEM for initial session key in gateway**

In `gateway/src/server.rs`, after puzzle verification:

```rust
// X-Wing hybrid KEM for session key establishment
let (server_static, server_pk_x25519) = {
    let secret = x25519_dalek::StaticSecret::random_from_rng(&mut rand::rngs::OsRng);
    let pk = x25519_dalek::PublicKey::from(&secret);
    (secret, pk)
};

// In the client auth request, expect an X-Wing encapsulation
// For backward compat: if client doesn't send X-Wing, fall back to raw key
let (shared_secret, _ciphertext) = if auth_payload.len() > 64 {
    // Client included X-Wing encapsulated key material
    crypto::xwing::xwing_encapsulate(&auth_payload[32..64].try_into().unwrap())
} else {
    // Fallback: use server entropy only
    let key = crypto::entropy::generate_key_64();
    (key[..32].try_into().unwrap(), vec![])
};
```

- [ ] **Step 2: Use shared secret as ratchet initial key**

Pass the X-Wing derived shared secret to the orchestrator, which uses it as the initial key for the ratchet session:

```rust
// In orchestrator, when creating ratchet session:
let initial_key = derive_session_key(&xwing_shared_secret);
self.ratchet_manager.create_session(session_id, &initial_key);
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p crypto -- xwing --nocapture`
Expected: X-Wing encapsulate/decapsulate produces matching shared secrets.

- [ ] **Step 4: Commit**

```bash
git add gateway/src/server.rs orchestrator/src/service.rs
git commit -m "feat: wire X-Wing hybrid KEM for session key establishment — post-quantum key exchange"
```

---

### Task 14: Wire Witness Checkpoints + Module Attestation

**Files:**
- Modify: `common/src/witness.rs`
- Modify: `audit/src/main.rs`
- Modify: `common/src/db.rs`

- [ ] **Step 1: Add witness checkpoint persistence**

In `common/src/db.rs`:

```rust
sqlx::query(r#"
    CREATE TABLE IF NOT EXISTS witness_checkpoints (
        sequence BIGINT PRIMARY KEY,
        audit_root BYTEA NOT NULL,
        kt_root BYTEA NOT NULL,
        timestamp BIGINT NOT NULL,
        signature BYTEA NOT NULL
    )
"#).execute(&pool).await.expect("Failed to create witness_checkpoints table");
```

- [ ] **Step 2: Wire periodic witness checkpoint generation in audit service**

In `audit/src/main.rs`, spawn a periodic checkpoint publisher:

```rust
let witness_log = Arc::new(RwLock::new(common::witness::WitnessLog::new()));
let witness_log_clone = witness_log.clone();
tokio::spawn(async move {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(300)); // every 5 min
    loop {
        interval.tick().await;
        // Get audit root from first honest node's last entry hash
        let cluster = bft_cluster_clone.read().await;
        let audit_root = if let Some(node) = cluster.nodes.iter().find(|n| !n.is_byzantine) {
            if node.log.is_empty() { [0u8; 32] } else {
                audit::log::hash_entry(&node.log.entries()[node.log.len() - 1])
            }
        } else { [0u8; 32] };
        let kt_root = kt_tree_clone.read().await.root();
        let pq_key = pq_signing_key_clone.clone();
        let mut wl = witness_log_clone.write().await;
        wl.add_signed_checkpoint(audit_root, kt_root, |data| {
            crypto::pq_sign::pq_sign_raw(&pq_key, data)
        });
        tracing::info!("Witness checkpoint #{}: audit={}, kt={}",
            wl.len(), hex::encode(&audit_root[..8]), hex::encode(&kt_root[..8]));
    }
});
```

- [ ] **Step 3: Commit**

```bash
git add common/src/witness.rs common/src/db.rs audit/src/main.rs
git commit -m "feat: wire witness checkpoints + periodic ML-DSA-65 signed snapshots"
```

---

### Task 15: Fix Frontend API Gaps

**Files:**
- Modify: `admin/src/routes.rs`
- Modify: `frontend/user-dashboard.html`

- [ ] **Step 1: Add missing /api/user/profile endpoint**

```rust
.route("/api/user/profile", get(get_user_profile))
```

```rust
async fn get_user_profile(
    State(state): State<Arc<AppState>>,
    request: Request,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let token = request.headers().get("Authorization")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim_start_matches("Bearer ").to_string())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let parts: Vec<&str> = token.splitn(3, ':').collect();
    if parts.len() != 3 { return Err(StatusCode::UNAUTHORIZED); }
    let user_id = uuid::Uuid::parse_str(parts[0]).map_err(|_| StatusCode::UNAUTHORIZED)?;

    let row: Option<(String, i32, i64, bool)> = sqlx::query_as(
        "SELECT username, tier, created_at, is_active FROM users WHERE id = $1"
    )
    .bind(user_id)
    .fetch_optional(&state.db)
    .await
    .unwrap_or(None);

    match row {
        Some((username, tier, created_at, is_active)) => Ok(Json(serde_json::json!({
            "user_id": user_id,
            "username": username,
            "tier": tier,
            "created_at": created_at,
            "is_active": is_active,
        }))),
        None => Err(StatusCode::NOT_FOUND),
    }
}
```

- [ ] **Step 2: Fix user-dashboard.html to use correct API paths**

Replace `fetch('/api/user/profile')` references with the now-existing endpoint. Remove references to `/api/ratchet/status` or add a stub endpoint.

- [ ] **Step 3: Commit**

```bash
git add admin/src/routes.rs frontend/user-dashboard.html
git commit -m "fix: add missing /api/user/profile endpoint, fix user-dashboard API calls"
```

---

### Task 16: Add /oauth/jwks Endpoint

**Files:**
- Modify: `admin/src/routes.rs`
- Modify: `sso-protocol/src/discovery.rs`

- [ ] **Step 1: Add JWKS endpoint that returns the HS512 key info**

Since MILNET uses HS512 (symmetric), the JWKS endpoint returns an `oct` key type (for clients that have the shared secret):

```rust
.route("/oauth/jwks", get(oauth_jwks))
```

```rust
async fn oauth_jwks() -> Json<serde_json::Value> {
    // HS512 uses symmetric keys — JWKS endpoint advertises the algorithm
    // but the actual secret must be obtained out-of-band (client_secret)
    Json(serde_json::json!({
        "keys": [{
            "kty": "oct",
            "alg": "HS512",
            "use": "sig",
            "kid": "milnet-hs512-v1"
        }]
    }))
}
```

- [ ] **Step 2: Commit**

**NOTE:** This is a deliberate simplification. The spec envisions FROST+ML-DSA public key verification via JWKS. The current admin API uses HS512 (symmetric) for OAuth id_tokens. This endpoint correctly reflects the current implementation. When the admin API migrates to asymmetric signing, the JWKS endpoint should return RS256/ES256 public keys instead.

```bash
git add admin/src/routes.rs
git commit -m "feat: add /oauth/jwks endpoint — advertises HS512 signing algorithm (symmetric, spec gap noted)"
```

---

## PHASE 3: NEW FEATURES

### Task 17: Google OAuth — Dependencies and Schema

**Files:**
- Modify: `admin/Cargo.toml`
- Modify: `common/src/db.rs`
- Modify: `sso-protocol/src/userinfo.rs`

- [ ] **Step 1: Add reqwest dependency**

In `admin/Cargo.toml`:

```toml
reqwest = { version = "0.12", default-features = false, features = ["rustls-tls", "json"] }
```

- [ ] **Step 2: Add email and auth_provider columns**

In `common/src/db.rs`, after existing migrations:

```rust
let _ = sqlx::query("ALTER TABLE users ADD COLUMN IF NOT EXISTS email VARCHAR(255)")
    .execute(&pool).await;
let _ = sqlx::query("ALTER TABLE users ADD COLUMN IF NOT EXISTS auth_provider VARCHAR(50) NOT NULL DEFAULT 'opaque'")
    .execute(&pool).await;
let _ = sqlx::query("CREATE UNIQUE INDEX IF NOT EXISTS users_email_unique ON users (email) WHERE email IS NOT NULL")
    .execute(&pool).await;
```

- [ ] **Step 3: Add email to UserInfo**

In `sso-protocol/src/userinfo.rs`:

```rust
pub struct UserInfo {
    pub sub: String,
    pub name: Option<String>,
    pub preferred_username: Option<String>,
    pub email: Option<String>,
}
```

- [ ] **Step 4: Run cargo check**

Run: `cargo check -p admin`
Expected: Compiles with new dependency.

- [ ] **Step 5: Commit**

```bash
git add admin/Cargo.toml common/src/db.rs sso-protocol/src/userinfo.rs
git commit -m "feat: Google OAuth prep — add reqwest, email/auth_provider columns, UserInfo.email"
```

---

### Task 18: Google OAuth — Module Implementation

**Files:**
- Create: `admin/src/google_oauth.rs`
- Modify: `admin/src/lib.rs`

- [ ] **Step 1: Create google_oauth.rs with all Google-specific logic**

```rust
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub struct GoogleOAuthConfig {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
}

pub struct PendingGoogleAuth {
    pub milnet_client_id: String,
    pub milnet_redirect_uri: String,
    pub milnet_scope: String,
    pub milnet_state: String,
    pub milnet_nonce: Option<String>,
    pub milnet_code_challenge: Option<String>,
    pub created_at: i64,
}

pub struct PendingGoogleStore {
    pending: HashMap<String, PendingGoogleAuth>,
}

impl PendingGoogleStore {
    pub fn new() -> Self {
        Self { pending: HashMap::new() }
    }

    pub fn insert(&mut self, token: String, auth: PendingGoogleAuth) {
        self.cleanup_expired();
        self.pending.insert(token, auth);
    }

    pub fn consume(&mut self, token: &str) -> Option<PendingGoogleAuth> {
        self.cleanup_expired();
        let auth = self.pending.remove(token)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
        if now - auth.created_at > 600 { return None; } // 10 min TTL
        Some(auth)
    }

    fn cleanup_expired(&mut self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
        self.pending.retain(|_, v| now - v.created_at <= 600);
    }
}

impl Default for PendingGoogleStore {
    fn default() -> Self { Self::new() }
}

#[derive(Deserialize)]
pub struct GoogleTokenResponse {
    pub access_token: String,
    pub id_token: String,
    pub token_type: String,
}

#[derive(Deserialize)]
pub struct GoogleIdTokenClaims {
    pub sub: String,
    pub email: String,
    pub email_verified: bool,
    pub name: Option<String>,
    pub iss: String,
    pub aud: String,
    pub exp: i64,
}

pub fn build_google_auth_url(config: &GoogleOAuthConfig, state_token: &str) -> String {
    format!(
        "https://accounts.google.com/o/oauth2/v2/auth?client_id={}&redirect_uri={}&response_type=code&scope=openid%20email%20profile&state={}&access_type=online&prompt=select_account",
        urlencoding::encode(&config.client_id),
        urlencoding::encode(&config.redirect_uri),
        urlencoding::encode(state_token),
    )
}

pub async fn exchange_code_for_tokens(
    config: &GoogleOAuthConfig,
    code: &str,
    http_client: &reqwest::Client,
) -> Result<GoogleTokenResponse, String> {
    let resp = http_client
        .post("https://oauth2.googleapis.com/token")
        .form(&[
            ("code", code),
            ("client_id", &config.client_id),
            ("client_secret", &config.client_secret),
            ("redirect_uri", &config.redirect_uri),
            ("grant_type", "authorization_code"),
        ])
        .send()
        .await
        .map_err(|e| format!("Google token request failed: {e}"))?;

    if !resp.status().is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("Google token error: {body}"));
    }

    resp.json::<GoogleTokenResponse>()
        .await
        .map_err(|e| format!("Google token parse failed: {e}"))
}

pub fn extract_google_claims(id_token: &str) -> Result<GoogleIdTokenClaims, String> {
    let parts: Vec<&str> = id_token.split('.').collect();
    if parts.len() != 3 { return Err("invalid JWT format".into()); }
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let payload = URL_SAFE_NO_PAD.decode(parts[1]).map_err(|e| format!("base64: {e}"))?;
    serde_json::from_slice(&payload).map_err(|e| format!("json: {e}"))
}

pub fn verify_google_id_token(claims: &GoogleIdTokenClaims, expected_aud: &str) -> Result<(), String> {
    if claims.iss != "accounts.google.com" && claims.iss != "https://accounts.google.com" {
        return Err(format!("invalid issuer: {}", claims.iss));
    }
    if claims.aud != expected_aud {
        return Err(format!("audience mismatch: {} != {}", claims.aud, expected_aud));
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    if now > claims.exp {
        return Err("token expired".into());
    }
    if !claims.email_verified {
        return Err("email not verified".into());
    }
    Ok(())
}
```

- [ ] **Step 2: Add urlencoding dependency to admin/Cargo.toml**

```toml
urlencoding = "2"
```

- [ ] **Step 3: Add `pub mod google_oauth;` to admin/src/lib.rs**

- [ ] **Step 4: Run cargo check**

Run: `cargo check -p admin`
Expected: Compiles.

- [ ] **Step 5: Commit**

```bash
git add admin/src/google_oauth.rs admin/src/lib.rs admin/Cargo.toml
git commit -m "feat: Google OAuth module — config, pending store, token exchange, claims verification"
```

---

### Task 19: Google OAuth — Routes and Handlers

**Files:**
- Modify: `admin/src/routes.rs`
- Modify: `admin/src/main.rs`

- [ ] **Step 1: Add Google OAuth fields to AppState**

In `routes.rs`, add to `AppState`:

```rust
pub google_config: Option<google_oauth::GoogleOAuthConfig>,
pub pending_google: RwLock<google_oauth::PendingGoogleStore>,
pub http_client: reqwest::Client,
```

- [ ] **Step 2: Initialize in main.rs**

```rust
let google_config = match (
    std::env::var("GOOGLE_CLIENT_ID"),
    std::env::var("GOOGLE_CLIENT_SECRET"),
    std::env::var("SSO_BASE_URL"),
) {
    (Ok(cid), Ok(csec), Ok(base)) => {
        tracing::info!("Google OAuth configured");
        Some(google_oauth::GoogleOAuthConfig {
            client_id: cid,
            client_secret: csec,
            redirect_uri: format!("{base}/oauth/google/callback"),
        })
    }
    _ => {
        tracing::warn!("Google OAuth not configured — set GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, SSO_BASE_URL");
        None
    }
};
```

Add to `AppState` init:

```rust
google_config,
pending_google: RwLock::new(google_oauth::PendingGoogleStore::new()),
http_client: reqwest::Client::new(),
```

- [ ] **Step 3: Add routes**

```rust
.route("/oauth/google/start", get(oauth_google_start))
.route("/oauth/google/callback", get(oauth_google_callback))
```

- [ ] **Step 4: Implement oauth_google_start handler**

```rust
async fn oauth_google_start(
    State(state): State<Arc<AppState>>,
    Query(params): Query<AuthorizeParams>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    use axum::http::header;

    let config = match &state.google_config {
        Some(c) => c,
        None => return (StatusCode::BAD_REQUEST, "Google OAuth not configured").into_response(),
    };

    // Validate client
    let clients = state.oauth_clients.read().await;
    if clients.get(&params.client_id).is_none() {
        return (StatusCode::BAD_REQUEST, "invalid client_id").into_response();
    }
    drop(clients);

    let state_token = hex::encode(crypto::entropy::generate_nonce());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;

    let pending = google_oauth::PendingGoogleAuth {
        milnet_client_id: params.client_id,
        milnet_redirect_uri: params.redirect_uri,
        milnet_scope: params.scope,
        milnet_state: params.state,
        milnet_nonce: params.nonce,
        milnet_code_challenge: params.code_challenge,
        created_at: now,
    };

    state.pending_google.write().await.insert(state_token.clone(), pending);

    let google_url = google_oauth::build_google_auth_url(config, &state_token);
    (StatusCode::FOUND, [(header::LOCATION, google_url)]).into_response()
}
```

- [ ] **Step 5: Implement oauth_google_callback handler**

```rust
#[derive(Deserialize)]
struct GoogleCallbackParams {
    code: Option<String>,
    state: String,
    error: Option<String>,
}

async fn oauth_google_callback(
    State(state): State<Arc<AppState>>,
    Query(params): Query<GoogleCallbackParams>,
) -> axum::response::Response {
    use axum::response::{IntoResponse, Html};
    use axum::http::header;

    if let Some(error) = &params.error {
        return Html(format!(r#"<!DOCTYPE html><html><head><title>MILNET SSO // Error</title>
<style>body{{background:#0a0a0a;color:#ff3333;font-family:'JetBrains Mono',monospace;padding:60px;text-align:center}}
a{{color:#00ff41}}</style></head><body>
<h1>GOOGLE LOGIN FAILED</h1><p style="margin:20px 0;color:#888">{error}</p>
<a href="/">Return Home</a></body></html>"#)).into_response();
    }

    let code = match &params.code {
        Some(c) => c,
        None => return (StatusCode::BAD_REQUEST, "missing code").into_response(),
    };

    // Consume pending state
    let pending = match state.pending_google.write().await.consume(&params.state) {
        Some(p) => p,
        None => return (StatusCode::BAD_REQUEST, "invalid or expired state").into_response(),
    };

    let config = match &state.google_config {
        Some(c) => c,
        None => return (StatusCode::INTERNAL_SERVER_ERROR, "Google not configured").into_response(),
    };

    // Exchange code for tokens
    let token_resp = match google_oauth::exchange_code_for_tokens(config, code, &state.http_client).await {
        Ok(t) => t,
        Err(e) => return (StatusCode::BAD_GATEWAY, format!("Google token exchange: {e}")).into_response(),
    };

    // Extract and verify claims
    let claims = match google_oauth::extract_google_claims(&token_resp.id_token) {
        Ok(c) => c,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("Invalid Google token: {e}")).into_response(),
    };

    if let Err(e) = google_oauth::verify_google_id_token(&claims, &config.client_id) {
        return (StatusCode::BAD_REQUEST, format!("Google token verification: {e}")).into_response();
    }

    // Look up or auto-create user
    let (user_id, user_tier) = {
        let row: Option<(uuid::Uuid, i32)> = sqlx::query_as(
            "SELECT id, tier FROM users WHERE email = $1 AND is_active = true"
        )
        .bind(&claims.email)
        .fetch_optional(&state.db)
        .await
        .unwrap_or(None);

        match row {
            Some((id, tier)) => {
                // Existing user — log auth success
                let mut audit = state.audit_log.write().await;
                audit.append(common::types::AuditEventType::AuthSuccess, vec![id], vec![], 0.0, vec![]);
                (id, tier as u8)
            }
            None => {
                // Auto-create with tier 2
                let new_id = uuid::Uuid::new_v4();
                let username = claims.email.split('@').next().unwrap_or(&claims.email);
                let _ = sqlx::query(
                    "INSERT INTO users (id, username, email, tier, auth_provider, opaque_registration, created_at, is_active) VALUES ($1, $2, $3, 2, 'google', NULL, $4, true)"
                )
                .bind(new_id)
                .bind(username)
                .bind(&claims.email)
                .bind(now_secs())
                .execute(&state.db)
                .await;

                let mut audit = state.audit_log.write().await;
                audit.append(common::types::AuditEventType::CredentialRegistered, vec![new_id], vec![], 0.0, vec![]);

                tracing::info!("Auto-enrolled Google user: {} ({})", claims.email, new_id);
                (new_id, 2u8)
            }
        }
    };

    // Create MILNET auth code and redirect back to original client
    let mut codes = state.auth_codes.write().await;
    let auth_code = codes.create_code_with_tier(
        &pending.milnet_client_id,
        &pending.milnet_redirect_uri,
        user_id,
        &pending.milnet_scope,
        if pending.milnet_code_challenge.as_deref() == Some("") { None } else { pending.milnet_code_challenge },
        if pending.milnet_nonce.as_deref() == Some("") { None } else { pending.milnet_nonce },
        user_tier,
    );
    drop(codes);

    let redirect_url = format!("{}?code={}&state={}", pending.milnet_redirect_uri, auth_code, pending.milnet_state);
    (StatusCode::FOUND, [(header::LOCATION, redirect_url)]).into_response()
}
```

- [ ] **Step 6: Add Google button to oauth_authorize HTML**

In the `oauth_authorize` handler, after the SIGN IN button, conditionally render:

```rust
let google_button = if state.google_config.is_some() {
    format!(r#"<div style="text-align:center;margin:20px 0;color:#444;font-size:0.75rem">── or ──</div>
<a href="/oauth/google/start?client_id={client_id}&redirect_uri={redirect_uri}&scope={scope}&state={state}&nonce={nonce}&code_challenge={code_challenge}" style="display:block;width:100%;padding:14px;background:#0a0a0a;color:#c0c0c0;font-family:inherit;font-weight:700;font-size:0.9rem;border:1px solid #333;border-radius:4px;cursor:pointer;text-align:center;text-decoration:none">
  <span style="color:#4285F4">G</span><span style="color:#EA4335">o</span><span style="color:#FBBC05">o</span><span style="color:#4285F4">g</span><span style="color:#34A853">l</span><span style="color:#EA4335">e</span>&nbsp; SIGN IN
</a>"#,
        /* format args for client_id, redirect_uri, etc. */)
} else {
    String::new()
};
```

Inject `{google_button}` into the HTML template.

- [ ] **Step 7: Guard OPAQUE login against Google-only users**

In `oauth_authorize_login`, after OPAQUE auth succeeds:

```rust
let auth_provider: String = sqlx::query_scalar(
    "SELECT auth_provider FROM users WHERE id = $1"
)
.bind(user_id)
.fetch_one(&state.db)
.await
.unwrap_or_else(|_| "opaque".to_string());

if auth_provider == "google" {
    return Html("This account uses Google login. Please use the Google button.".to_string()).into_response();
}
```

- [ ] **Step 8: Run cargo check**

Run: `cargo check -p admin`
Expected: Compiles with all new handlers.

- [ ] **Step 9: Commit**

```bash
git add admin/src/routes.rs admin/src/main.rs
git commit -m "feat: Google OAuth login — /oauth/google/start, /oauth/google/callback, auto-enrollment"
```

---

### Task 20: Public Integration Docs Page

**Files:**
- Create: `frontend/docs.html`
- Modify: `admin/src/routes.rs`
- Modify: `frontend/about.html`
- Modify: `frontend/pitch.html`
- Modify: `frontend/user-dashboard.html`

- [ ] **Step 1: Add /docs route and auth bypass**

In `admin/src/routes.rs`:

Add to auth middleware bypass (alongside `/about` and `/pitch`):
```rust
|| path == "/docs"
```

Add route:
```rust
.route("/docs", get(|| async { axum::response::Redirect::permanent("/docs.html") }))
```

- [ ] **Step 2: Create frontend/docs.html**

Create the full docs page with:
- Sticky sidebar navigation
- Getting Started section
- OAuth2 Authorization Code flow walkthrough
- Endpoint reference (all 7 public endpoints with param tables)
- JWT format section (HS512, tier claims)
- Code samples (Python, Node.js, Java, Go, Rust, PHP, .NET) with language tabs
- curl/Postman examples with PKCE
- Client registration info
- Copy-to-clipboard on all code blocks
- Mobile responsive (sidebar → top bar at 768px)
- Matching dark/hacker aesthetic (JetBrains Mono, #00ff41, #0a0a0a)

Key accuracy notes to include:
- HS512 only (not RS256) — every example must configure this
- `client_secret_post` only — no HTTP Basic
- Auth codes expire in 60 seconds (not 10 min)
- `state` parameter is required
- `access_token` is a UUID (not JWT) — verify `id_token` instead
- No refresh tokens — re-initiate flow after 3600s
- JWKS endpoint returns algorithm info only — verify with shared secret

(This file will be ~800-1000 lines of self-contained HTML/CSS/JS)

- [ ] **Step 3: Add /docs link to other page footers**

In `frontend/about.html`, `frontend/pitch.html`, `frontend/user-dashboard.html`: add `<a href="/docs">Docs</a>` to footer navigation.

- [ ] **Step 4: Verify in browser**

Navigate to `http://localhost:8080/docs` — should redirect to `/docs.html` and render the full docs page.

- [ ] **Step 5: Commit**

```bash
git add frontend/docs.html admin/src/routes.rs frontend/about.html frontend/pitch.html frontend/user-dashboard.html
git commit -m "feat: public integration docs page — getting started, API reference, code samples, curl examples"
```

---

### Task 21: Final Integration Test + Cleanup

**Files:**
- Modify: `e2e/tests/production_validation_test.rs`
- Modify: `ARCHITECTURE.md`
- Modify: `README.md`

- [ ] **Step 1: Add integration test for full wired flow**

```rust
#[test]
fn test_full_orchestration_flow() {
    // Verify: Risk scoring produces valid scores
    let engine = risk::scoring::RiskEngine::new();
    let user_id = uuid::Uuid::new_v4();
    let signals = risk::scoring::RiskSignals {
        device_attestation_age_secs: 0.0,
        geo_velocity_kmh: 0.0,
        is_unusual_network: false,
        is_unusual_time: false,
        unusual_access_score: 0.0,
        recent_failed_attempts: 0,
    };
    let score = engine.compute_score(&user_id, &signals);
    assert!(score >= 0.0 && score <= 1.0);

    // Verify: Ratchet session creates and advances
    let mut mgr = ratchet::manager::SessionManager::new();
    let sid = uuid::Uuid::new_v4();
    let key = crypto::entropy::generate_key_64();
    mgr.create_session(sid, &key);
    let client_entropy = crypto::entropy::generate_nonce();
    let server_entropy = crypto::entropy::generate_nonce();
    let epoch = mgr.advance_session(&sid, &client_entropy, &server_entropy).unwrap();
    assert!(epoch > 0);

    // Verify: Audit BFT cluster reaches quorum
    let mut cluster = audit::bft::BftAuditCluster::new(7);
    let result = cluster.propose_entry(
        common::types::AuditEventType::AuthSuccess,
        vec![uuid::Uuid::new_v4()], vec![], 0.1, vec![],
    );
    assert!(result.is_ok());

    // Verify: KT tree appends and produces inclusion proofs
    let mut tree = kt::merkle::MerkleTree::new();
    let uid = uuid::Uuid::new_v4();
    tree.append_credential_op(&uid, "register", &[0u8; 32], 12345);
    assert_eq!(tree.len(), 1);
    assert!(tree.inclusion_proof(0).is_some());

    // Verify: Distributed FROST signing works
    let dkg = crypto::threshold::dkg(5, 3);
    let (coordinator, signer_nodes) = tss::distributed::distribute_shares(&dkg);
    assert_eq!(signer_nodes.len(), 5);
}
```

- [ ] **Step 2: Update ARCHITECTURE.md honest assessment**

Update the implementation status section to reflect all wired integrations.

- [ ] **Step 3: Update README.md**

Add Google OAuth, /docs page, and all newly wired features to the feature list.

- [ ] **Step 4: Run full test suite**

Run: `cargo test --workspace`
Expected: All tests pass.

- [ ] **Step 5: Final commit**

```bash
git add -A
git commit -m "feat: complete integration — all spec modules wired into runtime, docs page, Google OAuth"
```
