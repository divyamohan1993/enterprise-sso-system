//! Public hacker challenge page for the MILNET SSO Security Challenge.

use axum::http::{header, StatusCode};
use axum::response::{Html, IntoResponse, Response};

/// Returns the static HTML challenge page.
pub async fn challenge_page() -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        Html(CHALLENGE_HTML),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    async fn get_challenge_response() -> axum::http::Response<Body> {
        let app = axum::Router::new().route("/challenge", axum::routing::get(challenge_page));
        let request = Request::builder()
            .uri("/challenge")
            .body(Body::empty())
            .unwrap();
        app.oneshot(request).await.unwrap()
    }

    // ── 1. Returns 200 OK ────────────────────────────────────────────────

    #[tokio::test]
    async fn challenge_page_returns_200() {
        let resp = get_challenge_response().await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // ── 2. Content-Type is text/html ─────────────────────────────────────

    #[tokio::test]
    async fn challenge_page_content_type_html() {
        let resp = get_challenge_response().await;
        let ct = resp.headers().get(header::CONTENT_TYPE).unwrap();
        assert_eq!(ct, "text/html; charset=utf-8");
    }

    // ── 3. Contains required security challenge fields ───────────────────

    #[tokio::test]
    async fn challenge_html_contains_required_sections() {
        let html = CHALLENGE_HTML;
        assert!(html.contains("MILNET SSO Security Challenge"));
        assert!(html.contains("Live Endpoints"));
        assert!(html.contains("Cryptographic Stack"));
        assert!(html.contains("Rules of Engagement"));
        assert!(html.contains("ML-DSA-87"));
        assert!(html.contains("FROST 3-of-5"));
        assert!(html.contains("OPAQUE"));
        assert!(html.contains("AES-256-GCM"));
    }

    // ── 4. HTML is valid DOCTYPE ─────────────────────────────────────────

    #[test]
    fn challenge_html_starts_with_doctype() {
        assert!(CHALLENGE_HTML.starts_with("<!DOCTYPE html>"));
    }

    // ── 5. Contains accessibility meta tags ──────────────────────────────

    #[test]
    fn challenge_html_has_viewport_meta() {
        assert!(CHALLENGE_HTML.contains("viewport"));
        assert!(CHALLENGE_HTML.contains("charset"));
    }

    // ── 6. Contains architecture diagram ─────────────────────────────────

    #[test]
    fn challenge_html_contains_architecture() {
        assert!(CHALLENGE_HTML.contains("GATEWAY VM"));
        assert!(CHALLENGE_HTML.contains("CORE VM"));
        assert!(CHALLENGE_HTML.contains("TSS VM"));
    }

    // ── 7. Two calls return identical HTML (deterministic) ───────────────

    #[tokio::test]
    async fn challenge_page_is_deterministic() {
        use http_body_util::BodyExt;
        let resp1 = get_challenge_response().await;
        let resp2 = get_challenge_response().await;

        let body1 = resp1.into_body().collect().await.unwrap().to_bytes();
        let body2 = resp2.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body1, body2);
    }

    // ── 8. Classification banner present ─────────────────────────────────

    #[test]
    fn challenge_html_has_classification_banner() {
        assert!(CHALLENGE_HTML.contains("UNCLASSIFIED // PUBLIC CHALLENGE"));
    }
}

const CHALLENGE_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>MILNET SSO Security Challenge</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0a0a0a;color:#c0c0c0;font-family:'Courier New',Consolas,monospace;line-height:1.7;min-height:100vh}
a{color:#00bcd4;text-decoration:none}
a:hover{text-decoration:underline;color:#00ff41}

.container{max-width:960px;margin:0 auto;padding:2rem 1.5rem}

header{text-align:center;padding:3rem 0 2rem;border-bottom:1px solid #1a1a2e}
h1{font-size:2.2rem;color:#00ff41;text-transform:uppercase;letter-spacing:4px;text-shadow:0 0 20px rgba(0,255,65,0.3)}
.subtitle{font-size:1.1rem;color:#00bcd4;margin-top:0.5rem;letter-spacing:2px}
.classification{display:inline-block;border:1px solid #ff4444;color:#ff4444;padding:0.2rem 1rem;margin-top:1rem;font-size:0.75rem;letter-spacing:3px}

section{margin:2.5rem 0;padding:1.5rem;border:1px solid #1a1a2e;border-left:3px solid #00bcd4;background:#0d0d0d}
section h2{color:#00ff41;font-size:1.1rem;text-transform:uppercase;letter-spacing:2px;margin-bottom:1rem;padding-bottom:0.5rem;border-bottom:1px solid #1a1a2e}

table{width:100%;border-collapse:collapse;margin:0.5rem 0}
th{text-align:left;color:#00bcd4;padding:0.4rem 0.8rem;border-bottom:1px solid #1a1a2e;font-size:0.85rem;text-transform:uppercase;letter-spacing:1px}
td{padding:0.4rem 0.8rem;border-bottom:1px solid #111;font-size:0.85rem}
tr:hover td{background:#111}

.endpoint{color:#00ff41;font-weight:bold}
.proto{color:#888;font-size:0.8rem}

pre{background:#050505;border:1px solid #1a1a2e;padding:1rem;overflow-x:auto;font-size:0.78rem;line-height:1.5;color:#00bcd4}

.warn{color:#ff9800}.ok{color:#00ff41}
.red{color:#ff4444}
.green{color:#00ff41}
.cyan{color:#00bcd4}
.dim{color:#555}

ul{list-style:none;padding-left:0}
ul li{padding:0.3rem 0;font-size:0.88rem}
ul li::before{content:">";color:#00ff41;margin-right:0.6rem}

.defense-grid{display:grid;grid-template-columns:1fr 1fr;gap:0;border:1px solid #1a1a2e}
.defense-grid .cell{padding:0.6rem 0.8rem;border:1px solid #111;font-size:0.82rem}
.defense-grid .cell-header{background:#111;color:#00bcd4;font-weight:bold;text-transform:uppercase;letter-spacing:1px;font-size:0.75rem}

footer{text-align:center;padding:2rem 0;border-top:1px solid #1a1a2e;margin-top:2rem;font-size:0.85rem;color:#555}
footer .tagline{color:#00ff41;font-size:0.9rem;margin-bottom:0.5rem}

@media(max-width:640px){
  h1{font-size:1.4rem;letter-spacing:2px}
  .defense-grid{grid-template-columns:1fr}
  pre{font-size:0.7rem}
  section{padding:1rem}
}
</style>
</head>
<body>
<div class="container">

<header>
  <div class="classification">UNCLASSIFIED // PUBLIC CHALLENGE</div>
  <h1>MILNET SSO Security Challenge</h1>
  <p class="subtitle">Break it. We dare you.</p>
</header>

<!-- ============================================================ -->
<section>
<h2>Live Endpoints</h2>
<table>
<tr>
  <th>Service</th><th>Address</th><th>Protocol</th>
</tr>
<tr>
  <td>Admin API</td>
  <td class="endpoint">https://&lt;ADMIN_API_HOST&gt;:8443</td>
  <td class="proto">HTTPS/1.1 REST (mTLS)</td>
</tr>
<tr>
  <td>Gateway</td>
  <td class="endpoint">34.100.250.234:9100</td>
  <td class="proto">TCP &mdash; X-Wing encrypted (ML-KEM-1024 + X25519)</td>
</tr>
</table>
</section>

<!-- ============================================================ -->
<section>
<h2>Architecture &mdash; 3-VM Distributed Layout</h2>
<pre>
 ┌─────────────────────────────────────────────────────────────────────┐
 │                        INTERNET                                    │
 └────────────────────────────┬────────────────────────────────────────┘
                              │
              ┌───────────────▼───────────────┐
              │         GATEWAY VM            │
              │  ┌─────────┐  ┌────────────┐  │
              │  │ gateway  │  │orchestrator│  │   No secrets.
              │  │ :9100    │  │            │  │   No DB access.
              │  └─────────┘  └────────────┘  │   X-Wing tunnel only.
              └───────────────┬───────────────┘
                              │ internal TCP
              ┌───────────────▼───────────────┐
              │           CORE VM             │
              │  ┌───────┐ ┌───────┐ ┌─────┐  │
              │  │opaque │ │ admin │ │audit│  │   DB + KMS access.
              │  │       │ │ :8080 │ │     │  │   Field-level AES-256-GCM.
              │  └───────┘ └───────┘ └─────┘  │   Master KEK in memory.
              │  ┌────────┐ ┌────────┐        │
              │  │verifier│ │ratchet │        │
              │  └────────┘ └────────┘        │
              └───────────────┬───────────────┘
                              │ internal TCP
              ┌───────────────▼───────────────┐
              │           TSS VM              │
              │  ┌────────┐┌────────┐┌──────┐ │
              │  │FROST #1││FROST #2││FROST │ │   No DB. No KEK.
              │  │        ││        ││  #3  │ │   Threshold shares only.
              │  └────────┘└────────┘└──────┘ │   3-of-5 EdDSA signing.
              └───────────────────────────────┘
</pre>
</section>

<!-- ============================================================ -->
<section>
<h2>Cryptographic Stack</h2>
<table>
<tr><th>Primitive</th><th>Specification</th><th>Purpose</th></tr>
<tr><td class="green">ML-KEM-1024 + X25519</td><td>X-Wing hybrid KEM</td><td>Post-quantum key encapsulation for gateway tunnel</td></tr>
<tr><td class="green">ML-DSA-87</td><td>FIPS 204</td><td>Post-quantum digital signatures (audit log, attestation)</td></tr>
<tr><td class="green">FROST 3-of-5</td><td>Threshold EdDSA (RFC 9645)</td><td>Distributed token signing &mdash; no single key holder</td></tr>
<tr><td class="green">AES-256-GCM</td><td>NIST SP 800-38D</td><td>Field-level encryption of all PII at rest</td></tr>
<tr><td class="green">OPAQUE</td><td>RFC 9497</td><td>Server-blind password authentication (server never sees passwords)</td></tr>
<tr><td class="green">Argon2id</td><td>RFC 9106</td><td>Memory-hard KDF: 64 MiB, 3 iterations, 4 lanes</td></tr>
<tr><td class="green">HKDF-SHA512 ratchet</td><td>RFC 5869</td><td>Forward-secret epoch keys: 10s epochs, &plusmn;3 window tolerance</td></tr>
<tr><td class="green">17 domain-separation prefixes</td><td>&mdash;</td><td>Prevents cross-context key/signature reuse</td></tr>
</table>
</section>

<!-- ============================================================ -->
<section>
<h2>Token Lifetimes</h2>
<table>
<tr><th>Tier</th><th>Auth Level</th><th>Token Lifetime</th><th>Requirements</th></tr>
<tr><td class="cyan">Tier 1</td><td>Password only</td><td class="warn">5 minutes</td><td>OPAQUE login</td></tr>
<tr><td class="cyan">Tier 2</td><td>+ Device attestation</td><td class="warn">10 minutes</td><td>FIDO2 / device bound key</td></tr>
<tr><td class="cyan">Tier 3</td><td>+ Biometric</td><td class="warn">30 minutes</td><td>Biometric confirmation + platform binding</td></tr>
<tr><td class="cyan">Tier 4</td><td>+ Multi-person ceremony</td><td class="warn">60 minutes</td><td>M-of-N approval by designated officers</td></tr>
<tr><td class="dim">Inactivity</td><td colspan="3">15-minute idle timeout across all tiers (AAL3 compliance)</td></tr>
</table>
</section>

<!-- ============================================================ -->
<section>
<h2>What You're Up Against</h2>
<p style="margin-bottom:1rem;font-size:0.85rem;color:#888">
  Every layer is independent. Compromising one does not give you the next.
</p>
<div class="defense-grid">
  <div class="cell cell-header">If you compromise...</div>
  <div class="cell cell-header">You still need...</div>

  <div class="cell">Gateway VM (full root)</div>
  <div class="cell">X-Wing session keys (ML-KEM-1024 + X25519 hybrid). Traffic is opaque ciphertext.</div>

  <div class="cell">Core VM database</div>
  <div class="cell">Master KEK (memory-only, never on disk) to decrypt any field. Plus OPAQUE registrations are server-blind.</div>

  <div class="cell">Master KEK</div>
  <div class="cell">FROST threshold shares on TSS VM to forge any token signature. 3-of-5 required.</div>

  <div class="cell">One TSS node</div>
  <div class="cell">Two more TSS nodes (3-of-5). Each node holds only its share, never the full signing key.</div>

  <div class="cell">A valid token</div>
  <div class="cell">It expires in 5-60 minutes. HKDF ratchet rotates verification keys every 10 seconds.</div>

  <div class="cell">Network traffic (MITM)</div>
  <div class="cell">Post-quantum KEM. Classical AND quantum break required simultaneously (X-Wing hybrid).</div>

  <div class="cell">User's password hash</div>
  <div class="cell">There isn't one. OPAQUE means the server never sees or stores password-equivalent material.</div>

  <div class="cell">Audit log</div>
  <div class="cell">ML-DSA-87 signatures + Merkle tree. Tampering is cryptographically detectable.</div>
</div>
</section>

<!-- ============================================================ -->
<section>
<h2>Rules of Engagement</h2>
<ul>
  <li>All endpoints listed above are <span class="green">live and accessible</span> right now</li>
  <li><strong>Objective:</strong> extract plaintext user passwords, forge valid tokens, or decrypt stored data</li>
  <li>The system uses post-quantum cryptography &mdash; <span class="warn">quantum computers won't help</span></li>
  <li>Source code is fully open: <a href="https://github.com/divyamohan1993/enterprise-sso-system">github.com/divyamohan1993/enterprise-sso-system</a></li>
  <li>No rate limiting on the challenge endpoints &mdash; go ahead, automate</li>
  <li>If you find a real vulnerability, responsible disclosure is appreciated</li>
</ul>
</section>

<!-- ============================================================ -->
<section>
<h2>Known Honest Limitations</h2>
<p style="margin-bottom:0.8rem;font-size:0.82rem;color:#888">
  We believe in transparency. These are the current gaps we know about:
</p>
<ul>
  <li><span class="ok">Master KEK:</span> 256-bit random, stored in GCP Secret Manager, fetched at runtime via IAM — never on disk, never in metadata</li>
  <li><span class="ok">Cloud KMS HSM:</span> FIPS 140-3 Level 3 hardware security module — key material never leaves the hardware</li>
  <li><span class="ok">DB Password:</span> 80-char random, stored in Secret Manager, auto-rotatable — never plaintext anywhere</li>
  <li><span class="ok">3-VM Isolation:</span> Gateway, Core, and TSS on separate VMs with separate service accounts and unique HMAC keys</li>
  <li><span class="warn">TSS co-location:</span> 3 FROST nodes share one VM (cost constraint); production would use 3 separate hosts in different zones</li>
  <li><span class="warn">No vTPM:</span> Platform attestation runs but SPOT VMs lack vTPM hardware; shielded VMs would fix this</li>
  <li><span class="warn">Plain TCP internal:</span> Inter-service uses unencrypted TCP over private VPC (mTLS code exists, not wired in sandbox)</li>
  <li><span class="warn">SPOT VMs:</span> Instances may be preempted; this is a sandbox, not HA</li>
</ul>
</section>

<!-- ============================================================ -->
<footer>
  <p class="tagline">Built with Rust. No unsafe shortcuts. 16 crates. 400+ tests. Zero tolerance.</p>
  <p class="dim">MILNET SSO &mdash; Enterprise Security System</p>
</footer>

</div>
</body>
</html>"#;
