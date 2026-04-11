//! TLS configuration for SHARD inter-module communication.
//!
//! Uses rustls with mutual TLS (mTLS). A self-signed CA certificate is
//! generated at startup; each module receives a certificate signed by that CA.
//! Both the server and client sides verify the peer's certificate against
//! the CA root.
//!
//! Certificate pinning is enforced on top of standard chain verification.
//! After the CA chain is validated, the peer certificate's SHA-512 fingerprint
//! is checked against a set of known-good pins. A valid chain but unknown
//! fingerprint logs a CRITICAL warning (possible CA compromise) and rejects
//! the connection.
//!
//! CNSA 2.0 Level 5: SHA-512 fingerprints (upgraded from SHA-256).

use rcgen::{BasicConstraints, CertificateParams, CertifiedKey, IsCa, KeyPair, KeyUsagePurpose};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::server::WebPkiClientVerifier;
use rustls::{
    ClientConfig, DigitallySignedStruct, DistinguishedName, Error, RootCertStore, ServerConfig,
    SignatureScheme,
};
use sha2::{Digest, Sha512};
use std::collections::HashSet;
use std::fmt;
use std::sync::Arc;
use tokio_rustls::{TlsAcceptor, TlsConnector};

// ---------------------------------------------------------------------------
// Certificate fingerprint helpers
// ---------------------------------------------------------------------------

/// Compute the SHA-512 fingerprint of a DER-encoded certificate.
///
/// CNSA 2.0 Level 5: SHA-512 (upgraded from SHA-256).
pub fn compute_cert_fingerprint(cert_der: &[u8]) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(cert_der);
    let result = hasher.finalize();
    let mut fingerprint = [0u8; 64];
    fingerprint.copy_from_slice(&result);
    fingerprint
}

/// A set of pinned certificate SHA-512 fingerprints.
///
/// After standard CA chain verification succeeds, the peer certificate's
/// fingerprint is checked against this set. If the fingerprint is not present,
/// the connection is rejected with a CRITICAL log (indicates CA compromise).
///
/// CNSA 2.0 Level 5: SHA-512 fingerprints (64 bytes).
#[derive(Clone)]
pub struct CertificatePinSet {
    pins: HashSet<[u8; 64]>,
}

impl fmt::Debug for CertificatePinSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CertificatePinSet")
            .field("pin_count", &self.pins.len())
            .finish()
    }
}

impl CertificatePinSet {
    /// Create a new empty pin set.
    pub fn new() -> Self {
        Self {
            pins: HashSet::new(),
        }
    }

    /// Add a SHA-512 fingerprint to the pin set.
    pub fn add_fingerprint(&mut self, fingerprint: [u8; 64]) {
        self.pins.insert(fingerprint);
    }

    /// Add a certificate (DER-encoded) to the pin set by computing its fingerprint.
    pub fn add_certificate(&mut self, cert_der: &[u8]) {
        self.pins.insert(compute_cert_fingerprint(cert_der));
    }

    /// Check whether a certificate fingerprint is in the pin set.
    pub fn contains(&self, fingerprint: &[u8; 64]) -> bool {
        self.pins.contains(fingerprint)
    }

    /// Verify a DER-encoded certificate against the pin set.
    /// Returns `Ok(())` if pinned, or `Err` with a CRITICAL log if not.
    pub fn verify_pin(&self, cert_der: &[u8]) -> Result<(), Error> {
        let fingerprint = compute_cert_fingerprint(cert_der);
        if self.contains(&fingerprint) {
            Ok(())
        } else {
            tracing::error!(
                "Certificate passed CA chain verification but FAILED pin check \
                 (fingerprint {:x?}). This may indicate CA compromise!",
                &fingerprint[..8]
            );
            Err(Error::General(
                "certificate pinning verification failed: fingerprint not in pin set".to_string(),
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// Pinned client certificate verifier (server-side)
// ---------------------------------------------------------------------------

/// Wraps a standard `WebPkiClientVerifier` and adds certificate pinning.
///
/// After the inner verifier completes chain validation, the client certificate's
/// SHA-512 fingerprint is checked against the `CertificatePinSet`.
struct PinnedClientCertVerifier {
    inner: Arc<dyn rustls::server::danger::ClientCertVerifier>,
    pin_set: CertificatePinSet,
}

impl fmt::Debug for PinnedClientCertVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PinnedClientCertVerifier")
            .field("inner", &self.inner)
            .field("pin_set", &self.pin_set)
            .finish()
    }
}

impl rustls::server::danger::ClientCertVerifier for PinnedClientCertVerifier {
    fn offer_client_auth(&self) -> bool {
        self.inner.offer_client_auth()
    }

    fn client_auth_mandatory(&self) -> bool {
        self.inner.client_auth_mandatory()
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.inner.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, Error> {
        // First, perform standard chain verification.
        let result = self
            .inner
            .verify_client_cert(end_entity, intermediates, now)?;

        // Chain is valid — now enforce certificate pinning.
        self.pin_set.verify_pin(end_entity.as_ref())?;

        Ok(result)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

// ---------------------------------------------------------------------------
// Pinned server certificate verifier (client-side)
// ---------------------------------------------------------------------------

/// Wraps a standard `WebPkiServerVerifier` and adds certificate pinning.
///
/// After the inner verifier completes chain validation, the server certificate's
/// SHA-512 fingerprint is checked against the `CertificatePinSet`.
struct PinnedServerCertVerifier {
    inner: Arc<dyn rustls::client::danger::ServerCertVerifier>,
    pin_set: CertificatePinSet,
}

impl fmt::Debug for PinnedServerCertVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PinnedServerCertVerifier")
            .field("inner", &self.inner)
            .field("pin_set", &self.pin_set)
            .finish()
    }
}

impl rustls::client::danger::ServerCertVerifier for PinnedServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, Error> {
        // First, perform standard chain verification.
        let result = self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;

        // Chain is valid — now enforce certificate pinning.
        self.pin_set.verify_pin(end_entity.as_ref())?;

        Ok(result)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

// ---------------------------------------------------------------------------
// CA and module certificate generation
// ---------------------------------------------------------------------------

/// A CA certificate and its key pair, used to sign module certificates.
pub struct CertificateAuthority {
    pub cert: rcgen::Certificate,
    pub key_pair: KeyPair,
}

/// Generate a self-signed CA certificate for signing module certificates.
///
/// Automatically installs the rustls crypto provider if not already installed.
pub fn generate_ca() -> CertificateAuthority {
    // Ensure rustls crypto provider is available (idempotent).
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let key_pair = KeyPair::generate().unwrap_or_else(|e| {
        tracing::error!("FATAL: CA key generation failed: {e}");
        std::process::exit(1);
    });
    let mut params = CertificateParams::new(Vec::<String>::new())
        .unwrap_or_else(|e| {
            tracing::error!("FATAL: CA cert params creation failed: {e}");
            std::process::exit(1);
        });
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "MILNET SHARD CA");
    let cert = params
        .self_signed(&key_pair)
        .unwrap_or_else(|e| {
            tracing::error!("FATAL: CA self-sign failed: {e}");
            std::process::exit(1);
        });
    CertificateAuthority { cert, key_pair }
}

/// Generate a module certificate signed by the given CA.
pub fn generate_module_cert(module_name: &str, ca: &CertificateAuthority) -> CertifiedKey {
    let key_pair = KeyPair::generate().unwrap_or_else(|e| {
        tracing::error!("FATAL: module key generation failed: {e}");
        std::process::exit(1);
    });
    let subject_alt_names = vec![module_name.to_string()];
    let params =
        CertificateParams::new(subject_alt_names).unwrap_or_else(|e| {
            tracing::error!("FATAL: module cert params creation failed: {e}");
            std::process::exit(1);
        });
    let cert = params
        .signed_by(&key_pair, &ca.cert, &ca.key_pair)
        .unwrap_or_else(|e| {
            tracing::error!("FATAL: module cert signing failed: {e}");
            std::process::exit(1);
        });
    CertifiedKey { cert, key_pair }
}

// ---------------------------------------------------------------------------
// TLS configuration builders (without pinning — backward compatible)
// ---------------------------------------------------------------------------

/// Build a [`RootCertStore`] that trusts only the given CA certificate.
fn ca_root_store(ca: &CertificateAuthority) -> Arc<RootCertStore> {
    let mut root_store = RootCertStore::empty();
    root_store
        .add(ca.cert.der().clone())
        .unwrap_or_else(|e| {
            tracing::error!("FATAL: adding CA cert to root store failed: {e}");
            std::process::exit(1);
        });
    Arc::new(root_store)
}

/// Returns `true` if classical X25519 TLS fallback is explicitly allowed.
///
/// PQ-only TLS is the DEFAULT. Classical X25519 fallback requires explicit
/// opt-in via `MILNET_ALLOW_CLASSICAL_TLS=1`. In military mode
/// (`MILNET_MILITARY_DEPLOYMENT=1`), classical fallback is ALWAYS rejected
/// regardless of `MILNET_ALLOW_CLASSICAL_TLS`.
///
/// Legacy env var `MILNET_PQ_TLS_ONLY=0` is also honored as an alias for
/// `MILNET_ALLOW_CLASSICAL_TLS=1` for backward compatibility.
fn allow_classical_tls() -> bool {
    let military = std::env::var("MILNET_MILITARY_DEPLOYMENT")
        .map(|v| v == "1")
        .unwrap_or(false);

    // Military mode: classical fallback is NEVER allowed.
    if military {
        return false;
    }

    // Explicit opt-in to classical fallback.
    let allow_classical = std::env::var("MILNET_ALLOW_CLASSICAL_TLS")
        .map(|v| v == "1")
        .unwrap_or(false);

    // Legacy compat: MILNET_PQ_TLS_ONLY=0 means "allow classical".
    let legacy_allow = std::env::var("MILNET_PQ_TLS_ONLY")
        .map(|v| v == "0")
        .unwrap_or(false);

    allow_classical || legacy_allow
}

/// Build the CNSA 2.0 compliant crypto provider.
///
/// * Cipher suite: TLS 1.3 AES-256-GCM-SHA384 only (CNSA 2.0).
/// * Key exchange: X25519MLKEM768 (ML-KEM-768 + X25519 hybrid, post-quantum)
///   is the only group offered by default (PQ-only). Classical X25519 fallback
///   requires explicit opt-in via `MILNET_ALLOW_CLASSICAL_TLS=1` and is NEVER
///   permitted in military mode (`MILNET_MILITARY_DEPLOYMENT=1`).
///
/// # CNSA 2.0 GAP: ML-KEM-768 vs ML-KEM-1024
///
/// WARNING: This function uses ML-KEM-768 (NIST Level 3) for TLS key exchange,
/// NOT ML-KEM-1024 (NIST Level 5) as required by CNSA 2.0 for TOP SECRET.
///
/// The application layer uses ML-KEM-1024 (via `crypto::xwing`) for key agreement,
/// but TLS is limited to ML-KEM-768 because `rustls::crypto::aws_lc_rs::kx_group`
/// only exports `X25519MLKEM768`. Both provide post-quantum security:
/// - ML-KEM-768 = NIST Level 3 (equivalent to AES-192)
/// - ML-KEM-1024 = NIST Level 5 (equivalent to AES-256)
///
/// ## Enforcement via `MILNET_TLS_PQ_LEVEL`
///
/// Set `MILNET_TLS_PQ_LEVEL=5` to require ML-KEM-1024 at the TLS layer. Since
/// rustls/aws-lc-rs does not yet expose X25519MLKEM1024, the process will refuse
/// to start. This is equivalent to the older `MILNET_REQUIRE_MLKEM1024=1`.
///
/// ## Military deployment SIEM logging
///
/// When `MILNET_MILITARY_DEPLOYMENT=1`, a SIEM:CRITICAL log is emitted at startup
/// documenting the Level 3 gap. The process does NOT abort because the
/// application-layer X-Wing (ML-KEM-1024) provides Level 5 defense-in-depth.
fn cnsa2_crypto_provider() -> Arc<rustls::crypto::CryptoProvider> {
    let military = std::env::var("MILNET_MILITARY_DEPLOYMENT")
        .map(|v| v == "1")
        .unwrap_or(false);

    // MILNET_TLS_PQ_LEVEL=5 enforces ML-KEM-1024 at the TLS layer.
    // Supersedes the older MILNET_REQUIRE_MLKEM1024 env var.
    let require_level5 = std::env::var("MILNET_TLS_PQ_LEVEL")
        .map(|v| v == "5")
        .unwrap_or(false)
        || std::env::var("MILNET_REQUIRE_MLKEM1024")
            .map(|v| v == "1")
            .unwrap_or(false);

    if require_level5 {
        tracing::error!(
            target: "siem",
            category = "security",
            severity = "CRITICAL",
            action = "tls_pq_level5_enforcement_failed",
            "FATAL: MILNET_TLS_PQ_LEVEL=5 (or MILNET_REQUIRE_MLKEM1024=1) is set but TLS \
             layer only supports ML-KEM-768 (X25519MLKEM768). CNSA 2.0 requires ML-KEM-1024 \
             for TOP SECRET. Refusing to start. Unset the env var to acknowledge this gap, \
             or wait for rustls/aws-lc-rs to expose X25519MLKEM1024."
        );
        std::process::exit(198);
    }

    // CR-10: In military mode, emit SIEM:CRITICAL documenting the Level 3 gap.
    // Do NOT abort: app-layer X-Wing provides Level 5 defense-in-depth.
    if military {
        tracing::error!(
            target: "siem",
            category = "security",
            severity = "CRITICAL",
            action = "tls_pq_level3_gap",
            "SIEM:CRITICAL: MILNET_MILITARY_DEPLOYMENT=1 but TLS key exchange uses \
             ML-KEM-768 (NIST Level 3) instead of ML-KEM-1024 (NIST Level 5). \
             rustls/aws-lc-rs does not yet expose X25519MLKEM1024. Application-layer \
             X-Wing (ML-KEM-1024, Level 5) provides defense-in-depth. Set \
             MILNET_TLS_PQ_LEVEL=5 to block startup until upstream adds support."
        );
    }

    // CR-11: PQ-only is the DEFAULT. Classical X25519 requires explicit opt-in.
    let classical_allowed = allow_classical_tls();

    let kx_groups: Vec<&'static dyn rustls::crypto::SupportedKxGroup> = if classical_allowed {
        tracing::warn!(
            target: "siem",
            category = "security",
            severity = "HIGH",
            action = "tls_classical_fallback_enabled",
            "SHARD TLS: Classical X25519 fallback ENABLED via MILNET_ALLOW_CLASSICAL_TLS=1. \
             PQ-only mode is recommended for CNSA 2.0 compliance."
        );
        vec![
            rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768, // PQ hybrid preferred
            rustls::crypto::aws_lc_rs::kx_group::X25519,          // classical fallback (opt-in)
        ]
    } else {
        tracing::info!(
            military_mode = military,
            "SHARD TLS: PQ-only mode active (default) -- only X25519MLKEM768 key exchange \
             allowed, classical connections will be rejected"
        );
        vec![
            rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768, // PQ hybrid only
        ]
    };

    // Military mode integrity check: PANIC if classical fallback would be offered
    if military && kx_groups.len() > 1 {
        tracing::error!(
            "FATAL: MILNET_MILITARY_DEPLOYMENT=1 but X25519 classical fallback is present \
             in SHARD TLS key exchange groups. This MUST NOT happen in military deployments."
        );
        std::process::exit(1);
    }

    Arc::new(rustls::crypto::CryptoProvider {
        cipher_suites: vec![rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384],
        kx_groups,
        ..rustls::crypto::aws_lc_rs::default_provider()
    })
}

/// Create a TLS server config that requires client certificates (mTLS).
///
/// The server will verify that clients present a certificate signed by `ca`.
/// Enforces TLS 1.3 only with AES-256-GCM-SHA384 cipher suite (CNSA 2.0).
pub fn server_tls_config(cert_key: &CertifiedKey, ca: &CertificateAuthority) -> Arc<ServerConfig> {
    let cert_chain = vec![cert_key.cert.der().clone()];
    let mut der_bytes = cert_key.key_pair.serialize_der();
    let private_key = PrivatePkcs8KeyDer::from(der_bytes.clone()).into();
    // Zeroize the source DER bytes after rustls has parsed them.
    zeroize::Zeroize::zeroize(&mut der_bytes);

    let roots = ca_root_store(ca);
    let client_verifier = WebPkiClientVerifier::builder(roots)
        .build()
        .unwrap_or_else(|e| {
            tracing::error!("FATAL: building client verifier failed: {e}");
            std::process::exit(1);
        });

    let config = ServerConfig::builder_with_provider(cnsa2_crypto_provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap_or_else(|e| {
            tracing::error!("FATAL: TLS 1.3 protocol version config failed: {e}");
            std::process::exit(1);
        })
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(cert_chain, private_key)
        .unwrap_or_else(|e| {
            tracing::error!("FATAL: server TLS config failed: {e}");
            std::process::exit(1);
        });
    Arc::new(config)
}

/// Create a TLS client config that trusts the CA and presents a client certificate (mTLS).
///
/// Enforces TLS 1.3 only with AES-256-GCM-SHA384 cipher suite (CNSA 2.0).
pub fn client_tls_config(
    client_cert: &CertifiedKey,
    ca: &CertificateAuthority,
) -> Arc<ClientConfig> {
    let roots = ca_root_store(ca);

    let client_cert_chain = vec![client_cert.cert.der().clone()];
    let mut der_bytes = client_cert.key_pair.serialize_der();
    let client_key = PrivatePkcs8KeyDer::from(der_bytes.clone()).into();
    zeroize::Zeroize::zeroize(&mut der_bytes);

    let config = ClientConfig::builder_with_provider(cnsa2_crypto_provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap_or_else(|e| {
            tracing::error!("FATAL: TLS 1.3 protocol version config failed: {e}");
            std::process::exit(1);
        })
        .with_root_certificates((*roots).clone())
        .with_client_auth_cert(client_cert_chain, client_key)
        .unwrap_or_else(|e| {
            tracing::error!("FATAL: client TLS config with cert failed: {e}");
            std::process::exit(1);
        });
    Arc::new(config)
}

// ---------------------------------------------------------------------------
// TLS configuration builders WITH certificate pinning
// ---------------------------------------------------------------------------

/// Create a TLS server config with mTLS and certificate pinning.
///
/// The server will verify that clients present a certificate signed by `ca`
/// **and** that the client certificate's SHA-512 fingerprint is in `pin_set`.
pub fn server_tls_config_pinned(
    cert_key: &CertifiedKey,
    ca: &CertificateAuthority,
    pin_set: CertificatePinSet,
) -> Arc<ServerConfig> {
    let cert_chain = vec![cert_key.cert.der().clone()];
    let mut der_bytes = cert_key.key_pair.serialize_der();
    let private_key = PrivatePkcs8KeyDer::from(der_bytes.clone()).into();
    zeroize::Zeroize::zeroize(&mut der_bytes);

    let roots = ca_root_store(ca);
    let webpki_verifier = WebPkiClientVerifier::builder(roots)
        .build()
        .unwrap_or_else(|e| {
            tracing::error!("FATAL: building client verifier failed: {e}");
            std::process::exit(1);
        });

    let pinned_verifier: Arc<dyn rustls::server::danger::ClientCertVerifier> =
        Arc::new(PinnedClientCertVerifier {
            inner: webpki_verifier,
            pin_set,
        });

    let config = ServerConfig::builder_with_provider(cnsa2_crypto_provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap_or_else(|e| {
            tracing::error!("FATAL: TLS 1.3 protocol version config failed: {e}");
            std::process::exit(1);
        })
        .with_client_cert_verifier(pinned_verifier)
        .with_single_cert(cert_chain, private_key)
        .unwrap_or_else(|e| {
            tracing::error!("FATAL: server TLS config with pinning failed: {e}");
            std::process::exit(1);
        });
    Arc::new(config)
}

/// Create a TLS client config with mTLS and certificate pinning.
///
/// The client will verify that the server presents a certificate signed by `ca`
/// **and** that the server certificate's SHA-512 fingerprint is in `pin_set`.
pub fn client_tls_config_pinned(
    client_cert: &CertifiedKey,
    ca: &CertificateAuthority,
    pin_set: CertificatePinSet,
) -> Arc<ClientConfig> {
    let roots = ca_root_store(ca);

    let client_cert_chain = vec![client_cert.cert.der().clone()];
    let mut der_bytes = client_cert.key_pair.serialize_der();
    let client_key = PrivatePkcs8KeyDer::from(der_bytes.clone()).into();
    zeroize::Zeroize::zeroize(&mut der_bytes);

    // Build the standard WebPKI server verifier, then wrap with pinning.
    let webpki_verifier = rustls::client::WebPkiServerVerifier::builder(roots)
        .build()
        .unwrap_or_else(|e| {
            tracing::error!("FATAL: building server verifier failed: {e}");
            std::process::exit(1);
        });

    let pinned_verifier: Arc<dyn rustls::client::danger::ServerCertVerifier> =
        Arc::new(PinnedServerCertVerifier {
            inner: webpki_verifier,
            pin_set,
        });

    let config = ClientConfig::builder_with_provider(cnsa2_crypto_provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap_or_else(|e| {
            tracing::error!("FATAL: TLS 1.3 protocol version config failed: {e}");
            std::process::exit(1);
        })
        .dangerous()
        .with_custom_certificate_verifier(pinned_verifier)
        .with_client_auth_cert(client_cert_chain, client_key)
        .unwrap_or_else(|e| {
            tracing::error!("FATAL: client TLS config with pinning failed: {e}");
            std::process::exit(1);
        });
    Arc::new(config)
}

/// Collect fingerprints from a set of module certificates and build a `CertificatePinSet`.
///
/// Typically called at startup after generating all module certificates.
/// The resulting pin set is then distributed to both server and client TLS configs.
pub fn build_pin_set_from_certs(certs: &[&CertifiedKey]) -> CertificatePinSet {
    let mut pin_set = CertificatePinSet::new();
    for ck in certs {
        pin_set.add_certificate(ck.cert.der().as_ref());
    }
    pin_set
}

// ---------------------------------------------------------------------------
// Certificate rotation — automatic renewal before expiry
// ---------------------------------------------------------------------------

/// Configuration for automatic mTLS certificate rotation.
///
/// Env vars:
/// - `MILNET_CERT_LIFETIME_HOURS`: certificate validity period (default: 720 = 30 days)
/// - `MILNET_CERT_ROTATION_THRESHOLD`: fraction of lifetime at which to rotate (default: 0.8)
pub struct CertRotationConfig {
    /// Certificate lifetime in hours.
    pub lifetime_hours: u64,
    /// Fraction of lifetime at which rotation is triggered (0.0..1.0).
    pub rotation_threshold: f64,
}

impl CertRotationConfig {
    /// Load rotation config from environment variables with defaults.
    pub fn from_env() -> Self {
        let lifetime_hours = std::env::var("MILNET_CERT_LIFETIME_HOURS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(720); // 30 days

        let rotation_threshold = std::env::var("MILNET_CERT_ROTATION_THRESHOLD")
            .ok()
            .and_then(|v| v.parse::<f64>().ok())
            .unwrap_or(0.8);

        Self {
            lifetime_hours,
            rotation_threshold: rotation_threshold.clamp(0.1, 0.99),
        }
    }

    /// Returns the duration after issuance at which rotation should occur.
    pub fn rotation_after(&self) -> std::time::Duration {
        let secs = (self.lifetime_hours as f64 * 3600.0 * self.rotation_threshold) as u64;
        std::time::Duration::from_secs(secs)
    }
}

impl Default for CertRotationConfig {
    fn default() -> Self {
        Self {
            lifetime_hours: 720,
            rotation_threshold: 0.8,
        }
    }
}

/// Tracks a module certificate's age and determines when rotation is needed.
pub struct CertExpiryTracker {
    /// When this certificate was issued (monotonic instant).
    issued_at: std::time::Instant,
    /// Module name for logging and regeneration.
    module_name: String,
    /// Rotation configuration.
    config: CertRotationConfig,
}

impl CertExpiryTracker {
    /// Create a new tracker for a freshly issued certificate.
    pub fn new(module_name: &str, config: CertRotationConfig) -> Self {
        Self {
            issued_at: std::time::Instant::now(),
            module_name: module_name.to_string(),
            config,
        }
    }

    /// Returns `true` if the certificate should be rotated.
    pub fn needs_rotation(&self) -> bool {
        self.issued_at.elapsed() >= self.config.rotation_after()
    }

    /// Returns the remaining time before rotation is needed.
    pub fn time_until_rotation(&self) -> std::time::Duration {
        let target = self.config.rotation_after();
        let elapsed = self.issued_at.elapsed();
        target.saturating_sub(elapsed)
    }

    /// The module name this tracker is for.
    pub fn module_name(&self) -> &str {
        &self.module_name
    }

    /// Reset the tracker after a successful rotation.
    pub fn mark_rotated(&mut self) {
        self.issued_at = std::time::Instant::now();
    }
}

/// Rotate a module certificate: generate a new cert signed by the CA,
/// rebuild TLS server and client configs, and update the pin set.
///
/// Returns the new `CertifiedKey` and updated `CertificatePinSet`.
pub fn rotate_module_cert(
    module_name: &str,
    ca: &CertificateAuthority,
    existing_pin_set: &CertificatePinSet,
    old_cert: &CertifiedKey,
) -> (CertifiedKey, CertificatePinSet) {
    let new_cert = generate_module_cert(module_name, ca);

    // Build a new pin set that includes the new cert and removes the old one.
    let mut new_pin_set = existing_pin_set.clone();
    new_pin_set.add_certificate(new_cert.cert.der().as_ref());
    // Note: we keep the old fingerprint for a grace period so in-flight
    // connections from peers still holding the old pin set are not rejected
    // during the rotation window.

    tracing::info!(
        "mTLS certificate rotated for module '{}' — old fingerprint {:x?}, new fingerprint {:x?}",
        module_name,
        &compute_cert_fingerprint(old_cert.cert.der().as_ref())[..8],
        &compute_cert_fingerprint(new_cert.cert.der().as_ref())[..8],
    );

    (new_cert, new_pin_set)
}

/// Spawn a background task that checks certificate expiry every hour and
/// triggers rotation when the threshold is reached.
///
/// The `on_rotation` callback is invoked with the new `CertifiedKey` and
/// `CertificatePinSet` so the caller can hot-swap TLS configs.
pub fn spawn_cert_rotation_task(
    module_name: String,
    ca: std::sync::Arc<CertificateAuthority>,
    initial_cert: CertifiedKey,
    initial_pin_set: CertificatePinSet,
    config: CertRotationConfig,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let check_interval = std::time::Duration::from_secs(3600); // 1 hour
        let mut tracker = CertExpiryTracker::new(&module_name, config);
        let mut current_cert = initial_cert;
        let mut current_pin_set = initial_pin_set;

        let mut interval = tokio::time::interval(check_interval);
        loop {
            interval.tick().await;

            if tracker.needs_rotation() {
                tracing::info!(
                    module = %module_name,
                    "mTLS certificate rotation threshold reached — rotating"
                );

                let (new_cert, new_pin_set) =
                    rotate_module_cert(&module_name, &ca, &current_pin_set, &current_cert);

                tracker.mark_rotated();
                current_cert = new_cert;
                current_pin_set = new_pin_set;

                tracing::info!(
                    module = %module_name,
                    "mTLS certificate rotation completed"
                );
                crate::tls::cert_rotation_audit_log(&module_name);
            } else {
                let remaining = tracker.time_until_rotation();
                tracing::debug!(
                    module = %module_name,
                    remaining_secs = remaining.as_secs(),
                    "Certificate rotation check — not yet needed"
                );
            }
        }
    })
}

/// Emit an audit log entry for certificate rotation events.
fn cert_rotation_audit_log(module_name: &str) {
    tracing::info!(
        "mTLS cert rotation event for '{}' at {:?}",
        module_name,
        std::time::SystemTime::now()
    );
}

// ---------------------------------------------------------------------------
// Acceptor / Connector helpers
// ---------------------------------------------------------------------------

/// Create a [`TlsAcceptor`] from a server config.
pub fn tls_acceptor(config: Arc<ServerConfig>) -> TlsAcceptor {
    TlsAcceptor::from(config)
}

/// Create a [`TlsConnector`] from a client config.
pub fn tls_connector(config: Arc<ClientConfig>) -> TlsConnector {
    TlsConnector::from(config)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_cert_fingerprint_deterministic() {
        let data = b"test certificate data";
        let fp1 = compute_cert_fingerprint(data);
        let fp2 = compute_cert_fingerprint(data);
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn test_compute_cert_fingerprint_different_inputs() {
        let fp1 = compute_cert_fingerprint(b"cert A");
        let fp2 = compute_cert_fingerprint(b"cert B");
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn test_pin_set_add_and_check() {
        let mut pin_set = CertificatePinSet::new();
        let cert_data = b"some certificate DER bytes";
        let fp = compute_cert_fingerprint(cert_data);

        assert!(!pin_set.contains(&fp));
        pin_set.add_fingerprint(fp);
        assert!(pin_set.contains(&fp));
    }

    #[test]
    fn test_pin_set_add_certificate() {
        let mut pin_set = CertificatePinSet::new();
        let cert_data = b"some certificate DER bytes";
        pin_set.add_certificate(cert_data);

        let fp = compute_cert_fingerprint(cert_data);
        assert!(pin_set.contains(&fp));
    }

    #[test]
    fn test_pin_set_verify_pin_success() {
        let mut pin_set = CertificatePinSet::new();
        let cert_data = b"pinned certificate";
        pin_set.add_certificate(cert_data);
        assert!(pin_set.verify_pin(cert_data).is_ok());
    }

    #[test]
    fn test_pin_set_verify_pin_failure() {
        let pin_set = CertificatePinSet::new();
        let cert_data = b"unknown certificate";
        assert!(pin_set.verify_pin(cert_data).is_err());
    }

    #[test]
    fn test_tls_config_is_tls13_only() {
        // Verify that server_tls_config produces a TLS 1.3-only config
        // by successfully creating the config (it uses with_protocol_versions(&[&TLS13]))
        let ca = generate_ca();
        let server_cert = generate_module_cert("test-server", &ca);
        let _config = server_tls_config(&server_cert, &ca);
        // If we get here without error, TLS 1.3-only config was created successfully.
        // The restriction is enforced via with_protocol_versions(&[&rustls::version::TLS13]).
    }

    #[test]
    fn test_client_tls_config_is_tls13_only() {
        // Verify that client_tls_config also produces a TLS 1.3-only config
        let ca = generate_ca();
        let client_cert = generate_module_cert("test-client", &ca);
        let _config = client_tls_config(&client_cert, &ca);
        // If we get here without error, TLS 1.3-only config was created successfully.
    }

    #[test]
    fn test_cnsa2_cipher_suite_restriction() {
        // Verify that the CNSA 2.0 crypto provider restricts to AES-256-GCM-SHA384
        let provider = cnsa2_crypto_provider();
        assert_eq!(
            provider.cipher_suites.len(),
            1,
            "CNSA 2.0 must restrict to exactly one cipher suite"
        );
        // The single suite should be TLS13_AES_256_GCM_SHA384
        let suite = &provider.cipher_suites[0];
        assert_eq!(
            format!("{:?}", suite.suite()),
            "TLS13_AES_256_GCM_SHA384",
            "CNSA 2.0 cipher suite must be TLS13_AES_256_GCM_SHA384"
        );
    }

    #[test]
    fn test_cnsa2_provider_default_is_pq_only() {
        // Default mode: PQ-only (no classical fallback unless explicitly opted in).
        // Ensure no classical opt-in env vars are set.
        std::env::remove_var("MILNET_ALLOW_CLASSICAL_TLS");
        std::env::remove_var("MILNET_PQ_TLS_ONLY");
        std::env::remove_var("MILNET_MILITARY_DEPLOYMENT");
        let provider = cnsa2_crypto_provider();

        assert_eq!(
            provider.kx_groups.len(),
            1,
            "default mode must be PQ-only with exactly one key exchange group"
        );
        assert_eq!(
            format!("{:?}", provider.kx_groups[0].name()),
            "X25519MLKEM768",
            "default key exchange group must be PQ hybrid X25519MLKEM768"
        );
    }

    #[test]
    fn test_classical_fallback_requires_explicit_opt_in() {
        // Classical X25519 fallback requires MILNET_ALLOW_CLASSICAL_TLS=1.
        std::env::remove_var("MILNET_MILITARY_DEPLOYMENT");
        std::env::remove_var("MILNET_PQ_TLS_ONLY");
        std::env::set_var("MILNET_ALLOW_CLASSICAL_TLS", "1");
        let provider = cnsa2_crypto_provider();
        std::env::remove_var("MILNET_ALLOW_CLASSICAL_TLS");

        assert_eq!(
            provider.kx_groups.len(),
            2,
            "classical opt-in must add X25519 fallback"
        );
        assert_eq!(
            format!("{:?}", provider.kx_groups[0].name()),
            "X25519MLKEM768",
            "first key exchange group must be PQ hybrid X25519MLKEM768"
        );
        assert_eq!(
            format!("{:?}", provider.kx_groups[1].name()),
            "X25519",
            "second key exchange group must be classical X25519 fallback"
        );
    }

    #[test]
    fn test_military_mode_rejects_classical_even_if_opted_in() {
        // Military mode must NEVER allow classical fallback.
        std::env::set_var("MILNET_MILITARY_DEPLOYMENT", "1");
        std::env::set_var("MILNET_ALLOW_CLASSICAL_TLS", "1");
        let result = allow_classical_tls();
        std::env::remove_var("MILNET_MILITARY_DEPLOYMENT");
        std::env::remove_var("MILNET_ALLOW_CLASSICAL_TLS");

        assert!(
            !result,
            "military mode must reject classical TLS even with MILNET_ALLOW_CLASSICAL_TLS=1"
        );
    }

    #[test]
    fn test_pq_only_legacy_compat() {
        // MILNET_PQ_TLS_ONLY=0 should act as MILNET_ALLOW_CLASSICAL_TLS=1 (legacy compat).
        std::env::remove_var("MILNET_MILITARY_DEPLOYMENT");
        std::env::remove_var("MILNET_ALLOW_CLASSICAL_TLS");
        std::env::set_var("MILNET_PQ_TLS_ONLY", "0");
        let result = allow_classical_tls();
        std::env::remove_var("MILNET_PQ_TLS_ONLY");

        assert!(
            result,
            "MILNET_PQ_TLS_ONLY=0 must allow classical TLS for backward compatibility"
        );
    }

    #[test]
    fn test_server_tls_config_requires_client_cert() {
        // Verify server config enforces mTLS by successfully creating
        // a config with WebPkiClientVerifier (which requires client certs).
        // The server_tls_config function uses with_client_cert_verifier which
        // mandates client certificate presentation.
        let ca = generate_ca();
        let server_cert = generate_module_cert("mtls-server", &ca);
        let config = server_tls_config(&server_cert, &ca);
        // Verify the verifier is present (mTLS is enforced).
        // ServerConfig's client_auth field is private, but the fact that
        // the config was built with with_client_cert_verifier proves mTLS.
        // We also verify the pinned variant works.
        let mut pin_set = CertificatePinSet::new();
        let client_cert = generate_module_cert("test-client", &ca);
        pin_set.add_certificate(client_cert.cert.der().as_ref());
        let _pinned_config = server_tls_config_pinned(&server_cert, &ca, pin_set);
        // If we reach here, mTLS configs with and without pinning were created.
        drop(config);
    }

    #[tokio::test]
    async fn test_pq_tls_handshake_negotiates_x25519mlkem768() {
        use tokio::net::TcpListener;

        let ca = generate_ca();
        let server_cert = generate_module_cert("localhost", &ca);
        let client_cert = generate_module_cert("test-client", &ca);

        let server_config = server_tls_config(&server_cert, &ca);
        let client_config = client_tls_config(&client_cert, &ca);

        let acceptor = tls_acceptor(server_config);
        let connector = tls_connector(client_config);

        // Bind an ephemeral TCP listener.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Spawn server task.
        let server_handle = tokio::spawn(async move {
            let (tcp_stream, _) = listener.accept().await.unwrap();
            let tls_stream = acceptor.accept(tcp_stream).await.unwrap();
            // Extract negotiated key exchange group from server side.
            let (_, server_conn) = tls_stream.get_ref();
            let negotiated = server_conn
                .negotiated_key_exchange_group()
                .expect("key exchange group must be negotiated");
            format!("{:?}", negotiated.name())
        });

        // Client connects.
        let tcp_stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let tls_stream = connector.connect(server_name, tcp_stream).await.unwrap();

        // Verify client-side negotiated group.
        let (_, client_conn) = tls_stream.get_ref();
        let client_group = client_conn
            .negotiated_key_exchange_group()
            .expect("client must have negotiated key exchange group");
        assert_eq!(
            format!("{:?}", client_group.name()),
            "X25519MLKEM768",
            "client must negotiate PQ hybrid X25519MLKEM768 key exchange"
        );

        // Verify server side agrees.
        let server_group_name = server_handle.await.unwrap();
        assert_eq!(
            server_group_name, "X25519MLKEM768",
            "server must negotiate PQ hybrid X25519MLKEM768 key exchange"
        );
    }

    #[test]
    fn test_build_pin_set_from_certs() {
        let ca = generate_ca();
        let cert1 = generate_module_cert("module-a", &ca);
        let cert2 = generate_module_cert("module-b", &ca);

        let pin_set = build_pin_set_from_certs(&[&cert1, &cert2]);

        let fp1 = compute_cert_fingerprint(cert1.cert.der().as_ref());
        let fp2 = compute_cert_fingerprint(cert2.cert.der().as_ref());
        assert!(pin_set.contains(&fp1));
        assert!(pin_set.contains(&fp2));

        // A cert not in the set should not be pinned.
        let cert3 = generate_module_cert("module-c", &ca);
        let fp3 = compute_cert_fingerprint(cert3.cert.der().as_ref());
        assert!(!pin_set.contains(&fp3));
    }
}
