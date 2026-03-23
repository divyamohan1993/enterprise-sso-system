//! TLS configuration for SHARD inter-module communication.
//!
//! Uses rustls with mutual TLS (mTLS). A self-signed CA certificate is
//! generated at startup; each module receives a certificate signed by that CA.
//! Both the server and client sides verify the peer's certificate against
//! the CA root.
//!
//! Certificate pinning is enforced on top of standard chain verification.
//! After the CA chain is validated, the peer certificate's SHA-256 fingerprint
//! is checked against a set of known-good pins. A valid chain but unknown
//! fingerprint logs a CRITICAL warning (possible CA compromise) and rejects
//! the connection.

use rcgen::{BasicConstraints, CertificateParams, CertifiedKey, IsCa, KeyPair, KeyUsagePurpose};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::server::WebPkiClientVerifier;
use rustls::{
    ClientConfig, DigitallySignedStruct, DistinguishedName, Error, RootCertStore, ServerConfig,
    SignatureScheme,
};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fmt;
use std::sync::Arc;
use tokio_rustls::{TlsAcceptor, TlsConnector};

// ---------------------------------------------------------------------------
// Certificate fingerprint helpers
// ---------------------------------------------------------------------------

/// Compute the SHA-256 fingerprint of a DER-encoded certificate.
pub fn compute_cert_fingerprint(cert_der: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(cert_der);
    let result = hasher.finalize();
    let mut fingerprint = [0u8; 32];
    fingerprint.copy_from_slice(&result);
    fingerprint
}

/// A set of pinned certificate SHA-256 fingerprints.
///
/// After standard CA chain verification succeeds, the peer certificate's
/// fingerprint is checked against this set. If the fingerprint is not present,
/// the connection is rejected with a CRITICAL log (indicates CA compromise).
#[derive(Clone)]
pub struct CertificatePinSet {
    pins: HashSet<[u8; 32]>,
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

    /// Add a SHA-256 fingerprint to the pin set.
    pub fn add_fingerprint(&mut self, fingerprint: [u8; 32]) {
        self.pins.insert(fingerprint);
    }

    /// Add a certificate (DER-encoded) to the pin set by computing its fingerprint.
    pub fn add_certificate(&mut self, cert_der: &[u8]) {
        self.pins.insert(compute_cert_fingerprint(cert_der));
    }

    /// Check whether a certificate fingerprint is in the pin set.
    pub fn contains(&self, fingerprint: &[u8; 32]) -> bool {
        self.pins.contains(fingerprint)
    }

    /// Verify a DER-encoded certificate against the pin set.
    /// Returns `Ok(())` if pinned, or `Err` with a CRITICAL log if not.
    pub fn verify_pin(&self, cert_der: &[u8]) -> Result<(), Error> {
        let fingerprint = compute_cert_fingerprint(cert_der);
        if self.contains(&fingerprint) {
            Ok(())
        } else {
            eprintln!(
                "CRITICAL: Certificate passed CA chain verification but FAILED pin check \
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
/// SHA-256 fingerprint is checked against the `CertificatePinSet`.
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
/// SHA-256 fingerprint is checked against the `CertificatePinSet`.
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
    let key_pair = KeyPair::generate().expect("CA key generation failed");
    let mut params = CertificateParams::new(Vec::<String>::new())
        .expect("empty SAN list is valid for a CA");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "MILNET SHARD CA");
    let cert = params
        .self_signed(&key_pair)
        .expect("CA self-sign failed");
    CertificateAuthority { cert, key_pair }
}

/// Generate a module certificate signed by the given CA.
pub fn generate_module_cert(module_name: &str, ca: &CertificateAuthority) -> CertifiedKey {
    let key_pair = KeyPair::generate().expect("module key generation failed");
    let subject_alt_names = vec![module_name.to_string(), "localhost".to_string()];
    let params =
        CertificateParams::new(subject_alt_names).expect("module cert params creation failed");
    let cert = params
        .signed_by(&key_pair, &ca.cert, &ca.key_pair)
        .expect("module cert signing failed");
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
        .expect("adding CA cert to root store failed");
    Arc::new(root_store)
}

/// Create a TLS server config that requires client certificates (mTLS).
///
/// The server will verify that clients present a certificate signed by `ca`.
pub fn server_tls_config(cert_key: &CertifiedKey, ca: &CertificateAuthority) -> Arc<ServerConfig> {
    let cert_chain = vec![cert_key.cert.der().clone()];
    let private_key = PrivatePkcs8KeyDer::from(cert_key.key_pair.serialize_der()).into();

    let roots = ca_root_store(ca);
    let client_verifier = WebPkiClientVerifier::builder(roots)
        .build()
        .expect("building client verifier failed");

    let config = ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(cert_chain, private_key)
        .expect("server TLS config failed");
    Arc::new(config)
}

/// Create a TLS client config that trusts the CA and presents a client certificate (mTLS).
pub fn client_tls_config(
    client_cert: &CertifiedKey,
    ca: &CertificateAuthority,
) -> Arc<ClientConfig> {
    let roots = ca_root_store(ca);

    let client_cert_chain = vec![client_cert.cert.der().clone()];
    let client_key = PrivatePkcs8KeyDer::from(client_cert.key_pair.serialize_der()).into();

    let config = ClientConfig::builder()
        .with_root_certificates((*roots).clone())
        .with_client_auth_cert(client_cert_chain, client_key)
        .expect("client TLS config with cert failed");
    Arc::new(config)
}

// ---------------------------------------------------------------------------
// TLS configuration builders WITH certificate pinning
// ---------------------------------------------------------------------------

/// Create a TLS server config with mTLS and certificate pinning.
///
/// The server will verify that clients present a certificate signed by `ca`
/// **and** that the client certificate's SHA-256 fingerprint is in `pin_set`.
pub fn server_tls_config_pinned(
    cert_key: &CertifiedKey,
    ca: &CertificateAuthority,
    pin_set: CertificatePinSet,
) -> Arc<ServerConfig> {
    let cert_chain = vec![cert_key.cert.der().clone()];
    let private_key = PrivatePkcs8KeyDer::from(cert_key.key_pair.serialize_der()).into();

    let roots = ca_root_store(ca);
    let webpki_verifier = WebPkiClientVerifier::builder(roots)
        .build()
        .expect("building client verifier failed");

    let pinned_verifier: Arc<dyn rustls::server::danger::ClientCertVerifier> =
        Arc::new(PinnedClientCertVerifier {
            inner: webpki_verifier,
            pin_set,
        });

    let config = ServerConfig::builder()
        .with_client_cert_verifier(pinned_verifier)
        .with_single_cert(cert_chain, private_key)
        .expect("server TLS config with pinning failed");
    Arc::new(config)
}

/// Create a TLS client config with mTLS and certificate pinning.
///
/// The client will verify that the server presents a certificate signed by `ca`
/// **and** that the server certificate's SHA-256 fingerprint is in `pin_set`.
pub fn client_tls_config_pinned(
    client_cert: &CertifiedKey,
    ca: &CertificateAuthority,
    pin_set: CertificatePinSet,
) -> Arc<ClientConfig> {
    let roots = ca_root_store(ca);

    let client_cert_chain = vec![client_cert.cert.der().clone()];
    let client_key = PrivatePkcs8KeyDer::from(client_cert.key_pair.serialize_der()).into();

    // Build the standard WebPKI server verifier, then wrap with pinning.
    let webpki_verifier = rustls::client::WebPkiServerVerifier::builder(roots)
        .build()
        .expect("building server verifier failed");

    let pinned_verifier: Arc<dyn rustls::client::danger::ServerCertVerifier> =
        Arc::new(PinnedServerCertVerifier {
            inner: webpki_verifier,
            pin_set,
        });

    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(pinned_verifier)
        .with_client_auth_cert(client_cert_chain, client_key)
        .expect("client TLS config with pinning failed");
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
