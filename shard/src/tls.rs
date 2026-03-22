//! TLS configuration for SHARD inter-module communication.
//!
//! Uses rustls with mutual TLS (mTLS). A self-signed CA certificate is
//! generated at startup; each module receives a certificate signed by that CA.
//! Both the server and client sides verify the peer's certificate against
//! the CA root.

use rcgen::{BasicConstraints, CertificateParams, CertifiedKey, IsCa, KeyPair, KeyUsagePurpose};
use rustls::pki_types::PrivatePkcs8KeyDer;
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use std::sync::Arc;
use tokio_rustls::{TlsAcceptor, TlsConnector};

/// A CA certificate and its key pair, used to sign module certificates.
pub struct CertificateAuthority {
    pub cert: rcgen::Certificate,
    pub key_pair: KeyPair,
}

/// Generate a self-signed CA certificate for signing module certificates.
pub fn generate_ca() -> CertificateAuthority {
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

/// Create a [`TlsAcceptor`] from a server config.
pub fn tls_acceptor(config: Arc<ServerConfig>) -> TlsAcceptor {
    TlsAcceptor::from(config)
}

/// Create a [`TlsConnector`] from a client config.
pub fn tls_connector(config: Arc<ClientConfig>) -> TlsConnector {
    TlsConnector::from(config)
}
