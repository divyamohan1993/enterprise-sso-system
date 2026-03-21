//! TLS configuration for SHARD inter-module communication.
//!
//! Uses rustls with self-signed certificates generated via `rcgen`.
//! In production this would be replaced with mTLS using CA-issued certs.

use rcgen::{CertifiedKey, generate_simple_self_signed};
use rustls::pki_types::PrivatePkcs8KeyDer;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use std::sync::Arc;
use tokio_rustls::{TlsAcceptor, TlsConnector};

/// Generate a self-signed TLS certificate for a module.
pub fn generate_module_cert(module_name: &str) -> CertifiedKey {
    let subject_alt_names = vec![module_name.to_string(), "localhost".to_string()];
    generate_simple_self_signed(subject_alt_names).unwrap()
}

/// Create a TLS server config from a certificate.
pub fn server_tls_config(cert_key: &CertifiedKey) -> Arc<ServerConfig> {
    let cert_chain = vec![cert_key.cert.der().clone()];
    let private_key = PrivatePkcs8KeyDer::from(cert_key.key_pair.serialize_der()).into();

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)
        .unwrap();
    Arc::new(config)
}

/// Create a TLS client config that trusts a specific server cert.
pub fn client_tls_config(server_cert: &CertifiedKey) -> Arc<ClientConfig> {
    let mut root_store = RootCertStore::empty();
    root_store.add(server_cert.cert.der().clone()).unwrap();

    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
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
