// Common QUIC transport helper functions, primarily for TLS configuration.

use crate::transport::TransportError; // Use the new central TransportError
use rustls;
use std::sync::Arc; // Keep rustls import for types used in signatures

#[cfg(not(feature = "insecure-tls"))]
fn load_native_roots() -> Result<rustls::RootCertStore, TransportError> {
    let mut roots = rustls::RootCertStore::empty();
    #[allow(deprecated)]
    roots.add_server_trust_anchors(
        webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
            rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        }),
    );
    Ok(roots)
}

// The old QuicTransport trait, TransportError enum, TransportResult type,
// and TransportMessage enum have been removed as they are superseded by
// the definitions in `shared_utils/src/transport/mod.rs`.

/// Create a self-signed certificate for testing.
/// Returns the certificate and private key.
pub fn generate_self_signed_cert()
-> Result<(rustls::Certificate, rustls::PrivateKey), TransportError> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).map_err(|e| {
        TransportError::Configuration(format!("Failed to generate certificate: {}", e))
    })?;

    let key_der = cert.serialize_private_key_der();
    let cert_der = cert.serialize_der().map_err(|e| {
        TransportError::Configuration(format!("Failed to serialize certificate: {}", e))
    })?;

    Ok((rustls::Certificate(cert_der), rustls::PrivateKey(key_der)))
}

/// Configure server-side TLS for QUIC using a certificate and private key.
pub fn configure_tls(
    cert: rustls::Certificate,
    key: rustls::PrivateKey,
) -> Result<Arc<rustls::ServerConfig>, TransportError> {
    let mut server_config = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .map_err(|e| TransportError::Tls(format!("Failed to create server TLS config: {}", e)))?;

    // Enable QUIC support (h3 is a common ALPN for QUIC)
    server_config.alpn_protocols = vec![b"h3".to_vec()];

    Ok(Arc::new(server_config))
}

/// Configure client-side TLS for QUIC.
/// This configuration uses a dangerous verifier that accepts any server certificate,
/// suitable for testing and development only.
pub fn configure_client_tls() -> Result<Arc<rustls::ClientConfig>, TransportError> {
    #[cfg(feature = "insecure-tls")]
    {
        // Development-only insecure verifier (feature-gated)
        let roots = rustls::RootCertStore::empty();
        let mut client_config = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client_config.alpn_protocols = vec![b"h3".to_vec()];
        client_config
            .dangerous()
            .set_certificate_verifier(Arc::new(danger::NoCertificateVerification {}));
        return Ok(Arc::new(client_config));
    }

    #[cfg(not(feature = "insecure-tls"))]
    {
        // Secure-by-default: use native root store and standard verification
        let roots = load_native_roots()?;
        let mut client_config = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client_config.alpn_protocols = vec![b"h3".to_vec()];
        Ok(Arc::new(client_config))
    }
}

/// Configure client-side TLS using an explicit set of trust anchors (pinned CAs).
pub fn configure_client_tls_with_roots(
    anchors: &[rustls::Certificate],
) -> Result<Arc<rustls::ClientConfig>, TransportError> {
    let mut store = rustls::RootCertStore::empty();
    for cert in anchors {
        store
            .add(cert)
            .map_err(|e| TransportError::Tls(format!("Invalid pinned CA: {}", e)))?;
    }
    let mut client_config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(store)
        .with_no_client_auth();
    client_config.alpn_protocols = vec![b"h3".to_vec()];
    Ok(Arc::new(client_config))
}

/// Contains dangerous TLS configurations, typically for development or testing.
pub mod danger {
    use rustls::client::{ServerCertVerified, ServerCertVerifier};
    use rustls::{Certificate, Error as TlsError, ServerName}; // Corrected import for TlsError
    use std::time::SystemTime;

    /// A certificate verifier that accepts any certificate.
    /// **WARNING: This is insecure and should only be used for testing.**
    #[derive(Debug)]
    pub struct NoCertificateVerification {}

    impl ServerCertVerifier for NoCertificateVerification {
        fn verify_server_cert(
            &self,
            _end_entity: &Certificate,
            _intermediates: &[Certificate],
            _server_name: &ServerName,
            _scts: &mut dyn Iterator<Item = &[u8]>,
            _ocsp_response: &[u8],
            _now: SystemTime,
        ) -> Result<ServerCertVerified, TlsError> {
            // In a real verifier, you would check the certificate chain,
            // validity period, server name, etc.
            // Here, we blindly trust the certificate.
            Ok(ServerCertVerified::assertion())
        }
    }
}
