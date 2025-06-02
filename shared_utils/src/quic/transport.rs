//! Common QUIC transport interface and error types.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::mpsc;
use quinn::{Connection, ConnectionError, ReadError, WriteError};

/// Errors that can occur during QUIC transport operations.
#[derive(Error, Debug)]
pub enum TransportError {
    /// Error during connection establishment
    #[error("Connection error: {0}")]
    Connection(#[from] ConnectionError),
    
    /// Error reading from a QUIC stream
    #[error("Read error: {0}")]
    Read(#[from] ReadError),
    
    /// Error writing to a QUIC stream
    #[error("Write error: {0}")]
    Write(#[from] WriteError),
    
    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    
    /// TLS error
    #[error("TLS error: {0}")]
    Tls(#[from] rustls::Error),
    
    /// Certificate generation error
    #[error("Certificate generation error: {0}")]
    CertificateGeneration(String),
    
    /// Stream closed unexpectedly
    #[error("Stream closed unexpectedly")]
    StreamClosed,
    
    /// Connection closed
    #[error("Connection closed: {0}")]
    ConnectionClosed(String),
    
    /// Other error
    #[error("Other error: {0}")]
    Other(String),
}

/// Result type for QUIC transport operations.
pub type TransportResult<T> = Result<T, TransportError>;

/// Message type for communication between QUIC transport components.
#[derive(Debug)]
pub enum TransportMessage {
    /// Data received from a stream
    Data(Vec<u8>),
    
    /// Stream closed
    StreamClosed,
    
    /// Connection closed
    ConnectionClosed,
    
    /// Error occurred
    Error(TransportError),
}

/// Common interface for QUIC transport.
pub trait QuicTransport {
    /// Connect to a remote endpoint.
    fn connect(&self, addr: SocketAddr) -> TransportResult<Connection>;
    
    /// Send data over a connection.
    fn send(&self, connection: Connection, data: Vec<u8>) -> impl std::future::Future<Output = TransportResult<()>> + Send;
    
    /// Receive data from a connection.
    fn receive(&self, connection: Connection) -> impl std::future::Future<Output = TransportResult<mpsc::Receiver<TransportMessage>>> + Send;
    
    /// Close a connection.
    fn close(&self, connection: Connection) -> impl std::future::Future<Output = ()> + Send;
}

/// Create a self-signed certificate for testing.
pub fn generate_self_signed_cert() -> TransportResult<(rustls::Certificate, rustls::PrivateKey)> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).map_err(|e| {
        TransportError::CertificateGeneration(format!("Failed to generate certificate: {}", e))
    })?;
    
    let key = rustls::PrivateKey(cert.serialize_private_key_der());
    let cert = rustls::Certificate(cert.serialize_der().map_err(|e| {
        TransportError::CertificateGeneration(format!("Failed to serialize certificate: {}", e))
    })?);
    
    Ok((cert, key))
}

/// Configure TLS for QUIC.
pub fn configure_tls(cert: rustls::Certificate, key: rustls::PrivateKey) -> TransportResult<Arc<rustls::ServerConfig>> {
    let mut server_config = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .map_err(|e| TransportError::Tls(e))?;
    
    // Enable QUIC support
    server_config.alpn_protocols = vec![b"h3".to_vec()];
    
    Ok(Arc::new(server_config))
}

/// Configure client TLS for QUIC.
pub fn configure_client_tls() -> TransportResult<Arc<rustls::ClientConfig>> {
    let mut client_config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    
    // Enable QUIC support
    client_config.alpn_protocols = vec![b"h3".to_vec()];
    
    // For development/testing, accept invalid certificates
    client_config.dangerous().set_certificate_verifier(Arc::new(danger::NoCertificateVerification {}));
    
    Ok(Arc::new(client_config))
}

/// Dangerous TLS configurations for development/testing.
pub mod danger {
    use std::time::SystemTime;
    use rustls::client::{ServerCertVerified, ServerCertVerifier};
    
    /// A certificate verifier that accepts any certificate.
    pub struct NoCertificateVerification {}
    
    impl ServerCertVerifier for NoCertificateVerification {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::Certificate,
            _intermediates: &[rustls::Certificate],
            _server_name: &rustls::ServerName,
            _scts: &mut dyn Iterator<Item = &[u8]>,
            _ocsp_response: &[u8],
            _now: SystemTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }
    }
}
