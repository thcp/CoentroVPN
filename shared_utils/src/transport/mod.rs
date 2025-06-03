use async_trait::async_trait;
use std::net::SocketAddr;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("Connection error: {0}")]
    Connection(String),
    #[error("Send error: {0}")]
    Send(String),
    #[error("Receive error: {0}")]
    Receive(String),
    #[error("Close error: {0}")]
    Close(String),
    #[error("Configuration error: {0}")]
    Configuration(String),
    #[error("Address parse error: {0}")]
    AddrParse(#[from] std::net::AddrParseError),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Operation timed out: {0}")]
    Timeout(String),
    #[error("Transport layer security error: {0}")]
    Tls(String),
    #[error("Underlying transport specific error: {0}")]
    Protocol(String),
    #[error("Generic error: {0}")]
    Generic(String),
}

/// Represents an active connection over a transport protocol.
#[async_trait]
pub trait Connection: Send + Sync {
    /// Sends data over the connection.
    async fn send_data(&mut self, data: &[u8]) -> Result<(), TransportError>;

    /// Receives data from the connection.
    /// Returns `Ok(None)` if the connection was gracefully closed by the peer.
    async fn recv_data(&mut self) -> Result<Option<Vec<u8>>, TransportError>;

    /// Returns the peer's socket address.
    fn peer_addr(&self) -> Result<SocketAddr, TransportError>;

    /// Returns the local socket address.
    fn local_addr(&self) -> Result<SocketAddr, TransportError>;

    /// Closes the connection.
    /// This method consumes the connection object.
    async fn close(self: Box<Self>) -> Result<(), TransportError>;
}

/// Trait for client-side transport protocols.
#[async_trait]
pub trait ClientTransport: Send + Sync {
    /// Establishes a connection to a server at the given address.
    /// The address format is transport-specific (e.g., "hostname:port" or "url").
    async fn connect(&self, server_address: &str) -> Result<Box<dyn Connection>, TransportError>;
}

/// Trait for server-side transport protocols.
#[async_trait]
pub trait ServerTransport: Send + Sync {
    type Listener: Listener;

    /// Starts listening for incoming connections on the given local address.
    /// The address format is transport-specific (e.g., "ip:port").
    async fn listen(&self, local_address: &str) -> Result<Self::Listener, TransportError>;
}

/// Trait for a transport listener, capable of accepting incoming connections.
#[async_trait]
pub trait Listener: Send + Sync {
    /// Accepts a new incoming connection.
    /// This method will block until a new connection is established or an error occurs.
    async fn accept(&mut self) -> Result<Box<dyn Connection>, TransportError>;

    /// Returns the local socket address this listener is bound to.
    fn local_addr(&self) -> Result<SocketAddr, TransportError>;

    // Consider adding a close method for the listener if needed.
    // async fn close(self: Box<Self>) -> Result<(), TransportError>;
}
