//! Error types for the tunnel module.

use std::io;
use thiserror::Error;

use crate::transport::TransportError; // Changed from crate::quic::TransportError

/// Result type for tunnel operations.
pub type TunnelResult<T> = Result<T, TunnelError>;

/// Error types that can occur in tunnel operations.
#[derive(Debug, Error)]
pub enum TunnelError {
    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// Transport layer error
    #[error("Transport error: {0}")]
    Transport(#[from] TransportError),

    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),

    /// Encryption error
    #[error("Encryption error: {0}")]
    Encryption(String),

    /// Protocol error
    #[error("Protocol error: {0}")]
    Protocol(String),

    /// Authentication error
    #[error("Authentication error: {0}")]
    Authentication(String),

    /// Connection error
    #[error("Connection error: {0}")]
    Connection(String),

    /// Tunnel closed
    #[error("Tunnel closed")]
    Closed,

    /// Tunnel already exists
    #[error("Tunnel already exists: {0}")]
    AlreadyExists(String),

    /// Tunnel not found
    #[error("Tunnel not found: {0}")]
    NotFound(String),

    /// Invalid state
    #[error("Invalid state: {0}")]
    InvalidState(String),

    /// Tunnel not connected
    #[error("Tunnel not connected: {0}")]
    NotConnected(String),

    /// Timeout
    #[error("Operation timed out: {0}")]
    Timeout(String),

    /// Other error
    #[error("Other error: {0}")]
    Other(String),
}

impl From<&str> for TunnelError {
    fn from(s: &str) -> Self {
        TunnelError::Other(s.to_string())
    }
}

impl From<String> for TunnelError {
    fn from(s: String) -> Self {
        TunnelError::Other(s)
    }
}
