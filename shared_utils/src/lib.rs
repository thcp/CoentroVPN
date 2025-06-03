//! Shared utilities for CoentroVPN components.
//!
//! This crate provides common functionality used by both client and server
//! components of CoentroVPN, including protocol definitions, cryptographic
//! utilities, and other shared code.

pub mod config;
pub mod crypto;
pub mod logging;
pub mod proto;
pub mod quic;
pub mod tcp; // Added
pub mod transport;
pub mod tunnel;
pub mod webtransport; // Added

// Re-export commonly used modules for convenience
pub use config::{Config, ConfigManager, Role};
pub use crypto::aes_gcm::AesGcmCipher;
pub use proto::framing;
// Removed QuicTransport from re-export
pub use quic::{QuicClient, QuicServer}; 
pub use tunnel::{
    TunnelBootstrapper, ClientBootstrapper, ServerBootstrapper,
    TunnelConfig, TunnelManager, TunnelError, TunnelResult,
};
