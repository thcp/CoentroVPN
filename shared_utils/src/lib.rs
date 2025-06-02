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

// Re-export commonly used modules for convenience
pub use config::{Config, ConfigManager, Role};
pub use crypto::aes_gcm::AesGcmCipher;
pub use proto::framing;
pub use quic::{QuicClient, QuicServer, QuicTransport};
