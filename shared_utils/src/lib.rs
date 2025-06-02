//! Shared utilities for CoentroVPN components.
//!
//! This crate provides common functionality used by both client and server
//! components of CoentroVPN, including protocol definitions, cryptographic
//! utilities, and other shared code.

pub mod proto;
pub mod config;
pub mod logging;
pub mod quic;
pub mod crypto;

// Re-export commonly used modules for convenience
pub use proto::framing;
pub use crypto::aes_gcm::AesGcmCipher;
pub use config::{Config, ConfigManager, Role};
pub use quic::{QuicTransport, QuicClient, QuicServer};
