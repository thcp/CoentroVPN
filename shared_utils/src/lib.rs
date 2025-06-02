//! Shared utilities for CoentroVPN components.
//!
//! This crate provides common functionality used by both client and server
//! components of CoentroVPN, including protocol definitions, cryptographic
//! utilities, and other shared code.

pub mod proto;
pub mod config;
pub mod logging;

// Re-export commonly used modules for convenience
pub use proto::framing;
pub use config::{Config, ConfigManager, Role};
