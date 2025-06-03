//! Tunnel bootstrapping and management abstractions for CoentroVPN.
//!
//! This module provides reusable abstractions for creating and managing
//! secure tunnels between CoentroVPN clients and servers. It handles
//! the common bootstrapping logic and provides a clean interface for
//! tunnel operations.

mod bootstrap;
mod config;
mod error;
mod manager;
pub mod types;

pub use bootstrap::{TunnelBootstrapper, ClientBootstrapper, ServerBootstrapper};
pub use config::TunnelConfig;
pub use error::{TunnelError, TunnelResult};
pub use manager::TunnelManager;
pub use types::{TunnelId, TunnelState, TunnelRole, TunnelStats};
