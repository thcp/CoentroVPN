//! Configuration management module for CoentroVPN.
//!
//! This module provides functionality for loading, parsing, and managing
//! configuration settings for CoentroVPN components.

mod config;

pub use config::{
    Config, ConfigError, ConfigManager,
    Role, NetworkConfig, SecurityConfig, ClientConfig, ServerConfig,
};
