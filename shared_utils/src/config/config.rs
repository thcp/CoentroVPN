//! Configuration management for CoentroVPN.
//!
//! This module provides functionality for loading, parsing, and managing
//! configuration settings for CoentroVPN components. It supports loading
//! configuration from TOML files and provides a structured representation
//! of the configuration settings.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors that can occur during configuration operations.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// Error reading configuration file
    #[error("Failed to read config file: {0}")]
    IoError(#[from] io::Error),

    /// Error parsing TOML configuration
    #[error("Failed to parse TOML config: {0}")]
    TomlError(#[from] toml::de::Error),

    /// Error serializing configuration to TOML
    #[error("Failed to serialize config to TOML: {0}")]
    TomlSerError(#[from] toml::ser::Error),

    /// Missing required configuration value
    #[error("Missing required configuration value: {0}")]
    MissingValue(String),

    /// Invalid configuration value
    #[error("Invalid configuration value for {key}: {message}")]
    InvalidValue {
        key: String,
        message: String,
    },

    /// Configuration file not found
    #[error("Configuration file not found at {0}")]
    FileNotFound(PathBuf),
}

/// Role of the CoentroVPN instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Client role
    Client,
    /// Server role
    Server,
}

impl Default for Role {
    fn default() -> Self {
        Role::Client
    }
}

/// Network configuration settings.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NetworkConfig {
    /// Port for the VPN server to listen on (default: 8080)
    #[serde(default = "default_port")]
    pub port: u16,

    /// Interface to bind to (default: "0.0.0.0")
    #[serde(default = "default_bind_address")]
    pub bind_address: String,

    /// Maximum number of concurrent connections (default: 100)
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
}

fn default_port() -> u16 {
    8080
}

fn default_bind_address() -> String {
    "0.0.0.0".to_string()
}

fn default_max_connections() -> usize {
    100
}

impl Default for NetworkConfig {
    fn default() -> Self {
        NetworkConfig {
            port: default_port(),
            bind_address: default_bind_address(),
            max_connections: default_max_connections(),
        }
    }
}

/// Security configuration settings.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SecurityConfig {
    /// Pre-shared key for authentication
    pub psk: Option<String>,

    /// Path to TLS certificate file
    pub cert_path: Option<String>,

    /// Path to TLS key file
    pub key_path: Option<String>,

    /// Enable TLS verification (default: true)
    #[serde(default = "default_true")]
    pub verify_tls: bool,
}

fn default_true() -> bool {
    true
}

impl Default for SecurityConfig {
    fn default() -> Self {
        SecurityConfig {
            psk: None,
            cert_path: None,
            key_path: None,
            verify_tls: default_true(),
        }
    }
}

/// Client-specific configuration settings.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct ClientConfig {
    /// Server address to connect to
    pub server_address: Option<String>,

    /// Reconnect automatically on disconnect (default: true)
    #[serde(default = "default_true")]
    pub auto_reconnect: bool,

    /// Reconnect interval in seconds (default: 5)
    #[serde(default = "default_reconnect_interval")]
    pub reconnect_interval: u64,
}

fn default_reconnect_interval() -> u64 {
    5
}

/// Server-specific configuration settings.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct ServerConfig {
    /// Virtual IP range for clients
    pub virtual_ip_range: Option<String>,

    /// DNS servers to push to clients
    #[serde(default)]
    pub dns_servers: Vec<String>,

    /// Routes to push to clients
    #[serde(default)]
    pub routes: Vec<String>,
}

/// Main configuration structure for CoentroVPN.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    /// Role of this CoentroVPN instance
    #[serde(default)]
    pub role: Role,

    /// Network configuration
    #[serde(default)]
    pub network: NetworkConfig,

    /// Security configuration
    #[serde(default)]
    pub security: SecurityConfig,

    /// Client-specific configuration (used when role is Client)
    #[serde(default)]
    pub client: ClientConfig,

    /// Server-specific configuration (used when role is Server)
    #[serde(default)]
    pub server: ServerConfig,

    /// Log level (default: "info")
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

fn default_log_level() -> String {
    "info".to_string()
}

impl Default for Config {
    fn default() -> Self {
        Config {
            role: Role::default(),
            network: NetworkConfig::default(),
            security: SecurityConfig::default(),
            client: ClientConfig::default(),
            server: ServerConfig::default(),
            log_level: default_log_level(),
        }
    }
}

impl Config {
    /// Create a new default configuration
    pub fn new() -> Self {
        Config::default()
    }

    /// Load configuration from a TOML file
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        
        if !path.exists() {
            return Err(ConfigError::FileNotFound(path.to_path_buf()));
        }
        
        let content = fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        
        // Validate the configuration
        config.validate()?;
        
        Ok(config)
    }

    /// Save configuration to a TOML file
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<(), ConfigError> {
        let content = toml::to_string_pretty(self)?;
        fs::write(path, content)?;
        Ok(())
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<(), ConfigError> {
        // Validate role-specific requirements
        match self.role {
            Role::Server => {
                // Server must have a port configured
                if self.network.port == 0 {
                    return Err(ConfigError::InvalidValue {
                        key: "network.port".to_string(),
                        message: "Server must have a valid port".to_string(),
                    });
                }
                
                // Server should have a virtual IP range
                if self.server.virtual_ip_range.is_none() {
                    return Err(ConfigError::MissingValue(
                        "server.virtual_ip_range".to_string(),
                    ));
                }
            }
            Role::Client => {
                // Client must have a server address
                if self.client.server_address.is_none() {
                    return Err(ConfigError::MissingValue(
                        "client.server_address".to_string(),
                    ));
                }
            }
        }
        
        // Validate security settings
        if self.security.psk.is_none() && (self.security.cert_path.is_none() || self.security.key_path.is_none()) {
            return Err(ConfigError::MissingValue(
                "Either security.psk or both security.cert_path and security.key_path must be provided".to_string(),
            ));
        }
        
        Ok(())
    }

    /// Reload configuration from the same file it was loaded from
    pub fn reload(&mut self, path: &Path) -> Result<(), ConfigError> {
        *self = Self::load(path)?;
        Ok(())
    }

    /// Get the default configuration file path
    pub fn default_path() -> PathBuf {
        if let Some(config_dir) = dirs::config_dir() {
            config_dir.join("coentrovpn").join("config.toml")
        } else {
            PathBuf::from("config.toml")
        }
    }
}

/// Configuration manager for handling configuration loading and reloading.
#[derive(Debug)]
pub struct ConfigManager {
    /// Current configuration
    config: Config,
    /// Path to the configuration file
    config_path: PathBuf,
}

impl ConfigManager {
    /// Create a new configuration manager with the default configuration
    pub fn new() -> Self {
        ConfigManager {
            config: Config::default(),
            config_path: Config::default_path(),
        }
    }

    /// Load configuration from the specified path
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let path = path.as_ref().to_path_buf();
        let config = Config::load(&path)?;
        
        Ok(ConfigManager {
            config,
            config_path: path,
        })
    }

    /// Load configuration from the default path
    pub fn load_default() -> Result<Self, ConfigError> {
        Self::load(Config::default_path())
    }

    /// Get a reference to the current configuration
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Get a mutable reference to the current configuration
    pub fn config_mut(&mut self) -> &mut Config {
        &mut self.config
    }

    /// Reload configuration from the current path
    pub fn reload(&mut self) -> Result<(), ConfigError> {
        self.config.reload(&self.config_path)
    }

    /// Save the current configuration to the current path
    pub fn save(&self) -> Result<(), ConfigError> {
        self.config.save(&self.config_path)
    }

    /// Save the current configuration to a new path
    pub fn save_as<P: AsRef<Path>>(&self, path: P) -> Result<(), ConfigError> {
        self.config.save(path)
    }

    /// Get the current configuration file path
    pub fn config_path(&self) -> &Path {
        &self.config_path
    }
}

impl Default for ConfigManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.role, Role::Client);
        assert_eq!(config.network.port, 8080);
        assert_eq!(config.network.bind_address, "0.0.0.0");
        assert_eq!(config.log_level, "info");
    }

    #[test]
    fn test_load_config() {
        let mut file = NamedTempFile::new().unwrap();
        
        let config_str = r#"
            role = "server"
            log_level = "debug"
            
            [network]
            port = 9090
            bind_address = "127.0.0.1"
            max_connections = 200
            
            [security]
            psk = "test-key"
            
            [server]
            virtual_ip_range = "10.0.0.0/24"
            dns_servers = ["8.8.8.8", "1.1.1.1"]
            routes = ["192.168.1.0/24"]
        "#;
        
        file.write_all(config_str.as_bytes()).unwrap();
        
        let config = Config::load(file.path()).unwrap();
        
        assert_eq!(config.role, Role::Server);
        assert_eq!(config.log_level, "debug");
        assert_eq!(config.network.port, 9090);
        assert_eq!(config.network.bind_address, "127.0.0.1");
        assert_eq!(config.network.max_connections, 200);
        assert_eq!(config.security.psk, Some("test-key".to_string()));
        assert_eq!(config.server.virtual_ip_range, Some("10.0.0.0/24".to_string()));
        assert_eq!(config.server.dns_servers, vec!["8.8.8.8".to_string(), "1.1.1.1".to_string()]);
        assert_eq!(config.server.routes, vec!["192.168.1.0/24".to_string()]);
    }

    #[test]
    fn test_save_config() {
        let mut config = Config::default();
        config.role = Role::Server;
        config.log_level = "debug".to_string();
        config.network.port = 9090;
        config.security.psk = Some("test-key".to_string());
        config.server.virtual_ip_range = Some("10.0.0.0/24".to_string());
        
        let file = NamedTempFile::new().unwrap();
        config.save(file.path()).unwrap();
        
        let loaded_config = Config::load(file.path()).unwrap();
        
        assert_eq!(loaded_config.role, Role::Server);
        assert_eq!(loaded_config.log_level, "debug");
        assert_eq!(loaded_config.network.port, 9090);
        assert_eq!(loaded_config.security.psk, Some("test-key".to_string()));
        assert_eq!(loaded_config.server.virtual_ip_range, Some("10.0.0.0/24".to_string()));
    }

    #[test]
    fn test_validation() {
        // Test server validation
        let mut config = Config::default();
        config.role = Role::Server;
        
        // Missing virtual_ip_range
        assert!(config.validate().is_err());
        
        config.server.virtual_ip_range = Some("10.0.0.0/24".to_string());
        
        // Missing security credentials
        assert!(config.validate().is_err());
        
        config.security.psk = Some("test-key".to_string());
        
        // Should be valid now
        assert!(config.validate().is_ok());
        
        // Test client validation
        let mut config = Config::default();
        config.role = Role::Client;
        
        // Missing server_address
        assert!(config.validate().is_err());
        
        config.client.server_address = Some("vpn.example.com".to_string());
        
        // Missing security credentials
        assert!(config.validate().is_err());
        
        config.security.psk = Some("test-key".to_string());
        
        // Should be valid now
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_manager() {
        let mut file = NamedTempFile::new().unwrap();
        
        let config_str = r#"
            role = "client"
            log_level = "info"
            
            [network]
            port = 8080
            
            [security]
            psk = "test-key"
            
            [client]
            server_address = "vpn.example.com"
        "#;
        
        file.write_all(config_str.as_bytes()).unwrap();
        
        let manager = ConfigManager::load(file.path()).unwrap();
        
        assert_eq!(manager.config().role, Role::Client);
        assert_eq!(manager.config().client.server_address, Some("vpn.example.com".to_string()));
        
        // Test saving with modifications
        let mut manager = manager;
        manager.config_mut().log_level = "debug".to_string();
        manager.save().unwrap();
        
        // Reload and check
        let manager = ConfigManager::load(file.path()).unwrap();
        assert_eq!(manager.config().log_level, "debug");
    }
}
