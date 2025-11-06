//! Configuration management module for CoentroVPN.
//!
//! This module provides functionality for loading, parsing, and managing
//! configuration settings for CoentroVPN components.

use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;
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
    InvalidValue { key: String, message: String },

    /// Configuration file not found
    #[error("Configuration file not found at {0}")]
    FileNotFound(PathBuf),
}

/// Role of the CoentroVPN instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Client role
    #[default]
    Client,
    /// Server role
    Server,
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
    /// Authentication mode for the data plane
    #[serde(default = "default_auth_mode")]
    pub auth_mode: AuthMode,

    /// Require authentication (fail-closed if credentials are missing)
    #[serde(default = "default_true")]
    pub auth_required: bool,

    /// Pre-shared key for authentication
    pub psk: Option<String>,

    /// Path to TLS certificate file
    pub cert_path: Option<String>,

    /// Path to TLS key file
    pub key_path: Option<String>,

    /// Enable TLS verification (default: true)
    #[serde(default = "default_true")]
    pub verify_tls: bool,

    /// Challenge TTL in milliseconds for PSK authentication
    #[serde(default = "default_challenge_ttl_ms")]
    pub challenge_ttl_ms: u64,

    /// Maximum entries retained in the replay cache
    #[serde(default = "default_replay_cache_max_entries")]
    pub replay_cache_max_entries: usize,

    /// Optional path to persist replay cache state
    #[serde(default)]
    pub replay_cache_path: Option<String>,
}

fn default_true() -> bool {
    true
}

impl Default for SecurityConfig {
    fn default() -> Self {
        SecurityConfig {
            auth_mode: AuthMode::Psk,
            auth_required: default_true(),
            psk: None,
            cert_path: None,
            key_path: None,
            verify_tls: default_true(),
            challenge_ttl_ms: default_challenge_ttl_ms(),
            replay_cache_max_entries: default_replay_cache_max_entries(),
            replay_cache_path: None,
        }
    }
}

impl SecurityConfig {
    /// Returns the challenge TTL as a [`Duration`].
    pub fn challenge_ttl(&self) -> Duration {
        // Safe because validation enforces non-zero TTL and upper bounds are left to caller policy.
        Duration::from_millis(self.challenge_ttl_ms)
    }
}

/// Authentication mode for the secure channel
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthMode {
    /// Pre-shared key authentication (default)
    Psk,
    /// Mutual TLS (client cert)
    Mtls,
    /// No authentication (allowed only when explicitly configured)
    None,
}

fn default_auth_mode() -> AuthMode {
    AuthMode::Psk
}

fn default_challenge_ttl_ms() -> u64 {
    60_000
}

fn default_replay_cache_max_entries() -> usize {
    2048
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

    /// Route policy: "default" (0.0.0.0/0) or "split" (0.0.0.0/1 + 128.0.0.0/1)
    #[serde(default = "default_route_mode")]
    pub route_mode: RouteMode,

    /// Additional routes to include (CIDRs)
    #[serde(default)]
    pub include_routes: Vec<String>,

    /// Routes to exclude (CIDRs)
    #[serde(default)]
    pub exclude_routes: Vec<String>,
}

fn default_reconnect_interval() -> u64 {
    5
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum RouteMode {
    #[default]
    Default,
    Split,
}

fn default_route_mode() -> RouteMode {
    RouteMode::Default
}

// Default derived on RouteMode

/// Server-specific configuration settings.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    /// Virtual IP range for clients
    pub virtual_ip_range: Option<String>,

    /// DNS servers to push to clients
    #[serde(default)]
    pub dns_servers: Vec<String>,

    /// Routes to push to clients
    #[serde(default)]
    pub routes: Vec<String>,

    /// DNS search domains pushed to clients
    #[serde(default)]
    pub dns_search_domains: Vec<String>,

    /// Helper socket path override
    #[serde(default = "default_helper_socket")]
    pub helper_socket: String,

    /// Enable NAT (MASQUERADE/PF) for server traffic
    #[serde(default)]
    pub enable_nat: bool,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            virtual_ip_range: None,
            dns_servers: Vec::new(),
            routes: Vec::new(),
            dns_search_domains: Vec::new(),
            helper_socket: default_helper_socket(),
            enable_nat: false,
        }
    }
}

fn default_helper_socket() -> String {
    "/var/run/coentrovpn/server_helper.sock".into()
}

/// Helper daemon configuration settings.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct HelperConfig {
    /// List of user IDs allowed to connect to the helper daemon
    #[serde(default)]
    pub allowed_uids: Vec<u32>,

    /// List of group IDs allowed to connect to the helper daemon
    #[serde(default)]
    pub allowed_gids: Vec<u32>,

    /// Optional shared HMAC tokens for authenticating remote helper requests
    #[serde(default)]
    pub session_tokens: Vec<HelperToken>,
}

/// Pre-shared token used to authenticate helper IPC requests.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HelperToken {
    /// Logical identifier for the token (carried in IPC headers)
    pub id: String,
    /// Secret material encoded as base64
    pub secret: String,
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

    /// Helper daemon configuration
    #[serde(default)]
    pub helper: HelperConfig,

    /// Log level (default: "info")
    #[serde(default = "default_log_level")]
    pub log_level: String,

    /// Metrics exporter configuration
    #[serde(default)]
    pub metrics: MetricsConfig,
}

fn default_log_level() -> String {
    "info".to_string()
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MetricsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_metrics_listen_addr")]
    pub listen_addr: String,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen_addr: default_metrics_listen_addr(),
        }
    }
}

fn default_metrics_listen_addr() -> String {
    "127.0.0.1:9100".to_string()
}

impl Default for Config {
    fn default() -> Self {
        Config {
            role: Role::default(),
            network: NetworkConfig::default(),
            security: SecurityConfig::default(),
            client: ClientConfig::default(),
            server: ServerConfig::default(),
            helper: HelperConfig::default(),
            log_level: default_log_level(),
            metrics: MetricsConfig::default(),
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

        // Apply environment variable overrides (take precedence over file)
        let mut config = config;
        Self::apply_env_overrides(&mut config);
        // Re-validate after overrides
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
                // Port 0 is allowed (means bind to any available port)
                // No validation needed for port

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
        if self.security.auth_required {
            match self.security.auth_mode {
                AuthMode::Psk => {
                    if self.security.psk.is_none() {
                        return Err(ConfigError::MissingValue(
                            "security.psk must be provided when auth_mode=psk and auth_required=true"
                                .to_string(),
                        ));
                    }
                }
                AuthMode::Mtls => {
                    if self.security.cert_path.is_none() || self.security.key_path.is_none() {
                        return Err(ConfigError::MissingValue(
                            "security.cert_path and security.key_path must be provided when auth_mode=mtls and auth_required=true"
                                .to_string(),
                        ));
                    }
                }
                AuthMode::None => {
                    return Err(ConfigError::InvalidValue {
                        key: "security.auth_mode".to_string(),
                        message: "auth_mode=none is not allowed when auth_required=true"
                            .to_string(),
                    });
                }
            }
        }

        if self.security.challenge_ttl_ms == 0 {
            return Err(ConfigError::InvalidValue {
                key: "security.challenge_ttl_ms".to_string(),
                message: "must be greater than 0".to_string(),
            });
        }

        if self.security.replay_cache_max_entries == 0 {
            return Err(ConfigError::InvalidValue {
                key: "security.replay_cache_max_entries".to_string(),
                message: "must be greater than 0".to_string(),
            });
        }

        if self.server.helper_socket.trim().is_empty() {
            return Err(ConfigError::InvalidValue {
                key: "server.helper_socket".to_string(),
                message: "helper socket path cannot be empty".to_string(),
            });
        }

        Ok(())
    }

    /// Apply environment variable overrides (prefix: COENTROVPN_)
    /// Example keys:
    /// - COENTROVPN_ROLE, COENTROVPN_LOG_LEVEL
    /// - COENTROVPN_NETWORK_PORT, COENTROVPN_NETWORK_BIND_ADDRESS, COENTROVPN_NETWORK_MAX_CONNECTIONS
    /// - COENTROVPN_SECURITY_AUTH_MODE, COENTROVPN_SECURITY_AUTH_REQUIRED, COENTROVPN_SECURITY_PSK,
    ///   COENTROVPN_SECURITY_CERT_PATH, COENTROVPN_SECURITY_KEY_PATH, COENTROVPN_SECURITY_VERIFY_TLS
    /// - COENTROVPN_CLIENT_SERVER_ADDRESS, COENTROVPN_CLIENT_AUTO_RECONNECT, COENTROVPN_CLIENT_RECONNECT_INTERVAL
    /// - COENTROVPN_SERVER_VIRTUAL_IP_RANGE, COENTROVPN_SERVER_DNS_SERVERS, COENTROVPN_SERVER_ROUTES
    /// - COENTROVPN_HELPER_ALLOWED_UIDS, COENTROVPN_HELPER_ALLOWED_GIDS
    fn apply_env_overrides(cfg: &mut Config) {
        use std::env;

        // Simple helpers
        fn parse_bool(s: &str) -> Option<bool> {
            match s.to_ascii_lowercase().as_str() {
                "true" | "1" | "yes" | "y" => Some(true),
                "false" | "0" | "no" | "n" => Some(false),
                _ => None,
            }
        }
        fn parse_u16(s: &str) -> Option<u16> {
            s.parse().ok()
        }
        fn parse_usize(s: &str) -> Option<usize> {
            s.parse().ok()
        }
        fn parse_u64(s: &str) -> Option<u64> {
            s.parse().ok()
        }
        fn split_csv(s: &str) -> Vec<String> {
            s.split(',')
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
                .collect()
        }
        fn split_csv_u32(s: &str) -> Vec<u32> {
            s.split(',')
                .filter_map(|v| v.trim().parse::<u32>().ok())
                .collect()
        }

        // Top-level
        if let Ok(v) = env::var("COENTROVPN_ROLE") {
            cfg.role = match v.to_ascii_lowercase().as_str() {
                "server" => Role::Server,
                _ => Role::Client,
            };
        }
        if let Ok(v) = env::var("COENTROVPN_LOG_LEVEL") {
            cfg.log_level = v;
        }
        if let Ok(v) = env::var("COENTROVPN_METRICS_ENABLED") {
            if let Some(b) = parse_bool(&v) {
                cfg.metrics.enabled = b;
            }
        }
        if let Ok(v) = env::var("COENTROVPN_METRICS_LISTEN_ADDR") {
            if !v.is_empty() {
                cfg.metrics.listen_addr = v;
            }
        }

        // Network
        if let Ok(v) = env::var("COENTROVPN_NETWORK_PORT") {
            if let Some(n) = parse_u16(&v) {
                cfg.network.port = n;
            }
        }
        if let Ok(v) = env::var("COENTROVPN_NETWORK_BIND_ADDRESS") {
            cfg.network.bind_address = v;
        }
        if let Ok(v) = env::var("COENTROVPN_NETWORK_MAX_CONNECTIONS") {
            if let Some(n) = parse_usize(&v) {
                cfg.network.max_connections = n;
            }
        }

        // Security
        if let Ok(v) = env::var("COENTROVPN_SECURITY_AUTH_MODE") {
            cfg.security.auth_mode = match v.to_ascii_lowercase().as_str() {
                "psk" => AuthMode::Psk,
                "mtls" => AuthMode::Mtls,
                "none" => AuthMode::None,
                _ => cfg.security.auth_mode,
            };
        }
        if let Ok(v) = env::var("COENTROVPN_SECURITY_AUTH_REQUIRED") {
            if let Some(b) = parse_bool(&v) {
                cfg.security.auth_required = b;
            }
        }
        if let Ok(v) = env::var("COENTROVPN_SECURITY_PSK") {
            if !v.is_empty() {
                cfg.security.psk = Some(v);
            }
        }
        if let Ok(v) = env::var("COENTROVPN_SECURITY_CERT_PATH") {
            if !v.is_empty() {
                cfg.security.cert_path = Some(v);
            }
        }
        if let Ok(v) = env::var("COENTROVPN_SECURITY_KEY_PATH") {
            if !v.is_empty() {
                cfg.security.key_path = Some(v);
            }
        }
        if let Ok(v) = env::var("COENTROVPN_SECURITY_VERIFY_TLS") {
            if let Some(b) = parse_bool(&v) {
                cfg.security.verify_tls = b;
            }
        }
        if let Ok(v) = env::var("COENTROVPN_SECURITY_CHALLENGE_TTL_MS") {
            if let Some(n) = parse_u64(&v) {
                cfg.security.challenge_ttl_ms = n;
            }
        }
        if let Ok(v) = env::var("COENTROVPN_SECURITY_REPLAY_CACHE_MAX_ENTRIES") {
            if let Some(n) = parse_usize(&v) {
                cfg.security.replay_cache_max_entries = n;
            }
        }
        if let Ok(v) = env::var("COENTROVPN_SECURITY_REPLAY_CACHE_PATH") {
            if !v.is_empty() {
                cfg.security.replay_cache_path = Some(v);
            }
        }

        // Client
        if let Ok(v) = env::var("COENTROVPN_CLIENT_SERVER_ADDRESS") {
            if !v.is_empty() {
                cfg.client.server_address = Some(v);
            }
        }
        if let Ok(v) = env::var("COENTROVPN_CLIENT_AUTO_RECONNECT") {
            if let Some(b) = parse_bool(&v) {
                cfg.client.auto_reconnect = b;
            }
        }
        if let Ok(v) = env::var("COENTROVPN_CLIENT_RECONNECT_INTERVAL") {
            if let Some(n) = parse_u64(&v) {
                cfg.client.reconnect_interval = n;
            }
        }

        // Client route policy (optional)
        if let Ok(v) = env::var("COENTROVPN_CLIENT_ROUTE_MODE") {
            cfg.client.route_mode = match v.to_ascii_lowercase().as_str() {
                "split" => RouteMode::Split,
                _ => RouteMode::Default,
            };
        }
        if let Ok(v) = env::var("COENTROVPN_CLIENT_INCLUDE_ROUTES") {
            let list = split_csv(&v);
            if !list.is_empty() {
                cfg.client.include_routes = list;
            }
        }
        if let Ok(v) = env::var("COENTROVPN_CLIENT_EXCLUDE_ROUTES") {
            let list = split_csv(&v);
            if !list.is_empty() {
                cfg.client.exclude_routes = list;
            }
        }

        // Server
        if let Ok(v) = env::var("COENTROVPN_SERVER_VIRTUAL_IP_RANGE") {
            if !v.is_empty() {
                cfg.server.virtual_ip_range = Some(v);
            }
        }
        if let Ok(v) = env::var("COENTROVPN_SERVER_DNS_SERVERS") {
            let list = split_csv(&v);
            if !list.is_empty() {
                cfg.server.dns_servers = list;
            }
        }
        if let Ok(v) = env::var("COENTROVPN_SERVER_DNS_SEARCH_DOMAINS") {
            let list = split_csv(&v);
            if !list.is_empty() {
                cfg.server.dns_search_domains = list;
            }
        }
        if let Ok(v) = env::var("COENTROVPN_SERVER_ROUTES") {
            let list = split_csv(&v);
            if !list.is_empty() {
                cfg.server.routes = list;
            }
        }
        if let Ok(v) = env::var("COENTROVPN_SERVER_HELPER_SOCKET") {
            if !v.is_empty() {
                cfg.server.helper_socket = v;
            }
        }
        if let Ok(v) = env::var("COENTROVPN_SERVER_ENABLE_NAT") {
            if let Some(b) = parse_bool(&v) {
                cfg.server.enable_nat = b;
            }
        }

        // Helper
        if let Ok(v) = env::var("COENTROVPN_HELPER_ALLOWED_UIDS") {
            cfg.helper.allowed_uids = split_csv_u32(&v);
        }
        if let Ok(v) = env::var("COENTROVPN_HELPER_ALLOWED_GIDS") {
            cfg.helper.allowed_gids = split_csv_u32(&v);
        }
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
        assert_eq!(
            config.server.virtual_ip_range,
            Some("10.0.0.0/24".to_string())
        );
        assert_eq!(
            config.server.dns_servers,
            vec!["8.8.8.8".to_string(), "1.1.1.1".to_string()]
        );
        assert_eq!(config.server.routes, vec!["192.168.1.0/24".to_string()]);
    }

    #[test]
    fn test_save_config() {
        let config = Config {
            role: Role::Server,
            log_level: "debug".to_string(),
            network: NetworkConfig {
                port: 9090,
                ..Default::default()
            },
            security: SecurityConfig {
                psk: Some("test-key".to_string()),
                ..Default::default()
            },
            server: ServerConfig {
                virtual_ip_range: Some("10.0.0.0/24".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };

        let file = NamedTempFile::new().unwrap();
        config.save(file.path()).unwrap();

        let loaded_config = Config::load(file.path()).unwrap();

        assert_eq!(loaded_config.role, Role::Server);
        assert_eq!(loaded_config.log_level, "debug");
        assert_eq!(loaded_config.network.port, 9090);
        assert_eq!(loaded_config.security.psk, Some("test-key".to_string()));
        assert_eq!(
            loaded_config.server.virtual_ip_range,
            Some("10.0.0.0/24".to_string())
        );
    }

    #[test]
    fn test_validation() {
        // Test server validation - step 1: missing virtual_ip_range
        let config = Config {
            role: Role::Server,
            ..Default::default()
        };
        assert!(config.validate().is_err());

        // Test server validation - step 2: missing security credentials
        let config = Config {
            role: Role::Server,
            server: ServerConfig {
                virtual_ip_range: Some("10.0.0.0/24".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(config.validate().is_err());

        // Test server validation - step 3: valid configuration
        let config = Config {
            role: Role::Server,
            server: ServerConfig {
                virtual_ip_range: Some("10.0.0.0/24".to_string()),
                ..Default::default()
            },
            security: SecurityConfig {
                psk: Some("test-key".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(config.validate().is_ok());

        // Test client validation - step 1: missing server_address
        let config = Config {
            role: Role::Client,
            ..Default::default()
        };
        assert!(config.validate().is_err());

        // Test client validation - step 2: missing security credentials
        let config = Config {
            role: Role::Client,
            client: ClientConfig {
                server_address: Some("vpn.example.com".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(config.validate().is_err());

        // Test client validation - step 3: valid configuration
        let config = Config {
            role: Role::Client,
            client: ClientConfig {
                server_address: Some("vpn.example.com".to_string()),
                ..Default::default()
            },
            security: SecurityConfig {
                psk: Some("test-key".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };
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
        assert_eq!(
            manager.config().client.server_address,
            Some("vpn.example.com".to_string())
        );

        // Test saving with modifications
        let mut manager = manager;
        manager.config_mut().log_level = "debug".to_string();
        manager.save().unwrap();

        // Reload and check
        let manager = ConfigManager::load(file.path()).unwrap();
        assert_eq!(manager.config().log_level, "debug");
    }
}
