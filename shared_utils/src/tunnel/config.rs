//! Configuration for tunnel bootstrapping and management.

use std::net::SocketAddr;
use std::time::Duration;

use crate::config::Config as GlobalConfig;
use crate::tunnel::error::{TunnelError, TunnelResult};
use crate::tunnel::types::TunnelRole;

/// Configuration for a tunnel.
#[derive(Debug, Clone)]
pub struct TunnelConfig {
    /// Role of this tunnel (client or server)
    pub role: TunnelRole,

    /// Remote endpoint address (for client tunnels)
    pub remote_addr: Option<SocketAddr>,

    /// Local bind address (for server tunnels)
    pub bind_addr: Option<SocketAddr>,

    /// Pre-shared key for encryption
    pub psk: Option<Vec<u8>>,

    /// Path to TLS certificate file
    pub cert_path: Option<String>,

    /// Path to TLS key file
    pub key_path: Option<String>,

    /// Enable TLS verification
    pub verify_tls: bool,

    /// Connection timeout
    pub connect_timeout: Duration,

    /// Keepalive interval
    pub keepalive_interval: Duration,

    /// Maximum idle time before closing the tunnel
    pub max_idle_time: Duration,

    /// Maximum reconnect attempts
    pub max_reconnect_attempts: u32,

    /// Reconnect interval
    pub reconnect_interval: Duration,

    /// Maximum packet size
    pub max_packet_size: usize,
}

impl Default for TunnelConfig {
    fn default() -> Self {
        TunnelConfig {
            role: TunnelRole::Client,
            remote_addr: None,
            bind_addr: None,
            psk: None,
            cert_path: None,
            key_path: None,
            verify_tls: true,
            connect_timeout: Duration::from_secs(30),
            keepalive_interval: Duration::from_secs(15),
            max_idle_time: Duration::from_secs(300),
            max_reconnect_attempts: 5,
            reconnect_interval: Duration::from_secs(5),
            max_packet_size: 65_535,
        }
    }
}

impl TunnelConfig {
    /// Create a new tunnel configuration with default values.
    pub fn new() -> Self {
        TunnelConfig::default()
    }

    /// Create a client tunnel configuration.
    pub fn new_client(remote_addr: SocketAddr) -> Self {
        TunnelConfig {
            role: TunnelRole::Client,
            remote_addr: Some(remote_addr),
            ..Default::default()
        }
    }

    /// Create a server tunnel configuration.
    pub fn new_server(bind_addr: SocketAddr) -> Self {
        TunnelConfig {
            role: TunnelRole::Server,
            bind_addr: Some(bind_addr),
            ..Default::default()
        }
    }

    /// Set the pre-shared key.
    pub fn with_psk(mut self, psk: Vec<u8>) -> Self {
        self.psk = Some(psk);
        self
    }

    /// Set the TLS certificate and key paths.
    pub fn with_tls(mut self, cert_path: String, key_path: String) -> Self {
        self.cert_path = Some(cert_path);
        self.key_path = Some(key_path);
        self
    }

    /// Set TLS verification.
    pub fn with_tls_verification(mut self, verify: bool) -> Self {
        self.verify_tls = verify;
        self
    }

    /// Set connection timeout.
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Set keepalive interval.
    pub fn with_keepalive_interval(mut self, interval: Duration) -> Self {
        self.keepalive_interval = interval;
        self
    }

    /// Set maximum idle time.
    pub fn with_max_idle_time(mut self, max_idle_time: Duration) -> Self {
        self.max_idle_time = max_idle_time;
        self
    }

    /// Set maximum reconnect attempts.
    pub fn with_max_reconnect_attempts(mut self, attempts: u32) -> Self {
        self.max_reconnect_attempts = attempts;
        self
    }

    /// Set reconnect interval.
    pub fn with_reconnect_interval(mut self, interval: Duration) -> Self {
        self.reconnect_interval = interval;
        self
    }

    /// Set maximum packet size.
    pub fn with_max_packet_size(mut self, size: usize) -> Self {
        self.max_packet_size = size;
        self
    }

    /// Validate the configuration.
    pub fn validate(&self) -> TunnelResult<()> {
        match self.role {
            TunnelRole::Client => {
                if self.remote_addr.is_none() {
                    return Err(TunnelError::Config(
                        "Client tunnel requires a remote address".to_string(),
                    ));
                }
            }
            TunnelRole::Server => {
                if self.bind_addr.is_none() {
                    return Err(TunnelError::Config(
                        "Server tunnel requires a bind address".to_string(),
                    ));
                }
            }
        }

        // Check that we have either a PSK or TLS credentials
        if self.psk.is_none() && (self.cert_path.is_none() || self.key_path.is_none()) {
            return Err(TunnelError::Config(
                "Either PSK or TLS credentials (cert_path and key_path) must be provided"
                    .to_string(),
            ));
        }

        Ok(())
    }

    /// Create a tunnel configuration from the global configuration.
    pub fn from_global_config(config: &GlobalConfig) -> TunnelResult<Self> {
        let role = match config.role {
            crate::config::Role::Client => TunnelRole::Client,
            crate::config::Role::Server => TunnelRole::Server,
        };

        let mut tunnel_config = TunnelConfig {
            role,
            ..Default::default()
        };

        // Set addresses
        match tunnel_config.role {
            TunnelRole::Client => {
                if let Some(server_address) = &config.client.server_address {
                    // Parse server address
                    let addr = server_address.parse::<SocketAddr>().map_err(|_| {
                        TunnelError::Config(format!("Invalid server address: {}", server_address))
                    })?;

                    tunnel_config.remote_addr = Some(addr);
                } else {
                    return Err(TunnelError::Config(
                        "Client configuration missing server_address".to_string(),
                    ));
                }
            }
            TunnelRole::Server => {
                // Construct bind address from config
                let addr = format!("{}:{}", config.network.bind_address, config.network.port)
                    .parse::<SocketAddr>()
                    .map_err(|e| TunnelError::Config(format!("Invalid bind address: {}", e)))?;

                tunnel_config.bind_addr = Some(addr);
            }
        }

        // Set security parameters
        if let Some(psk) = &config.security.psk {
            // Derive a 32-byte key from the PSK string using SHA-256
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(psk.as_bytes());
            let key = hasher.finalize().to_vec();
            tunnel_config.psk = Some(key);
        }

        tunnel_config.cert_path = config.security.cert_path.clone();
        tunnel_config.key_path = config.security.key_path.clone();
        tunnel_config.verify_tls = config.security.verify_tls;

        // Set client-specific parameters
        if let TunnelRole::Client = tunnel_config.role {
            tunnel_config.max_reconnect_attempts = if config.client.auto_reconnect { 5 } else { 0 };
            tunnel_config.reconnect_interval =
                Duration::from_secs(config.client.reconnect_interval);
        }

        // Validate the configuration
        tunnel_config.validate()?;

        Ok(tunnel_config)
    }
}
