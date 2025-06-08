//! Network Manager for the CoentroVPN Helper Daemon
//!
//! This module defines the network manager trait and platform-specific implementations
//! for managing TUN interfaces, routing tables, and DNS configuration.

use async_trait::async_trait;
use thiserror::Error;

// Import platform-specific implementations
mod linux;
mod macos;
#[cfg(any(target_os = "linux", not(any(target_os = "linux", target_os = "macos"))))]
use linux::LinuxNetworkManager;
pub use macos::MacOsNetworkManager;

/// Result type for network operations
pub type NetworkResult<T> = Result<T, NetworkError>;

/// Error type for network operations
#[derive(Error, Debug)]
pub enum NetworkError {
    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// TUN device error
    #[error("TUN device error: {0}")]
    #[allow(dead_code)]
    TunDevice(String),

    /// Routing error
    #[error("Routing error: {0}")]
    #[allow(dead_code)]
    Routing(String),

    /// DNS configuration error
    #[error("DNS configuration error: {0}")]
    #[allow(dead_code)]
    DnsConfig(String),

    /// Permission error
    #[error("Permission error: {0}")]
    #[allow(dead_code)]
    Permission(String),

    /// System command error
    #[error("System command error: {0}")]
    #[allow(dead_code)]
    SystemCommand(String),

    /// Other error
    #[error("Other error: {0}")]
    Other(String),
}

/// Configuration for a TUN interface
#[derive(Debug, Clone)]
pub struct TunConfig {
    /// Name of the interface (may be ignored on some platforms)
    #[allow(dead_code)]
    pub name: Option<String>,

    /// IP address and prefix length (e.g., "10.0.0.1/24")
    #[allow(dead_code)]
    pub ip_config: String,

    /// MTU value
    #[allow(dead_code)]
    pub mtu: u32,
}

/// Details about a created TUN interface
#[derive(Debug, Clone)]
pub struct TunDetails {
    /// Name of the created interface
    #[allow(dead_code)]
    pub name: String,

    /// Assigned IP address and prefix length
    #[allow(dead_code)]
    pub ip_config: String,

    /// Assigned MTU value
    #[allow(dead_code)]
    pub mtu: u32,

    /// File descriptor for the TUN device (platform-specific)
    #[allow(dead_code)]
    pub fd: i32,
}

/// Network Manager trait
#[allow(dead_code)]
#[async_trait]
pub trait NetworkManager: Send + Sync {
    /// Create a TUN interface
    async fn create_tun(&self, config: TunConfig) -> NetworkResult<TunDetails>;

    /// Destroy a TUN interface
    async fn destroy_tun(&self, name: &str) -> NetworkResult<()>;

    /// Add a route to the routing table
    async fn add_route(
        &self,
        destination: &str,
        gateway: Option<&str>,
        interface: &str,
    ) -> NetworkResult<()>;

    /// Remove a route from the routing table
    async fn remove_route(
        &self,
        destination: &str,
        gateway: Option<&str>,
        interface: &str,
    ) -> NetworkResult<()>;

    /// Configure DNS servers
    async fn configure_dns(&self, servers: &[String]) -> NetworkResult<()>;

    /// Restore original DNS configuration
    async fn restore_dns(&self) -> NetworkResult<()>;
}

/// Create a platform-specific network manager
///
/// This function detects the platform and returns the appropriate implementation.
pub fn create_network_manager() -> Box<dyn NetworkManager> {
    #[cfg(target_os = "linux")]
    {
        Box::new(LinuxNetworkManager::new())
    }

    #[cfg(target_os = "macos")]
    {
        Box::new(MacOsNetworkManager::new())
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        // For unsupported platforms, we default to Linux implementation
        // This should be updated as more platforms are supported
        Box::new(LinuxNetworkManager::new())
    }
}
