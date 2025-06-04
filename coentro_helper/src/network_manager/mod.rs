//! Network Manager for the CoentroVPN Helper Daemon
//!
//! This module defines the network manager trait and platform-specific implementations
//! for managing TUN interfaces, routing tables, and DNS configuration.

use async_trait::async_trait;
use thiserror::Error;

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
    TunDevice(String),

    /// Routing error
    #[error("Routing error: {0}")]
    Routing(String),

    /// DNS configuration error
    #[error("DNS configuration error: {0}")]
    DnsConfig(String),

    /// Permission error
    #[error("Permission error: {0}")]
    Permission(String),

    /// System command error
    #[error("System command error: {0}")]
    SystemCommand(String),

    /// Other error
    #[error("Other error: {0}")]
    Other(String),
}

/// Configuration for a TUN interface
#[derive(Debug, Clone)]
pub struct TunConfig {
    /// Name of the interface (may be ignored on some platforms)
    pub name: Option<String>,
    
    /// IP address and prefix length (e.g., "10.0.0.1/24")
    pub ip_config: String,
    
    /// MTU value
    pub mtu: u32,
}

/// Details about a created TUN interface
#[derive(Debug, Clone)]
pub struct TunDetails {
    /// Name of the created interface
    pub name: String,
    
    /// Assigned IP address and prefix length
    pub ip_config: String,
    
    /// Assigned MTU value
    pub mtu: u32,
    
    /// File descriptor for the TUN device (platform-specific)
    pub fd: i32,
}

/// Network Manager trait
#[async_trait]
pub trait NetworkManager: Send + Sync {
    /// Create a TUN interface
    async fn create_tun(&self, config: TunConfig) -> NetworkResult<TunDetails>;
    
    /// Destroy a TUN interface
    async fn destroy_tun(&self, name: &str) -> NetworkResult<()>;
    
    /// Add a route to the routing table
    async fn add_route(&self, destination: &str, gateway: Option<&str>, interface: &str) -> NetworkResult<()>;
    
    /// Remove a route from the routing table
    async fn remove_route(&self, destination: &str, gateway: Option<&str>, interface: &str) -> NetworkResult<()>;
    
    /// Configure DNS servers
    async fn configure_dns(&self, servers: &[String]) -> NetworkResult<()>;
    
    /// Restore original DNS configuration
    async fn restore_dns(&self) -> NetworkResult<()>;
}

// In Sprint 1, we're just setting up the basic structure
// Platform-specific implementations will be added in later sprints

// For now, create a dummy implementation for Linux
pub struct LinuxNetworkManager;

impl LinuxNetworkManager {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl NetworkManager for LinuxNetworkManager {
    async fn create_tun(&self, _config: TunConfig) -> NetworkResult<TunDetails> {
        // This will be implemented in Sprint 2
        Err(NetworkError::Other("Not implemented yet".to_string()))
    }
    
    async fn destroy_tun(&self, _name: &str) -> NetworkResult<()> {
        // This will be implemented in Sprint 2
        Err(NetworkError::Other("Not implemented yet".to_string()))
    }
    
    async fn add_route(&self, _destination: &str, _gateway: Option<&str>, _interface: &str) -> NetworkResult<()> {
        // This will be implemented in Sprint 2
        Err(NetworkError::Other("Not implemented yet".to_string()))
    }
    
    async fn remove_route(&self, _destination: &str, _gateway: Option<&str>, _interface: &str) -> NetworkResult<()> {
        // This will be implemented in Sprint 2
        Err(NetworkError::Other("Not implemented yet".to_string()))
    }
    
    async fn configure_dns(&self, _servers: &[String]) -> NetworkResult<()> {
        // This will be implemented in Sprint 2
        Err(NetworkError::Other("Not implemented yet".to_string()))
    }
    
    async fn restore_dns(&self) -> NetworkResult<()> {
        // This will be implemented in Sprint 2
        Err(NetworkError::Other("Not implemented yet".to_string()))
    }
}

/// Create a platform-specific network manager
/// 
/// For Sprint 1, we're just returning a concrete type instead of a trait object
/// since async traits are not yet fully supported for trait objects.
/// This will be refactored in a future sprint.
pub fn create_network_manager() -> LinuxNetworkManager {
    // For now, just return a Linux network manager
    // In later sprints, this will detect the platform and return the appropriate implementation
    LinuxNetworkManager::new()
}
