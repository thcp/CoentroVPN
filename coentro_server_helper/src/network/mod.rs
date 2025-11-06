//! Platform-specific network interface management for the server helper.
//!
//! The helper must be able to provision and tear down privileged TUN/TAP
//! interfaces in an idempotent manner while also ensuring system level toggles
//! such as IP forwarding are applied. This module exposes a thin abstraction
//! that hides the per-platform differences so the higher level tunnel logic can
//! remain uniform.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::os::fd::OwnedFd;
use std::path::PathBuf;
use thiserror::Error;

use crate::ipc::messages::{DnsConfig, RouteSpec};
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::LinuxInterfaceManager;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::MacOsInterfaceManager;

/// Errors surfaced by interface management operations.
#[derive(Debug, Error)]
pub enum InterfaceError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("System command `{command}` failed: {stderr}")]
    CommandFailure { command: String, stderr: String },

    #[error("Platform error: {0}")]
    Platform(String),
}

/// Result alias for interface operations.
pub type InterfaceResult<T> = Result<T, InterfaceError>;

/// Desired properties for a provisioned TUN/TAP interface.
#[derive(Debug, Clone)]
pub struct TunConfig {
    /// Optional explicit name to assign to the interface.
    pub name_hint: Option<String>,
    /// Prefix used when auto-generating interface names (e.g. "srv")
    pub name_prefix: String,
    /// Primary IPv4 address expressed as CIDR (e.g. "10.20.0.1/24").
    pub ipv4_cidr: String,
    /// MTU that should be applied to the interface.
    pub mtu: u32,
    /// Whether the interface should be brought up automatically.
    pub bring_up: bool,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            name_hint: None,
            name_prefix: "srv".into(),
            ipv4_cidr: "10.0.0.1/24".into(),
            mtu: 1500,
            bring_up: true,
        }
    }
}

/// Details returned once a TUN interface has been provisioned.
#[allow(dead_code)]
#[derive(Debug)]
pub struct TunDescriptor {
    pub name: String,
    pub fd: OwnedFd,
    pub mtu: u32,
    pub ipv4_cidr: String,
    /// Location where the interface specific sysctl flag was toggled (if any).
    pub sysctl_touched: Option<PathBuf>,
}

#[allow(dead_code)]
impl TunDescriptor {
    pub fn display_name(&self) -> impl fmt::Display + '_ {
        &self.name
    }
}

/// DNS rollback metadata captured per session so crash recovery can restore host settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DnsRollback {
    LinuxResolvectl,
    LinuxResolvConf {
        original: Option<String>,
    },
    Macos {
        service: String,
        servers: Vec<String>,
        search_domains: Vec<String>,
    },
}

/// Policy state applied for a session; persisted so teardown/crash recovery can revert changes.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PolicyState {
    pub routes: Vec<RouteSpec>,
    pub dns: Option<DnsRollback>,
    pub nat: Option<NatState>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NatState {
    LinuxMasquerade { cidr: String },
}

/// Abstraction implemented per platform.
#[allow(dead_code)]
#[async_trait]
pub trait InterfaceManager: Send + Sync {
    /// Ensure the platform level forwarding toggles are enabled.
    async fn ensure_forwarding(&self) -> InterfaceResult<()>;

    /// Create (or re-create) a TUN interface that matches the provided config.
    async fn ensure_tun(&self, config: &TunConfig) -> InterfaceResult<TunDescriptor>;

    /// Tear down the named interface. Missing interfaces should be treated as
    /// success to keep the operation idempotent.
    async fn teardown_tun(&self, name: &str) -> InterfaceResult<()>;

    /// Remove any stale interfaces that match the provided prefix. This is used
    /// on helper start to clean up state that might have been left behind after
    /// a crash or unclean reboot.
    async fn cleanup_stale_interfaces(&self, prefix: &str) -> InterfaceResult<()>;

    /// Apply routing/DNS policy for the given interface, returning the state required for rollback.
    async fn apply_policy(
        &self,
        interface: &str,
        routes: &[RouteSpec],
        dns: Option<&DnsConfig>,
    ) -> InterfaceResult<PolicyState>;

    /// Roll back routing/DNS policy using the previously captured state.
    async fn rollback_policy(&self, interface: &str, state: &PolicyState) -> InterfaceResult<()>;

    /// Apply NAT behaviour for the provided CIDR, returning rollback metadata when supported.
    async fn apply_nat(&self, interface: &str, cidr: &str) -> InterfaceResult<Option<NatState>>;

    /// Roll back previously applied NAT state.
    async fn rollback_nat(&self, interface: &str, state: &NatState) -> InterfaceResult<()>;
}

/// Construct the concrete interface manager for the current platform.
#[allow(dead_code)]
pub fn build_interface_manager() -> Box<dyn InterfaceManager> {
    #[cfg(target_os = "linux")]
    {
        Box::new(LinuxInterfaceManager::default())
    }

    #[cfg(target_os = "macos")]
    {
        Box::new(MacOsInterfaceManager::default())
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        compile_error!("Unsupported platform for server helper");
    }
}

#[cfg(test)]
mod tests {
    use super::TunConfig;

    #[test]
    fn config_default_has_reasonable_values() {
        let cfg = TunConfig::default();
        assert_eq!(cfg.name_prefix, "srv");
        assert_eq!(cfg.mtu, 1500);
        assert!(cfg.bring_up);
    }
}
