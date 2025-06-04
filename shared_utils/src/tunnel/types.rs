//! Type definitions for the tunnel module.

use std::fmt;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Unique identifier for a tunnel.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TunnelId(pub String);

impl fmt::Display for TunnelId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for TunnelId {
    fn from(s: String) -> Self {
        TunnelId(s)
    }
}

impl From<&str> for TunnelId {
    fn from(s: &str) -> Self {
        TunnelId(s.to_string())
    }
}

/// Role of the tunnel (client or server).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelRole {
    /// Client role
    Client,
    /// Server role
    Server,
}

/// State of the tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelState {
    /// Tunnel is initializing
    Initializing,
    /// Tunnel is connecting (client) or listening (server)
    Connecting,
    /// Server is listening for incoming connections
    Listening,
    /// Tunnel is connected and ready
    Connected,
    /// Tunnel is disconnecting
    Disconnecting,
    /// Tunnel is disconnected
    Disconnected,
    /// Tunnel has failed
    Failed,
}

/// Statistics for a tunnel.
#[derive(Debug, Clone)]
pub struct TunnelStats {
    /// When the tunnel was created
    pub created_at: Instant,
    /// When the tunnel was last active
    pub last_active: Instant,
    /// Total bytes sent
    pub bytes_sent: u64,
    /// Total bytes received
    pub bytes_received: u64,
    /// Number of packets sent
    pub packets_sent: u64,
    /// Number of packets received
    pub packets_received: u64,
    /// Connection uptime
    pub uptime: Duration,
    /// Remote endpoint address
    pub remote_addr: SocketAddr,
    /// Current state of the tunnel
    pub state: TunnelState,
}

impl TunnelStats {
    /// Create new tunnel statistics.
    pub fn new(remote_addr: SocketAddr) -> Self {
        let now = Instant::now();
        TunnelStats {
            created_at: now,
            last_active: now,
            bytes_sent: 0,
            bytes_received: 0,
            packets_sent: 0,
            packets_received: 0,
            uptime: Duration::from_secs(0),
            remote_addr,
            state: TunnelState::Initializing,
        }
    }

    /// Update the last active time.
    pub fn update_last_active(&mut self) {
        self.last_active = Instant::now();
    }

    /// Update the uptime.
    pub fn update_uptime(&mut self) {
        self.uptime = self.last_active.duration_since(self.created_at);
    }

    /// Record bytes sent.
    pub fn record_bytes_sent(&mut self, bytes: usize) {
        self.bytes_sent += bytes as u64;
        self.packets_sent += 1;
        self.update_last_active();
    }

    /// Record bytes received.
    pub fn record_bytes_received(&mut self, bytes: usize) {
        self.bytes_received += bytes as u64;
        self.packets_received += 1;
        self.update_last_active();
    }

    /// Set the tunnel state.
    pub fn set_state(&mut self, state: TunnelState) {
        self.state = state;
        self.update_last_active();
    }

    /// Update the remote address.
    pub fn update_remote_addr(&mut self, remote_addr: SocketAddr) {
        self.remote_addr = remote_addr;
        self.update_last_active();
    }
}
