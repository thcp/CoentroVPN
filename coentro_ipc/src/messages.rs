//! IPC Message Definitions
//!
//! This module defines the message types used for communication between
//! the client and helper daemon.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};

/// Request sent from the client to the helper daemon
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum ClientRequest {
    /// Simple ping to check if the helper is alive
    Ping,

    /// Request to set up a VPN tunnel
    SetupTunnel(TunnelSetupRequest),

    /// Request to tear down an active tunnel
    TeardownTunnel,

    /// Request to get the current status of the helper
    GetStatus,
}

/// Details for setting up a tunnel
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TunnelSetupRequest {
    /// Unique identifier for the client
    pub client_id: String,

    /// Optional requested IP configuration
    pub requested_ip_config: Option<String>,

    /// List of routes to add to the routing table
    pub routes_to_add: Vec<String>,

    /// Optional list of DNS servers to configure
    pub dns_servers: Option<Vec<String>>,

    /// Optional MTU value for the tunnel interface
    pub mtu: Option<u32>,
}

impl TunnelSetupRequest {
    /// Validate the request parameters
    pub fn validate(&self) -> Result<(), String> {
        // Validate client_id
        if self.client_id.is_empty() {
            return Err("Client ID cannot be empty".to_string());
        }
        if self.client_id.len() > 64 {
            return Err("Client ID is too long (max 64 characters)".to_string());
        }

        // Validate client_id contains only safe characters (alphanumeric, dash, underscore)
        let safe_id_regex = Regex::new(r"^[a-zA-Z0-9_\-]+$").unwrap();
        if !safe_id_regex.is_match(&self.client_id) {
            return Err("Client ID contains invalid characters. Only alphanumeric characters, underscores, and dashes are allowed.".to_string());
        }

        // Validate requested_ip_config if provided
        if let Some(ip_config) = &self.requested_ip_config {
            if !Self::is_valid_cidr(ip_config) {
                return Err(format!("Invalid IP configuration: {}", ip_config));
            }
        }

        // Validate routes_to_add is not empty
        if self.routes_to_add.is_empty() {
            return Err("At least one route must be specified".to_string());
        }

        // Validate routes_to_add
        for route in &self.routes_to_add {
            if !Self::is_valid_cidr(route) {
                return Err(format!("Invalid route: {}", route));
            }
        }

        // Validate dns_servers if provided
        if let Some(dns_servers) = &self.dns_servers {
            if dns_servers.is_empty() {
                return Err("DNS servers list cannot be empty".to_string());
            }

            for dns in dns_servers {
                if !Self::is_valid_ip(dns) {
                    return Err(format!("Invalid DNS server IP: {}", dns));
                }
            }
        }

        // Validate mtu if provided
        if let Some(mtu) = self.mtu {
            // MTU should be between reasonable bounds
            // 1280 is the minimum for IPv6, 9000 is a common jumbo frame size
            if !(1280..=9000).contains(&mtu) {
                return Err(format!(
                    "Invalid MTU value: {}. Must be between 1280 and 9000",
                    mtu
                ));
            }
        }

        Ok(())
    }

    /// Check if a string is a valid CIDR notation
    fn is_valid_cidr(cidr: &str) -> bool {
        // Split into IP and prefix
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return false;
        }

        // Validate IP part
        if !Self::is_valid_ip(parts[0]) {
            return false;
        }

        // Validate prefix part
        if let Ok(prefix) = parts[1].parse::<u8>() {
            // Check if the prefix is valid for the IP version
            let is_ipv4 = parts[0].parse::<Ipv4Addr>().is_ok();

            if is_ipv4 {
                // IPv4 prefix should be 0-32
                prefix <= 32
            } else {
                // IPv6 prefix should be 0-128
                prefix <= 128
            }
        } else {
            false
        }
    }

    /// Check if a string is a valid IP address
    fn is_valid_ip(ip: &str) -> bool {
        // Check for common invalid patterns
        if ip.contains("..") || ip.starts_with('.') || ip.ends_with('.') {
            return false;
        }

        // Try to parse as IPv4
        if let Ok(ipv4) = ip.parse::<Ipv4Addr>() {
            // Reject certain special addresses
            if ipv4.is_broadcast() || ipv4.is_unspecified() {
                return false;
            }
            return true;
        }

        // Try to parse as IPv6
        if let Ok(ipv6) = ip.parse::<Ipv6Addr>() {
            // Reject unspecified address
            if ipv6.is_unspecified() {
                return false;
            }
            return true;
        }

        false
    }
}

/// Response sent from the helper daemon to the client
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum HelperResponse {
    /// Response to a ping request
    Pong,

    /// Generic success response
    Success,

    /// Response indicating that a tunnel is ready
    TunnelReady(TunnelReadyDetails),

    /// Response containing status information
    StatusReport(StatusDetails),

    /// Error response with a message
    Error(String),
}

/// Details about a ready tunnel
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TunnelReadyDetails {
    /// Name of the created interface
    pub interface_name: String,

    /// IP address assigned to the interface
    pub assigned_ip: String,

    /// MTU value assigned to the interface
    pub assigned_mtu: u32,

    /// File descriptor for the TUN device
    #[serde(skip)]
    pub fd: i32,
}

/// Status information about the helper daemon
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StatusDetails {
    /// Whether a tunnel is currently active
    pub tunnel_active: bool,

    /// Name of the active interface, if any
    pub active_interface: Option<String>,

    /// Current IP configuration, if any
    pub current_ip_config: Option<String>,

    /// Version of the helper daemon
    pub helper_version: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use bincode::{deserialize, serialize};

    #[test]
    fn test_serialize_deserialize_request() {
        let request = ClientRequest::SetupTunnel(TunnelSetupRequest {
            client_id: "test-client".to_string(),
            requested_ip_config: Some("10.0.0.1/24".to_string()),
            routes_to_add: vec!["0.0.0.0/0".to_string()],
            dns_servers: Some(vec!["8.8.8.8".to_string(), "1.1.1.1".to_string()]),
            mtu: Some(1500),
        });

        let serialized = serialize(&request).expect("Failed to serialize request");
        let deserialized: ClientRequest =
            deserialize(&serialized).expect("Failed to deserialize request");

        match deserialized {
            ClientRequest::SetupTunnel(setup) => {
                assert_eq!(setup.client_id, "test-client");
                assert_eq!(setup.requested_ip_config, Some("10.0.0.1/24".to_string()));
                assert_eq!(setup.routes_to_add, vec!["0.0.0.0/0".to_string()]);
                assert_eq!(
                    setup.dns_servers,
                    Some(vec!["8.8.8.8".to_string(), "1.1.1.1".to_string()])
                );
                assert_eq!(setup.mtu, Some(1500));
            }
            _ => panic!("Deserialized to wrong variant"),
        }
    }

    #[test]
    fn test_serialize_deserialize_response() {
        let response = HelperResponse::TunnelReady(TunnelReadyDetails {
            interface_name: "tun0".to_string(),
            assigned_ip: "10.0.0.1/24".to_string(),
            assigned_mtu: 1500,
            fd: 0, // Not actually used in the test since it's skipped in serialization
        });

        let serialized = serialize(&response).expect("Failed to serialize response");
        let deserialized: HelperResponse =
            deserialize(&serialized).expect("Failed to deserialize response");

        match deserialized {
            HelperResponse::TunnelReady(details) => {
                assert_eq!(details.interface_name, "tun0");
                assert_eq!(details.assigned_ip, "10.0.0.1/24");
                assert_eq!(details.assigned_mtu, 1500);
            }
            _ => panic!("Deserialized to wrong variant"),
        }
    }
}
