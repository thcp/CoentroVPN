//! IPC Message Definitions
//!
//! This module defines the message types used for communication between
//! the client and helper daemon.

use serde::{Deserialize, Serialize};

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
