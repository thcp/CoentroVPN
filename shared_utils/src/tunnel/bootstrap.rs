//! Tunnel bootstrapping abstractions.
//!
//! This module provides abstractions for bootstrapping tunnels,
//! handling the common setup logic for both client and server tunnels.

use std::net::SocketAddr;
use tokio::sync::mpsc;
use tracing::{debug, error, info};

use crate::crypto::aes_gcm::AesGcmCipher;
use crate::quic::{QuicClient, QuicServer, QuicTransport, TransportMessage};
use crate::tunnel::config::TunnelConfig;
use crate::tunnel::error::{TunnelError, TunnelResult};
use crate::tunnel::types::{TunnelId, TunnelRole, TunnelState, TunnelStats};

/// Common interface for tunnel bootstrapping.
#[allow(async_fn_in_trait)]
pub trait TunnelBootstrapper {
    /// Bootstrap a tunnel with the given configuration.
    async fn bootstrap(&self, config: TunnelConfig) -> TunnelResult<TunnelHandle>;
}

/// Handle to a bootstrapped tunnel.
#[derive(Debug)]
pub struct TunnelHandle {
    /// Unique identifier for the tunnel
    pub id: TunnelId,
    
    /// Current state of the tunnel
    pub state: TunnelState,
    
    /// Remote endpoint address
    pub remote_addr: SocketAddr,
    
    /// QUIC connection (if connected)
    pub connection: Option<quinn::Connection>,
    
    /// Channel for sending data to the tunnel
    pub tx: mpsc::Sender<Vec<u8>>,
    
    /// Channel for receiving data from the tunnel
    pub rx: mpsc::Receiver<Vec<u8>>,
    
    /// Channel for receiving transport messages
    pub transport_rx: Option<mpsc::Receiver<TransportMessage>>,
    
    /// Tunnel statistics
    pub stats: TunnelStats,
}

impl TunnelHandle {
    /// Create a new tunnel handle.
    fn new(
        id: TunnelId,
        remote_addr: SocketAddr,
        tx: mpsc::Sender<Vec<u8>>,
        rx: mpsc::Receiver<Vec<u8>>,
    ) -> Self {
        let stats = TunnelStats::new(remote_addr);
        
        TunnelHandle {
            id,
            state: TunnelState::Initializing,
            remote_addr,
            connection: None,
            tx,
            rx,
            transport_rx: None,
            stats,
        }
    }
    
    /// Set the tunnel state.
    pub fn set_state(&mut self, state: TunnelState) {
        self.state = state;
        self.stats.set_state(state);
    }
    
    /// Set the QUIC connection.
    pub fn set_connection(&mut self, connection: quinn::Connection) {
        self.connection = Some(connection);
    }
    
    /// Set the transport receiver.
    pub fn set_transport_rx(&mut self, rx: mpsc::Receiver<TransportMessage>) {
        self.transport_rx = Some(rx);
    }
}

/// Client tunnel bootstrapper.
#[derive(Debug)]
pub struct ClientBootstrapper;

impl Default for ClientBootstrapper {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientBootstrapper {
    /// Create a new client tunnel bootstrapper.
    pub fn new() -> Self {
        ClientBootstrapper
    }
}

impl TunnelBootstrapper for ClientBootstrapper {
    async fn bootstrap(&self, config: TunnelConfig) -> TunnelResult<TunnelHandle> {
        // Validate role
        if config.role != TunnelRole::Client {
            return Err(TunnelError::Config(
                "ClientBootstrapper requires client role".to_string(),
            ));
        }
        
        // Get remote address
        let remote_addr = config.remote_addr.ok_or_else(|| {
            TunnelError::Config("Client tunnel requires remote_addr".to_string())
        })?;
        
        // Generate a unique tunnel ID
        let id = TunnelId::from(format!("client-{}", uuid::Uuid::new_v4()));
        
        info!(tunnel_id = %id, remote_addr = %remote_addr, "Bootstrapping client tunnel");
        
        // Create channels for data
        let (tx, rx) = mpsc::channel(100);
        
        // Create tunnel handle
        let mut handle = TunnelHandle::new(id.clone(), remote_addr, tx, rx);
        
        // Initialize encryption
        let key = if let Some(psk) = &config.psk {
            psk.clone()
        } else {
            // In a real implementation, we would use TLS credentials
            // For now, just generate a random key
            let key_array = AesGcmCipher::generate_key();
            debug!(tunnel_id = %id, "Generated random encryption key");
            key_array.to_vec()
        };
        
        // Create QUIC client
        let client = match QuicClient::new(&key) {
            Ok(client) => client,
            Err(e) => {
                error!(tunnel_id = %id, error = %e, "Failed to create QUIC client");
                return Err(TunnelError::Transport(e));
            }
        };
        
        // Update state
        handle.set_state(TunnelState::Connecting);
        
        // Connect to server
        debug!(tunnel_id = %id, remote_addr = %remote_addr, "Connecting to server");
        
        let connection = match client.connect_to_server(remote_addr).await {
            Ok(conn) => conn,
            Err(e) => {
                error!(tunnel_id = %id, error = %e, "Failed to connect to server");
                handle.set_state(TunnelState::Failed);
                return Err(TunnelError::Transport(e));
            }
        };
        
        // Set connection in handle
        handle.set_connection(connection.clone());
        
        // Set up receiver for transport messages
        match client.receive(connection.clone()).await {
            Ok(transport_rx) => {
                handle.set_transport_rx(transport_rx);
            }
            Err(e) => {
                error!(tunnel_id = %id, error = %e, "Failed to set up transport receiver");
                handle.set_state(TunnelState::Failed);
                return Err(TunnelError::Transport(e));
            }
        }
        
        // Update state
        handle.set_state(TunnelState::Connected);
        
        info!(tunnel_id = %id, remote_addr = %remote_addr, "Client tunnel bootstrapped successfully");
        
        Ok(handle)
    }
}

/// Server tunnel bootstrapper.
#[derive(Debug)]
pub struct ServerBootstrapper;

impl Default for ServerBootstrapper {
    fn default() -> Self {
        Self::new()
    }
}

impl ServerBootstrapper {
    /// Create a new server tunnel bootstrapper.
    pub fn new() -> Self {
        ServerBootstrapper
    }
}

impl TunnelBootstrapper for ServerBootstrapper {
    async fn bootstrap(&self, config: TunnelConfig) -> TunnelResult<TunnelHandle> {
        // Validate role
        if config.role != TunnelRole::Server {
            return Err(TunnelError::Config(
                "ServerBootstrapper requires server role".to_string(),
            ));
        }
        
        // Get bind address
        let bind_addr = config.bind_addr.ok_or_else(|| {
            TunnelError::Config("Server tunnel requires bind_addr".to_string())
        })?;
        
        // Generate a unique tunnel ID
        let id = TunnelId::from(format!("server-{}", uuid::Uuid::new_v4()));
        
        info!(tunnel_id = %id, bind_addr = %bind_addr, "Bootstrapping server tunnel");
        
        // Create channels for data
        let (tx, rx) = mpsc::channel(100);
        
        // Create tunnel handle
        // For server, we use the bind address as the remote address initially
        let mut handle = TunnelHandle::new(id.clone(), bind_addr, tx, rx);
        
        // Initialize encryption
        let key = if let Some(psk) = &config.psk {
            psk.clone()
        } else {
            // In a real implementation, we would use TLS credentials
            // For now, just generate a random key
            let key_array = AesGcmCipher::generate_key();
            debug!(tunnel_id = %id, "Generated random encryption key");
            key_array.to_vec()
        };
        
        // Create QUIC server
        let server = match QuicServer::new(bind_addr, &key) {
            Ok(server) => server,
            Err(e) => {
                error!(tunnel_id = %id, error = %e, "Failed to create QUIC server");
                return Err(TunnelError::Transport(e));
            }
        };
        
        // Update state
        handle.set_state(TunnelState::Connecting);
        
        // Start server
        debug!(tunnel_id = %id, bind_addr = %bind_addr, "Starting server");
        
        let transport_rx = match server.start().await {
            Ok(rx) => rx,
            Err(e) => {
                error!(tunnel_id = %id, error = %e, "Failed to start server");
                handle.set_state(TunnelState::Failed);
                return Err(TunnelError::Transport(e));
            }
        };
        
        // Set transport receiver in handle
        handle.set_transport_rx(transport_rx);
        
        // Update state
        handle.set_state(TunnelState::Connected);
        
        info!(tunnel_id = %id, bind_addr = %bind_addr, "Server tunnel bootstrapped successfully");
        
        Ok(handle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    
    #[tokio::test]
    async fn test_client_bootstrapper_validation() {
        let bootstrapper = ClientBootstrapper::new();
        
        // Test with server role (should fail)
        let config = TunnelConfig::new_server(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            8080,
        ))
        .with_psk(vec![0; 32]);
        
        let result = bootstrapper.bootstrap(config).await;
        assert!(result.is_err());
        
        if let Err(TunnelError::Config(msg)) = result {
            assert!(msg.contains("requires client role"));
        } else {
            panic!("Expected Config error");
        }
    }
    
    #[tokio::test]
    async fn test_server_bootstrapper_validation() {
        let bootstrapper = ServerBootstrapper::new();
        
        // Test with client role (should fail)
        let config = TunnelConfig::new_client(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            8080,
        ))
        .with_psk(vec![0; 32]);
        
        let result = bootstrapper.bootstrap(config).await;
        assert!(result.is_err());
        
        if let Err(TunnelError::Config(msg)) = result {
            assert!(msg.contains("requires server role"));
        } else {
            panic!("Expected Config error");
        }
    }
}
