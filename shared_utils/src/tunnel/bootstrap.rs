//! Tunnel bootstrapping abstractions.
//!
//! This module provides abstractions for bootstrapping tunnels,
//! handling the common setup logic for both client and server tunnels.

use std::net::SocketAddr;
use tokio::sync::mpsc;
use tracing::{debug, error, info};

use crate::crypto::aes_gcm::AesGcmCipher;
// Updated imports for the new transport traits
use crate::quic::{QuicClient, QuicServer}; // These are now concrete types implementing the traits
use crate::transport::{
    ClientTransport,
    Connection as TraitConnection,
    Listener as TraitListener,
    ServerTransport,
    TransportError as NewTransportError, // Alias to avoid conflict if old one was used locally
};
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
// #[derive(Debug)] // Manual Debug impl needed due to Box<dyn TraitConnection>
pub struct TunnelHandle {
    /// Unique identifier for the tunnel
    pub id: TunnelId,

    /// Current state of the tunnel
    pub state: TunnelState,

    /// Remote endpoint address (for client) or local listening address (for server before accept)
    pub peer_or_listen_addr: SocketAddr,

    /// Active connection, implementing the transport::Connection trait
    pub connection: Option<Box<dyn TraitConnection + Send + Sync>>, // Make it Send + Sync

    /// For server tunnels, the listener that's waiting for connections
    pub listener: Option<Box<dyn TraitListener + Send + Sync>>,

    /// Channel for sending application data to the tunnel
    pub tx: mpsc::Sender<Vec<u8>>,

    /// Channel for receiving application data from the tunnel
    pub rx: mpsc::Receiver<Vec<u8>>,

    // transport_rx is removed as recv_data is now a direct async call on the Connection trait
    /// Tunnel statistics
    pub stats: TunnelStats,
}

impl std::fmt::Debug for TunnelHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let connection_status = if self.connection.is_some() {
            "Some(Connection)"
        } else {
            "None"
        };
        let listener_status = if self.listener.is_some() {
            "Some(Listener)"
        } else {
            "None"
        };
        f.debug_struct("TunnelHandle")
            .field("id", &self.id)
            .field("state", &self.state)
            .field("peer_or_listen_addr", &self.peer_or_listen_addr)
            .field("connection", &connection_status)
            .field("listener", &listener_status)
            .field("tx", &"mpsc::Sender") // Placeholder for non-Debug type
            .field("rx", &"mpsc::Receiver") // Placeholder for non-Debug type
            .field("stats", &self.stats)
            .finish()
    }
}

impl TunnelHandle {
    /// Create a new tunnel handle.
    pub(crate) fn new(
        id: TunnelId,
        peer_or_listen_addr: SocketAddr,
        tx: mpsc::Sender<Vec<u8>>,
        rx: mpsc::Receiver<Vec<u8>>,
    ) -> Self {
        let stats = TunnelStats::new(peer_or_listen_addr);

        TunnelHandle {
            id,
            state: TunnelState::Initializing,
            peer_or_listen_addr,
            connection: None,
            listener: None,
            tx,
            rx,
            stats,
        }
    }

    /// Set the tunnel state.
    pub fn set_state(&mut self, state: TunnelState) {
        self.state = state;
        self.stats.set_state(state);
    }

    /// Set the active connection.
    pub fn set_connection(&mut self, connection: Box<dyn TraitConnection + Send + Sync>) {
        // Update peer_or_listen_addr to the actual peer address from the connection if possible
        if let Ok(peer_addr) = connection.peer_addr() {
            self.peer_or_listen_addr = peer_addr;
            self.stats.update_remote_addr(peer_addr); // Update stats too
        }
        self.connection = Some(connection);
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
        if config.role != TunnelRole::Client {
            return Err(TunnelError::Config(
                "ClientBootstrapper requires client role".to_string(),
            ));
        }

        let remote_addr_str = config
            .remote_addr
            .ok_or_else(|| TunnelError::Config("Client tunnel requires remote_addr".to_string()))?
            .to_string(); // connect expects &str

        let remote_addr_socket = remote_addr_str
            .parse::<SocketAddr>()
            .map_err(|e| TunnelError::Config(format!("Invalid remote_addr: {}", e)))?;

        let id = TunnelId::from(format!("client-{}", uuid::Uuid::new_v4()));
        info!(tunnel_id = %id, remote_addr = %remote_addr_str, "ClientBootstrapper: bootstrap - START");

        let (tx, rx) = mpsc::channel(100);
        let mut handle = TunnelHandle::new(id.clone(), remote_addr_socket, tx, rx);

        let key = config.psk.clone().unwrap_or_else(|| {
            let key_array = AesGcmCipher::generate_key();
            debug!(tunnel_id = %id, "Generated random encryption key for client");
            key_array.to_vec()
        });

        let quic_client = QuicClient::new(&key).map_err(|e: NewTransportError| {
            error!(tunnel_id = %id, error = %e, "Failed to create QUIC client");
            TunnelError::Transport(e) // Assuming TunnelError::Transport can take NewTransportError
        })?;

        handle.set_state(TunnelState::Connecting);
        info!(tunnel_id = %id, remote_addr = %remote_addr_str, "ClientBootstrapper: bootstrap - Connecting to server. START_AWAIT for quic_client.connect");

        let connection_result = quic_client.connect(&remote_addr_str).await;
        info!(tunnel_id = %id, remote_addr = %remote_addr_str, "ClientBootstrapper: bootstrap - Connecting to server. END_AWAIT for quic_client.connect");

        let connection = connection_result.map_err(|e: NewTransportError| {
            error!(tunnel_id = %id, error = %e, "Failed to connect to server");
            handle.set_state(TunnelState::Failed);
            TunnelError::Transport(e)
        })?;

        // The connection object itself is now Box<dyn TraitConnection + Send + Sync>
        // The old handle.set_connection took quinn::Connection. This needs to be updated.
        // Let's assume set_connection is updated to take the trait object.
        handle.set_connection(connection); // This will also update peer_or_listen_addr in handle

        // Removed transport_rx setup as recv_data is called directly on the connection.

        handle.set_state(TunnelState::Connected);
        info!(tunnel_id = %id, remote_addr = %handle.peer_or_listen_addr, "ClientBootstrapper: bootstrap - Client tunnel bootstrapped successfully. END");

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
    pub fn new() -> Self {
        ServerBootstrapper
    }
}

impl TunnelBootstrapper for ServerBootstrapper {
    async fn bootstrap(&self, config: TunnelConfig) -> TunnelResult<TunnelHandle> {
        if config.role != TunnelRole::Server {
            return Err(TunnelError::Config(
                "ServerBootstrapper requires server role".to_string(),
            ));
        }

        let bind_addr = config
            .bind_addr
            .ok_or_else(|| TunnelError::Config("Server tunnel requires bind_addr".to_string()))?;

        let id = TunnelId::from(format!("server-{}", uuid::Uuid::new_v4()));
        info!(
            "ServerBootstrapper: bootstrap - START for id {} at {}",
            id, bind_addr
        );

        let (tx, rx) = mpsc::channel(100);
        // Initially, peer_or_listen_addr is the bind address for the server.
        // It will be updated to the client's address once a connection is accepted.
        let mut handle = TunnelHandle::new(id.clone(), bind_addr, tx, rx);

        let key = config.psk.clone().unwrap_or_else(|| {
            let key_array = AesGcmCipher::generate_key();
            info!(
                "ServerBootstrapper: bootstrap - Generated random encryption key for server {}",
                id
            );
            key_array.to_vec()
        });

        info!(
            "ServerBootstrapper: bootstrap - Creating QuicServer for {}",
            id
        );
        let quic_server = QuicServer::new(bind_addr, &key).map_err(|e: NewTransportError| {
            error!(
                "ServerBootstrapper: bootstrap - Failed to create QUIC server for {}: {}",
                id, e
            );
            TunnelError::Transport(e)
        })?;
        info!(
            "ServerBootstrapper: bootstrap - QuicServer created for {}",
            id
        );

        handle.set_state(TunnelState::Listening); // New state for server waiting for connection

        info!(
            "ServerBootstrapper: bootstrap - Server {} starting to listen at {}. START_AWAIT for quic_server.listen",
            id, bind_addr
        );

        // Listen for an incoming connection
        let listener_result = quic_server.listen(&bind_addr.to_string()).await;
        debug!(
            "ServerBootstrapper: bootstrap - Server {} finished listen() call. END_AWAIT for quic_server.listen",
            id
        );
        let listener = match listener_result {
            Ok(l) => {
                info!(
                    "ServerBootstrapper: bootstrap - Server {} successfully created listener",
                    id
                );
                l
            }
            Err(e) => {
                error!(
                    "ServerBootstrapper: bootstrap - Server {} failed to start listening: {}",
                    id, e
                );
                handle.set_state(TunnelState::Failed);
                return Err(TunnelError::Transport(e));
            }
        };

        debug!(
            "ServerBootstrapper: bootstrap - Server {} getting local_addr",
            id
        );
        let actual_listen_addr = match listener.local_addr() {
            Ok(addr) => {
                info!(
                    "ServerBootstrapper: bootstrap - Server {} got local_addr: {}",
                    id, addr
                );
                addr
            }
            Err(e) => {
                error!(
                    "ServerBootstrapper: bootstrap - Server {} failed to get actual listen address: {}",
                    id, e
                );
                return Err(TunnelError::Transport(e));
            }
        };

        info!(
            "ServerBootstrapper: bootstrap - Server {} listening on {}",
            id, actual_listen_addr
        );
        handle.peer_or_listen_addr = actual_listen_addr; // Update with actual listening address
        handle.stats.update_remote_addr(actual_listen_addr);

        // IMPORTANT: We're not waiting for a client connection during bootstrap anymore
        // This fixes the deadlock where the server waits for a client, but the client can't be created
        // until the server bootstrap completes

        // Store the listener in the handle for later use
        handle.listener = Some(Box::new(listener));

        // Set state to Listening instead of Connected since we haven't accepted a connection yet
        handle.set_state(TunnelState::Listening);
        info!(
            "ServerBootstrapper: bootstrap - Server {} tunnel bootstrapped (in Listening state). END",
            id
        );

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
            panic!("Expected Config error, got {:?}", result);
        }
    }

    #[tokio::test]
    async fn test_server_bootstrapper_validation() {
        let bootstrapper = ServerBootstrapper::new();

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
            panic!("Expected Config error, got {:?}", result);
        }
    }
}
