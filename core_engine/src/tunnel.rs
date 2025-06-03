//! Tunnel implementation for CoentroVPN.
//!
//! This module handles the creation and management of network tunnels
//! for secure communication between CoentroVPN clients and servers.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc};
use tracing::{debug, error, info, instrument, trace, warn};

use shared_utils::crypto::aes_gcm::AesGcmCipher;
use shared_utils::proto::framing::{Frame, StreamFramer};
// Updated imports for the new transport traits
use shared_utils::quic::{QuicClient, QuicServer}; // Concrete types
use shared_utils::transport::{
    ClientTransport, Connection as TraitConnection, Listener as TraitListener, ServerTransport,
    TransportError as NewTransportError, // Alias to avoid conflict
};

/// Error types that can occur in tunnel operations
#[derive(Debug, thiserror::Error)]
#[allow(dead_code)]
pub enum TunnelError {
    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// Transport layer error
    #[error("Transport error: {0}")]
    Transport(#[from] NewTransportError), // Changed from String

    /// Framing error
    #[error("Framing error: {0}")]
    Framing(String),

    /// Encryption error
    #[error("Encryption error: {0}")]
    Encryption(String),

    /// Tunnel closed
    #[error("Tunnel closed")]
    Closed,

    /// Operation attempted on a non-connected tunnel
    #[error("Tunnel not connected")]
    NotConnected,
}

/// Tunnel state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum TunnelState {
    /// Tunnel is initializing
    Initializing,
    /// Server tunnel is listening
    Listening,
    /// Client tunnel is connecting
    Connecting,
    /// Tunnel is connected and ready
    Connected,
    /// Tunnel is closing
    Closing,
    /// Tunnel is closed
    Closed,
    /// Tunnel has failed
    Failed,
}

/// Enum to represent the type of transport provider (QuicClient or QuicServer)
#[allow(dead_code)]
enum TransportProvider {
    Client(QuicClient),
    Server(QuicServer),
    // We might add TcpClient, TcpServer etc. here later
}

/// A secure tunnel for CoentroVPN communication
#[allow(dead_code)]
pub struct Tunnel {
    /// Unique identifier for the tunnel
    id: String,

    /// Remote endpoint address (client) or listen address (server)
    address: SocketAddr,

    /// Current state of the tunnel
    state: TunnelState,

    /// Transport provider (e.g., QuicClient, QuicServer)
    provider: TransportProvider,

    /// Active connection object
    connection: Option<Box<dyn TraitConnection + Send + Sync>>,

    /// Listener object (for server tunnels)
    listener: Option<Box<dyn TraitListener + Send + Sync>>,

    /// Frame encoder/decoder
    framer: Arc<Mutex<StreamFramer>>,

    /// Encryption cipher
    cipher: Option<Arc<AesGcmCipher>>,

    // Channels for application data (tx to send into tunnel, rx to receive from tunnel)
    // These are not used by the tunnel's internal send/receive directly anymore
    // but can be used by an application layer above the tunnel.
    app_tx: mpsc::Sender<Vec<u8>>,
    app_rx: mpsc::Receiver<Vec<u8>>,
}

impl Tunnel {
    /// Create a new tunnel with a client transport provider
    #[instrument(level = "info", skip(client))]
    pub fn new_client(id: String, remote_addr: SocketAddr, client: QuicClient) -> Self {
        info!(tunnel_id = %id, remote = %remote_addr, "Creating new client tunnel");
        let (app_tx, app_rx) = mpsc::channel(100);
        Tunnel {
            id,
            address: remote_addr,
            state: TunnelState::Initializing,
            provider: TransportProvider::Client(client),
            connection: None,
            listener: None,
            framer: Arc::new(Mutex::new(StreamFramer::new())),
            cipher: None,
            app_tx,
            app_rx,
        }
    }

    /// Create a new tunnel with a server transport provider
    #[instrument(level = "info", skip(server))]
    pub fn new_server(id: String, listen_addr: SocketAddr, server: QuicServer) -> Self {
        info!(tunnel_id = %id, listen_addr = %listen_addr, "Creating new server tunnel");
        let (app_tx, app_rx) = mpsc::channel(100);
        Tunnel {
            id,
            address: listen_addr,
            state: TunnelState::Initializing,
            provider: TransportProvider::Server(server),
            connection: None,
            listener: None,
            framer: Arc::new(Mutex::new(StreamFramer::new())),
            cipher: None,
            app_tx,
            app_rx,
        }
    }

    pub fn id(&self) -> &str { &self.id }
    pub fn state(&self) -> TunnelState { self.state }
    pub fn address(&self) -> SocketAddr { self.address }


    #[instrument(level = "debug", skip(self, cipher))]
    pub fn set_cipher(&mut self, cipher: AesGcmCipher) {
        debug!(tunnel_id = %self.id, "Setting encryption cipher");
        self.cipher = Some(Arc::new(cipher));
    }

    /// Initialize a client tunnel (connects to server)
    #[instrument(level = "info", skip(self))]
    pub async fn initialize_client(&mut self) -> Result<(), TunnelError> {
        info!(tunnel_id = %self.id, "Initializing client tunnel");
        if !matches!(self.provider, TransportProvider::Client(_)) {
            return Err(TunnelError::Transport(NewTransportError::Generic("Not a client tunnel provider".to_string())));
        }
        self.state = TunnelState::Connecting;
        let client = match &self.provider {
            TransportProvider::Client(c) => c,
            _ => unreachable!(), // Already checked
        };
        let conn = client.connect(&self.address.to_string()).await?;
        self.connection = Some(conn);
        self.state = TunnelState::Connected;
        info!(tunnel_id = %self.id, "Client tunnel initialized and connected to {}", self.address);
        Ok(())
    }

    /// Start listening on a server tunnel (does not accept yet)
    #[instrument(level = "info", skip(self))]
    pub async fn start_server_listening(&mut self) -> Result<(), TunnelError> {
        info!(tunnel_id = %self.id, "Starting server tunnel listening");
        if !matches!(self.provider, TransportProvider::Server(_)) {
            return Err(TunnelError::Transport(NewTransportError::Generic("Not a server tunnel provider".to_string())));
        }
        self.state = TunnelState::Listening;
        let server = match &self.provider {
            TransportProvider::Server(s) => s,
            _ => unreachable!(),
        };
        let listener = server.listen(&self.address.to_string()).await?;
        self.address = listener.local_addr()?; // Update to actual listening address
        self.listener = Some(Box::new(listener));
        info!(tunnel_id = %self.id, "Server tunnel listening on {}", self.address);
        Ok(())
    }

    /// Accept a connection on a listening server tunnel
    #[instrument(level = "info", skip(self))]
    pub async fn accept_server_connection(&mut self) -> Result<(), TunnelError> {
        info!(tunnel_id = %self.id, "Server tunnel accepting connection");
        if self.state != TunnelState::Listening {
            return Err(TunnelError::NotConnected); // Or a more specific "NotListening"
        }
        if let Some(listener) = self.listener.as_mut() {
            let conn = listener.accept().await?;
            info!(tunnel_id = %self.id, "Server accepted connection from {}", conn.peer_addr()?);
            self.connection = Some(conn);
            self.state = TunnelState::Connected;
            Ok(())
        } else {
            Err(TunnelError::Transport(NewTransportError::Generic("Server listener not available".to_string())))
        }
    }


    /// Send application data through the tunnel (encrypts and frames)
    #[instrument(level = "debug", skip(self, data), fields(data_len = data.len()))]
    pub async fn send_app_data(&mut self, data: &[u8]) -> Result<(), TunnelError> {
        if self.state != TunnelState::Connected {
            warn!(tunnel_id = %self.id, state = ?self.state, "Cannot send data: tunnel not connected");
            return Err(TunnelError::NotConnected);
        }
        let conn = self.connection.as_mut().ok_or(TunnelError::NotConnected)?;
        
        debug!(tunnel_id = %self.id, data_len = data.len(), "Sending application data");
        let payload = if let Some(cipher) = &self.cipher {
            trace!(tunnel_id = %self.id, "Encrypting data");
            cipher.encrypt(data).map_err(|e| TunnelError::Encryption(e.to_string()))?
        } else {
            data.to_vec()
        };
        let frame = Frame::new_data(payload).map_err(|e| TunnelError::Framing(e.to_string()))?;
        let framer = self.framer.lock().await;
        let encoded = framer.encode(&frame);
        
        conn.send_data(&encoded).await?;
        debug!(tunnel_id = %self.id, frame_type = ?frame.frame_type, "Data sent successfully");
        Ok(())
    }

    /// Receive application data from the tunnel (deframes and decrypts)
    #[instrument(level = "debug", skip(self))]
    pub async fn recv_app_data(&mut self) -> Result<Vec<u8>, TunnelError> {
        if self.state != TunnelState::Connected {
            warn!(tunnel_id = %self.id, state = ?self.state, "Cannot receive data: tunnel not connected");
            return Err(TunnelError::NotConnected);
        }
        let conn = self.connection.as_mut().ok_or(TunnelError::NotConnected)?;

        debug!(tunnel_id = %self.id, "Receiving data from tunnel");
        
        // Loop to process incoming data until a full application frame is available
        loop {
            // Check if framer already has a complete frame
            let mut framer_guard = self.framer.lock().await;
            if let Some(frame) = framer_guard.next_frame() {
                debug!(tunnel_id = %self.id, frame_type = ?frame.frame_type, payload_len = frame.payload.len(), "Dequeued frame");
                // Unlock framer before potential decryption
                drop(framer_guard);
                return if let Some(cipher) = &self.cipher {
                    trace!(tunnel_id = %self.id, "Decrypting data");
                    cipher.decrypt(&frame.payload).map_err(|e| TunnelError::Encryption(e.to_string()))
                } else {
                    Ok(frame.payload)
                };
            }
            // Unlock framer before await
            drop(framer_guard);

            // No complete frame yet, read more data from transport
            match conn.recv_data().await {
                Ok(Some(raw_data)) => {
                    trace!(tunnel_id = %self.id, bytes_recvd = raw_data.len(), "Received raw data chunk from transport");
                    let mut framer_guard = self.framer.lock().await;
                    framer_guard.process_data(&raw_data).map_err(|e| TunnelError::Framing(e.to_string()))?;
                    // Loop will continue and check next_frame() again
                }
                Ok(None) => { // Connection closed gracefully by peer
                    warn!(tunnel_id = %self.id, "Connection closed by peer while receiving data");
                    self.state = TunnelState::Closed;
                    return Err(TunnelError::Closed);
                }
                Err(e) => { // Transport error
                    error!(tunnel_id = %self.id, error = ?e, "Transport error receiving data");
                    self.state = TunnelState::Failed;
                    return Err(TunnelError::Transport(e));
                }
            }
        }
    }

    /// Close the tunnel
    #[instrument(level = "info", skip(self))]
    pub async fn close(&mut self) -> Result<(), TunnelError> {
        info!(tunnel_id = %self.id, "Closing tunnel");
        if self.state == TunnelState::Closed || self.state == TunnelState::Closing {
            debug!(tunnel_id = %self.id, "Tunnel already closed or closing");
            return Ok(());
        }
        self.state = TunnelState::Closing;

        if let Some(mut conn) = self.connection.take() {
            // Try to send a control frame indicating closure (best effort)
            let frame = Frame::new_control(b"close".to_vec()).map_err(|e| TunnelError::Framing(e.to_string()))?;
            let framer = self.framer.lock().await;
            let encoded = framer.encode(&frame);
            if let Err(e) = conn.send_data(&encoded).await {
                warn!(tunnel_id = %self.id, error = %e, "Failed to send close control frame");
            }
            // Now close the transport connection
            conn.close().await?;
        }
        
        self.state = TunnelState::Closed;
        info!(tunnel_id = %self.id, "Tunnel closed");
        Ok(())
    }
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        // Note: Dropping a Tunnel doesn't automatically close the async connection.
        // Explicit close() should be called for graceful shutdown.
        // If connection is still Some here, it means close was not called.
        if self.connection.is_some() {
             warn!(tunnel_id = %self.id, "Tunnel dropped without explicit close, connection might linger.");
        } else {
             info!(tunnel_id = %self.id, "Tunnel being dropped");
        }
    }
}

#[cfg(test)]
mod tests {
    // Tests would need significant rework due to async nature and transport changes.
    // Mocking the transport traits would be necessary for effective unit tests.
}
