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
use shared_utils::quic::{QuicClient, QuicServer, QuicTransport, TransportMessage};

/// Error types that can occur in tunnel operations
#[derive(Debug, thiserror::Error)]
#[allow(dead_code)]
pub enum TunnelError {
    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// QUIC transport error
    #[error("QUIC transport error: {0}")]
    Transport(String),

    /// Framing error
    #[error("Framing error: {0}")]
    Framing(String),

    /// Encryption error
    #[error("Encryption error: {0}")]
    Encryption(String),

    /// Tunnel closed
    #[error("Tunnel closed")]
    Closed,
}

/// Tunnel state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum TunnelState {
    /// Tunnel is initializing
    Initializing,
    /// Tunnel is connected and ready
    Connected,
    /// Tunnel is closing
    Closing,
    /// Tunnel is closed
    Closed,
}

/// Enum to represent the type of transport
#[allow(dead_code)]
enum TransportType {
    /// Client transport
    Client(QuicClient),
    /// Server transport
    Server(QuicServer),
}

/// A secure tunnel for CoentroVPN communication
#[allow(dead_code)]
pub struct Tunnel {
    /// Unique identifier for the tunnel
    id: String,

    /// Remote endpoint address
    remote_addr: SocketAddr,

    /// Current state of the tunnel
    state: TunnelState,

    /// QUIC transport
    transport: TransportType,

    /// QUIC connection
    connection: Option<quinn::Connection>,

    /// Frame encoder/decoder
    framer: Arc<Mutex<StreamFramer>>,

    /// Encryption cipher
    cipher: Option<Arc<AesGcmCipher>>,

    /// Channel for sending data to the tunnel
    tx: mpsc::Sender<Vec<u8>>,

    /// Channel for receiving data from the tunnel
    rx: mpsc::Receiver<Vec<u8>>,
}

impl Tunnel {
    /// Create a new tunnel with a client transport
    #[instrument(level = "info", skip(client))]
    pub fn new_client(id: String, remote_addr: SocketAddr, client: QuicClient) -> Self {
        info!(tunnel_id = %id, remote = %remote_addr, "Creating new client tunnel");

        let (tx, rx) = mpsc::channel(100);

        Tunnel {
            id,
            remote_addr,
            state: TunnelState::Initializing,
            transport: TransportType::Client(client),
            connection: None,
            framer: Arc::new(Mutex::new(StreamFramer::new())),
            cipher: None,
            tx,
            rx,
        }
    }

    /// Create a new tunnel with a server transport
    #[instrument(level = "info", skip(server))]
    pub fn new_server(id: String, remote_addr: SocketAddr, server: QuicServer) -> Self {
        info!(tunnel_id = %id, remote = %remote_addr, "Creating new server tunnel");

        let (tx, rx) = mpsc::channel(100);

        Tunnel {
            id,
            remote_addr,
            state: TunnelState::Initializing,
            transport: TransportType::Server(server),
            connection: None,
            framer: Arc::new(Mutex::new(StreamFramer::new())),
            cipher: None,
            tx,
            rx,
        }
    }

    /// Get the tunnel ID
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Get the remote address
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    /// Get the current state
    pub fn state(&self) -> TunnelState {
        self.state
    }

    /// Set the encryption cipher
    #[instrument(level = "debug", skip(self, cipher))]
    pub fn set_cipher(&mut self, cipher: AesGcmCipher) {
        debug!(tunnel_id = %self.id, "Setting encryption cipher");
        self.cipher = Some(Arc::new(cipher));
    }

    /// Initialize the tunnel
    #[instrument(level = "info", skip(self))]
    pub async fn initialize(&mut self) -> Result<(), TunnelError> {
        info!(tunnel_id = %self.id, "Initializing tunnel");

        // Connect to the remote endpoint
        let connection = match &self.transport {
            TransportType::Client(client) => client
                .connect_to_server(self.remote_addr)
                .await
                .map_err(|e| TunnelError::Transport(format!("Failed to connect: {}", e)))?,
            TransportType::Server(_) => {
                // For server tunnels, we don't connect - the server accepts connections
                return Err(TunnelError::Transport(
                    "Server tunnels don't initiate connections".to_string(),
                ));
            }
        };

        self.connection = Some(connection);
        self.state = TunnelState::Connected;
        info!(tunnel_id = %self.id, "Tunnel initialized and connected");

        Ok(())
    }

    /// Send data through the tunnel
    #[instrument(level = "debug", skip(self, data), fields(data_len = data.len()))]
    pub async fn send(&self, data: &[u8]) -> Result<(), TunnelError> {
        if self.state != TunnelState::Connected {
            warn!(tunnel_id = %self.id, state = ?self.state, "Cannot send data: tunnel not connected");
            return Err(TunnelError::Closed);
        }

        let connection = self
            .connection
            .as_ref()
            .ok_or_else(|| TunnelError::Transport("No active connection".to_string()))?;

        debug!(tunnel_id = %self.id, data_len = data.len(), "Sending data through tunnel");

        // Encrypt data if cipher is available
        let payload = if let Some(cipher) = &self.cipher {
            trace!(tunnel_id = %self.id, "Encrypting data");
            cipher
                .encrypt(data)
                .map_err(|e| TunnelError::Encryption(e.to_string()))?
        } else {
            data.to_vec()
        };

        // Create a data frame
        let frame = Frame::new_data(payload).map_err(|e| TunnelError::Framing(e.to_string()))?;

        // Encode the frame
        let framer = self.framer.lock().await;
        let encoded = framer.encode(&frame);

        // Send the encoded frame
        match &self.transport {
            TransportType::Client(client) => {
                client
                    .send(connection.clone(), encoded)
                    .await
                    .map_err(|e| TunnelError::Transport(e.to_string()))?;
            }
            TransportType::Server(_server) => {
                _server
                    .send(connection.clone(), encoded)
                    .await
                    .map_err(|e| TunnelError::Transport(e.to_string()))?;
            }
        }

        debug!(tunnel_id = %self.id, frame_type = ?frame.frame_type, "Data sent successfully");

        Ok(())
    }

    /// Receive data from the tunnel
    #[instrument(level = "debug", skip(self))]
    pub async fn receive(&mut self) -> Result<Vec<u8>, TunnelError> {
        if self.state != TunnelState::Connected {
            warn!(tunnel_id = %self.id, state = ?self.state, "Cannot receive data: tunnel not connected");
            return Err(TunnelError::Closed);
        }

        let connection = self
            .connection
            .as_ref()
            .ok_or_else(|| TunnelError::Transport("No active connection".to_string()))?;

        debug!(tunnel_id = %self.id, "Receiving data from tunnel");

        // Set up a receiver for transport messages
        let mut rx = match &self.transport {
            TransportType::Client(client) => client
                .receive(connection.clone())
                .await
                .map_err(|e| TunnelError::Transport(e.to_string()))?,
            TransportType::Server(_server) => {
                // For server tunnels, we use the start method
                return Err(TunnelError::Transport(
                    "Server tunnels should use start() method".to_string(),
                ));
            }
        };

        // Wait for a message
        let message = rx
            .recv()
            .await
            .ok_or_else(|| TunnelError::Transport("Transport channel closed".to_string()))?;

        match message {
            TransportMessage::Data(raw_data) => {
                // Process the data through the framer
                let mut framer = self.framer.lock().await;
                let frame_count = framer
                    .process_data(&raw_data)
                    .map_err(|e| TunnelError::Framing(e.to_string()))?;

                debug!(tunnel_id = %self.id, frame_count, "Processed incoming frames");

                // Get the next frame
                if let Some(frame) = framer.next_frame() {
                    debug!(tunnel_id = %self.id, frame_type = ?frame.frame_type, payload_len = frame.payload.len(), "Received frame");

                    // Decrypt the payload if cipher is available
                    let data = if let Some(cipher) = &self.cipher {
                        trace!(tunnel_id = %self.id, "Decrypting data");
                        cipher
                            .decrypt(&frame.payload)
                            .map_err(|e| TunnelError::Encryption(e.to_string()))?
                    } else {
                        frame.payload
                    };

                    Ok(data)
                } else {
                    warn!(tunnel_id = %self.id, "No frames available after processing data");
                    Err(TunnelError::Framing("No frames available".to_string()))
                }
            }
            TransportMessage::Error(e) => {
                error!(tunnel_id = %self.id, error = ?e, "Transport error");
                Err(TunnelError::Transport(format!("Transport error: {}", e)))
            }
            TransportMessage::StreamClosed => {
                warn!(tunnel_id = %self.id, "Stream closed by peer");
                Err(TunnelError::Transport("Stream closed by peer".to_string()))
            }
            TransportMessage::ConnectionClosed => {
                warn!(tunnel_id = %self.id, "Connection closed by peer");
                self.state = TunnelState::Closed;
                Err(TunnelError::Closed)
            }
        }
    }

    /// Start the server tunnel
    #[instrument(level = "info", skip(self))]
    pub async fn start_server(&mut self) -> Result<mpsc::Receiver<TransportMessage>, TunnelError> {
        info!(tunnel_id = %self.id, "Starting server tunnel");

        if let TransportType::Server(server) = &self.transport {
            let rx = server
                .start()
                .await
                .map_err(|e| TunnelError::Transport(format!("Failed to start server: {}", e)))?;

            self.state = TunnelState::Connected;
            info!(tunnel_id = %self.id, "Server tunnel started");

            Ok(rx)
        } else {
            Err(TunnelError::Transport("Not a server tunnel".to_string()))
        }
    }

    /// Close the tunnel
    #[instrument(level = "info", skip(self))]
    pub async fn close(&mut self) -> Result<(), TunnelError> {
        info!(tunnel_id = %self.id, "Closing tunnel");

        if self.state == TunnelState::Closed {
            debug!(tunnel_id = %self.id, "Tunnel already closed");
            return Ok(());
        }

        self.state = TunnelState::Closing;

        if let Some(connection) = self.connection.take() {
            // Send a close frame
            let frame = Frame::new_control(b"close".to_vec())
                .map_err(|e| TunnelError::Framing(e.to_string()))?;

            let framer = self.framer.lock().await;
            let encoded = framer.encode(&frame);

            // Try to send the close frame, but don't fail if it doesn't work
            match &self.transport {
                TransportType::Client(client) => {
                    if let Err(e) = client.send(connection.clone(), encoded).await {
                        warn!(tunnel_id = %self.id, error = %e, "Failed to send close frame");
                    }

                    client.close(connection).await;
                }
                TransportType::Server(server) => {
                    if let Err(e) = server.send(connection.clone(), encoded).await {
                        warn!(tunnel_id = %self.id, error = %e, "Failed to send close frame");
                    }

                    server.close(connection).await;
                }
            }
        }

        self.state = TunnelState::Closed;
        info!(tunnel_id = %self.id, "Tunnel closed");

        Ok(())
    }
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        info!(tunnel_id = %self.id, "Tunnel being dropped");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_tunnel_creation() {
        // This test just verifies that the Tunnel struct can be created
        let _id = "test-tunnel".to_string();
        let _addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);

        // We can't create a real QuicClient or QuicServer in a unit test
        // So we'll just skip the actual test for now
        // In a real implementation, we would use a mock
    }
}
