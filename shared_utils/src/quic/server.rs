//! QUIC server implementation for CoentroVPN.

use crate::crypto::aes_gcm::AesGcmCipher;
use quinn::{Connection, Endpoint, RecvStream, SendStream, ServerConfig};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use super::transport::{
    QuicTransport, TransportError, TransportMessage, TransportResult, configure_tls,
    generate_self_signed_cert,
};

/// QUIC server for CoentroVPN.
pub struct QuicServer {
    endpoint: Endpoint,
    cipher: Arc<AesGcmCipher>,
    local_addr: SocketAddr,
}

impl QuicServer {
    /// Create a new QUIC server bound to the specified address.
    pub fn new(bind_addr: SocketAddr, key: &[u8]) -> TransportResult<Self> {
        // Generate self-signed certificate for testing
        let (cert, key_pair) = generate_self_signed_cert()?; // Renamed key to key_pair to avoid conflict

        // Configure TLS
        let server_tls = configure_tls(cert, key_pair)?;

        // Initialize cipher
        let cipher = Arc::new(AesGcmCipher::new(key).map_err(|e| {
            TransportError::Other(format!("Failed to initialize server cipher: {}", e))
        })?);

        // Configure QUIC server
        let mut server_config = ServerConfig::with_crypto(server_tls);
        let mut transport_config = quinn::TransportConfig::default();

        // Set transport parameters
        transport_config
            .max_idle_timeout(Some(std::time::Duration::from_secs(30).try_into().unwrap()));
        transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(5)));

        server_config.transport = Arc::new(transport_config);

        // Create endpoint
        let endpoint = Endpoint::server(server_config, bind_addr)?;
        
        // Get the actual bound address (important when using port 0)
        let local_addr = endpoint.local_addr()?;

        info!("QUIC server listening on {}", local_addr);

        Ok(Self { endpoint, cipher, local_addr })
    }

    /// Get the local address the server is bound to.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Start the server and handle incoming connections.
    pub async fn start(&self) -> TransportResult<mpsc::Receiver<TransportMessage>> {
        let (tx, rx) = mpsc::channel(100);

        let endpoint = self.endpoint.clone();
        let cipher = self.cipher.clone(); // Clone Arc for the server task

        tokio::spawn(async move {
            loop {
                match endpoint.accept().await {
                    Some(conn) => {
                        let tx_clone = tx.clone();
                        let cipher_clone = cipher.clone(); // Clone Arc for each connection

                        tokio::spawn(async move {
                            match conn.await {
                                Ok(connection) => {
                                    info!("New connection from {}", connection.remote_address());

                                    if let Err(e) =
                                        Self::handle_connection(connection, tx_clone, cipher_clone)
                                            .await
                                    {
                                        error!("Error handling connection: {}", e);
                                    }
                                }
                                Err(e) => {
                                    error!("Error accepting connection: {}", e);
                                }
                            }
                        });
                    }
                    None => {
                        info!("Endpoint closed");
                        break;
                    }
                }
            }
        });

        Ok(rx)
    }

    /// Handle a connection.
    async fn handle_connection(
        connection: quinn::Connection,
        tx: mpsc::Sender<TransportMessage>,
        cipher: Arc<AesGcmCipher>, // Pass cipher
    ) -> TransportResult<()> {
        loop {
            // Accept a bidirectional stream directly
            match connection.accept_bi().await {
                Ok((send, recv)) => {
                    let tx_clone = tx.clone();
                    let cipher_clone = cipher.clone(); // Clone Arc for the stream task

                    tokio::spawn(async move {
                        if let Err(e) =
                            Self::handle_bidirectional_stream(send, recv, tx_clone, cipher_clone)
                                .await
                        {
                            error!("Error handling bidirectional stream: {}", e);
                        }
                    });
                }
                Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                    info!("Connection closed by application");
                    break;
                }
                Err(e) => {
                    warn!("Error accepting bidirectional stream: {}", e);
                    return Err(TransportError::Other(format!(
                        "Error accepting stream: {}",
                        e
                    )));
                }
            }
        }

        Ok(())
    }

    /// Handle a bidirectional stream.
    async fn handle_bidirectional_stream(
        mut send: SendStream,
        mut recv: RecvStream,
        tx: mpsc::Sender<TransportMessage>,
        cipher: Arc<AesGcmCipher>, // Pass cipher
    ) -> TransportResult<()> {
        let mut received_buffer = Vec::new();
        let mut eof_received = false;

        // Read all chunks from the stream until it's closed by the client
        loop {
            match recv.read_chunk(8192, false).await {
                Ok(Some(chunk)) => {
                    debug!("Received {} encrypted bytes from client", chunk.bytes.len());
                    received_buffer.extend_from_slice(&chunk.bytes);
                }
                Ok(None) => {
                    info!("Stream closed by client (EOF)");
                    eof_received = true;
                    break; // Finished reading all data from this stream
                }
                Err(e) => {
                    error!("Error reading from stream: {}", e);
                    let err_clone = TransportError::from(e.clone());
                    let _ = tx.send(TransportMessage::Error(e.into())).await;
                    return Err(err_clone); // Propagate read error
                }
            }
        }

        if !received_buffer.is_empty() {
            debug!("Total encrypted bytes received: {}", received_buffer.len());
            match cipher.decrypt(&received_buffer) {
                Ok(decrypted_data) => {
                    debug!("Decrypted to {} bytes", decrypted_data.len());
                    if let Err(e) = tx.send(TransportMessage::Data(decrypted_data)).await {
                        error!("Failed to send decrypted data to channel: {}", e);
                    }
                }
                Err(e) => {
                    error!("Failed to decrypt data from client: {}", e);
                    let _ = tx
                        .send(TransportMessage::Error(TransportError::Other(format!(
                            "Server decryption failed: {}",
                            e
                        ))))
                        .await;
                }
            }
        } else if eof_received {
            // Stream was closed without sending any data, or after sending data that was processed.
            // This is normal if the client just opens and closes a stream.
            info!("Stream closed by client without sending new data in this cycle.");
        }
        
        if eof_received {
             let _ = tx.send(TransportMessage::StreamClosed).await;
        }

        // Try to finish the sending side of the stream, but don't fail if it's already closed
        match send.finish().await {
            Ok(_) => debug!("Stream finished successfully"),
            Err(e) => {
                // If the error is because the peer closed the stream, that's expected
                if e.to_string().contains("sending stopped by peer") {
                    debug!("Stream already closed by peer, couldn't finish");
                } else {
                    // Only log as error for unexpected issues
                    error!("Failed to finish stream: {}", e);
                }
                // Don't return an error here, as the stream is already closed
            }
        }

        Ok(())
    }
}

impl QuicTransport for QuicServer {
    fn connect(&self, _addr: SocketAddr) -> TransportResult<Connection> {
        // Servers don't connect to clients, they accept connections
        Err(TransportError::Other(
            "Servers don't connect to clients".to_string(),
        ))
    }

    async fn send(&self, connection: Connection, data: Vec<u8>) -> TransportResult<()> {
        debug!("Encrypting {} bytes before sending from server", data.len());
        let encrypted_data = self
            .cipher
            .encrypt(&data)
            .map_err(|e| TransportError::Other(format!("Server encryption failed: {}", e)))?;
        debug!(
            "Encrypted to {} bytes for sending from server",
            encrypted_data.len()
        );

        let (mut send, _) = connection.open_bi().await.map_err(|e| {
            TransportError::Other(format!("Failed to open bidirectional stream: {}", e))
        })?;

        send.write_all(&encrypted_data)
            .await
            .map_err(TransportError::Write)?;

        send.finish().await.map_err(TransportError::Write)?;

        Ok(())
    }

    async fn receive(
        &self,
        _connection: Connection,
    ) -> TransportResult<mpsc::Receiver<TransportMessage>> {
        // For servers, use the start() method instead
        Err(TransportError::Other(
            "Use start() method for servers".to_string(),
        ))
    }

    async fn close(&self, connection: Connection) {
        connection.close(0u32.into(), b"Server closed connection");
    }
}
