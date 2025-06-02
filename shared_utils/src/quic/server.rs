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

        info!("QUIC server listening on {}", bind_addr);

        Ok(Self { endpoint, cipher })
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
        loop {
            match recv.read_chunk(8192, false).await {
                Ok(Some(chunk)) => {
                    debug!("Received {} encrypted bytes from client", chunk.bytes.len());

                    match cipher.decrypt(&chunk.bytes) {
                        Ok(decrypted_data) => {
                            debug!("Decrypted to {} bytes", decrypted_data.len());
                            // Forward the decrypted data to the channel
                            if let Err(e) = tx
                                .send(TransportMessage::Data(decrypted_data.clone()))
                                .await
                            {
                                // Clone data if used again
                                error!("Failed to send data to channel: {}", e);
                                break;
                            }

                            // Only try to echo back if the client requested a response
                            // In a real implementation, you might check a flag in the protocol
                            // or have a specific message type that requires a response
                            if false {
                                // Disabled echo for now to avoid errors when client closes stream
                                debug!(
                                    "Encrypting {} bytes before echoing to client",
                                    decrypted_data.len()
                                );
                                match cipher.encrypt(&decrypted_data) {
                                    Ok(encrypted_response) => {
                                        debug!(
                                            "Encrypted to {} bytes for echoing",
                                            encrypted_response.len()
                                        );
                                        // Try to write, but don't fail the whole stream if it doesn't work
                                        if let Err(e) = send.write_all(&encrypted_response).await {
                                            debug!(
                                                "Could not echo back to client (likely stream closed): {}",
                                                e
                                            );
                                            // Don't return error here, just log and continue
                                        }
                                    }
                                    Err(e) => {
                                        error!("Failed to encrypt response for client: {}", e);
                                        // Log the error but don't fail the whole stream
                                        // Just continue processing other messages
                                    }
                                }
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
                            // If decryption fails, we probably shouldn't try to send anything back on this stream.
                            // The error is sent via the channel, and we break the loop.
                            break;
                        }
                    }
                }
                Ok(None) => {
                    info!("Stream closed by client");
                    let _ = tx.send(TransportMessage::StreamClosed).await;
                    break;
                }
                Err(e) => {
                    error!("Error reading from stream: {}", e);
                    // Clone the error before moving it
                    let err_clone = TransportError::from(e.clone());
                    let _ = tx.send(TransportMessage::Error(e.into())).await;
                    return Err(err_clone);
                }
            }
        }

        // Try to finish the stream, but don't fail if it's already closed
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
