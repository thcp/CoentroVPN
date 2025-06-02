//! QUIC client implementation for CoentroVPN.

use crate::crypto::aes_gcm::AesGcmCipher;
use quinn::{ClientConfig, Connection, Endpoint, RecvStream, SendStream};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use super::transport::{
    QuicTransport, TransportError, TransportMessage, TransportResult, configure_client_tls,
};

/// QUIC client for CoentroVPN.
pub struct QuicClient {
    endpoint: Endpoint,
    cipher: Arc<AesGcmCipher>,
}

impl QuicClient {
    /// Create a new QUIC client.
    pub fn new(key: &[u8]) -> TransportResult<Self> {
        // Configure client TLS
        let client_tls = configure_client_tls()?;

        // Initialize cipher
        let cipher =
            Arc::new(AesGcmCipher::new(key).map_err(|e| {
                TransportError::Other(format!("Failed to initialize cipher: {}", e))
            })?);

        // Configure QUIC client
        let mut client_config = ClientConfig::new(client_tls);
        let mut transport_config = quinn::TransportConfig::default();

        // Set transport parameters
        transport_config
            .max_idle_timeout(Some(std::time::Duration::from_secs(30).try_into().unwrap()));
        transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(5)));

        client_config.transport_config(Arc::new(transport_config));

        // Create endpoint
        let mut endpoint = Endpoint::client(SocketAddr::from(([0, 0, 0, 0], 0)))?;
        endpoint.set_default_client_config(client_config);

        Ok(Self { endpoint, cipher })
    }

    /// Connect to a server and establish a new connection.
    pub async fn connect_to_server(&self, server_addr: SocketAddr) -> TransportResult<Connection> {
        info!("Connecting to QUIC server at {}", server_addr);

        let connecting = self
            .endpoint
            .connect(server_addr, "localhost")
            .map_err(|e| TransportError::Other(format!("Failed to connect: {}", e)))?;

        let new_conn = connecting
            .await
            .map_err(TransportError::Connection)?;

        info!("Connected to QUIC server at {}", server_addr);

        Ok(new_conn)
    }

    /// Handle a bidirectional stream.
    pub async fn handle_bidirectional_stream(
        // No longer &self as cipher is passed directly
        _send: SendStream,
        mut recv: RecvStream, // Made mut recv here
        tx: mpsc::Sender<TransportMessage>,
        cipher: Arc<AesGcmCipher>,
    ) {
        // let mut recv = recv; // recv is already mut

        loop {
            match recv.read_chunk(8192, false).await {
                Ok(Some(chunk)) => {
                    debug!("Received {} encrypted bytes from server", chunk.bytes.len());
                    match cipher.decrypt(&chunk.bytes) {
                        Ok(decrypted_data) => {
                            debug!("Decrypted to {} bytes", decrypted_data.len());
                            if let Err(e) = tx.send(TransportMessage::Data(decrypted_data)).await {
                                error!("Failed to send data to channel: {}", e);
                                break;
                            }
                        }
                        Err(e) => {
                            error!("Failed to decrypt data from server: {}", e);
                            // Optionally send an error message through tx or handle appropriately
                            // For now, we break the loop on decryption failure.
                            let _ = tx
                                .send(TransportMessage::Error(TransportError::Other(format!(
                                    "Decryption failed: {}",
                                    e
                                ))))
                                .await;
                            break;
                        }
                    }
                }
                Ok(None) => {
                    info!("Stream closed by server");
                    let _ = tx.send(TransportMessage::StreamClosed).await;
                    break;
                }
                Err(e) => {
                    error!("Error reading from stream: {}", e);
                    let _ = tx.send(TransportMessage::Error(e.into())).await;
                    break;
                }
            }
        }
    }

    /// Open a bidirectional stream on a connection.
    pub async fn open_bidirectional_stream(
        &self,
        connection: &Connection,
    ) -> TransportResult<(SendStream, RecvStream)> {
        let stream = connection.open_bi().await.map_err(|e| {
            TransportError::Other(format!("Failed to open bidirectional stream: {}", e))
        })?;

        info!("Opened bidirectional stream");

        Ok(stream)
    }

    /// Process incoming bidirectional streams.
    async fn process_incoming_streams(
        connection: Connection,
        tx: mpsc::Sender<TransportMessage>,
        cipher: Arc<AesGcmCipher>, // Pass cipher
    ) {
        // Use a manual approach to handle incoming streams
        tokio::spawn(async move {
            loop {
                // Accept a bidirectional stream directly
                match connection.accept_bi().await {
                    Ok((send, recv)) => {
                        let tx_clone = tx.clone();
                        let cipher_clone = cipher.clone(); // Clone Arc for the new task
                        tokio::spawn(async move {
                            // Call handle_bidirectional_stream directly, passing the cipher
                            QuicClient::handle_bidirectional_stream(
                                send,
                                recv,
                                tx_clone,
                                cipher_clone,
                            )
                            .await;
                        });
                    }
                    Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                        info!("Connection closed by application");
                        let _ = tx.send(TransportMessage::ConnectionClosed).await;
                        break;
                    }
                    Err(e) => {
                        warn!("Error accepting bidirectional stream: {}", e);
                        if let Err(e) = tx.send(TransportMessage::Error(e.into())).await {
                            error!("Failed to send error to channel: {}", e);
                        }
                    }
                }
            }
        });
    }
}

impl QuicTransport for QuicClient {
    fn connect(&self, _addr: SocketAddr) -> TransportResult<Connection> {
        // This is a synchronous function in the trait, but we need to perform async operations.
        // We'll return an error suggesting to use the async connect_to_server method instead.
        Err(TransportError::Other(
            "Use connect_to_server async method instead".to_string(),
        ))
    }

    async fn send(&self, connection: Connection, data: Vec<u8>) -> TransportResult<()> {
        debug!("Encrypting {} bytes before sending", data.len());
        let encrypted_data = self
            .cipher
            .encrypt(&data)
            .map_err(|e| TransportError::Other(format!("Client encryption failed: {}", e)))?;
        debug!("Encrypted to {} bytes", encrypted_data.len());

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
        connection: Connection,
    ) -> TransportResult<mpsc::Receiver<TransportMessage>> {
        let (tx, rx) = mpsc::channel(100);

        // Pass the client's cipher to process_incoming_streams
        tokio::spawn(Self::process_incoming_streams(
            connection,
            tx,
            self.cipher.clone(),
        ));

        Ok(rx)
    }

    async fn close(&self, connection: Connection) {
        connection.close(0u32.into(), b"Client closed connection");
    }
}
