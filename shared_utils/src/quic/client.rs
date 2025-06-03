use crate::crypto::aes_gcm::AesGcmCipher;
use crate::transport::{ClientTransport, Connection as TraitConnection, TransportError};
use async_trait::async_trait;
use quinn::{ClientConfig, Endpoint, RecvStream, SendStream};
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{debug, error, info};

// Note: The old `super::transport::TransportError` and related items might need to be removed
// or reconciled if they are still used elsewhere. For now, we focus on the new traits.
// We will also need to update `configure_client_tls` if it's still used.
// For simplicity, I'll assume `configure_client_tls` is available from `crate::quic::transport` for now.
use crate::quic::transport::configure_client_tls;

/// Represents an active client-side QUIC connection (a single bidirectional stream).
pub struct QuicClientConnection {
    conn_handle: Arc<quinn::Connection>, // To get local/peer addresses and close the main connection
    local_s_addr: SocketAddr,            // Store local socket address
    send_stream: SendStream,
    recv_stream: RecvStream,
    cipher: Arc<AesGcmCipher>,
}

#[async_trait]
impl TraitConnection for QuicClientConnection {
    async fn send_data(&mut self, data: &[u8]) -> Result<(), TransportError> {
        debug!(
            "Encrypting {} bytes before sending via QUIC client connection",
            data.len()
        );
        let encrypted_data = self.cipher.encrypt(data).map_err(|e| {
            TransportError::Generic(format!("Client-side encryption failed: {}", e))
        })?;
        debug!("Encrypted to {} bytes", encrypted_data.len());

        self.send_stream
            .write_all(&encrypted_data)
            .await
            .map_err(|e| TransportError::Send(format!("Failed to write to QUIC stream: {}", e)))?;
        Ok(())
    }

    async fn recv_data(&mut self) -> Result<Option<Vec<u8>>, TransportError> {
        // QUIC streams don't have a fixed max size for read_chunk like TCP,
        // but we need a buffer. Let's use a reasonable size.
        // `read_chunk` reads *up to* the buffer size.
        // For VPN packets, they might be around MTU size (e.g., 1500 bytes).
        // A larger buffer (e.g., 8192) can reduce the number of reads for larger messages.
        match self.recv_stream.read_chunk(8192, false).await {
            Ok(Some(chunk)) => {
                debug!(
                    "Received {} encrypted bytes from server via QUIC client connection",
                    chunk.bytes.len()
                );
                let decrypted_data = self.cipher.decrypt(&chunk.bytes).map_err(|e| {
                    TransportError::Generic(format!("Client-side decryption failed: {}", e))
                })?;
                debug!("Decrypted to {} bytes", decrypted_data.len());
                Ok(Some(decrypted_data))
            }
            Ok(None) => {
                info!("QUIC stream closed by server (client connection)");
                Ok(None) // Stream gracefully closed
            }
            Err(quinn::ReadError::ConnectionLost(e)) => {
                error!(
                    "QUIC connection lost while reading from stream (client): {}",
                    e
                );
                Err(TransportError::Connection(format!(
                    "Connection lost: {}",
                    e
                )))
            }
            Err(quinn::ReadError::Reset(reason)) => {
                info!(
                    "QUIC stream reset by server (client connection), reason code: {}",
                    reason.into_inner()
                );
                // Treat as graceful closure for now, or map to a specific error if needed
                Ok(None)
            }
            Err(quinn::ReadError::UnknownStream) => {
                error!("QUIC stream unknown (client connection)");
                Err(TransportError::Connection("Stream unknown".to_string()))
            }
            Err(e) => {
                error!("Error reading from QUIC stream (client connection): {}", e);
                Err(TransportError::Receive(format!(
                    "Failed to read from QUIC stream: {}",
                    e
                )))
            }
        }
    }

    fn peer_addr(&self) -> Result<SocketAddr, TransportError> {
        Ok(self.conn_handle.remote_address())
    }

    fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        Ok(self.local_s_addr)
    }

    async fn close(mut self: Box<Self>) -> Result<(), TransportError> {
        info!("Closing QUIC client connection stream");
        // Finish the send stream to signal no more data will be sent.
        if let Err(e) = self.send_stream.finish().await {
            // Log error but proceed, as we still want to try stopping the recv stream
            // and potentially closing the connection.
            error!("Error finishing QUIC send stream: {}", e);
        }

        // Optionally, stop the receive stream if we want to signal we're not expecting more data.
        // This sends a STOP_SENDING frame.
        // self.recv_stream.stop(0u32.into()).unwrap_or_else(|e| {
        //     error!("Error stopping QUIC recv stream: {}", e);
        // });

        // The `Connection` trait's close is for the logical connection.
        // Here, it means this specific stream. If this is the primary/only stream,
        // we might consider closing the entire quinn::Connection.
        // For now, closing the stream is sufficient.
        // If the `QuicClientConnection` is the sole user of `conn_handle`,
        // and `conn_handle` is an Arc, dropping this struct might not close the QUIC connection
        // if other Arcs exist.
        // A more explicit close of the underlying quinn::Connection might be needed
        // if this `close` is meant to terminate the entire QUIC session.
        // Let's assume for now it's about this specific data channel.
        // The `quinn::Connection` itself can be closed using `conn_handle.close()`.
        // For now, we'll just ensure the stream is properly finished.
        // If the user wants to close the entire QUIC session, they might need a different method
        // on the `QuicClient` itself, or this `close` implies closing the underlying `quinn::Connection`.
        // Let's make it close the underlying connection for now.
        self.conn_handle
            .close(0u32.into(), b"Client initiated close");
        info!("QUIC client connection (underlying quinn::Connection) closed.");
        Ok(())
    }
}

/// QUIC client for CoentroVPN.
pub struct QuicClient {
    endpoint: Endpoint,
    cipher: Arc<AesGcmCipher>,
    client_config: ClientConfig, // Store client_config to be used in connect
}

impl QuicClient {
    /// Create a new QUIC client.
    /// The `key` is used for AES-GCM encryption/decryption of the payload.
    pub fn new(key: &[u8]) -> Result<Self, TransportError> {
        let client_tls_config =
            configure_client_tls().map_err(|e| TransportError::Configuration(e.to_string()))?;

        let cipher = Arc::new(AesGcmCipher::new(key).map_err(|e| {
            TransportError::Configuration(format!("Failed to initialize cipher: {}", e))
        })?);

        let mut client_config = ClientConfig::new(client_tls_config);
        let mut transport_config = quinn::TransportConfig::default();

        let idle_timeout = std::time::Duration::from_secs(30).try_into().map_err(|_| {
            TransportError::Configuration("Invalid timeout duration for QUIC".into())
        })?;
        transport_config.max_idle_timeout(Some(idle_timeout));
        transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(5)));

        client_config.transport_config(Arc::new(transport_config));

        let endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap()) // Binds to any available local port
            .map_err(|e| {
                TransportError::Configuration(format!("Failed to create QUIC endpoint: {}", e))
            })?;
        // Note: `set_default_client_config` is not needed if we pass config to `connect_with`

        Ok(Self {
            endpoint,
            cipher,
            client_config,
        })
    }
}

#[async_trait]
impl ClientTransport for QuicClient {
    async fn connect(
        &self,
        server_address_str: &str,
    ) -> Result<Box<dyn TraitConnection>, TransportError> {
        let server_addr: SocketAddr = server_address_str
            .parse()
            .map_err(TransportError::AddrParse)?;

        info!("Connecting to QUIC server at {}", server_addr);

        let connecting = self
            .endpoint
            .connect_with(self.client_config.clone(), server_addr, "localhost") // Corrected argument order
            .map_err(|e| {
                TransportError::Connection(format!("Failed to initiate QUIC connection: {}", e))
            })?;

        let new_conn = connecting.await.map_err(|e| {
            TransportError::Connection(format!("QUIC connection attempt failed: {}", e))
        })?;

        info!(
            "Successfully established QUIC connection to {}",
            server_addr
        );

        // Open a bidirectional stream for this connection
        let (send_stream, recv_stream) = new_conn.open_bi().await.map_err(|e| {
            TransportError::Connection(format!("Failed to open bidirectional QUIC stream: {}", e))
        })?;
        info!("Opened bidirectional stream for QUIC client connection");

        // Get the local address from the endpoint that made the connection
        let local_socket_addr = self.endpoint.local_addr().map_err(|e| {
            TransportError::Generic(format!("Failed to get local endpoint address: {}", e))
        })?;

        let quic_connection = QuicClientConnection {
            conn_handle: Arc::new(new_conn),
            local_s_addr: local_socket_addr,
            send_stream,
            recv_stream,
            cipher: self.cipher.clone(),
        };

        Ok(Box::new(quic_connection))
    }
}

// Old QuicClient methods like `connect_to_server`, `handle_bidirectional_stream`,
// `open_bidirectional_stream`, `process_incoming_streams` and the `QuicTransport` trait
// implementation would be removed or significantly refactored.
// For this step, we are focusing on implementing the new `ClientTransport` trait.
// The `mpsc` channel logic previously in `receive` and `handle_bidirectional_stream`
// is now encapsulated within the `QuicClientConnection::recv_data` method for a single stream.
// If multiple concurrent streams from the server to the client on the same QUIC connection
// need to be handled and multiplexed into a single `Connection` trait object,
// the design of `QuicClientConnection` would need to be more complex, possibly involving
// its own internal task for multiplexing incoming streams.
// However, the `Connection` trait seems to represent a single logical data pipe.
