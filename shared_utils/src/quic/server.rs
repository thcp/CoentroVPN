use crate::crypto::aes_gcm::AesGcmCipher;
use crate::transport::{
    Connection as TraitConnection, Listener as TraitListener, ServerTransport, TransportError,
};
use async_trait::async_trait;
use quinn::{Endpoint, RecvStream, SendStream, ServerConfig};
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{debug, error, info, warn};

// Assuming these are correctly located in crate::quic::transport
use crate::quic::transport::{configure_tls, generate_self_signed_cert};

/// Represents an active server-side QUIC connection (a single accepted bidirectional stream).
pub struct QuicServerConnection {
    conn_handle: Arc<quinn::Connection>, // Handle to the underlying QUIC connection
    local_s_addr: SocketAddr, // Store local socket address
    send_stream: SendStream,
    recv_stream: RecvStream,
    cipher: Arc<AesGcmCipher>,
}

#[async_trait]
impl TraitConnection for QuicServerConnection {
    async fn send_data(&mut self, data: &[u8]) -> Result<(), TransportError> {
        debug!("Encrypting {} bytes before sending via QUIC server connection", data.len());
        let encrypted_data = self.cipher.encrypt(data).map_err(|e| {
            TransportError::Generic(format!("Server-side encryption failed: {}", e))
        })?;
        debug!("Encrypted to {} bytes", encrypted_data.len());

        self.send_stream
            .write_all(&encrypted_data)
            .await
            .map_err(|e| TransportError::Send(format!("Failed to write to QUIC stream: {}", e)))?;
        Ok(())
    }

    async fn recv_data(&mut self) -> Result<Option<Vec<u8>>, TransportError> {
        match self.recv_stream.read_chunk(8192, false).await {
            Ok(Some(chunk)) => {
                debug!("Received {} encrypted bytes from client via QUIC server connection", chunk.bytes.len());
                let decrypted_data = self.cipher.decrypt(&chunk.bytes).map_err(|e| {
                    TransportError::Generic(format!("Server-side decryption failed: {}", e))
                })?;
                debug!("Decrypted to {} bytes", decrypted_data.len());
                Ok(Some(decrypted_data))
            }
            Ok(None) => {
                info!("QUIC stream closed by client (server connection)");
                Ok(None) // Stream gracefully closed
            }
            Err(quinn::ReadError::ConnectionLost(e)) => {
                error!("QUIC connection lost while reading from stream (server): {}", e);
                Err(TransportError::Connection(format!("Connection lost: {}", e)))
            }
            Err(quinn::ReadError::Reset(reason)) => {
                info!("QUIC stream reset by client (server connection), reason code: {}", reason.into_inner());
                Ok(None)
            }
            Err(quinn::ReadError::UnknownStream) => {
                 error!("QUIC stream unknown (server connection)");
                 Err(TransportError::Connection("Stream unknown".to_string()))
            }
            Err(e) => {
                error!("Error reading from QUIC stream (server connection): {}", e);
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
        info!("Closing QUIC server connection stream");
        if let Err(e) = self.send_stream.finish().await {
            error!("Error finishing QUIC send stream on server connection: {}", e);
            // Potentially map to TransportError::Close if severe
        }
        // The underlying quinn::Connection is managed by the Listener/Server.
        // Closing this TraitConnection means this specific stream is done.
        // The actual QUIC connection might stay open for other streams if the design supported it,
        // or be closed by the listener if this was the only/primary interaction.
        // For consistency with client and to ensure prompt cleanup, explicitly close the underlying connection.
        self.conn_handle.close(0u32.into(), b"Server initiated stream close");
        info!("QUIC server connection (underlying quinn::Connection) closed.");
        Ok(())
    }
}

/// QUIC server listener.
pub struct QuicServerListener {
    endpoint: Endpoint, // The QUIC endpoint listening for new connections
    cipher: Arc<AesGcmCipher>, // Cipher for encrypting/decrypting data
    // We need to store the active connection to accept new streams on it.
    // This design assumes one QUIC connection per listener, and then multiple streams (TraitConnection) on it.
    // If a listener should handle multiple independent QUIC connections, this needs adjustment.
    // For now, let's assume accept() on Listener gives a new stream on an *existing* or *newly accepted* QUIC connection.
    // The current `Listener` trait's `accept` returns `Box<dyn Connection>`.
    // This implies that `accept` might first accept a new underlying QUIC connection if one isn't active,
    // and then accept a stream on it.
    active_connection: Option<Arc<quinn::Connection>>, // Stores the currently active QUIC connection
    local_addr: SocketAddr,
}

#[async_trait]
impl TraitListener for QuicServerListener {
    async fn accept(&mut self) -> Result<Box<dyn TraitConnection>, TransportError> {
        // If there's no active QUIC connection, accept one first.
        if self.active_connection.is_none() {
            info!("QUIC Server Listener: No active connection, attempting to accept a new QUIC connection...");
            match self.endpoint.accept().await {
                Some(conn_pending) => {
                    match conn_pending.await {
                        Ok(new_quinn_conn) => {
                            info!("QUIC Server Listener: Accepted new QUIC connection from {}", new_quinn_conn.remote_address());
                            self.active_connection = Some(Arc::new(new_quinn_conn));
                        }
                        Err(e) => {
                            error!("QUIC Server Listener: Failed to establish incoming QUIC connection: {}", e);
                            return Err(TransportError::Connection(format!("QUIC connection establishment failed: {}", e)));
                        }
                    }
                }
                None => {
                    error!("QUIC Server Listener: Endpoint closed, cannot accept new connections.");
                    return Err(TransportError::Connection("Endpoint closed".to_string()));
                }
            }
        }

        // Now, with an active QUIC connection, accept a bidirectional stream on it.
        let quinn_conn = self.active_connection.as_ref().unwrap().clone(); // Clone Arc

        info!("QUIC Server Listener: Attempting to accept a new bidirectional stream on existing QUIC connection from {}", quinn_conn.remote_address());
        match quinn_conn.accept_bi().await {
            Ok((send_stream, recv_stream)) => {
                info!("QUIC Server Listener: Accepted new bidirectional stream from {}", quinn_conn.remote_address());
                let server_connection = QuicServerConnection {
                    conn_handle: quinn_conn.clone(), // Clone Arc for the new stream handler
                    local_s_addr: self.local_addr, // Use listener's stored local_addr
                    send_stream,
                    recv_stream,
                    cipher: self.cipher.clone(),
                };
                Ok(Box::new(server_connection))
            }
            Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                warn!("QUIC Server Listener: Connection was application closed while trying to accept a stream. Clearing active connection.");
                self.active_connection = None; // Connection is gone, need to accept a new one next time.
                Err(TransportError::Connection("QUIC Connection application closed".to_string()))
            }
            Err(quinn::ConnectionError::LocallyClosed) => {
                warn!("QUIC Server Listener: Connection was locally closed while trying to accept a stream. Clearing active connection.");
                self.active_connection = None;
                Err(TransportError::Connection("QUIC Connection locally closed".to_string()))
            }
            Err(e) => {
                error!("QUIC Server Listener: Failed to accept bidirectional stream: {}. Clearing active connection.", e);
                self.active_connection = None; // Assume connection is problematic
                Err(TransportError::Connection(format!("Failed to accept QUIC stream: {}", e)))
            }
        }
    }

    fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        Ok(self.local_addr)
    }
}

/// QUIC server for CoentroVPN.
pub struct QuicServer {
    // We don't store the endpoint directly in QuicServer anymore if listen returns a Listener
    // The listener will hold the endpoint.
    // QuicServer will primarily hold configuration needed to create a listener.
    server_config: ServerConfig,
    cipher: Arc<AesGcmCipher>,
    bind_addr: SocketAddr, // The address to bind to when listen is called
}

impl QuicServer {
    /// Create a new QUIC server configuration.
    /// The server is not started until `listen` is called.
    pub fn new(bind_addr: SocketAddr, key: &[u8]) -> Result<Self, TransportError> {
        let (cert_chain, key_der) = generate_self_signed_cert()
            .map_err(|e| TransportError::Configuration(format!("Failed to generate cert: {}", e)))?;
        let server_tls_config = configure_tls(cert_chain, key_der)
            .map_err(|e| TransportError::Configuration(format!("Failed to configure TLS: {}", e)))?;

        let cipher = Arc::new(
            AesGcmCipher::new(key)
                .map_err(|e| TransportError::Configuration(format!("Failed to initialize server cipher: {}", e)))?,
        );

        let mut server_config = ServerConfig::with_crypto(server_tls_config);
        let mut transport_config = quinn::TransportConfig::default();
        let idle_timeout = std::time::Duration::from_secs(30)
            .try_into()
            .map_err(|_| TransportError::Configuration("Invalid timeout duration for QUIC".into()))?;
        transport_config.max_idle_timeout(Some(idle_timeout));
        transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(5)));
        server_config.transport = Arc::new(transport_config);

        Ok(Self {
            server_config,
            cipher,
            bind_addr,
        })
    }
}

#[async_trait]
impl ServerTransport for QuicServer {
    type Listener = QuicServerListener;

    async fn listen(&self, local_address_str: &str) -> Result<Self::Listener, TransportError> {
        // local_address_str might be different from self.bind_addr if we want to allow overriding.
        // For now, let's use self.bind_addr, assuming local_address_str is for consistency with the trait
        // and might be used if QuicServer didn't store bind_addr.
        // Or, parse local_address_str and use it. Let's parse it.
        let listen_addr: SocketAddr = local_address_str
            .parse()
            .map_err(|e| TransportError::AddrParse(e))?;

        if listen_addr != self.bind_addr {
            warn!(
                "Listen address {} from trait differs from configured bind_addr {}. Using address from trait.",
                listen_addr, self.bind_addr
            );
        }

        let endpoint = Endpoint::server(self.server_config.clone(), listen_addr)
            .map_err(|e| TransportError::Io(e))?; // quinn::Endpoint::server returns std::io::Error

        let actual_local_addr = endpoint.local_addr()
            .map_err(|e| TransportError::Io(e))?; // Also std::io::Error

        info!("QUIC server endpoint created, listening on {}", actual_local_addr);

        Ok(QuicServerListener {
            endpoint,
            cipher: self.cipher.clone(),
            active_connection: None,
            local_addr: actual_local_addr,
        })
    }
}
