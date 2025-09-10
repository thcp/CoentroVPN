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
    local_s_addr: SocketAddr,            // Store local socket address
    send_stream: SendStream,
    recv_stream: RecvStream,
    cipher: Arc<AesGcmCipher>,
}

#[async_trait]
impl TraitConnection for QuicServerConnection {
    async fn send_data(&mut self, data: &[u8]) -> Result<(), TransportError> {
        debug!(
            "Encrypting {} bytes before sending via QUIC server connection",
            data.len()
        );
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
                debug!(
                    "Received {} encrypted bytes from client via QUIC server connection",
                    chunk.bytes.len()
                );
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
                error!(
                    "QUIC connection lost while reading from stream (server): {}",
                    e
                );
                Err(TransportError::Connection(format!(
                    "Connection lost: {}",
                    e
                )))
            }
            Err(quinn::ReadError::Reset(reason)) => {
                info!(
                    "QUIC stream reset by client (server connection), reason code: {}",
                    reason.into_inner()
                );
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
            error!(
                "Error finishing QUIC send stream on server connection: {}",
                e
            );
            // Potentially map to TransportError::Close if severe
        }
        // The underlying quinn::Connection is managed by the Listener/Server.
        // Closing this TraitConnection means this specific stream is done.
        // The actual QUIC connection might stay open for other streams if the design supported it,
        // or be closed by the listener if this was the only/primary interaction.
        // For consistency with client and to ensure prompt cleanup, explicitly close the underlying connection.
        info!(local = ?self.local_s_addr, peer = ?self.conn_handle.remote_address(), "QuicServerConnection: close - Closing underlying quinn::Connection.");
        self.conn_handle
            .close(0u32.into(), b"Server initiated stream close");
        info!(local = ?self.local_s_addr, peer = ?self.conn_handle.remote_address(), "QuicServerConnection: close - Underlying quinn::Connection close initiated.");
        Ok(())
    }
}

/// QUIC server listener.
pub struct QuicServerListener {
    endpoint: Endpoint,        // The QUIC endpoint listening for new connections
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
            info!(
                local_addr = %self.local_addr,
                "QuicServerListener: accept - No active QUIC connection, awaiting endpoint.accept"
            );
            let endpoint_accept_result = self.endpoint.accept().await;
            debug!(
                local_addr = %self.local_addr,
                "QuicServerListener: accept - endpoint.accept completed"
            );

            match endpoint_accept_result {
                Some(conn_pending) => {
                    info!(
                        local_addr = %self.local_addr,
                        "QuicServerListener: accept - New connection pending; awaiting handshake"
                    );
                    let conn_pending_result = conn_pending.await;
                    debug!(
                        local_addr = %self.local_addr,
                        "QuicServerListener: accept - Handshake completed"
                    );

                    match conn_pending_result {
                        Ok(new_quinn_conn) => {
                            info!(
                                peer = %new_quinn_conn.remote_address(),
                                local = %self.local_addr,
                                "QuicServerListener: accept - Accepted new QUIC connection"
                            );
                            self.active_connection = Some(Arc::new(new_quinn_conn));
                        }
                        Err(e) => {
                            error!(local = %self.local_addr, error = %e, "QuicServerListener: accept - Failed to establish incoming QUIC connection");
                            return Err(TransportError::Connection(format!(
                                "QUIC connection establishment failed: {}",
                                e
                            )));
                        }
                    }
                }
                None => {
                    warn!(local = %self.local_addr, "QuicServerListener: accept - Endpoint closed; cannot accept new connections");
                    return Err(TransportError::Connection("Endpoint closed".to_string()));
                }
            }
        }

        // Now, with an active QUIC connection, accept a bidirectional stream on it.
        let quinn_conn = self.active_connection.as_ref().unwrap().clone(); // Clone Arc

        info!(peer = %quinn_conn.remote_address(), local = %self.local_addr, "QuicServerListener: accept - Awaiting bidirectional stream");
        let accept_bi_result = quinn_conn.accept_bi().await;
        debug!(peer = %quinn_conn.remote_address(), local = %self.local_addr, "QuicServerListener: accept - accept_bi completed");

        match accept_bi_result {
            Ok((send_stream, recv_stream)) => {
                info!(peer = %quinn_conn.remote_address(), local = %self.local_addr, "QuicServerListener: accept - Accepted new bidirectional stream");
                let server_connection = QuicServerConnection {
                    conn_handle: quinn_conn.clone(), // Clone Arc for the new stream handler
                    local_s_addr: self.local_addr,   // Use listener's stored local_addr
                    send_stream,
                    recv_stream,
                    cipher: self.cipher.clone(),
                };
                Ok(Box::new(server_connection))
            }
            Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                info!(local = %self.local_addr, "QuicServerListener: accept - Connection application-closed while accepting stream; clearing active connection");
                self.active_connection = None; // Connection is gone, need to accept a new one next time.
                Err(TransportError::Connection(
                    "QUIC Connection application closed".to_string(),
                ))
            }
            Err(quinn::ConnectionError::LocallyClosed) => {
                info!(local = %self.local_addr, "QuicServerListener: accept - Connection locally closed while accepting stream; clearing active connection");
                self.active_connection = None;
                Err(TransportError::Connection(
                    "QUIC Connection locally closed".to_string(),
                ))
            }
            Err(e) => {
                error!(local = %self.local_addr, error = %e, "QuicServerListener: accept - Failed to accept bidirectional stream; clearing active connection");
                self.active_connection = None; // Assume connection is problematic
                Err(TransportError::Connection(format!(
                    "Failed to accept QUIC stream: {}",
                    e
                )))
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
        let (cert_chain, key_der) = generate_self_signed_cert().map_err(|e| {
            TransportError::Configuration(format!("Failed to generate cert: {}", e))
        })?;
        let server_tls_config = configure_tls(cert_chain, key_der).map_err(|e| {
            TransportError::Configuration(format!("Failed to configure TLS: {}", e))
        })?;

        let cipher = Arc::new(AesGcmCipher::new(key).map_err(|e| {
            TransportError::Configuration(format!("Failed to initialize server cipher: {}", e))
        })?);

        let mut server_config = ServerConfig::with_crypto(server_tls_config);
        let mut transport_config = quinn::TransportConfig::default();
        let idle_timeout = std::time::Duration::from_secs(30).try_into().map_err(|_| {
            TransportError::Configuration("Invalid timeout duration for QUIC".into())
        })?;
        transport_config.max_idle_timeout(Some(idle_timeout));
        transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(5)));
        server_config.transport = Arc::new(transport_config);

        Ok(Self {
            server_config,
            cipher,
            bind_addr,
        })
    }

    /// Create a QUIC server using an explicit certificate and private key.
    /// Useful for tests that want to pin the server certificate on the client.
    pub fn new_with_cert(
        bind_addr: SocketAddr,
        key: &[u8],
        cert_chain: rustls::Certificate,
        key_der: rustls::PrivateKey,
    ) -> Result<Self, TransportError> {
        let server_tls_config = configure_tls(cert_chain, key_der).map_err(|e| {
            TransportError::Configuration(format!("Failed to configure TLS: {}", e))
        })?;

        let cipher = Arc::new(AesGcmCipher::new(key).map_err(|e| {
            TransportError::Configuration(format!("Failed to initialize server cipher: {}", e))
        })?);

        let mut server_config = quinn::ServerConfig::with_crypto(server_tls_config);
        let mut transport_config = quinn::TransportConfig::default();
        let idle_timeout = std::time::Duration::from_secs(30).try_into().map_err(|_| {
            TransportError::Configuration("Invalid timeout duration for QUIC".into())
        })?;
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
            .map_err(TransportError::AddrParse)?;

        if listen_addr != self.bind_addr {
            warn!(
                "Listen address {} from trait differs from configured bind_addr {}. Using address from trait.",
                listen_addr, self.bind_addr
            );
        }

        info!(listen_addr = %listen_addr, "QuicServer: listen - Creating server endpoint");
        let endpoint_result = Endpoint::server(self.server_config.clone(), listen_addr);

        let endpoint = match endpoint_result {
            Ok(ep) => {
                info!("QuicServer: listen - Successfully created server endpoint");
                ep
            }
            Err(e) => {
                error!(error = %e, "QuicServer: listen - Failed to create server endpoint");
                return Err(TransportError::Io(e));
            }
        };

        debug!("QuicServer: listen - Getting local_addr from endpoint");
        let local_addr_result = endpoint.local_addr();

        let actual_local_addr = match local_addr_result {
            Ok(addr) => {
                info!(local_addr = %addr, "QuicServer: listen - Got local_addr");
                addr
            }
            Err(e) => {
                error!(error = %e, "QuicServer: listen - Failed to get local_addr");
                return Err(TransportError::Io(e));
            }
        };

        info!(local_addr = %actual_local_addr, "QuicServer: listen - Endpoint created and listening");

        Ok(QuicServerListener {
            endpoint,
            cipher: self.cipher.clone(),
            active_connection: None,
            local_addr: actual_local_addr,
        })
    }
}
