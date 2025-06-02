//! QUIC server implementation for CoentroVPN.

use std::net::SocketAddr;
use std::sync::Arc;
use quinn::{Connection, Endpoint, RecvStream, SendStream, ServerConfig};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use super::transport::{
    QuicTransport, TransportError, TransportMessage, TransportResult,
    generate_self_signed_cert, configure_tls,
};

/// QUIC server for CoentroVPN.
pub struct QuicServer {
    endpoint: Endpoint,
}

impl QuicServer {
    /// Create a new QUIC server bound to the specified address.
    pub fn new(bind_addr: SocketAddr) -> TransportResult<Self> {
        // Generate self-signed certificate for testing
        let (cert, key) = generate_self_signed_cert()?;
        
        // Configure TLS
        let server_tls = configure_tls(cert, key)?;
        
        // Configure QUIC server
        let mut server_config = ServerConfig::with_crypto(server_tls);
        let mut transport_config = quinn::TransportConfig::default();
        
        // Set transport parameters
        transport_config.max_idle_timeout(Some(std::time::Duration::from_secs(30).try_into().unwrap()));
        transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(5)));
        
        server_config.transport = Arc::new(transport_config);
        
        // Create endpoint
        let endpoint = Endpoint::server(server_config, bind_addr)?;
        
        info!("QUIC server listening on {}", bind_addr);
        
        Ok(Self { endpoint })
    }
    
    /// Start the server and handle incoming connections.
    pub async fn start(&self) -> TransportResult<mpsc::Receiver<TransportMessage>> {
        let (tx, rx) = mpsc::channel(100);
        
        let endpoint = self.endpoint.clone();
        
        tokio::spawn(async move {
            loop {
                match endpoint.accept().await {
                    Some(conn) => {
                        let tx_clone = tx.clone();
                        
                        tokio::spawn(async move {
                            match conn.await {
                                Ok(connection) => {
                                    info!("New connection from {}", connection.remote_address());
                                    
                                    if let Err(e) = Self::handle_connection(connection, tx_clone).await {
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
    ) -> TransportResult<()> {
        loop {
            // Accept a bidirectional stream directly
            match connection.accept_bi().await {
                Ok((send, recv)) => {
                    let tx_clone = tx.clone();
                    
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_bidirectional_stream(send, recv, tx_clone).await {
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
                    return Err(TransportError::Other(format!("Error accepting stream: {}", e)));
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
    ) -> TransportResult<()> {
        loop {
            match recv.read_chunk(8192, false).await {
                Ok(Some(chunk)) => {
                    debug!("Received {} bytes from client", chunk.bytes.len());
                    
                    // Forward the data to the channel
                    if let Err(e) = tx.send(TransportMessage::Data(chunk.bytes.to_vec())).await {
                        error!("Failed to send data to channel: {}", e);
                        break;
                    }
                    
                    // Echo the data back to the client (for demonstration)
                    if let Err(e) = send.write_all(&chunk.bytes).await {
                        error!("Failed to write data to stream: {}", e);
                        return Err(TransportError::Write(e));
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
        
        // Finish the stream
        if let Err(e) = send.finish().await {
            error!("Failed to finish stream: {}", e);
            return Err(TransportError::Write(e));
        }
        
        Ok(())
    }
}

impl QuicTransport for QuicServer {
    fn connect(&self, _addr: SocketAddr) -> TransportResult<Connection> {
        // Servers don't connect to clients, they accept connections
        Err(TransportError::Other("Servers don't connect to clients".to_string()))
    }
    
    async fn send(&self, connection: Connection, data: Vec<u8>) -> TransportResult<()> {
        let (mut send, _) = connection.open_bi().await
            .map_err(|e| TransportError::Other(format!("Failed to open bidirectional stream: {}", e)))?;
            
        send.write_all(&data).await
            .map_err(|e| TransportError::Write(e))?;
            
        send.finish().await
            .map_err(|e| TransportError::Write(e))?;
            
        Ok(())
    }
    
    async fn receive(&self, _connection: Connection) -> TransportResult<mpsc::Receiver<TransportMessage>> {
        // For servers, use the start() method instead
        Err(TransportError::Other("Use start() method for servers".to_string()))
    }
    
    async fn close(&self, connection: Connection) {
        connection.close(0u32.into(), b"Server closed connection");
    }
}
