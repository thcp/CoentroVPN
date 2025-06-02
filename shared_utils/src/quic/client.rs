//! QUIC client implementation for CoentroVPN.

use std::net::SocketAddr;
use std::sync::Arc;
use quinn::{ClientConfig, Connection, Endpoint, RecvStream, SendStream};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use super::transport::{
    QuicTransport, TransportError, TransportMessage, TransportResult,
    configure_client_tls,
};

/// QUIC client for CoentroVPN.
pub struct QuicClient {
    endpoint: Endpoint,
}

impl QuicClient {
    /// Create a new QUIC client.
    pub fn new() -> TransportResult<Self> {
        // Configure client TLS
        let client_tls = configure_client_tls()?;
        
        // Configure QUIC client
        let mut client_config = ClientConfig::new(client_tls);
        let mut transport_config = quinn::TransportConfig::default();
        
        // Set transport parameters
        transport_config.max_idle_timeout(Some(std::time::Duration::from_secs(30).try_into().unwrap()));
        transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(5)));
        
        client_config.transport_config(Arc::new(transport_config));
        
        // Create endpoint
        let mut endpoint = Endpoint::client(SocketAddr::from(([0, 0, 0, 0], 0)))?;
        endpoint.set_default_client_config(client_config);
        
        Ok(Self { endpoint })
    }
    
    /// Connect to a server and establish a new connection.
    pub async fn connect_to_server(&self, server_addr: SocketAddr) -> TransportResult<Connection> {
        info!("Connecting to QUIC server at {}", server_addr);
        
        let connecting = self.endpoint.connect(server_addr, "localhost")
            .map_err(|e| TransportError::Other(format!("Failed to connect: {}", e)))?;
            
        let new_conn = connecting.await
            .map_err(|e| TransportError::Connection(e))?;
            
        info!("Connected to QUIC server at {}", server_addr);
        
        Ok(new_conn)
    }
    
    /// Handle a bidirectional stream.
    pub async fn handle_bidirectional_stream(
        &self,
        _send: SendStream,
        recv: RecvStream,
        tx: mpsc::Sender<TransportMessage>,
    ) {
        let mut recv = recv;
        
        loop {
            match recv.read_chunk(8192, false).await {
                Ok(Some(chunk)) => {
                    debug!("Received {} bytes from server", chunk.bytes.len());
                    
                    if let Err(e) = tx.send(TransportMessage::Data(chunk.bytes.to_vec())).await {
                        error!("Failed to send data to channel: {}", e);
                        break;
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
        let stream = connection.open_bi().await
            .map_err(|e| TransportError::Other(format!("Failed to open bidirectional stream: {}", e)))?;
            
        info!("Opened bidirectional stream");
        
        Ok(stream)
    }
    
    /// Process incoming bidirectional streams.
    async fn process_incoming_streams(
        connection: Connection,
        tx: mpsc::Sender<TransportMessage>,
    ) {
        // Use a manual approach to handle incoming streams
        tokio::spawn(async move {
            loop {
                // Accept a bidirectional stream directly
                match connection.accept_bi().await {
                    Ok((send, recv)) => {
                        let tx_clone = tx.clone();
                        tokio::spawn(async move {
                            let client = QuicClient::new().unwrap();
                            client.handle_bidirectional_stream(send, recv, tx_clone).await;
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
        let (mut send, _) = connection.open_bi().await
            .map_err(|e| TransportError::Other(format!("Failed to open bidirectional stream: {}", e)))?;
            
        send.write_all(&data).await
            .map_err(|e| TransportError::Write(e))?;
            
        send.finish().await
            .map_err(|e| TransportError::Write(e))?;
            
        Ok(())
    }
    
    async fn receive(&self, connection: Connection) -> TransportResult<mpsc::Receiver<TransportMessage>> {
        let (tx, rx) = mpsc::channel(100);
        
        tokio::spawn(Self::process_incoming_streams(connection, tx));
        
        Ok(rx)
    }
    
    async fn close(&self, connection: Connection) {
        connection.close(0u32.into(), b"Client closed connection");
    }
}
