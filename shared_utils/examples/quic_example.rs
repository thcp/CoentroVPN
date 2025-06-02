//! Example demonstrating QUIC transport usage.
//!
//! This example shows how to set up a QUIC server and client,
//! establish a connection, and exchange data over bidirectional streams.
//!
//! Run with:
//! ```
//! cargo run --example quic_example
//! ```

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use shared_utils::quic::{QuicClient, QuicServer, QuicTransport, TransportMessage};
use tokio::time;
use tracing::{info, Level};
use shared_utils::logging;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    let log_options = logging::LogOptions {
        level: Level::DEBUG,
        ..Default::default()
    };
    let _guard = logging::init_logging(log_options);
    
    info!("Starting QUIC example");
    
    // Server address
    let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5000);
    
    // Start server
    let server = QuicServer::new(server_addr)?;
    let mut server_receiver = server.start().await?;
    
    // Spawn a task to handle server messages
    tokio::spawn(async move {
        while let Some(message) = server_receiver.recv().await {
            match message {
                TransportMessage::Data(data) => {
                    let message = String::from_utf8_lossy(&data);
                    info!("Server received: {}", message);
                }
                TransportMessage::StreamClosed => {
                    info!("Server: Stream closed");
                }
                TransportMessage::ConnectionClosed => {
                    info!("Server: Connection closed");
                }
                TransportMessage::Error(e) => {
                    info!("Server error: {}", e);
                }
            }
        }
    });
    
    // Wait for server to start
    time::sleep(Duration::from_millis(100)).await;
    
    // Create client
    let client = QuicClient::new()?;
    
    // Connect to server
    let connection = client.connect_to_server(server_addr).await?;
    
    // Open a bidirectional stream
    let (mut send, _) = client.open_bidirectional_stream(&connection).await?;
    
    // Send a message
    let message = b"Hello from QUIC client!";
    send.write_all(message).await?;
    send.finish().await?;
    
    // Wait for a moment to allow the message to be processed
    time::sleep(Duration::from_secs(1)).await;
    
    // Close the connection
    client.close(connection).await;
    
    info!("QUIC example completed successfully");
    
    Ok(())
}
