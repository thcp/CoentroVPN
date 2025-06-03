//! Example demonstrating QUIC transport usage.
//!
//! This example shows how to set up a QUIC server and client,
//! establish a connection, and exchange data over bidirectional streams.
//!
//! Run with:
//! ```
//! cargo run --example quic_example
//! ```

use shared_utils::crypto::aes_gcm::AesGcmCipher;
use shared_utils::logging;
use shared_utils::quic::{QuicClient, QuicServer};
// Import new transport traits
use shared_utils::transport::{ClientTransport, Listener as TraitListener, ServerTransport}; // Removed unused Connection as TraitConnection
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::time;
use tracing::{Level, info};

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

    // Generate a shared encryption key for testing
    // In a real application, this would be securely exchanged or derived
    let encryption_key = AesGcmCipher::generate_key();
    info!("Generated encryption key for testing");

    // Create server
    let server = QuicServer::new(server_addr, &encryption_key)?;
    let mut listener = server.listen(&server_addr.to_string()).await?;
    info!("Server listening on {}", listener.local_addr()?);

    // Spawn a task to handle server connection and messages
    tokio::spawn(async move {
        match listener.accept().await {
            Ok(mut conn) => {
                info!(
                    "Server accepted connection from: {}",
                    conn.peer_addr().unwrap_or(server_addr)
                );
                loop {
                    match conn.recv_data().await {
                        Ok(Some(data)) => {
                            let message_text = String::from_utf8_lossy(&data);
                            info!("Server received: {}", message_text);
                            // Echo back
                            let echo_response = format!("Server echoes: {}", message_text);
                            if let Err(e) = conn.send_data(echo_response.as_bytes()).await {
                                info!("Server: Error sending echo: {}", e);
                                break;
                            }
                        }
                        Ok(None) => {
                            info!("Server: Connection closed by client");
                            break;
                        }
                        Err(e) => {
                            info!("Server error receiving data: {}", e);
                            break;
                        }
                    }
                }
                if let Err(e) = conn.close().await {
                    info!("Server: Error closing connection: {}", e);
                }
            }
            Err(e) => {
                info!("Server failed to accept connection: {}", e);
            }
        }
    });

    // Wait for server to be ready to accept
    time::sleep(Duration::from_millis(200)).await;

    // Create client
    let client = QuicClient::new(&encryption_key)?;

    // Connect to server
    let mut client_conn = client.connect(&server_addr.to_string()).await?;
    info!("Client connected to server: {}", client_conn.peer_addr()?);

    // Send a message
    let client_message = "Hello from QUIC client!";
    info!("Client sending: {}", client_message);
    client_conn.send_data(client_message.as_bytes()).await?;

    // Receive echo
    match client_conn.recv_data().await {
        Ok(Some(data)) => {
            info!("Client received echo: {}", String::from_utf8_lossy(&data));
        }
        Ok(None) => {
            info!("Client: Connection closed by server while waiting for echo.");
        }
        Err(e) => {
            info!("Client: Error receiving echo: {}", e);
        }
    }

    // Wait for a moment
    time::sleep(Duration::from_millis(100)).await;

    // Close the client connection
    client_conn.close().await?;
    info!("Client connection closed.");

    info!("QUIC example completed successfully");

    Ok(())
}
