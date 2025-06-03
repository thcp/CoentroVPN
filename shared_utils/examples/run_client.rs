//! Custom client example for CoentroVPN
//!
//! This example demonstrates how to run a standalone QUIC client
//! that connects to a server at a specified address.
//!
//! Run with:
//! ```
//! cargo run --example run_client -- 127.0.0.1:4433
//! ```

use shared_utils::crypto::aes_gcm::AesGcmCipher;
use shared_utils::logging;
use shared_utils::quic::QuicClient;
// Import new transport traits
use shared_utils::transport::ClientTransport; // Removed unused Connection as TraitConnection
use std::env;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::time;
use tracing::{Level, info};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    let log_options = logging::LogOptions {
        level: Level::DEBUG,
        ..Default::default()
    };
    let _guard = logging::init_logging(log_options);

    // Parse command line arguments
    let args: Vec<String> = env::args().collect();
    let server_addr = if args.len() > 1 {
        args[1].parse::<SocketAddr>()?
    } else {
        "127.0.0.1:5000".parse::<SocketAddr>()?
    };

    info!("Starting CoentroVPN QUIC client");
    info!("Connecting to server at {}", server_addr);

    // Generate a test encryption key
    // In a real application, this would be the same key used by the server
    let encryption_key = AesGcmCipher::generate_key();
    info!("Generated encryption key for testing");

    // Create the client
    let client = QuicClient::new(&encryption_key)?;

    // Connect to the server
    info!("Connecting to server...");
    let mut connection = match client.connect(&server_addr.to_string()).await {
        Ok(conn_box) => {
            info!(
                "Connected to server successfully: {}",
                conn_box.peer_addr()?
            );
            conn_box
        }
        Err(e) => {
            info!("Failed to connect to server: {}", e);
            return Err(e.into());
        }
    };

    // Send a test message
    let message_to_send = "Hello from CoentroVPN client! This is a test message.";
    info!("Sending message: {}", message_to_send);

    if let Err(e) = connection.send_data(message_to_send.as_bytes()).await {
        info!("Failed to send message: {}", e);
        // Attempt to close connection even if send failed
        connection.close().await?;
        return Err(e.into());
    }
    info!("Message sent successfully");

    // Try to receive an echo
    info!("Waiting for echo...");
    match connection.recv_data().await {
        Ok(Some(data)) => match String::from_utf8(data) {
            Ok(text) => info!("Received echo: {}", text),
            Err(_) => info!("Received binary echo data"),
        },
        Ok(None) => {
            info!("Connection closed by server while waiting for echo.");
        }
        Err(e) => {
            info!("Error receiving echo: {}", e);
        }
    }

    // Wait a moment before closing
    time::sleep(Duration::from_secs(1)).await;

    // Close the connection
    info!("Closing connection");
    connection.close().await?;

    info!("Client completed successfully");

    Ok(())
}
