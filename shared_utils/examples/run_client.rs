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
use shared_utils::quic::{QuicClient, QuicTransport};
use std::env;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::time;
use tracing::{info, Level};

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
    let connection = match client.connect_to_server(server_addr).await {
        Ok(conn) => {
            info!("Connected to server successfully");
            conn
        }
        Err(e) => {
            info!("Failed to connect to server: {}", e);
            return Err(e.into());
        }
    };

    // Send a test message
    let message = "Hello from CoentroVPN client! This is a test message.";
    info!("Sending message: {}", message);
    
    match client.send(connection.clone(), message.as_bytes().to_vec()).await {
        Ok(_) => {
            info!("Message sent successfully");
        }
        Err(e) => {
            info!("Failed to send message: {}", e);
            return Err(e.into());
        }
    }

    // Wait a moment before closing
    time::sleep(Duration::from_secs(2)).await;

    // Close the connection
    info!("Closing connection");
    client.close(connection).await;
    
    info!("Client completed successfully");

    Ok(())
}
