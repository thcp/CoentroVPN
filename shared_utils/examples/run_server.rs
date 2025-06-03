//! Custom server example for CoentroVPN
//!
//! This example demonstrates how to run a standalone QUIC server
//! that listens on a specified address.
//!
//! Run with:
//! ```
//! cargo run --example run_server -- 127.0.0.1:4433
//! ```

use shared_utils::crypto::aes_gcm::AesGcmCipher;
use shared_utils::logging;
use shared_utils::quic::{QuicServer, TransportMessage};
use std::env;
use std::net::SocketAddr;
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
    let listen_addr = if args.len() > 1 {
        args[1].parse::<SocketAddr>()?
    } else {
        "127.0.0.1:5000".parse::<SocketAddr>()?
    };

    info!("Starting CoentroVPN QUIC server on {}", listen_addr);

    // Generate a test encryption key
    // In a real application, this would be loaded from configuration
    let encryption_key = AesGcmCipher::generate_key();
    info!("Generated encryption key for testing");

    // Create and start the server
    let server = QuicServer::new(listen_addr, &encryption_key)?;
    let mut receiver = server.start().await?;

    info!("Server started and listening for connections");
    info!("Press Ctrl+C to stop the server");

    // Process incoming messages
    while let Some(message) = receiver.recv().await {
        match message {
            TransportMessage::Data(data) => {
                // Try to convert to string if it's text data
                match String::from_utf8(data.clone()) {
                    Ok(text) => {
                        info!("Received message: {}", text);
                    }
                    Err(_) => {
                        info!("Received binary data: {:?}", data);
                    }
                }
            }
            TransportMessage::StreamClosed => {
                info!("Stream closed by client");
            }
            TransportMessage::ConnectionClosed => {
                info!("Connection closed");
            }
            TransportMessage::Error(e) => {
                info!("Error: {}", e);
            }
        }
    }

    Ok(())
}
