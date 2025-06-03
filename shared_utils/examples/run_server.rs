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
use shared_utils::quic::QuicServer;
// Import new transport traits
use shared_utils::transport::{Listener as TraitListener, ServerTransport}; // Removed unused Connection as TraitConnection
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

    // Create the server
    let server = QuicServer::new(listen_addr, &encryption_key)?;
    let mut listener = server.listen(&listen_addr.to_string()).await?;
    let actual_listen_addr = listener.local_addr()?;
    info!("Server started and listening on {}", actual_listen_addr);
    info!("Press Ctrl+C to stop the server");

    // Accept one connection
    match listener.accept().await {
        Ok(mut conn) => {
            info!("Accepted connection from: {}", conn.peer_addr()?);
            // Process incoming data on this connection
            loop {
                match conn.recv_data().await {
                    Ok(Some(data)) => {
                        match String::from_utf8(data.clone()) {
                            Ok(text) => {
                                info!("Received message: {}", text);
                                // Echo back
                                if let Err(e) =
                                    conn.send_data(format!("Echo: {}", text).as_bytes()).await
                                {
                                    info!("Error sending echo: {}", e);
                                    break;
                                }
                            }
                            Err(_) => {
                                info!("Received binary data: {:?}", data);
                            }
                        }
                    }
                    Ok(None) => {
                        info!("Connection closed by client");
                        break;
                    }
                    Err(e) => {
                        info!("Error receiving data: {}", e);
                        break;
                    }
                }
            }
            conn.close().await?;
        }
        Err(e) => {
            info!("Failed to accept connection: {}", e);
        }
    }
    Ok(())
}
