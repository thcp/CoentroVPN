//! End-to-End Test Stub for CoentroVPN
//!
//! This example demonstrates a simple end-to-end test where:
//! - Client sends an encrypted message
//! - Server receives, decrypts, and prints it

use shared_utils::crypto::aes_gcm::AesGcmCipher;
use shared_utils::quic::{QuicClient, QuicServer, QuicTransport, TransportMessage};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::time::sleep;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    println!("Starting End-to-End Encryption Test");
    println!("===================================");

    // Generate a shared encryption key (in a real scenario, this would be securely exchanged)
    let key = AesGcmCipher::generate_key();
    println!("Generated shared encryption key");

    // Set up server address
    let server_addr: SocketAddr = "127.0.0.1:5000".parse()?;
    println!("Server will listen on {}", server_addr);

    // Start the server in a separate task
    let server_key = key.clone();
    let _server_handle = tokio::spawn(async move { run_server(server_addr, &server_key).await });

    // Give the server a moment to start
    sleep(Duration::from_millis(500)).await;

    // Run the client
    let client_result = run_client(server_addr, &key).await;

    // Wait for the server to process the message
    sleep(Duration::from_secs(2)).await;

    // Print the result
    match client_result {
        Ok(_) => println!("Client completed successfully"),
        Err(e) => println!("Client error: {}", e),
    }

    // We don't explicitly join the server_handle as it will be terminated when the main function exits
    // This is fine for a simple test stub

    Ok(())
}

/// Run the QUIC server
async fn run_server(addr: SocketAddr, key: &[u8]) -> anyhow::Result<()> {
    println!("\n[SERVER] Starting QUIC server...");

    // Create a new QUIC server
    let server = QuicServer::new(addr, key)?;
    println!("[SERVER] QUIC server created");

    // Start the server and get a receiver for messages
    let mut rx = server.start().await?;
    println!("[SERVER] QUIC server started and listening");

    println!("[SERVER] Waiting for messages...");

    // Process incoming messages
    while let Some(message) = rx.recv().await {
        match message {
            TransportMessage::Data(data) => {
                // Convert the decrypted data to a string if possible
                match String::from_utf8(data.clone()) {
                    Ok(text) => {
                        println!("[SERVER] Received and decrypted message: \"{}\"", text);
                        println!("[SERVER] Message bytes: {:?}", data);
                    }
                    Err(_) => {
                        println!("[SERVER] Received binary data: {:?}", data);
                    }
                }

                // In a real implementation, we might process the message further
                // or send a response back to the client
            }
            TransportMessage::StreamClosed => {
                println!("[SERVER] Stream closed by client");
            }
            TransportMessage::ConnectionClosed => {
                println!("[SERVER] Connection closed");
                break;
            }
            TransportMessage::Error(e) => {
                println!("[SERVER] Error: {}", e);
                break;
            }
        }
    }

    println!("[SERVER] Server shutting down");
    Ok(())
}

/// Run the QUIC client
async fn run_client(server_addr: SocketAddr, key: &[u8]) -> anyhow::Result<()> {
    println!("\n[CLIENT] Starting QUIC client...");

    // Create a new QUIC client
    let client = QuicClient::new(key)?;
    println!("[CLIENT] QUIC client created");

    // Connect to the server
    let connection = client.connect_to_server(server_addr).await?;
    println!("[CLIENT] Connected to server at {}", server_addr);

    // Create a message to send
    let message = "Hello from CoentroVPN client! This is an encrypted message.";
    println!("[CLIENT] Preparing to send message: \"{}\"", message);

    // Send the message
    client
        .send(connection.clone(), message.as_bytes().to_vec())
        .await?;
    println!("[CLIENT] Message sent successfully");

    // In a real implementation, we might wait for a response from the server
    // and process it here

    // Close the connection
    println!("[CLIENT] Closing connection");
    client.close(connection).await;

    Ok(())
}
