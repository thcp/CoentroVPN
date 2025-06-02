//! End-to-end integration tests for CoentroVPN.
//!
//! This module contains tests that verify the complete functionality
//! of CoentroVPN by starting both server and client components and
//! exchanging encrypted, framed packets between them.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::timeout;

use shared_utils::crypto::aes_gcm::AesGcmCipher;
use shared_utils::proto::framing::{Frame, FrameEncoder, FrameDecoder, FrameType};
use shared_utils::quic::{client::QuicClient, server::QuicServer};

// Test constants
const SERVER_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 4433);
const TEST_TIMEOUT: Duration = Duration::from_secs(5);
const TEST_MESSAGE: &[u8] = b"Hello, CoentroVPN E2E test!";

#[tokio::test]
async fn test_e2e_connection_and_data_exchange() {
    // Initialize tracing for the test
    let _ = tracing_subscriber::fmt()
        .with_env_filter("e2e=debug,shared_utils=debug")
        .with_test_writer()
        .try_init();

    tracing::info!("Starting E2E test");

    // Generate encryption key
    let key = AesGcmCipher::generate_key();
    let cipher = AesGcmCipher::new(&key).expect("Failed to create cipher");

    // Channel for server to signal it's ready
    let (tx, mut rx) = mpsc::channel::<()>(1);

    // Start server in a separate task
    let server_handle = tokio::spawn(async move {
        tracing::info!("Starting test server on {}", SERVER_ADDR);
        
        // Create and start the server
        let mut server = QuicServer::new(SERVER_ADDR)
            .expect("Failed to create QUIC server");
        
        // Signal that the server is ready
        tx.send(()).await.expect("Failed to send ready signal");
        
        // Accept a connection
        let mut conn = server.accept().await.expect("Failed to accept connection");
        tracing::info!("Server accepted connection from {}", conn.remote_addr());
        
        // Receive data
        let data = conn.receive().await.expect("Failed to receive data");
        tracing::info!("Server received {} bytes", data.len());
        
        // Decode the frame
        let mut decoder = FrameDecoder::new();
        let frames = decoder.decode(&data).expect("Failed to decode frame");
        assert_eq!(frames.len(), 1, "Expected 1 frame");
        
        let frame = &frames[0];
        assert_eq!(frame.frame_type, FrameType::Data, "Expected Data frame");
        
        // Decrypt the payload
        let decrypted = cipher.decrypt(&frame.payload).expect("Failed to decrypt payload");
        tracing::info!("Server decrypted message: {:?}", String::from_utf8_lossy(&decrypted));
        
        // Verify the message
        assert_eq!(&decrypted, TEST_MESSAGE, "Message mismatch");
        
        // Send a response
        let response = b"ACK from server".to_vec();
        let encrypted_response = cipher.encrypt(&response).expect("Failed to encrypt response");
        
        let response_frame = Frame::new_data(encrypted_response).expect("Failed to create response frame");
        let encoder = FrameEncoder::new();
        let encoded_response = encoder.encode(&response_frame);
        
        conn.send(&encoded_response).await.expect("Failed to send response");
        tracing::info!("Server sent response");
        
        // Close the connection
        conn.close().await.expect("Failed to close connection");
        tracing::info!("Server closed connection");
    });
    
    // Wait for server to be ready
    timeout(Duration::from_secs(1), rx.recv())
        .await
        .expect("Server startup timed out")
        .expect("Failed to receive ready signal");
    
    // Give the server a moment to fully initialize
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // Start client
    tracing::info!("Starting test client connecting to {}", SERVER_ADDR);
    let mut client = QuicClient::connect(SERVER_ADDR)
        .await
        .expect("Failed to connect to server");
    
    tracing::info!("Client connected to server");
    
    // Encrypt and frame the test message
    let encrypted_message = cipher.encrypt(TEST_MESSAGE).expect("Failed to encrypt message");
    let frame = Frame::new_data(encrypted_message).expect("Failed to create frame");
    
    // Encode the frame
    let encoder = FrameEncoder::new();
    let encoded = encoder.encode(&frame);
    
    // Send the encoded frame
    client.send(&encoded).await.expect("Failed to send data");
    tracing::info!("Client sent message");
    
    // Receive response
    let response_data = client.receive().await.expect("Failed to receive response");
    tracing::info!("Client received {} bytes", response_data.len());
    
    // Decode the response frame
    let mut decoder = FrameDecoder::new();
    let response_frames = decoder.decode(&response_data).expect("Failed to decode response frame");
    assert_eq!(response_frames.len(), 1, "Expected 1 response frame");
    
    let response_frame = &response_frames[0];
    assert_eq!(response_frame.frame_type, FrameType::Data, "Expected Data frame");
    
    // Decrypt the response payload
    let decrypted_response = cipher.decrypt(&response_frame.payload).expect("Failed to decrypt response");
    let response_text = String::from_utf8_lossy(&decrypted_response);
    tracing::info!("Client decrypted response: {:?}", response_text);
    
    // Verify the response
    assert_eq!(response_text, "ACK from server", "Response mismatch");
    
    // Close the client connection
    client.close().await.expect("Failed to close client connection");
    tracing::info!("Client closed connection");
    
    // Wait for server to finish
    timeout(TEST_TIMEOUT, server_handle)
        .await
        .expect("Server task timed out")
        .expect("Server task failed");
    
    tracing::info!("E2E test completed successfully");
}

#[tokio::test]
async fn test_e2e_encryption_tamper_resistance() {
    // Initialize tracing for the test
    let _ = tracing_subscriber::fmt()
        .with_env_filter("e2e=debug,shared_utils=debug")
        .with_test_writer()
        .try_init();

    tracing::info!("Starting encryption tamper resistance test");

    // Generate encryption keys
    let key1 = AesGcmCipher::generate_key();
    let key2 = AesGcmCipher::generate_key(); // Different key
    
    let cipher1 = AesGcmCipher::new(&key1).expect("Failed to create cipher1");
    let cipher2 = AesGcmCipher::new(&key2).expect("Failed to create cipher2");

    // Channel for server to signal it's ready
    let (tx, mut rx) = mpsc::channel::<()>(1);

    // Start server in a separate task with key1
    let server_handle = tokio::spawn(async move {
        tracing::info!("Starting test server on {}", SERVER_ADDR);
        
        // Create and start the server
        let mut server = QuicServer::new(SERVER_ADDR)
            .expect("Failed to create QUIC server");
        
        // Signal that the server is ready
        tx.send(()).await.expect("Failed to send ready signal");
        
        // Accept a connection
        let mut conn = server.accept().await.expect("Failed to accept connection");
        tracing::info!("Server accepted connection from {}", conn.remote_addr());
        
        // Receive data
        let data = conn.receive().await.expect("Failed to receive data");
        tracing::info!("Server received {} bytes", data.len());
        
        // Decode the frame
        let mut decoder = FrameDecoder::new();
        let frames = decoder.decode(&data).expect("Failed to decode frame");
        assert_eq!(frames.len(), 1, "Expected 1 frame");
        
        let frame = &frames[0];
        
        // Try to decrypt with the correct key - should succeed
        let decryption_result = cipher1.decrypt(&frame.payload);
        assert!(decryption_result.is_ok(), "Decryption with correct key failed");
        
        // Send a response
        let response = b"Decryption successful".to_vec();
        let encrypted_response = cipher1.encrypt(&response).expect("Failed to encrypt response");
        
        let response_frame = Frame::new_data(encrypted_response).expect("Failed to create response frame");
        let encoder = FrameEncoder::new();
        let encoded_response = encoder.encode(&response_frame);
        
        conn.send(&encoded_response).await.expect("Failed to send response");
        tracing::info!("Server sent response");
        
        // Close the connection
        conn.close().await.expect("Failed to close connection");
        tracing::info!("Server closed connection");
    });
    
    // Wait for server to be ready
    timeout(Duration::from_secs(1), rx.recv())
        .await
        .expect("Server startup timed out")
        .expect("Failed to receive ready signal");
    
    // Give the server a moment to fully initialize
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // Start client
    tracing::info!("Starting test client connecting to {}", SERVER_ADDR);
    let mut client = QuicClient::connect(SERVER_ADDR)
        .await
        .expect("Failed to connect to server");
    
    tracing::info!("Client connected to server");
    
    // Encrypt with key2 (different from server's key1)
    let encrypted_message = cipher2.encrypt(TEST_MESSAGE).expect("Failed to encrypt message");
    let frame = Frame::new_data(encrypted_message).expect("Failed to create frame");
    
    // Encode the frame
    let encoder = FrameEncoder::new();
    let encoded = encoder.encode(&frame);
    
    // Send the encoded frame
    client.send(&encoded).await.expect("Failed to send data");
    tracing::info!("Client sent message encrypted with different key");
    
    // Receive response
    let response_data = client.receive().await.expect("Failed to receive response");
    
    // Decode the response frame
    let mut decoder = FrameDecoder::new();
    let response_frames = decoder.decode(&response_data).expect("Failed to decode response frame");
    assert_eq!(response_frames.len(), 1, "Expected 1 response frame");
    
    let response_frame = &response_frames[0];
    
    // Try to decrypt with key2 - should fail because server used key1
    let decryption_result = cipher2.decrypt(&response_frame.payload);
    assert!(decryption_result.is_err(), "Decryption with wrong key should fail");
    
    // Close the client connection
    client.close().await.expect("Failed to close client connection");
    
    // Wait for server to finish
    timeout(TEST_TIMEOUT, server_handle)
        .await
        .expect("Server task timed out")
        .expect("Server task failed");
    
    tracing::info!("Encryption tamper resistance test completed successfully");
}
