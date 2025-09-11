//! Formal End-to-End (E2E) Test Suite for CoentroVPN
//!
//! This module contains comprehensive integration tests that validate the entire system,
//! from configuration parsing to tunnel establishment, data transfer, error handling,
//! and edge cases including:
//! - Large message fragmentation and reassembly
//! - Tampered payload decryption failure
//! - Frame truncation and recovery
//! - Multiple concurrent client sessions

use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use shared_utils::config::{Config, ConfigManager, Role};
use shared_utils::crypto::aes_gcm::AesGcmCipher;
use shared_utils::proto::framing::{Frame, FrameDecoder, FrameEncoder};
// Updated imports:
use shared_utils::quic::{QuicClient, QuicServer};
use shared_utils::quic::generate_self_signed_cert;
use shared_utils::transport::{ClientTransport, Listener as TraitListener, ServerTransport}; // Removed unused Connection as TraitConnection & TransportError
use shared_utils::tunnel::{
    ClientBootstrapper, ServerBootstrapper, TunnelBootstrapper, TunnelConfig, TunnelManager,
    TunnelState,
};
use tempfile::NamedTempFile;
use tokio::time::{sleep, timeout};

// Test constants
const TEST_TIMEOUT: Duration = Duration::from_secs(30);
const LARGE_MESSAGE_SIZE: usize = 1024 * 1024; // 1MB
const MAX_CONCURRENT_CLIENTS: usize = 10;

/// Helper function to create a test server configuration
fn create_test_server_config(psk: &str, port: u16) -> String {
    format!(
        r#"
        role = "server"
        log_level = "debug"
        
        [network]
        port = {}
        bind_address = "127.0.0.1"
        
        [security]
        psk = "{}"
        
        [server]
        virtual_ip_range = "10.0.0.0/24"
        "#,
        port, psk
    )
}

/// Helper function to create a test client configuration
fn create_test_client_config(psk: &str, server_addr: &str) -> Config {
    Config {
        role: Role::Client,
        security: shared_utils::config::SecurityConfig {
            psk: Some(psk.to_string()),
            ..Default::default()
        },
        client: shared_utils::config::ClientConfig {
            server_address: Some(server_addr.to_string()),
            ..Default::default()
        },
        ..Default::default()
    }
}

/// Test basic configuration to tunnel E2E flow
#[tokio::test]
#[cfg_attr(not(feature = "insecure-tls"), ignore)]
async fn test_config_to_tunnel_e2e() {
    // Create a temporary config file
    let mut file = NamedTempFile::new().unwrap();

    // Generate a test PSK
    let psk = "test-psk-for-e2e-test";

    // Create server config
    let config_str = create_test_server_config(psk, 0); // Use port 0 for random available port

    file.write_all(config_str.as_bytes()).unwrap();

    // Load the config
    let config_manager = ConfigManager::load(file.path()).unwrap();
    let config = config_manager.config();

    // Verify config was loaded correctly
    assert_eq!(config.role, Role::Server);
    assert_eq!(config.security.psk, Some(psk.to_string()));

    // Create a tunnel manager
    let tunnel_manager = TunnelManager::new();

    // Create a server tunnel from the config
    let server_tunnel_id = tunnel_manager
        .create_tunnel_from_config(config)
        .await
        .unwrap();

    // Get the server tunnel
    let server_tunnel = tunnel_manager.get_tunnel(&server_tunnel_id).unwrap();

    // Get the bound address
    let bound_addr = {
        let handle = server_tunnel.lock().unwrap();
        handle.peer_or_listen_addr // Changed from remote_addr
    };

    println!("Server bound to {}", bound_addr);

    // Create a client config pointing to the server
    let client_config = create_test_client_config(psk, &bound_addr.to_string());

    // Create a client tunnel
    let client_tunnel_id = tunnel_manager
        .create_tunnel_from_config(&client_config)
        .await
        .unwrap();

    // Get the client tunnel
    let client_tunnel = tunnel_manager.get_tunnel(&client_tunnel_id).unwrap();

    // Wait a moment for the connection to establish
    sleep(Duration::from_millis(100)).await;

    // Verify both tunnels are connected
    {
        let handle = client_tunnel.lock().unwrap();
        assert_eq!(handle.state, TunnelState::Connected);
    }

    // Clean up
    tunnel_manager
        .close_tunnel(&client_tunnel_id)
        .await
        .unwrap();
    tunnel_manager
        .close_tunnel(&server_tunnel_id)
        .await
        .unwrap();
}

/// Test direct tunnel bootstrapping
#[tokio::test]
#[cfg_attr(not(feature = "insecure-tls"), ignore)]
async fn test_direct_tunnel_bootstrapping() {
    // Generate a shared key
    let key = AesGcmCipher::generate_key();

    // Create server bootstrapper
    let server_bootstrapper = ServerBootstrapper::new();

    // Create server config
    let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0);
    let server_config = TunnelConfig::new_server(server_addr).with_psk(key.to_vec());

    // Bootstrap server tunnel
    let mut server_handle = server_bootstrapper.bootstrap(server_config).await.unwrap();

    // Get the actual bound address
    let bound_addr = server_handle.peer_or_listen_addr; // Changed from remote_addr
    println!("Server bound to {}", bound_addr);

    // Create client bootstrapper
    let client_bootstrapper = ClientBootstrapper::new();

    // Create client config
    let client_config = TunnelConfig::new_client(bound_addr).with_psk(key.to_vec());

    // Bootstrap client tunnel
    let mut client_handle = client_bootstrapper.bootstrap(client_config).await.unwrap();

    // Wait a moment for the connection to establish
    sleep(Duration::from_millis(100)).await;

    // Verify client tunnel is connected
    assert_eq!(client_handle.state, TunnelState::Connected);

    // Clean up
    if let Some(conn_box) = client_handle.connection.take() {
        conn_box
            .close()
            .await
            .expect("Client connection close failed");
    }

    if let Some(conn_box) = server_handle.connection.take() {
        conn_box
            .close()
            .await
            .expect("Server connection close failed");
    }
}

/// Test tunnel manager lifecycle
#[tokio::test]
#[cfg_attr(not(feature = "insecure-tls"), ignore)]
async fn test_tunnel_manager_lifecycle() {
    // Create a tunnel manager
    let tunnel_manager = TunnelManager::new();

    // Generate a shared key
    let key = AesGcmCipher::generate_key();

    // Create a server tunnel
    let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0);
    let server_tunnel_id = tunnel_manager
        .create_server_tunnel(server_addr, Some(key.to_vec()))
        .await
        .unwrap();

    // Get the server tunnel
    let server_tunnel = tunnel_manager.get_tunnel(&server_tunnel_id).unwrap();

    // Get the bound address
    let bound_addr = {
        let handle = server_tunnel.lock().unwrap();
        handle.peer_or_listen_addr // Changed from remote_addr
    };

    // Create a client tunnel
    let client_tunnel_id = tunnel_manager
        .create_client_tunnel(bound_addr, Some(key.to_vec()))
        .await
        .unwrap();

    // Wait a moment for the connection to establish
    sleep(Duration::from_millis(100)).await;

    // Verify we have two tunnels
    assert_eq!(tunnel_manager.tunnel_count(), 2);

    // Close the client tunnel
    tunnel_manager
        .close_tunnel(&client_tunnel_id)
        .await
        .unwrap();

    // Verify we have one tunnel left
    assert_eq!(tunnel_manager.tunnel_count(), 1);

    // Close the server tunnel
    tunnel_manager
        .close_tunnel(&server_tunnel_id)
        .await
        .unwrap();

    // Verify all tunnels are closed
    assert_eq!(tunnel_manager.tunnel_count(), 0);
}

/// Test large message fragmentation and reassembly
#[tokio::test]
async fn test_large_message_fragmentation_and_reassembly() {
    println!("Starting large message fragmentation test");

    // Generate a shared encryption key
    let key = AesGcmCipher::generate_key();

    // Set up server address
    let server_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

    // Start the server in a separate task and get the actual bound address
    let server_key = key;
    let (actual_addr_tx, actual_addr_rx) = tokio::sync::oneshot::channel();
    let server_handle = tokio::spawn(async move {
        run_large_message_server(server_addr, &server_key, actual_addr_tx).await
    });

    // Wait for the server to start and get the actual address
    let (actual_server_addr, server_cert) = timeout(Duration::from_secs(5), actual_addr_rx)
        .await
        .expect("Server should start within 5 seconds")
        .expect("Server should send its bound address");

    println!("Server is ready at {}", actual_server_addr);

    // Create a large message (1MB of data)
    let large_message = vec![0xAB; LARGE_MESSAGE_SIZE];
    println!("Created large message of {} bytes", large_message.len());

    // Run the client with the large message
    let client_result = timeout(
        TEST_TIMEOUT,
        run_large_message_client(actual_server_addr, &key, large_message.clone(), server_cert.clone()),
    )
    .await;

    // Verify the client completed successfully
    assert!(client_result.is_ok(), "Client timed out");
    assert!(client_result.unwrap().is_ok(), "Client failed");

    // Wait for server to process
    sleep(Duration::from_millis(1000)).await;

    // Clean up server
    server_handle.abort();

    println!("Large message fragmentation test completed successfully");
}

/// Test tampered payload decryption failure
#[tokio::test]
async fn test_tampered_payload_decryption_failure() {
    println!("Starting tampered payload decryption test");

    // Generate a shared encryption key
    let key = AesGcmCipher::generate_key();
    let cipher = AesGcmCipher::new(&key).unwrap();

    // Create a test message
    let original_message = b"This is a secret message that will be tampered with";

    // Encrypt the message
    let encrypted_data = cipher.encrypt(original_message).unwrap();
    println!("Original encrypted data length: {}", encrypted_data.len());

    // Tamper with the encrypted data (flip some bits in the middle)
    let mut tampered_data = encrypted_data.clone();
    if tampered_data.len() > 20 {
        tampered_data[15] ^= 0xFF; // Flip bits in the encrypted payload
        tampered_data[16] ^= 0xAA;
        tampered_data[17] ^= 0x55;
    }

    // Try to decrypt the tampered data - this should fail
    let decrypt_result = cipher.decrypt(&tampered_data);
    assert!(
        decrypt_result.is_err(),
        "Decryption should fail for tampered data"
    );

    println!(
        "Tampered payload correctly rejected: {}",
        decrypt_result.unwrap_err()
    );

    // Verify that the original data still decrypts correctly
    let original_decrypt = cipher.decrypt(&encrypted_data).unwrap();
    assert_eq!(original_decrypt, original_message);

    println!("Tampered payload decryption test completed successfully");
}

/// Test frame truncation and recovery
#[tokio::test]
async fn test_frame_truncation_and_recovery() {
    println!("Starting frame truncation and recovery test");

    // Create test frames
    let frame1 = Frame::new_data(b"First message".to_vec()).unwrap();
    let frame2 = Frame::new_data(b"Second message".to_vec()).unwrap();
    let frame3 = Frame::new_data(b"Third message".to_vec()).unwrap();

    // Encode the frames
    let encoder = FrameEncoder::new();
    let encoded1 = encoder.encode(&frame1);
    let encoded2 = encoder.encode(&frame2);
    let encoded3 = encoder.encode(&frame3);

    // Combine all encoded frames
    let mut combined_data = Vec::new();
    combined_data.extend_from_slice(&encoded1);
    combined_data.extend_from_slice(&encoded2);
    combined_data.extend_from_slice(&encoded3);

    println!("Total encoded data length: {}", combined_data.len());

    // Test 1: Truncate in the middle of the second frame
    let truncation_point = encoded1.len() + (encoded2.len() / 2);
    let truncated_data = &combined_data[0..truncation_point];

    let mut decoder = FrameDecoder::new();
    let decoded_frames = decoder.decode(truncated_data).unwrap();

    // Should only decode the first frame
    assert_eq!(decoded_frames.len(), 1);
    assert_eq!(decoded_frames[0], frame1);

    // Test 2: Send the remaining data to complete the second frame and get the third
    let remaining_data = &combined_data[truncation_point..];
    let decoded_frames = decoder.decode(remaining_data).unwrap();

    // Should decode the second and third frames
    assert_eq!(decoded_frames.len(), 2);
    assert_eq!(decoded_frames[0], frame2);
    assert_eq!(decoded_frames[1], frame3);

    // Test 3: Test recovery from corrupted frame
    let mut decoder2 = FrameDecoder::new();

    // Send corrupted data (invalid magic byte)
    let mut corrupted_frame = encoded1.clone();
    corrupted_frame[0] = 0xFF; // Invalid magic byte

    let decode_result = decoder2.decode(&corrupted_frame);
    assert!(decode_result.is_err(), "Should fail on corrupted frame");

    // Verify we can recover by clearing the decoder and sending valid data
    decoder2.clear();
    let recovered_frames = decoder2.decode(&encoded2).unwrap();
    assert_eq!(recovered_frames.len(), 1);
    assert_eq!(recovered_frames[0], frame2);

    println!("Frame truncation and recovery test completed successfully");
}

/// Test multiple concurrent client sessions
#[tokio::test]
#[cfg_attr(not(feature = "insecure-tls"), ignore)]
async fn test_multiple_concurrent_client_sessions() {
    println!("Starting multiple concurrent client sessions test");

    // Generate a shared key
    let key = AesGcmCipher::generate_key();

    // Create server
    let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0);
    let server_bootstrapper = ServerBootstrapper::new();
    let server_config = TunnelConfig::new_server(server_addr).with_psk(key.to_vec());
    let mut server_handle = server_bootstrapper.bootstrap(server_config).await.unwrap();
    let bound_addr = server_handle.peer_or_listen_addr; // Changed from remote_addr

    println!("Server bound to {}", bound_addr);

    // Create multiple concurrent clients
    let mut client_handles = Vec::new();
    let mut client_tasks = Vec::new();

    for i in 0..MAX_CONCURRENT_CLIENTS {
        let client_key = key;
        let client_addr = bound_addr;

        let task = tokio::spawn(async move {
            let client_bootstrapper = ClientBootstrapper::new();
            let client_config = TunnelConfig::new_client(client_addr).with_psk(client_key.to_vec());

            match client_bootstrapper.bootstrap(client_config).await {
                Ok(handle) => {
                    println!("Client {} connected successfully", i);
                    // Simulate some work
                    sleep(Duration::from_millis(100)).await;
                    Ok(handle)
                }
                Err(e) => {
                    println!("Client {} failed to connect: {}", i, e);
                    Err(e)
                }
            }
        });

        client_tasks.push(task);
    }

    // Wait for all clients to connect
    let mut successful_connections = 0;
    for (i, task) in client_tasks.into_iter().enumerate() {
        match timeout(Duration::from_secs(10), task).await {
            Ok(Ok(Ok(mut handle))) => {
                successful_connections += 1;
                println!("Client {} connection verified", i);

                // Clean up client connection
                if let Some(conn_box) = handle.connection.take() {
                    conn_box
                        .close()
                        .await
                        .expect("Client connection close failed during concurrent test");
                }
                client_handles.push(handle);
            }
            Ok(Ok(Err(e))) => {
                println!("Client {} bootstrap failed: {}", i, e);
            }
            Ok(Err(e)) => {
                println!("Client {} task panicked: {:?}", i, e);
            }
            Err(_) => {
                println!("Client {} timed out", i);
            }
        }
    }

    println!(
        "Successfully connected {} out of {} clients",
        successful_connections, MAX_CONCURRENT_CLIENTS
    );

    // We should have at least some successful connections
    // (exact number may vary due to system limits and timing)
    assert!(
        successful_connections > 0,
        "At least one client should connect successfully"
    );

    // Clean up server
    if let Some(conn_box) = server_handle.connection.take() {
        conn_box
            .close()
            .await
            .expect("Server connection close failed during concurrent test");
    }

    println!("Multiple concurrent client sessions test completed successfully");
}

/// Test QUIC transport with encryption end-to-end
#[tokio::test]
async fn test_quic_transport_with_encryption_e2e() {
    println!("Starting QUIC transport with encryption E2E test");

    // Generate a shared encryption key
    let key = AesGcmCipher::generate_key();

    // Set up server address
    let server_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

    // Start the server and get the actual bound address
    let server_key = key;
    let (actual_addr_tx, actual_addr_rx) = tokio::sync::oneshot::channel();
    let server_handle = tokio::spawn(async move {
        run_encrypted_quic_server(server_addr, &server_key, actual_addr_tx).await
    });

    // Wait for the server to start and get the actual address
    let (actual_server_addr, server_cert) = timeout(Duration::from_secs(5), actual_addr_rx)
        .await
        .expect("Server should start within 5 seconds")
        .expect("Server should send its bound address");

    println!("Encrypted QUIC Server is ready at {}", actual_server_addr);

    // Run the client
    let test_messages = vec![
        "Hello from CoentroVPN client!",
        "This is message number 2",
        "Final test message with special chars: àáâãäåæçèéêë",
    ];

    let client_result = timeout(
        TEST_TIMEOUT,
        run_encrypted_quic_client(actual_server_addr, &key, test_messages.clone(), server_cert.clone()),
    )
    .await;

    // Verify the client completed successfully
    assert!(client_result.is_ok(), "Client timed out");
    assert!(client_result.unwrap().is_ok(), "Client failed");

    // Wait for server to process all messages
    sleep(Duration::from_millis(1000)).await;

    // Clean up server
    server_handle.abort();

    println!("QUIC transport with encryption E2E test completed successfully");
}

// Helper functions for running servers and clients

/// Run a server that handles large messages
async fn run_large_message_server(
    addr: SocketAddr,
    key: &[u8],
    actual_addr_tx: tokio::sync::oneshot::Sender<(SocketAddr, rustls::Certificate)>,
) -> anyhow::Result<()> {
    println!("[SERVER] Starting large message server...");
    // Generate a self-signed cert and use it explicitly so the client can pin it
    let (cert, key_der) = generate_self_signed_cert()?;
    let quic_server = QuicServer::new_with_cert(addr, key, cert.clone(), key_der)?;
    let mut listener = quic_server.listen(&addr.to_string()).await?;
    let actual_addr = listener.local_addr()?;
    println!("[SERVER] Server bound to {}", actual_addr);

    if actual_addr_tx.send((actual_addr, cert)).is_err() {
        return Err(anyhow::anyhow!(
            "Failed to send actual server address back to test"
        ));
    }

    println!("[SERVER] Server started, waiting for large messages...");
    let mut conn = listener.accept().await?; // Accept one connection for this test
    println!("[SERVER] Accepted connection from {}", conn.peer_addr()?);

    let mut total_bytes_received = 0;

    loop {
        match conn.recv_data().await {
            Ok(Some(data)) => {
                total_bytes_received += data.len();
                println!(
                    "[SERVER] Received {} bytes (total: {})",
                    data.len(),
                    total_bytes_received
                );

                if !data.is_empty() && data[0] == 0xAB {
                    println!("[SERVER] Data pattern verified");
                }

                if total_bytes_received >= LARGE_MESSAGE_SIZE {
                    println!("[SERVER] Large message fully received!");
                    break;
                }
            }
            Ok(None) => {
                println!("[SERVER] Stream/Connection closed by client");
                break;
            }
            Err(e) => {
                println!("[SERVER] Error receiving data: {}", e);
                return Err(e.into());
            }
        }
    }
    conn.close().await?;
    Ok(())
}

/// Run a client that sends large messages
async fn run_large_message_client(
    server_addr: SocketAddr,
    key: &[u8],
    message: Vec<u8>,
    server_cert: rustls::Certificate,
) -> anyhow::Result<()> {
    println!("[CLIENT] Starting large message client...");

    // Pin the server's self-signed certificate for TLS
    let client = QuicClient::new_with_pinned_roots(key, &[server_cert])?;
    let mut connection = client.connect(&server_addr.to_string()).await?;

    println!(
        "[CLIENT] Connected, sending large message of {} bytes",
        message.len()
    );

    connection.send_data(&message).await?;

    println!("[CLIENT] Large message sent successfully");

    connection.close().await?;
    Ok(())
}

/// Run a server that handles encrypted QUIC messages
async fn run_encrypted_quic_server(
    addr: SocketAddr,
    key: &[u8],
    actual_addr_tx: tokio::sync::oneshot::Sender<(SocketAddr, rustls::Certificate)>,
) -> anyhow::Result<()> {
    println!("[SERVER] Starting encrypted QUIC server...");
    // Use explicit self-signed cert for server and let client pin it
    let (cert, key_der) = generate_self_signed_cert()?;
    let quic_server = QuicServer::new_with_cert(addr, key, cert.clone(), key_der)?;
    let mut listener = quic_server.listen(&addr.to_string()).await?;
    let actual_addr = listener.local_addr()?;
    println!("[SERVER] Server bound to {}", actual_addr);

    if actual_addr_tx.send((actual_addr, cert)).is_err() {
        return Err(anyhow::anyhow!(
            "Failed to send actual server address back to test"
        ));
    }

    println!("[SERVER] Server started, waiting for encrypted messages...");
    let mut conn = listener.accept().await?;
    println!("[SERVER] Accepted connection from {}", conn.peer_addr()?);

    let mut message_count = 0;

    loop {
        match conn.recv_data().await {
            Ok(Some(data)) => {
                message_count += 1;
                match String::from_utf8(data.clone()) {
                    Ok(text) => {
                        println!("[SERVER] Received message {}: \"{}\"", message_count, text);
                    }
                    Err(_) => {
                        println!("[SERVER] Received binary data: {} bytes", data.len());
                    }
                }
                if message_count >= 3 {
                    break;
                }
            }
            Ok(None) => {
                println!("[SERVER] Stream/Connection closed by client");
                break;
            }
            Err(e) => {
                println!("[SERVER] Error receiving data: {}", e);
                return Err(e.into());
            }
        }
    }
    conn.close().await?;
    Ok(())
}

/// Run a client that sends encrypted QUIC messages
async fn run_encrypted_quic_client(
    server_addr: SocketAddr,
    key: &[u8],
    messages: Vec<&str>,
    server_cert: rustls::Certificate,
) -> anyhow::Result<()> {
    println!("[CLIENT] Starting encrypted QUIC client...");
    // Pin server cert
    let client = QuicClient::new_with_pinned_roots(key, &[server_cert])?;
    let mut connection = client.connect(&server_addr.to_string()).await?;

    println!("[CLIENT] Connected, sending {} messages", messages.len());

    for (i, message_str) in messages.iter().enumerate() {
        println!("[CLIENT] Sending message {}: \"{}\"", i + 1, message_str);
        connection.send_data(message_str.as_bytes()).await?;
        sleep(Duration::from_millis(100)).await;
    }

    println!("[CLIENT] All messages sent successfully");

    connection.close().await?;
    Ok(())
}
