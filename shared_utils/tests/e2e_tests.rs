//! End-to-End tests for CoentroVPN.
//!
//! This module contains integration tests that validate the entire system,
//! from configuration parsing to tunnel establishment and data transfer.

use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use shared_utils::config::{Config, ConfigManager, Role};
use shared_utils::crypto::aes_gcm::AesGcmCipher;
use shared_utils::tunnel::{
    ClientBootstrapper, ServerBootstrapper, TunnelBootstrapper, TunnelConfig, TunnelManager,
    TunnelState,
};
use tempfile::NamedTempFile;
use tokio::time::sleep;

#[tokio::test]
#[cfg_attr(not(feature = "insecure-tls"), ignore)]
async fn test_config_to_tunnel_e2e() {
    // Create a temporary config file
    let mut file = NamedTempFile::new().unwrap();

    // Generate a test PSK
    let psk = "test-psk-for-e2e-test";

    // Create server config
    let config_str = format!(
        r#"
        role = "server"
        log_level = "debug"
        
        [network]
        port = 8080  # Use a specific port for testing
        bind_address = "127.0.0.1"
        
        [security]
        psk = "{}"
        
        [server]
        virtual_ip_range = "10.0.0.0/24"
        "#,
        psk
    );

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
    let client_config = Config {
        role: Role::Client,
        security: shared_utils::config::SecurityConfig {
            psk: Some(psk.to_string()),
            ..Default::default()
        },
        client: shared_utils::config::ClientConfig {
            server_address: Some(bound_addr.to_string()),
            ..Default::default()
        },
        ..Default::default()
    };

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

#[tokio::test]
#[cfg_attr(not(feature = "insecure-tls"), ignore)]
async fn test_direct_tunnel_bootstrapping() {
    // Generate a shared key
    let key = AesGcmCipher::generate_key();

    // Create server bootstrapper
    let server_bootstrapper = ServerBootstrapper::new();

    // Create server config
    let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
    let server_config = TunnelConfig::new_server(server_addr).with_psk(key.clone().to_vec());

    // Bootstrap server tunnel
    let mut server_handle = server_bootstrapper.bootstrap(server_config).await.unwrap();

    // Get the actual bound address
    let bound_addr = server_handle.peer_or_listen_addr; // Changed from remote_addr
    println!("Server bound to {}", bound_addr);

    // Create client bootstrapper
    let client_bootstrapper = ClientBootstrapper::new();

    // Create client config
    let client_config = TunnelConfig::new_client(bound_addr).with_psk(key.clone().to_vec());

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
            .expect("Client connection close failed in e2e_tests");
    }

    if let Some(conn_box) = server_handle.connection.take() {
        conn_box
            .close()
            .await
            .expect("Server connection close failed in e2e_tests");
    }
}

#[tokio::test(flavor = "multi_thread")]
#[cfg_attr(not(feature = "insecure-tls"), ignore)]
async fn test_tunnel_manager_lifecycle() {
    println!("test_tunnel_manager_lifecycle: START");
    // Create a tunnel manager
    println!("test_tunnel_manager_lifecycle: Creating TunnelManager...");
    let tunnel_manager = TunnelManager::new();
    println!("test_tunnel_manager_lifecycle: TunnelManager created.");

    // Generate a shared key
    let key = AesGcmCipher::generate_key();

    // Create a server tunnel
    let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8081);
    println!("test_tunnel_manager_lifecycle: Creating server tunnel...");

    // Use tokio::time::timeout to prevent hanging indefinitely
    let server_tunnel_id = match tokio::time::timeout(
        std::time::Duration::from_secs(10), // 10 second timeout
        tunnel_manager.create_server_tunnel(server_addr, Some(key.clone().to_vec())),
    )
    .await
    {
        Ok(result) => result.unwrap(),
        Err(_) => {
            println!("test_tunnel_manager_lifecycle: TIMEOUT creating server tunnel!");
            panic!("Timeout creating server tunnel");
        }
    };
    println!(
        "test_tunnel_manager_lifecycle: Server tunnel created with ID: {}",
        server_tunnel_id
    );

    // Get the server tunnel
    let server_tunnel = tunnel_manager.get_tunnel(&server_tunnel_id).unwrap();

    // Get the bound address
    let bound_addr = {
        let handle = server_tunnel.lock().unwrap();
        handle.peer_or_listen_addr // Changed from remote_addr
    };

    // Create a client tunnel
    println!(
        "test_tunnel_manager_lifecycle: Creating client tunnel to {}...",
        bound_addr
    );

    // Use tokio::time::timeout to prevent hanging indefinitely
    let client_tunnel_id = match tokio::time::timeout(
        std::time::Duration::from_secs(10), // 10 second timeout
        tunnel_manager.create_client_tunnel(bound_addr, Some(key.clone().to_vec())),
    )
    .await
    {
        Ok(result) => result.unwrap(),
        Err(_) => {
            println!("test_tunnel_manager_lifecycle: TIMEOUT creating client tunnel!");
            panic!("Timeout creating client tunnel");
        }
    };
    println!(
        "test_tunnel_manager_lifecycle: Client tunnel created with ID: {}",
        client_tunnel_id
    );

    // Wait a moment for the connection to establish
    println!("test_tunnel_manager_lifecycle: Sleeping for 100ms...");
    sleep(Duration::from_millis(100)).await;
    println!("test_tunnel_manager_lifecycle: Sleep finished.");

    // Verify we have two tunnels
    assert_eq!(tunnel_manager.tunnel_count(), 2);

    // Close the client tunnel
    println!(
        "test_tunnel_manager_lifecycle: Closing client tunnel {}...",
        client_tunnel_id
    );

    // Use tokio::time::timeout to prevent hanging indefinitely
    match tokio::time::timeout(
        std::time::Duration::from_secs(10), // 10 second timeout
        tunnel_manager.close_tunnel(&client_tunnel_id),
    )
    .await
    {
        Ok(result) => result.unwrap(),
        Err(_) => {
            println!("test_tunnel_manager_lifecycle: TIMEOUT closing client tunnel!");
            panic!("Timeout closing client tunnel");
        }
    };
    println!(
        "test_tunnel_manager_lifecycle: Client tunnel {} closed.",
        client_tunnel_id
    );

    // Verify we have one tunnel left
    assert_eq!(tunnel_manager.tunnel_count(), 1);

    // Close the server tunnel
    println!(
        "test_tunnel_manager_lifecycle: Closing server tunnel {}...",
        server_tunnel_id
    );

    // Use tokio::time::timeout to prevent hanging indefinitely
    match tokio::time::timeout(
        std::time::Duration::from_secs(10), // 10 second timeout
        tunnel_manager.close_tunnel(&server_tunnel_id),
    )
    .await
    {
        Ok(result) => result.unwrap(),
        Err(_) => {
            println!("test_tunnel_manager_lifecycle: TIMEOUT closing server tunnel!");
            panic!("Timeout closing server tunnel");
        }
    };
    println!(
        "test_tunnel_manager_lifecycle: Server tunnel {} closed.",
        server_tunnel_id
    );

    // Verify all tunnels are closed
    assert_eq!(tunnel_manager.tunnel_count(), 0);
    println!("test_tunnel_manager_lifecycle: END");
}
