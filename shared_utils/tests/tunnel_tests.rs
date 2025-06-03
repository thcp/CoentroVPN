use shared_utils::tunnel::{
    ClientBootstrapper, ServerBootstrapper, TunnelBootstrapper, TunnelConfig, TunnelManager,
    TunnelResult, TunnelRole, TunnelState,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::time::sleep;

#[tokio::test]
async fn test_tunnel_config_validation() {
    // Test client config without remote_addr
    let config = TunnelConfig::default();
    let result = config.validate();
    assert!(result.is_err());
    
    // Test server config without bind_addr
    let config = TunnelConfig {
        role: TunnelRole::Server,
        ..TunnelConfig::default()
    };
    let result = config.validate();
    assert!(result.is_err());
    
    // Test config without security credentials
    let config = TunnelConfig::new_client(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        8080,
    ));
    let result = config.validate();
    assert!(result.is_err());
    
    // Test valid client config
    let config = TunnelConfig::new_client(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        8080,
    ))
    .with_psk(vec![0; 32]);
    let result = config.validate();
    assert!(result.is_ok());
    
    // Test valid server config
    let config = TunnelConfig::new_server(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        8080,
    ))
    .with_psk(vec![0; 32]);
    let result = config.validate();
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_tunnel_manager_creation() {
    let manager = TunnelManager::new();
    assert_eq!(manager.tunnel_count(), 0);
    assert!(manager.get_all_tunnel_ids().is_empty());
}

// This test requires a running server to connect to, so we'll mark it as ignored
// In a real test suite, we would use mocks or a test server
#[tokio::test]
#[ignore]
async fn test_client_tunnel_creation() {
    let manager = TunnelManager::new();
    
    // Create a client tunnel
    let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
    let psk = Some(vec![0; 32]);
    
    let result = manager.create_client_tunnel(remote_addr, psk).await;
    
    // This will likely fail since there's no server running
    assert!(result.is_err());
}

// This test creates a server tunnel and then tries to connect to it with a client
// It's a more comprehensive E2E test
#[tokio::test]
#[ignore]
async fn test_tunnel_e2e() -> TunnelResult<()> {
    // Generate a shared key
    let psk = vec![0; 32]; // In a real test, use a proper key
    
    // Create server tunnel
    let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0); // Use port 0 to get a random available port
    let server_bootstrapper = ServerBootstrapper::new();
    
    let server_config = TunnelConfig::new_server(server_addr)
        .with_psk(psk.clone());
    
    let mut server_handle = server_bootstrapper.bootstrap(server_config).await?;
    
    // Get the actual bound address
    let bound_addr = server_handle.peer_or_listen_addr; // Changed from remote_addr
    println!("Server bound to {}", bound_addr);
    
    // Wait a moment for the server to start
    sleep(Duration::from_millis(100)).await;
    
    // Create client tunnel
    let client_bootstrapper = ClientBootstrapper::new();
    
    let client_config = TunnelConfig::new_client(bound_addr)
        .with_psk(psk.clone());
    
    let mut client_handle = client_bootstrapper.bootstrap(client_config).await?;
    
    // Wait a moment for the connection to establish
    sleep(Duration::from_millis(100)).await;
    
    // Check that both tunnels are connected
    assert_eq!(
        client_handle.state,
        TunnelState::Connected
    );
    
    // Send a test message from client to server
    let _test_message = b"Hello, CoentroVPN!".to_vec();
    
    // In a real test, we would send the message and verify it was received
    // For now, just check that we have the channels
    // The tx and rx are not Options, they're directly accessible
    assert!(client_handle.tx.capacity() > 0);
    assert!(server_handle.rx.capacity() > 0);
    
    // Clean up
    if let Some(conn_box) = client_handle.connection.take() {
        conn_box.close().await?;
    }
    
    if let Some(conn_box) = server_handle.connection.take() {
        conn_box.close().await?;
    }
    
    Ok(())
}
