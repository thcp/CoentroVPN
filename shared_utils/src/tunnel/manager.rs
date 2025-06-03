//! Tunnel management abstraction.
//!
//! This module provides a manager for handling multiple tunnels,
//! including creation, tracking, and cleanup.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::task::JoinHandle;
use tracing::{debug, error, info};

use crate::config::Config as GlobalConfig;
use crate::tunnel::bootstrap::{
    ClientBootstrapper, ServerBootstrapper, TunnelBootstrapper, TunnelHandle,
};
use crate::tunnel::config::TunnelConfig;
use crate::tunnel::error::{TunnelError, TunnelResult};
use crate::tunnel::types::{TunnelId, TunnelRole, TunnelState};

/// Manager for handling multiple tunnels.
pub struct TunnelManager {
    /// Active tunnels
    tunnels: Arc<Mutex<HashMap<TunnelId, Arc<Mutex<TunnelHandle>>>>>,
    
    /// Task handles for tunnel processing
    tasks: Arc<Mutex<HashMap<TunnelId, JoinHandle<()>>>>,
    
    /// Client bootstrapper
    client_bootstrapper: ClientBootstrapper,
    
    /// Server bootstrapper
    server_bootstrapper: ServerBootstrapper,
}

impl TunnelManager {
    /// Create a new tunnel manager.
    pub fn new() -> Self {
        TunnelManager {
            tunnels: Arc::new(Mutex::new(HashMap::new())),
            tasks: Arc::new(Mutex::new(HashMap::new())),
            client_bootstrapper: ClientBootstrapper::new(),
            server_bootstrapper: ServerBootstrapper::new(),
        }
    }
    
    /// Create a new client tunnel.
    pub async fn create_client_tunnel(
        &self,
        remote_addr: SocketAddr,
        psk: Option<Vec<u8>>,
    ) -> TunnelResult<TunnelId> {
        // Create tunnel configuration
        let mut config = TunnelConfig::new_client(remote_addr);
        if let Some(key) = psk {
            config = config.with_psk(key);
        }
        
        // Bootstrap the tunnel
        let handle = self.client_bootstrapper.bootstrap(config).await?;
        let id = handle.id.clone();
        
        // Store the tunnel
        self.add_tunnel(handle)?;
        
        Ok(id)
    }
    
    /// Create a new server tunnel.
    pub async fn create_server_tunnel(
        &self,
        bind_addr: SocketAddr,
        psk: Option<Vec<u8>>,
    ) -> TunnelResult<TunnelId> {
        // Create tunnel configuration
        let mut config = TunnelConfig::new_server(bind_addr);
        if let Some(key) = psk {
            config = config.with_psk(key);
        }
        
        // Bootstrap the tunnel
        let handle = self.server_bootstrapper.bootstrap(config).await?;
        let id = handle.id.clone();
        
        // Store the tunnel
        self.add_tunnel(handle)?;
        
        Ok(id)
    }
    
    /// Create a tunnel from global configuration.
    pub async fn create_tunnel_from_config(&self, config: &GlobalConfig) -> TunnelResult<TunnelId> {
        // Convert global config to tunnel config
        let tunnel_config = TunnelConfig::from_global_config(config)?;
        
        // Bootstrap the tunnel based on role
        let handle = match tunnel_config.role {
            TunnelRole::Client => self.client_bootstrapper.bootstrap(tunnel_config).await?,
            TunnelRole::Server => self.server_bootstrapper.bootstrap(tunnel_config).await?,
        };
        
        let id = handle.id.clone();
        
        // Store the tunnel
        self.add_tunnel(handle)?;
        
        Ok(id)
    }
    
    /// Add a tunnel to the manager.
    fn add_tunnel(&self, handle: TunnelHandle) -> TunnelResult<()> {
        let id = handle.id.clone();
        
        // Check if tunnel already exists
        if self.tunnels.lock().unwrap().contains_key(&id) {
            return Err(TunnelError::AlreadyExists(id.to_string()));
        }
        
        // Wrap handle in Arc<Mutex<>>
        let handle = Arc::new(Mutex::new(handle));
        
        // Store the tunnel
        self.tunnels.lock().unwrap().insert(id.clone(), handle.clone());
        
        // Start processing task
        let task = self.start_tunnel_processing(id.clone(), handle);
        self.tasks.lock().unwrap().insert(id.clone(), task);
        
        info!(tunnel_id = %id, "Added tunnel to manager");
        
        Ok(())
    }
    
    /// Start a task to process tunnel messages.
    fn start_tunnel_processing(
        &self,
        id: TunnelId,
        handle: Arc<Mutex<TunnelHandle>>,
    ) -> JoinHandle<()> {
        let tunnels = self.tunnels.clone();
        
        tokio::spawn(async move {
            info!(tunnel_id = %id, "Starting tunnel processing task");
            
            // Get transport_rx from handle
            let transport_rx = {
                let mut handle = handle.lock().unwrap();
                handle.transport_rx.take()
            };
            
            // If we have a transport receiver, process messages
            if let Some(mut rx) = transport_rx {
                while let Some(message) = rx.recv().await {
                    match message {
                        crate::quic::TransportMessage::Data(data) => {
                            debug!(tunnel_id = %id, data_len = data.len(), "Received data from transport");
                            
                            // Update stats
                            {
                                let mut handle = handle.lock().unwrap();
                                handle.stats.record_bytes_received(data.len());
                            }
                            
                            // Forward data to tunnel's rx channel
                            // In a real implementation, we would process the data through framing
                            // and encryption layers before forwarding
                            let tx = {
                                let handle = handle.lock().unwrap();
                                handle.tx.clone()
                            };
                            
                            if let Err(e) = tx.send(data).await {
                                error!(tunnel_id = %id, error = %e, "Failed to forward data to tunnel channel");
                            }
                        }
                        crate::quic::TransportMessage::StreamClosed => {
                            info!(tunnel_id = %id, "Stream closed");
                        }
                        crate::quic::TransportMessage::ConnectionClosed => {
                            info!(tunnel_id = %id, "Connection closed");
                            
                            // Update state
                            {
                                let mut handle = handle.lock().unwrap();
                                handle.set_state(TunnelState::Disconnected);
                            }
                            
                            // In a real implementation, we might try to reconnect here
                            // if the tunnel is configured for auto-reconnect
                            break;
                        }
                        crate::quic::TransportMessage::Error(e) => {
                            error!(tunnel_id = %id, error = %e, "Transport error");
                            
                            // Update state
                            {
                                let mut handle = handle.lock().unwrap();
                                handle.set_state(TunnelState::Failed);
                            }
                            
                            break;
                        }
                    }
                }
            }
            
            info!(tunnel_id = %id, "Tunnel processing task completed");
            
            // Remove the tunnel from the manager
            tunnels.lock().unwrap().remove(&id);
        })
    }
    
    /// Get a tunnel by ID.
    pub fn get_tunnel(&self, id: &TunnelId) -> Option<Arc<Mutex<TunnelHandle>>> {
        self.tunnels.lock().unwrap().get(id).cloned()
    }
    
    /// Send data through a tunnel.
    pub async fn send_data(&self, id: &TunnelId, data: Vec<u8>) -> TunnelResult<()> {
        // Get the tunnel
        let tunnel = self.get_tunnel(id).ok_or_else(|| {
            TunnelError::NotFound(id.to_string())
        })?;
        
        // Get the sender
        let tx = {
            let handle = tunnel.lock().unwrap();
            
            // Check tunnel state
            if handle.state != TunnelState::Connected {
                return Err(TunnelError::InvalidState(format!(
                    "Tunnel {} is not connected (state: {:?})",
                    id, handle.state
                )));
            }
            
            handle.tx.clone()
        };
        
        // Send the data
        tx.send(data.clone()).await.map_err(|_| {
            TunnelError::Closed
        })?;
        
        // Update stats
        {
            let mut handle = tunnel.lock().unwrap();
            handle.stats.record_bytes_sent(data.len());
        }
        
        Ok(())
    }
    
    /// Close a tunnel.
    pub async fn close_tunnel(&self, id: &TunnelId) -> TunnelResult<()> {
        // Get the tunnel
        let tunnel = self.get_tunnel(id).ok_or_else(|| {
            TunnelError::NotFound(id.to_string())
        })?;
        
        // Update state and get connection
        let connection = {
            let mut handle = tunnel.lock().unwrap();
            handle.set_state(TunnelState::Disconnecting);
            handle.connection.take()
        };
        
        // Close the connection if we have one
        if let Some(conn) = connection {
            // In a real implementation, we would send a close frame
            // For now, just close the connection
            conn.close(0u32.into(), b"Tunnel closed by manager");
        }
        
        // Remove the tunnel from the manager
        self.tunnels.lock().unwrap().remove(id);
        
        // Cancel the processing task
        if let Some(task) = self.tasks.lock().unwrap().remove(id) {
            task.abort();
        }
        
        info!(tunnel_id = %id, "Tunnel closed");
        
        Ok(())
    }
    
    /// Get all tunnel IDs.
    pub fn get_all_tunnel_ids(&self) -> Vec<TunnelId> {
        self.tunnels
            .lock()
            .unwrap()
            .keys()
            .cloned()
            .collect()
    }
    
    /// Get the number of active tunnels.
    pub fn tunnel_count(&self) -> usize {
        self.tunnels.lock().unwrap().len()
    }
}

impl Default for TunnelManager {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for TunnelManager {
    fn drop(&mut self) {
        // Cancel all processing tasks
        for (id, task) in self.tasks.lock().unwrap().iter() {
            info!(tunnel_id = %id, "Aborting tunnel processing task");
            task.abort();
        }
        
        // Clear tasks
        self.tasks.lock().unwrap().clear();
        
        // Clear tunnels
        self.tunnels.lock().unwrap().clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_tunnel_manager_creation() {
        let manager = TunnelManager::new();
        assert_eq!(manager.tunnel_count(), 0);
    }
    
    // Note: More comprehensive tests would require mocking the QUIC transport
    // which is beyond the scope of this implementation
}
