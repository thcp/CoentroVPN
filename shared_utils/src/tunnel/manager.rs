//! Tunnel management abstraction.
//!
//! This module provides a manager for handling multiple tunnels,
//! including creation, tracking, and cleanup.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

use crate::config::Config as GlobalConfig;
use crate::transport::Connection as TraitConnection; // Import the trait
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
        info!(manager_id = ?Arc::as_ptr(&self.tunnels), remote_addr = %remote_addr, "TunnelManager: create_client_tunnel - START");
        let mut config = TunnelConfig::new_client(remote_addr);
        if let Some(key) = psk {
            config = config.with_psk(key);
        }

        info!(manager_id = ?Arc::as_ptr(&self.tunnels), remote_addr = %remote_addr, "TunnelManager: create_client_tunnel - Bootstrapping client...");
        let handle = self.client_bootstrapper.bootstrap(config).await?;
        info!(manager_id = ?Arc::as_ptr(&self.tunnels), tunnel_id = %handle.id, "TunnelManager: create_client_tunnel - Client bootstrapped.");
        let id = handle.id.clone();
        self.add_tunnel(handle)?;
        info!(manager_id = ?Arc::as_ptr(&self.tunnels), tunnel_id = %id, "TunnelManager: create_client_tunnel - END");
        Ok(id)
    }

    /// Create a new server tunnel.
    pub async fn create_server_tunnel(
        &self,
        bind_addr: SocketAddr,
        psk: Option<Vec<u8>>,
    ) -> TunnelResult<TunnelId> {
        info!(manager_id = ?Arc::as_ptr(&self.tunnels), bind_addr = %bind_addr, "TunnelManager: create_server_tunnel - START");
        let mut config = TunnelConfig::new_server(bind_addr);
        if let Some(key) = psk {
            config = config.with_psk(key);
        }

        info!(manager_id = ?Arc::as_ptr(&self.tunnels), bind_addr = %bind_addr, "TunnelManager: create_server_tunnel - Bootstrapping server...");
        let handle = self.server_bootstrapper.bootstrap(config).await?;
        info!(manager_id = ?Arc::as_ptr(&self.tunnels), tunnel_id = %handle.id, "TunnelManager: create_server_tunnel - Server bootstrapped.");
        let id = handle.id.clone();
        self.add_tunnel(handle)?;
        info!(manager_id = ?Arc::as_ptr(&self.tunnels), tunnel_id = %id, "TunnelManager: create_server_tunnel - END");
        Ok(id)
    }

    /// Create a tunnel from global configuration.
    pub async fn create_tunnel_from_config(&self, config: &GlobalConfig) -> TunnelResult<TunnelId> {
        let tunnel_config = TunnelConfig::from_global_config(config)?;
        let handle = match tunnel_config.role {
            TunnelRole::Client => self.client_bootstrapper.bootstrap(tunnel_config).await?,
            TunnelRole::Server => self.server_bootstrapper.bootstrap(tunnel_config).await?,
        };
        let id = handle.id.clone();
        self.add_tunnel(handle)?;
        Ok(id)
    }

    /// Add a tunnel to the manager.
    fn add_tunnel(&self, handle: TunnelHandle) -> TunnelResult<()> {
        let id = handle.id.clone();
        if self.tunnels.lock().unwrap().contains_key(&id) {
            return Err(TunnelError::AlreadyExists(id.to_string()));
        }

        let handle_arc = Arc::new(Mutex::new(handle));
        self.tunnels
            .lock()
            .unwrap()
            .insert(id.clone(), handle_arc.clone());

        // Start processing task
        let task = self.start_tunnel_processing(id.clone(), handle_arc);
        self.tasks.lock().unwrap().insert(id.clone(), task);

        info!(tunnel_id = %id, "Added tunnel to manager");
        Ok(())
    }

    /// Start a task to process incoming data on a tunnel's connection.
    fn start_tunnel_processing(
        &self,
        id: TunnelId,
        handle_arc: Arc<Mutex<TunnelHandle>>,
    ) -> JoinHandle<()> {
        let tunnels_map_clone = self.tunnels.clone(); // Clone Arc for the task
        let tasks_map_clone = self.tasks.clone(); // Clone Arc for the task to remove itself

        tokio::spawn(async move {
            info!(tunnel_id = %id, "Starting tunnel data processing task");

            // We need to extract the connection from the handle to use it.
            // This is tricky because recv_data needs `&mut self`.
            // A better approach might be for the TunnelHandle itself to own the read loop
            // and expose a channel for received application data.
            // For now, let's try to make it work by taking the connection.
            // This implies a tunnel handle is for one connection lifecycle.

            let (connection_opt, is_listening) = {
                // Removed mut
                let mut handle_guard = handle_arc.lock().unwrap();
                // Check if this is a server tunnel in Listening state
                let is_listening =
                    handle_guard.state == TunnelState::Listening && handle_guard.listener.is_some();
                (handle_guard.connection.take(), is_listening) // Take ownership of the connection
            };

            // If this is a server tunnel in Listening state, we don't want to remove it
            // from the manager just because it doesn't have a connection yet
            if is_listening {
                info!(tunnel_id = %id, "Tunnel is in Listening state, keeping it in the manager");
                return; // Exit the task without removing the tunnel
            }

            if let Some(mut conn) = connection_opt {
                loop {
                    // Check if the task should terminate (e.g., tunnel being closed)
                    // This check is a bit indirect. If the tunnel is removed from `tunnels_map_clone`,
                    // it's a signal to stop. Or, if the handle's state changes to Disconnecting/Failed.
                    let current_state = handle_arc.lock().unwrap().state;
                    if matches!(
                        current_state,
                        TunnelState::Disconnecting
                            | TunnelState::Disconnected
                            | TunnelState::Failed
                    ) {
                        info!(tunnel_id = %id, state = ?current_state, "Stopping processing task due to tunnel state.");
                        break;
                    }

                    match conn.recv_data().await {
                        Ok(Some(data)) => {
                            debug!(tunnel_id = %id, data_len = data.len(), "Received data from transport");
                            let tx_channel = {
                                // Scope for lock
                                let mut handle_guard = handle_arc.lock().unwrap();
                                handle_guard.stats.record_bytes_received(data.len());
                                handle_guard.tx.clone() // tx is for sending data *to* the application
                            };

                            // Forward data to the application-side receiver of the tunnel
                            if let Err(e) = tx_channel.send(data).await {
                                error!(tunnel_id = %id, error = %e, "Failed to forward data to tunnel's application channel");
                                // This usually means the application side is no longer listening.
                                // We might want to close the connection then.
                                handle_arc.lock().unwrap().set_state(TunnelState::Failed);
                                break;
                            }
                        }
                        Ok(None) => {
                            info!(tunnel_id = %id, "Transport connection closed by peer (EOF)");
                            handle_arc
                                .lock()
                                .unwrap()
                                .set_state(TunnelState::Disconnected);
                            break;
                        }
                        Err(e) => {
                            error!(tunnel_id = %id, error = %e, "Transport error during recv_data");
                            handle_arc.lock().unwrap().set_state(TunnelState::Failed);
                            break;
                        }
                    }
                }
                // If the loop exited, try to gracefully close the connection if it wasn't already.
                // This is a best-effort, as `conn.close()` consumes `conn`.
                info!(tunnel_id = %id, "Attempting to close connection after processing loop.");
                if let Err(e) = conn.close().await {
                    warn!(tunnel_id = %id, error = %e, "Error during explicit close in processing task");
                }
            } else {
                warn!(tunnel_id = %id, "Tunnel processing task started without a connection.");
            }

            info!(tunnel_id = %id, "Tunnel data processing task completed");

            // Clean up: remove the tunnel and its task from the manager's tracking
            // This ensures that if the task ends (e.g. connection closed, error),
            // the manager doesn't keep a dead tunnel reference.
            tunnels_map_clone.lock().unwrap().remove(&id);
            tasks_map_clone.lock().unwrap().remove(&id);
            info!(tunnel_id = %id, "Tunnel and task removed from manager after processing.");
        })
    }

    /// Get a tunnel by ID.
    pub fn get_tunnel(&self, id: &TunnelId) -> Option<Arc<Mutex<TunnelHandle>>> {
        self.tunnels.lock().unwrap().get(id).cloned()
    }

    /// Send data through a tunnel.
    /// This now sends data directly over the transport::Connection.
    pub async fn send_data(&self, id: &TunnelId, data: Vec<u8>) -> TunnelResult<()> {
        let tunnel_handle_arc = self
            .get_tunnel(id)
            .ok_or_else(|| TunnelError::NotFound(id.to_string()))?;

        // Initial check for state and to take the connection
        let taken_connection = {
            let mut handle_guard = tunnel_handle_arc.lock().unwrap();
            if handle_guard.state != TunnelState::Connected {
                // If not connected, release lock and return error
                return Err(TunnelError::InvalidState(format!(
                    "Tunnel {} is not connected (state: {:?})",
                    id, handle_guard.state
                )));
            }
            // Take the connection out of the handle, releasing the lock implicitly afterwards
            handle_guard.connection.take()
        };

        if let Some(mut conn_box) = taken_connection {
            // The MutexGuard is dropped, so the lock is released.
            // Now, we can safely .await on the connection operation.
            let send_result = conn_box.send_data(&data).await;

            // Re-acquire the lock to put the connection back and update stats
            let mut handle_guard = tunnel_handle_arc.lock().unwrap();

            // Put the connection back into the handle.
            // It's important that `handle_guard.connection` is an Option type.
            handle_guard.connection = Some(conn_box);

            match send_result {
                Ok(_) => {
                    // If send was successful, update stats, but only if still connected.
                    // The state could have changed during the .await
                    if handle_guard.state == TunnelState::Connected {
                        handle_guard.stats.record_bytes_sent(data.len());
                    }
                    Ok(())
                }
                Err(e) => {
                    // If send failed, map to TunnelError::Transport
                    Err(TunnelError::Transport(e))
                }
            }
        } else {
            // Connection was None after state check, implies an issue or tunnel was modified.
            // This path is taken if `handle_guard.connection.take()` returned None.
            Err(TunnelError::NotConnected(id.to_string()))
        }
    }

    /// Close a tunnel.
    pub async fn close_tunnel(&self, id: &TunnelId) -> TunnelResult<()> {
        let tunnel_handle_arc = self
            .get_tunnel(id)
            .ok_or_else(|| TunnelError::NotFound(id.to_string()))?;

        let mut connection_to_close: Option<Box<dyn TraitConnection + Send + Sync>> = None;
        {
            // Scope for the lock
            let mut handle = tunnel_handle_arc.lock().unwrap();
            if handle.state != TunnelState::Disconnecting
                && handle.state != TunnelState::Disconnected
            {
                handle.set_state(TunnelState::Disconnecting);
                // Take the connection to close it outside the lock
                connection_to_close = handle.connection.take();
            }
        } // Lock released here

        if let Some(conn_box) = connection_to_close {
            info!(tunnel_id = %id, "TunnelManager: close_tunnel - Closing taken connection for tunnel. START_AWAIT");
            let close_result = conn_box.close().await;
            info!(tunnel_id = %id, "TunnelManager: close_tunnel - Closing taken connection for tunnel. END_AWAIT");
            if let Err(e) = close_result {
                error!(tunnel_id = %id, error = %e, "Error closing transport connection");
                // Even if close fails, proceed with cleanup
            }
        } else {
            info!(tunnel_id = %id, "TunnelManager: close_tunnel - No active connection to close or already disconnecting/disconnected.");
        }

        // Remove the tunnel from active tracking
        info!(tunnel_id = %id, "TunnelManager: close_tunnel - Removing tunnel from active tracking.");
        self.tunnels.lock().unwrap().remove(id);

        // Abort and remove the processing task
        if let Some(task) = self.tasks.lock().unwrap().remove(id) {
            info!(tunnel_id = %id, "Aborting tunnel processing task.");
            task.abort();
        }

        info!(tunnel_id = %id, "Tunnel closed and removed from manager.");
        Ok(())
    }

    pub fn get_all_tunnel_ids(&self) -> Vec<TunnelId> {
        self.tunnels.lock().unwrap().keys().cloned().collect()
    }

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
        let task_ids: Vec<TunnelId> = self.tasks.lock().unwrap().keys().cloned().collect();
        for id in task_ids {
            if let Some(task) = self.tasks.lock().unwrap().remove(&id) {
                info!(tunnel_id = %id, "Aborting tunnel processing task during TunnelManager drop");
                task.abort();
            }
        }
        self.tunnels.lock().unwrap().clear();
        info!("TunnelManager dropped, all tasks aborted and tunnels cleared.");
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
}
