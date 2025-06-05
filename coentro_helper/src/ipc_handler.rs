//! IPC Handler for the CoentroVPN Helper Daemon
//!
//! This module handles IPC connections and requests from the client.

use coentro_ipc::messages::{ClientRequest, HelperResponse, StatusDetails};
use coentro_ipc::transport::{AuthConfig, IpcResult, UnixSocketConnection, UnixSocketListener};
use log::{debug, error, info};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use tokio::sync::{mpsc, oneshot};

/// IPC Handler for the helper daemon
pub struct IpcHandler {
    /// Active client connections
    active_clients: Arc<Mutex<HashMap<u32, ClientState>>>,
    /// Helper daemon version
    version: String,
}

/// State for an active client
#[derive(Clone)]
struct ClientState {
    /// Client process ID (for logging/debugging)
    pid: u32,
    /// Whether the client has an active tunnel
    tunnel_active: bool,
    /// Name of the active interface, if any
    active_interface: Option<String>,
    /// Current IP configuration, if any
    current_ip_config: Option<String>,
}

impl IpcHandler {
    /// Create a new IPC handler
    pub fn new() -> Self {
        Self {
            active_clients: Arc::new(Mutex::new(HashMap::new())),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    /// Run the IPC handler
    pub async fn run<P: AsRef<Path>>(
        &self,
        socket_path: P,
        mut shutdown_rx: oneshot::Receiver<()>,
        allowed_uids: Vec<u32>,
    ) -> anyhow::Result<()> {
        // Create an authentication configuration
        let mut auth_config = AuthConfig::new().allow_root(true); // Allow root by default

        // If SUDO_UID is set, allow the original user
        if let Ok(uid) = std::env::var("SUDO_UID") {
            if let Ok(uid) = uid.parse::<u32>() {
                debug!("Allowing UID {} (from SUDO_UID)", uid);
                auth_config = auth_config.allow_uid(uid);
            }
        }

        // Allow UIDs from configuration
        for uid in allowed_uids {
            debug!("Allowing UID {} (from configuration)", uid);
            auth_config = auth_config.allow_uid(uid);
        }

        // Create the Unix Domain Socket listener with authentication
        let listener = UnixSocketListener::bind_with_auth(&socket_path, auth_config)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to bind to socket: {}", e))?;

        info!(
            "IPC handler listening on {}",
            socket_path.as_ref().display()
        );

        // Channel for client tasks to signal completion
        let (client_done_tx, mut client_done_rx) = mpsc::channel::<u32>(10);

        // Set of active client tasks
        let mut client_tasks = HashMap::new();

        loop {
            tokio::select! {
                // Accept a new connection
                accept_result = listener.accept() => {
                    match accept_result {
                        Ok(connection) => {
                            // Get the client ID from the peer credentials
                            let client_id = connection.peer_uid();
                            info!("Accepted connection from client ID={} (UID={})", client_id, client_id);

                            // Create a new client state
                            let client_state = ClientState {
                                pid: client_id,
                                tunnel_active: false,
                                active_interface: None,
                                current_ip_config: None,
                            };

                            // Store the client state
                            {
                                let mut active_clients = self.active_clients.lock().unwrap();
                                active_clients.insert(client_id, client_state);
                            }

                            // Clone necessary data for the client task
                            let active_clients = Arc::clone(&self.active_clients);
                            let client_done_tx = client_done_tx.clone();
                            let version = self.version.clone();

                            // Spawn a task to handle the client
                            let handle = tokio::spawn(async move {
                                if let Err(e) = Self::handle_client(
                                    connection,
                                    client_id,
                                    active_clients,
                                    version,
                                ).await {
                                    error!("Error handling client ID={}: {}", client_id, e);
                                }

                                // Signal that the client task is done
                                if let Err(e) = client_done_tx.send(client_id).await {
                                    error!("Failed to send client done signal: {}", e);
                                }
                            });

                            // Store the client task handle
                            client_tasks.insert(client_id, handle);
                        },
                        Err(e) => {
                            error!("Failed to accept connection: {}", e);
                        }
                    }
                },

                // Handle client task completion
                Some(client_id) = client_done_rx.recv() => {
                    debug!("Client ID={} task completed", client_id);

                    // Remove the client state
                    {
                        let mut active_clients = self.active_clients.lock().unwrap();
                        active_clients.remove(&client_id);
                    }

                    // Remove the client task handle
                    client_tasks.remove(&client_id);
                },

                // Handle shutdown signal
                _ = &mut shutdown_rx => {
                    info!("Received shutdown signal, closing IPC handler");
                    break;
                }
            }
        }

        // Wait for all client tasks to complete
        for (id, handle) in client_tasks {
            debug!("Waiting for client ID={} task to complete", id);
            if let Err(e) = handle.await {
                error!("Error waiting for client ID={} task to complete: {}", id, e);
            }
        }

        info!("IPC handler shut down");
        Ok(())
    }

    /// Handle a client connection
    async fn handle_client(
        mut connection: UnixSocketConnection,
        client_id: u32,
        active_clients: Arc<Mutex<HashMap<u32, ClientState>>>,
        version: String,
    ) -> anyhow::Result<()> {
        let peer_uid = connection.peer_uid();
        let peer_gid = connection.peer_gid();
        debug!(
            "Handling client ID={} (UID={}, GID={})",
            client_id, peer_uid, peer_gid
        );

        loop {
            // Receive a request from the client
            let request = match connection.receive_request().await {
                Ok(req) => req,
                Err(e) => {
                    // If the client disconnected, just return
                    if let coentro_ipc::transport::IpcError::Io(io_err) = &e {
                        if io_err.kind() == std::io::ErrorKind::UnexpectedEof {
                            debug!("Client ID={} disconnected", client_id);
                            return Ok(());
                        }
                    }
                    error!(
                        "Error receiving request from client ID={}: {}",
                        client_id, e
                    );
                    return Err(anyhow::anyhow!("Failed to receive request: {}", e));
                }
            };

            debug!(
                "Received request from client ID={}: {:?}",
                client_id, request
            );

            // Process the request
            let response = match request {
                ClientRequest::Ping => {
                    debug!("Responding to ping from client ID={}", client_id);
                    HelperResponse::Pong
                }
                ClientRequest::GetStatus => {
                    debug!("Responding to status request from client ID={}", client_id);

                    // Get the client state
                    let client_state = {
                        let active_clients = active_clients.lock().unwrap();
                        active_clients.get(&client_id).cloned()
                    };

                    if let Some(state) = client_state {
                        HelperResponse::StatusReport(StatusDetails {
                            tunnel_active: state.tunnel_active,
                            active_interface: state.active_interface,
                            current_ip_config: state.current_ip_config,
                            helper_version: version.clone(),
                        })
                    } else {
                        HelperResponse::Error("Client state not found".to_string())
                    }
                }
                ClientRequest::SetupTunnel(_) => {
                    // In Sprint 1, we're just implementing the basic IPC framework
                    // Actual tunnel setup will be implemented in Sprint 2
                    debug!("Tunnel setup not implemented yet");
                    HelperResponse::Error("Tunnel setup not implemented yet".to_string())
                }
                ClientRequest::TeardownTunnel => {
                    // In Sprint 1, we're just implementing the basic IPC framework
                    // Actual tunnel teardown will be implemented in Sprint 2
                    debug!("Tunnel teardown not implemented yet");
                    HelperResponse::Error("Tunnel teardown not implemented yet".to_string())
                }
            };

            // Send the response to the client
            if let Err(e) = connection.send_response(&response).await {
                error!("Error sending response to client ID={}: {}", client_id, e);
                return Err(anyhow::anyhow!("Failed to send response: {}", e));
            }
        }
    }
}
