//! IPC Handler for the CoentroVPN Helper Daemon
//!
//! This module handles IPC connections and requests from the client.

use crate::network_manager::{create_network_manager, TunConfig};
use coentro_ipc::messages::{
    ClientRequest, HelperResponse, StatusDetails, TunnelReadyDetails, TunnelSetupRequest,
};
use coentro_ipc::transport::{AuthConfig, UnixSocketConnection, UnixSocketListener};
use governor::{Quota, RateLimiter};
use log::{debug, error, info, warn};
use std::collections::HashMap;
use std::num::NonZeroU32;
use std::os::unix::io::RawFd;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

/// Get the group ID (GID) for a given group name
/// Returns None if the group doesn't exist
fn get_group_id(group_name: &str) -> Option<u32> {
    #[cfg(unix)]
    {
        // Try to get the group entry
        unsafe {
            let group_entry = libc::getgrnam(std::ffi::CString::new(group_name).ok()?.as_ptr());
            if group_entry.is_null() {
                return None;
            }
            Some((*group_entry).gr_gid)
        }
    }

    #[cfg(not(unix))]
    {
        // On non-Unix platforms, just return None
        let _ = group_name; // Suppress unused variable warning
        None
    }
}

/// IPC Handler for the helper daemon
pub struct IpcHandler {
    /// Active client connections
    active_clients: Arc<Mutex<HashMap<u32, ClientState>>>,
    /// Helper daemon version
    version: String,
}

/// Rate limit configuration
const RATE_LIMIT_REQUESTS: u32 = 30; // Maximum number of requests
const RATE_LIMIT_PERIOD: u64 = 60; // Period in seconds

/// State for an active client
#[derive(Clone)]
struct ClientState {
    /// Client process ID (for logging/debugging)
    #[allow(dead_code)]
    pid: u32,
    /// Whether the client has an active tunnel
    tunnel_active: bool,
    /// Name of the active interface, if any
    active_interface: Option<String>,
    /// Current IP configuration, if any
    current_ip_config: Option<String>,
    /// File descriptor for the TUN device, if any
    tun_fd: Option<i32>,
    /// Rate limiter for this client
    #[allow(dead_code)] // Clone trait requires this, but we use Arc internally
    rate_limiter: Arc<
        RateLimiter<
            governor::state::NotKeyed,
            governor::state::InMemoryState,
            governor::clock::DefaultClock,
        >,
    >,
}

impl IpcHandler {
    /// Sanitize error messages to prevent information leakage
    fn sanitize_error_message(error_msg: &str) -> String {
        // Check for common patterns that might contain sensitive information
        if error_msg.contains("Permission denied") {
            return "Operation not permitted due to insufficient privileges".to_string();
        } else if error_msg.contains("/etc")
            || error_msg.contains("/var")
            || error_msg.contains("/usr")
        {
            return "System configuration error".to_string();
        } else if error_msg.contains("No such file") || error_msg.contains("not found") {
            return "Required resource not available".to_string();
        } else if error_msg.contains("Device") || error_msg.contains("interface") {
            return "Network device error".to_string();
        } else if error_msg.contains("route") || error_msg.contains("routing") {
            return "Routing configuration error".to_string();
        } else if error_msg.contains("DNS") || error_msg.contains("resolv.conf") {
            return "DNS configuration error".to_string();
        } else if error_msg.contains("Invalid") || error_msg.contains("invalid") {
            // Keep validation errors as they are generally safe and helpful
            return error_msg.to_string();
        }

        // Default generic error message
        "Operation failed due to a system error".to_string()
    }

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
        allowed_gids: Option<Vec<u32>>,
    ) -> anyhow::Result<()> {
        // Ensure the socket directory exists with correct permissions
        if let Some(parent) = socket_path.as_ref().parent() {
            if !parent.exists() {
                info!("Creating socket directory: {}", parent.display());
                std::fs::create_dir_all(parent)
                    .map_err(|e| anyhow::anyhow!("Failed to create socket directory: {}", e))?;

                // Set directory permissions to 755 (rwxr-xr-x)
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let metadata = std::fs::metadata(parent)
                        .map_err(|e| anyhow::anyhow!("Failed to get directory metadata: {}", e))?;
                    let mut permissions = metadata.permissions();
                    permissions.set_mode(0o755); // rwxr-xr-x
                    std::fs::set_permissions(parent, permissions).map_err(|e| {
                        anyhow::anyhow!("Failed to set directory permissions: {}", e)
                    })?;
                }
            }
        }

        // Get the current user's UID
        let current_uid = unsafe { libc::getuid() };
        info!("Helper daemon running as UID={}", current_uid);

        // Create an authentication configuration
        let mut auth_config = AuthConfig::new().allow_root(true); // Allow root by default

        // If SUDO_UID is set, allow the original user
        if let Ok(uid) = std::env::var("SUDO_UID") {
            if let Ok(uid) = uid.parse::<u32>() {
                info!("Allowing UID {} (from SUDO_UID)", uid);
                auth_config = auth_config.allow_uid(uid);
            }
        } else {
            // If not running with sudo, allow the current user
            info!(
                "Allowing current UID {} (not running with sudo)",
                current_uid
            );
            auth_config = auth_config.allow_uid(current_uid);
        }

        // Allow UIDs from configuration
        for uid in allowed_uids {
            info!("Allowing UID {} (from configuration)", uid);
            auth_config = auth_config.allow_uid(uid);
        }

        // Get the current user's GID
        let current_gid = unsafe { libc::getgid() };
        info!("Helper daemon running with GID={}", current_gid);

        // If SUDO_GID is set, allow the original user's group
        if let Ok(gid) = std::env::var("SUDO_GID") {
            if let Ok(gid) = gid.parse::<u32>() {
                info!("Allowing GID {} (from SUDO_GID)", gid);
                auth_config = auth_config.allow_gid(gid);
            }
        } else {
            // If not running with sudo, allow the current user's group
            info!(
                "Allowing current GID {} (not running with sudo)",
                current_gid
            );
            auth_config = auth_config.allow_gid(current_gid);
        }

        // Allow GIDs from configuration
        if let Some(gids) = allowed_gids {
            for gid in gids {
                info!("Allowing GID {} (from configuration)", gid);
                auth_config = auth_config.allow_gid(gid);
            }
        }

        // Try to create a dedicated group for the socket
        // This is a common group name for VPN-related operations
        let vpn_group_name = "coentrovpn";
        let _vpn_group_gid = match get_group_id(vpn_group_name) {
            Some(gid) => {
                info!("Found existing group '{}' with GID={}", vpn_group_name, gid);
                auth_config = auth_config.allow_gid(gid);
                Some(gid)
            }
            None => {
                info!(
                    "Group '{}' not found, socket will use default group",
                    vpn_group_name
                );
                None
            }
        };

        // Create the Unix Domain Socket listener with authentication
        info!(
            "Creating socket with permissions 660 (rw-rw----) at {}",
            socket_path.as_ref().display()
        );
        let listener = UnixSocketListener::bind_with_auth(&socket_path, auth_config)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to bind to socket: {}", e))?;

        // Set socket permissions to 660 (rw-rw----)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = std::fs::metadata(socket_path.as_ref())
                .map_err(|e| anyhow::anyhow!("Failed to get socket metadata: {}", e))?;
            let mut permissions = metadata.permissions();
            permissions.set_mode(0o660); // rw-rw----
            std::fs::set_permissions(socket_path.as_ref(), permissions)
                .map_err(|e| anyhow::anyhow!("Failed to set socket permissions: {}", e))?;
        }

        // If we found a dedicated VPN group, set the socket's group ownership
        #[cfg(unix)]
        if let Some(gid) = _vpn_group_gid {
            use std::os::unix::fs::chown;
            info!(
                "Setting socket group ownership to GID={} ({})",
                gid, vpn_group_name
            );
            if let Err(e) = chown(socket_path.as_ref(), None, Some(gid)) {
                warn!("Failed to set socket group ownership: {}", e);
            }
        }

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

                // Create a rate limiter for the client
                // Allow RATE_LIMIT_REQUESTS requests per RATE_LIMIT_PERIOD seconds
                let quota = Quota::with_period(Duration::from_secs(RATE_LIMIT_PERIOD))
                    .expect("Failed to create rate limit period")
                    .allow_burst(NonZeroU32::new(RATE_LIMIT_REQUESTS).expect("Failed to create rate limit burst"));

                let rate_limiter = Arc::new(RateLimiter::direct(quota));

                // Create a new client state
                let client_state = ClientState {
                    pid: client_id,
                    tunnel_active: false,
                    active_interface: None,
                    current_ip_config: None,
                    tun_fd: None,
                    rate_limiter,
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
                    info!("Client ID={} task completed, checking for cleanup", client_id);

                    // Check if the client had an active tunnel
                    let client_state = {
                        let active_clients = self.active_clients.lock().unwrap();
                        active_clients.get(&client_id).cloned()
                    };

                    if let Some(state) = client_state {
                        if state.tunnel_active {
                            if let Some(interface_name) = &state.active_interface {
                                info!("Client ID={} disconnected with active tunnel on interface {}, performing automatic cleanup", client_id, interface_name);

                                // Create a network manager
                                let network_manager = create_network_manager();

                                // Attempt to destroy the TUN interface
                                match network_manager.destroy_tun(interface_name).await {
                                    Ok(()) => info!("Successfully cleaned up TUN interface {} for disconnected client ID={}", interface_name, client_id),
                                    Err(e) => error!("Failed to clean up TUN interface {} for disconnected client ID={}: {}", interface_name, client_id, e),
                                }
                            } else {
                                warn!("Client ID={} had active tunnel but no interface name", client_id);
                            }
                        } else {
                            debug!("Client ID={} had no active tunnel, no cleanup needed", client_id);
                        }
                    } else {
                        warn!("Client ID={} state not found", client_id);
                    }

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

    /// Run the IPC handler with a pre-existing socket file descriptor (for launchd socket activation)
    pub async fn run_with_socket_fd(
        &self,
        socket_fd: RawFd,
        mut shutdown_rx: oneshot::Receiver<()>,
        allowed_uids: Vec<u32>,
        allowed_gids: Option<Vec<u32>>,
    ) -> anyhow::Result<()> {
        // Get the current user's UID
        let current_uid = unsafe { libc::getuid() };
        info!("Helper daemon running as UID={}", current_uid);

        // Create an authentication configuration
        let mut auth_config = AuthConfig::new().allow_root(true); // Allow root by default

        // If SUDO_UID is set, allow the original user
        if let Ok(uid) = std::env::var("SUDO_UID") {
            if let Ok(uid) = uid.parse::<u32>() {
                info!("Allowing UID {} (from SUDO_UID)", uid);
                auth_config = auth_config.allow_uid(uid);
            }
        } else {
            // If not running with sudo, allow the current user
            info!(
                "Allowing current UID {} (not running with sudo)",
                current_uid
            );
            auth_config = auth_config.allow_uid(current_uid);
        }

        // Allow UIDs from configuration
        for uid in allowed_uids {
            info!("Allowing UID {} (from configuration)", uid);
            auth_config = auth_config.allow_uid(uid);
        }

        // Get the current user's GID
        let current_gid = unsafe { libc::getgid() };
        info!("Helper daemon running with GID={}", current_gid);

        // If SUDO_GID is set, allow the original user's group
        if let Ok(gid) = std::env::var("SUDO_GID") {
            if let Ok(gid) = gid.parse::<u32>() {
                info!("Allowing GID {} (from SUDO_GID)", gid);
                auth_config = auth_config.allow_gid(gid);
            }
        } else {
            // If not running with sudo, allow the current user's group
            info!(
                "Allowing current GID {} (not running with sudo)",
                current_gid
            );
            auth_config = auth_config.allow_gid(current_gid);
        }

        // Allow GIDs from configuration
        if let Some(gids) = allowed_gids {
            for gid in gids {
                info!("Allowing GID {} (from configuration)", gid);
                auth_config = auth_config.allow_gid(gid);
            }
        }

        // Try to create a dedicated group for the socket
        // This is a common group name for VPN-related operations
        let vpn_group_name = "coentrovpn";
        let _vpn_group_gid = match get_group_id(vpn_group_name) {
            Some(gid) => {
                info!("Found existing group '{}' with GID={}", vpn_group_name, gid);
                auth_config = auth_config.allow_gid(gid);
                Some(gid)
            }
            None => {
                info!(
                    "Group '{}' not found, socket will use default group",
                    vpn_group_name
                );
                None
            }
        };

        // Create the Unix Domain Socket listener with authentication from the existing socket
        info!("Using socket provided by launchd (fd: {})", socket_fd);
        let listener = UnixSocketListener::from_raw_fd_with_auth(socket_fd, auth_config)
            .map_err(|e| anyhow::anyhow!("Failed to create listener from socket fd: {}", e))?;

        info!("IPC handler listening on socket provided by launchd");

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

                // Create a rate limiter for the client
                // Allow RATE_LIMIT_REQUESTS requests per RATE_LIMIT_PERIOD seconds
                let quota = Quota::with_period(Duration::from_secs(RATE_LIMIT_PERIOD))
                    .expect("Failed to create rate limit period")
                    .allow_burst(NonZeroU32::new(RATE_LIMIT_REQUESTS).expect("Failed to create rate limit burst"));

                let rate_limiter = Arc::new(RateLimiter::direct(quota));

                // Create a new client state
                let client_state = ClientState {
                    pid: client_id,
                    tunnel_active: false,
                    active_interface: None,
                    current_ip_config: None,
                    tun_fd: None,
                    rate_limiter,
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
                    info!("Client ID={} task completed, checking for cleanup", client_id);

                    // Check if the client had an active tunnel
                    let client_state = {
                        let active_clients = self.active_clients.lock().unwrap();
                        active_clients.get(&client_id).cloned()
                    };

                    if let Some(state) = client_state {
                        if state.tunnel_active {
                            if let Some(interface_name) = &state.active_interface {
                                info!("Client ID={} disconnected with active tunnel on interface {}, performing automatic cleanup", client_id, interface_name);

                                // Create a network manager
                                let network_manager = create_network_manager();

                                // Attempt to destroy the TUN interface
                                match network_manager.destroy_tun(interface_name).await {
                                    Ok(()) => info!("Successfully cleaned up TUN interface {} for disconnected client ID={}", interface_name, client_id),
                                    Err(e) => error!("Failed to clean up TUN interface {} for disconnected client ID={}: {}", interface_name, client_id, e),
                                }
                            } else {
                                warn!("Client ID={} had active tunnel but no interface name", client_id);
                            }
                        } else {
                            debug!("Client ID={} had no active tunnel, no cleanup needed", client_id);
                        }
                    } else {
                        warn!("Client ID={} state not found", client_id);
                    }

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

    /// Set up a tunnel for a client
    async fn setup_tunnel(
        client_id: u32,
        setup: TunnelSetupRequest,
        active_clients: Arc<Mutex<HashMap<u32, ClientState>>>,
    ) -> anyhow::Result<TunnelReadyDetails> {
        // Validate the request parameters
        if let Err(validation_error) = setup.validate() {
            return Err(anyhow::anyhow!(
                "Invalid request parameters: {}",
                validation_error
            ));
        }

        // Check if the client already has an active tunnel
        let client_state = {
            let active_clients = active_clients.lock().unwrap();
            active_clients.get(&client_id).cloned()
        };

        if let Some(state) = client_state {
            if state.tunnel_active {
                return Err(anyhow::anyhow!(
                    "Client already has an active tunnel: {}",
                    state.active_interface.unwrap_or_default()
                ));
            }
        }

        // Create a network manager
        let network_manager = create_network_manager();

        // Create a TUN configuration
        let tun_config = TunConfig {
            name: Some(format!("tun{}", client_id % 10)), // Use client_id to generate a unique name
            ip_config: setup
                .requested_ip_config
                .unwrap_or_else(|| "10.0.0.1/24".to_string()),
            mtu: setup.mtu.unwrap_or(1500),
        };

        // Create the TUN interface
        let tun_details = network_manager
            .create_tun(tun_config)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to create TUN interface: {}", e))?;

        // Add routes if specified
        for route in &setup.routes_to_add {
            network_manager
                .add_route(route, None, &tun_details.name)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to add route {}: {}", route, e))?;
        }

        // Configure DNS if specified
        if let Some(dns_servers) = &setup.dns_servers {
            network_manager
                .configure_dns(dns_servers)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to configure DNS: {}", e))?;
        }

        // Update the client state
        {
            let mut active_clients = active_clients.lock().unwrap();
            if let Some(state) = active_clients.get_mut(&client_id) {
                state.tunnel_active = true;
                state.active_interface = Some(tun_details.name.clone());
                state.current_ip_config = Some(tun_details.ip_config.clone());
                state.tun_fd = Some(tun_details.fd);
            }
        }

        // Return the tunnel details with the real file descriptor
        // The file descriptor will be passed over the Unix socket
        Ok(TunnelReadyDetails {
            interface_name: tun_details.name,
            assigned_ip: tun_details.ip_config,
            assigned_mtu: tun_details.mtu,
            fd: tun_details.fd, // Real file descriptor from the TUN device
        })
    }

    /// Tear down a tunnel for a client
    async fn teardown_tunnel(
        client_id: u32,
        active_clients: Arc<Mutex<HashMap<u32, ClientState>>>,
    ) -> anyhow::Result<()> {
        // Get the client state
        let client_state = {
            let active_clients = active_clients.lock().unwrap();
            active_clients.get(&client_id).cloned()
        };

        // Check if the client has an active tunnel
        let (interface_name, _) = match client_state {
            Some(state) if state.tunnel_active => {
                if let Some(name) = &state.active_interface {
                    (name.clone(), state.tun_fd)
                } else {
                    return Err(anyhow::anyhow!("Client has no active interface"));
                }
            }
            _ => {
                return Err(anyhow::anyhow!("Client has no active tunnel"));
            }
        };

        // Create a network manager
        let network_manager = create_network_manager();

        // Restore DNS configuration
        network_manager
            .restore_dns()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to restore DNS configuration: {}", e))?;

        // Destroy the TUN interface
        network_manager
            .destroy_tun(&interface_name)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to destroy TUN interface: {}", e))?;

        // Update the client state
        {
            let mut active_clients = active_clients.lock().unwrap();
            if let Some(state) = active_clients.get_mut(&client_id) {
                state.tunnel_active = false;
                state.active_interface = None;
                state.current_ip_config = None;
                state.tun_fd = None;
            }
        }

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

        // Get the client's rate limiter
        let rate_limiter = {
            let active_clients = active_clients.lock().unwrap();
            if let Some(state) = active_clients.get(&client_id) {
                state.rate_limiter.clone()
            } else {
                // This should never happen, but just in case
                error!(
                    "Client ID={} state not found when getting rate limiter",
                    client_id
                );
                return Err(anyhow::anyhow!("Client state not found"));
            }
        };

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

            // Check rate limit before processing the request
            if rate_limiter.check().is_err() {
                warn!("Rate limit exceeded for client ID={}", client_id);

                // Send rate limit error response
                let response = HelperResponse::Error(
                    "Rate limit exceeded. Please try again later.".to_string(),
                );
                if let Err(e) = connection.send_response(&response).await {
                    error!(
                        "Error sending rate limit response to client ID={}: {}",
                        client_id, e
                    );
                    return Err(anyhow::anyhow!("Failed to send rate limit response: {}", e));
                }

                // Continue to the next iteration of the loop
                continue;
            }

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
                ClientRequest::SetupTunnel(setup) => {
                    debug!("Setting up tunnel for client ID={}: {:?}", client_id, setup);
                    match IpcHandler::setup_tunnel(client_id, setup, active_clients.clone()).await {
                        Ok(details) => {
                            debug!(
                                "Tunnel setup successful for client ID={}: {:?}",
                                client_id, details
                            );
                            HelperResponse::TunnelReady(details)
                        }
                        Err(e) => {
                            // Log the detailed error for debugging
                            error!("Failed to set up tunnel for client ID={}: {}", client_id, e);

                            // Send a sanitized error message to the client
                            let sanitized_error = Self::sanitize_error_message(&e.to_string());
                            HelperResponse::Error(format!(
                                "Failed to set up tunnel: {}",
                                sanitized_error
                            ))
                        }
                    }
                }
                ClientRequest::TeardownTunnel => {
                    debug!("Tearing down tunnel for client ID={}", client_id);
                    match IpcHandler::teardown_tunnel(client_id, active_clients.clone()).await {
                        Ok(()) => {
                            debug!("Tunnel teardown successful for client ID={}", client_id);
                            HelperResponse::Success
                        }
                        Err(e) => {
                            // Log the detailed error for debugging
                            error!(
                                "Failed to tear down tunnel for client ID={}: {}",
                                client_id, e
                            );

                            // Send a sanitized error message to the client
                            let sanitized_error = Self::sanitize_error_message(&e.to_string());
                            HelperResponse::Error(format!(
                                "Failed to tear down tunnel: {}",
                                sanitized_error
                            ))
                        }
                    }
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
