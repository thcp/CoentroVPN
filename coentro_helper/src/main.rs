//! CoentroVPN Helper Daemon
//!
//! This is the privileged helper daemon for the CoentroVPN split daemon architecture.
//! It handles system-level operations requiring elevated privileges, such as creating
//! TUN interfaces, modifying routing tables, and configuring DNS.
//!
//! This daemon supports socket activation via launchd on macOS.

mod ipc_handler;
mod network_manager;
mod sleep_monitor;

use clap::Parser;
use shared_utils::config::Config;
use shared_utils::logging::{init_logging, LogOptions};
use std::os::unix::io::RawFd;
use std::path::PathBuf;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::oneshot;
use tracing::{debug, error, info, warn};

/// Command-line arguments for the helper daemon
#[derive(Parser, Debug)]
#[clap(author, version, about)]
struct Args {
    /// Path to the Unix Domain Socket for IPC
    #[clap(short, long, default_value = "/var/run/coentrovpn/helper.sock")]
    socket_path: PathBuf,

    /// Log level
    #[clap(short, long, default_value = "info")]
    log_level: String,

    /// Run in foreground (don't daemonize)
    #[clap(short, long)]
    foreground: bool,

    /// Path to the configuration file
    #[clap(short, long, default_value = "config.toml")]
    config: PathBuf,

    /// Use socket activation (for launchd on macOS)
    #[clap(long)]
    socket_activation: bool,
}

/// Check if another instance of the helper daemon is already running
fn is_already_running() -> bool {
    let output = std::process::Command::new("pgrep")
        .arg("-f")
        .arg("coentro_helper")
        .output();

    match output {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let pids: Vec<&str> = stdout.trim().split('\n').collect();
            // If there's more than one PID (including our own), another instance is running
            pids.len() > 1
        }
        Err(_) => false,
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Parse command-line arguments
    let args = Args::parse();

    // Check if another instance is already running (skip if using socket activation)
    if !args.socket_activation && is_already_running() {
        error!("Another instance of the helper daemon is already running. Exiting.");
        std::process::exit(1);
    }

    // Initialize tracing-based logging
    let level = match args.log_level.to_lowercase().as_str() {
        "trace" => tracing::Level::TRACE,
        "debug" => tracing::Level::DEBUG,
        "info" => tracing::Level::INFO,
        "warn" => tracing::Level::WARN,
        "error" => tracing::Level::ERROR,
        _ => tracing::Level::INFO,
    };
    let _guard = init_logging(LogOptions {
        level,
        ..Default::default()
    });

    info!("CoentroVPN Helper Daemon starting up");

    if args.socket_activation {
        info!("Using socket activation mode (launchd)");
    } else {
        debug!("Socket path: {}", args.socket_path.display());

        // Ensure the socket directory exists
        if let Some(parent) = args.socket_path.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent)?;
            }
        }
    }

    // Load configuration
    info!(
        "Attempting to load configuration from {}",
        args.config.display()
    );
    let config_result = Config::load(&args.config);
    let allowed_uids = match &config_result {
        Ok(config) => {
            info!("Loaded configuration from {}", args.config.display());
            info!("Allowed UIDs: {:?}", config.helper.allowed_uids);
            config.helper.allowed_uids.clone()
        }
        Err(e) => {
            warn!(
                "Failed to load configuration from {}: {}",
                args.config.display(),
                e
            );
            warn!("Using default configuration");
            Vec::new()
        }
    };

    // Group-based auth from configuration (optional)
    let allowed_gids = match &config_result {
        Ok(config) if !config.helper.allowed_gids.is_empty() => {
            info!(
                "Group-based authentication: allowing GIDs from config: {:?}",
                config.helper.allowed_gids
            );
            Some(config.helper.allowed_gids.clone())
        }
        _ => Some(Vec::new()),
    };

    // Create a channel for shutdown signaling
    let (shutdown_tx, shutdown_rx) = oneshot::channel();

    // Start the IPC handler
    let ipc_handler = ipc_handler::IpcHandler::new();

    // Handle socket activation or regular socket creation
    let ipc_handle = if args.socket_activation {
        // Get the socket from launchd
        let socket_fd = match get_socket_from_launchd() {
            Ok(fd) => {
                info!("Successfully received socket from launchd (fd: {})", fd);
                fd
            }
            Err(e) => {
                error!("Failed to get socket from launchd: {}", e);
                return Err(anyhow::anyhow!("Failed to get socket from launchd: {}", e));
            }
        };

        tokio::spawn(async move {
            if let Err(e) = ipc_handler
                .run_with_socket_fd(socket_fd, shutdown_rx, allowed_uids, allowed_gids)
                .await
            {
                error!("Error running IPC handler with socket activation: {}", e);
            }
        })
    } else {
        let socket_path = args.socket_path.clone();
        tokio::spawn(async move {
            if let Err(e) = ipc_handler
                .run(socket_path, shutdown_rx, allowed_uids, allowed_gids)
                .await
            {
                error!("Error running IPC handler: {}", e);
            }
        })
    };

    // Set up signal handlers
    let mut sigint = signal(SignalKind::interrupt())?;
    let mut sigterm = signal(SignalKind::terminate())?;

    // Wait for a signal
    tokio::select! {
        _ = sigint.recv() => {
            info!("Received SIGINT, shutting down");
        }
        _ = sigterm.recv() => {
            info!("Received SIGTERM, shutting down");
        }
    }

    // Signal the IPC handler to shut down
    if shutdown_tx.send(()).is_err() {
        error!("Failed to send shutdown signal");
    }

    // Wait for the IPC handler to finish
    if let Err(e) = ipc_handle.await {
        error!("Error waiting for IPC handler to finish: {}", e);
    }

    info!("CoentroVPN Helper Daemon shut down");
    Ok(())
}

/// Get the socket file descriptor from launchd
fn get_socket_from_launchd() -> anyhow::Result<RawFd> {
    // On macOS, launchd passes socket file descriptors through environment variables
    // There are several possible formats that launchd might use:
    // 1. LAUNCH_ACTIVATE_SOCKET_<name>=<fd>
    // 2. LAUNCH_ACTIVATE_SOCKET=<name>;<fd>
    // 3. Direct file descriptor inheritance (fd 3 is typically the first socket)

    // Try different environment variable formats
    let possible_env_vars = ["LAUNCH_ACTIVATE_SOCKET_Listeners", "LAUNCH_ACTIVATE_SOCKET"];

    // Log all environment variables for debugging
    debug!("Environment variables:");
    for (key, value) in std::env::vars() {
        debug!("  {}={}", key, value);
    }

    // Try to get the socket file descriptor from environment variables
    for env_var_name in possible_env_vars {
        if let Ok(value) = std::env::var(env_var_name) {
            info!("Found environment variable {}={}", env_var_name, value);

            // If it's the LAUNCH_ACTIVATE_SOCKET format, parse it
            if env_var_name == "LAUNCH_ACTIVATE_SOCKET" {
                // Format is "name;fd"
                if let Some((name, fd_str)) = value.split_once(';') {
                    if name == "Listeners" {
                        if let Ok(fd) = fd_str.parse::<RawFd>() {
                            info!("Parsed socket file descriptor {} from {}", fd, env_var_name);
                            return Ok(fd);
                        }
                    }
                }
            } else {
                // Direct format: LAUNCH_ACTIVATE_SOCKET_Listeners=fd
                if let Ok(fd) = value.parse::<RawFd>() {
                    info!("Parsed socket file descriptor {} from {}", fd, env_var_name);
                    return Ok(fd);
                }
            }
        }
    }

    // If we couldn't find the socket file descriptor in environment variables,
    // try to use the default socket file descriptor (3)
    info!("No socket file descriptor found in environment variables, trying default fd 3");

    // Check if fd 3 is a valid socket
    let fd = 3;
    let result = unsafe {
        let mut addr: libc::sockaddr = std::mem::zeroed();
        let mut len = std::mem::size_of::<libc::sockaddr>() as libc::socklen_t;
        libc::getsockname(fd, &mut addr, &mut len)
    };

    if result == 0 {
        info!("Using default socket file descriptor {}", fd);
        return Ok(fd);
    }

    // If all else fails, try to create the socket ourselves
    warn!("Could not get socket from launchd, creating socket manually");

    // Create the socket directory if it doesn't exist
    let socket_dir = std::path::Path::new("/var/run/coentrovpn");
    if !socket_dir.exists() {
        std::fs::create_dir_all(socket_dir)
            .map_err(|e| anyhow::anyhow!("Failed to create socket directory: {}", e))?;
    }

    // Create the socket
    let socket_path = socket_dir.join("helper.sock");

    // Remove the socket file if it already exists
    if socket_path.exists() {
        std::fs::remove_file(&socket_path)
            .map_err(|e| anyhow::anyhow!("Failed to remove existing socket file: {}", e))?;
    }

    // Create a Unix domain socket
    let socket_fd = unsafe {
        let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
        if fd < 0 {
            return Err(anyhow::anyhow!(
                "Failed to create socket: {}",
                std::io::Error::last_os_error()
            ));
        }

        // Set up the socket address
        let mut addr: libc::sockaddr_un = std::mem::zeroed();
        addr.sun_family = libc::AF_UNIX as libc::sa_family_t;

        // Copy the socket path to the address
        let path_bytes = socket_path.to_str().unwrap().as_bytes();
        if path_bytes.len() >= addr.sun_path.len() {
            return Err(anyhow::anyhow!("Socket path too long"));
        }

        for (i, &byte) in path_bytes.iter().enumerate() {
            addr.sun_path[i] = byte as libc::c_char;
        }

        // Bind the socket
        let addr_ptr = &addr as *const libc::sockaddr_un as *const libc::sockaddr;
        let addr_len = std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t;

        if libc::bind(fd, addr_ptr, addr_len) < 0 {
            let err = std::io::Error::last_os_error();
            libc::close(fd);
            return Err(anyhow::anyhow!("Failed to bind socket: {}", err));
        }

        // Listen on the socket
        if libc::listen(fd, 128) < 0 {
            let err = std::io::Error::last_os_error();
            libc::close(fd);
            return Err(anyhow::anyhow!("Failed to listen on socket: {}", err));
        }
        fd
    };

    // Harden socket file permissions to 0660 (rw-rw----)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = std::fs::metadata(&socket_path) {
            let mut permissions = metadata.permissions();
            permissions.set_mode(0o660);
            if let Err(e) = std::fs::set_permissions(&socket_path, permissions) {
                warn!("Failed to set socket permissions to 0660: {}", e);
            }
        } else {
            warn!("Failed to read metadata for socket to set permissions");
        }
    }

    info!("Created socket manually with file descriptor {}", socket_fd);

    Ok(socket_fd)
}
