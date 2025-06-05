//! CoentroVPN Helper Daemon
//!
//! This is the privileged helper daemon for the CoentroVPN split daemon architecture.
//! It handles system-level operations requiring elevated privileges, such as creating
//! TUN interfaces, modifying routing tables, and configuring DNS.

mod ipc_handler;
mod network_manager;

use clap::Parser;
use log::{debug, error, info, warn, LevelFilter};
use shared_utils::config::{Config, ConfigManager};
use std::path::PathBuf;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::oneshot;

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

    // Check if another instance is already running
    if is_already_running() {
        eprintln!("Another instance of the helper daemon is already running. Exiting.");
        std::process::exit(1);
    }

    // Initialize logging
    let log_level = match args.log_level.to_lowercase().as_str() {
        "trace" => LevelFilter::Trace,
        "debug" => LevelFilter::Debug,
        "info" => LevelFilter::Info,
        "warn" => LevelFilter::Warn,
        "error" => LevelFilter::Error,
        _ => LevelFilter::Info,
    };

    env_logger::Builder::new()
        .filter_level(log_level)
        .format_timestamp_secs()
        .init();

    info!("CoentroVPN Helper Daemon starting up");
    debug!("Socket path: {}", args.socket_path.display());

    // Ensure the socket directory exists
    if let Some(parent) = args.socket_path.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent)?;
        }
    }

    // Load configuration
    info!(
        "Attempting to load configuration from {}",
        args.config.display()
    );
    let config_result = Config::load(&args.config);
    let allowed_uids = match config_result {
        Ok(config) => {
            info!("Loaded configuration from {}", args.config.display());
            info!("Allowed UIDs: {:?}", config.helper.allowed_uids);
            config.helper.allowed_uids
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

    // Create a channel for shutdown signaling
    let (shutdown_tx, shutdown_rx) = oneshot::channel();

    // Start the IPC handler
    let ipc_handler = ipc_handler::IpcHandler::new();
    let socket_path = args.socket_path.clone();
    let ipc_handle = tokio::spawn(async move {
        if let Err(e) = ipc_handler
            .run(socket_path, shutdown_rx, allowed_uids)
            .await
        {
            error!("Error running IPC handler: {}", e);
        }
    });

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
    if let Err(_) = shutdown_tx.send(()) {
        error!("Failed to send shutdown signal");
    }

    // Wait for the IPC handler to finish
    if let Err(e) = ipc_handle.await {
        error!("Error waiting for IPC handler to finish: {}", e);
    }

    info!("CoentroVPN Helper Daemon shut down");
    Ok(())
}
