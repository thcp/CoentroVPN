//! CoentroVPN Client
//!
//! This is the unprivileged client for the CoentroVPN split daemon architecture.
//! It handles user interactions, QUIC connections, encryption, and packet processing,
//! while delegating system-level operations to the privileged helper daemon.

mod helper_comms;

use clap::Parser;
use log::{debug, error, info, warn, LevelFilter};
use std::path::PathBuf;

/// Command-line arguments for the client
#[derive(Parser, Debug)]
#[clap(author, version, about)]
struct Args {
    /// Path to the Unix Domain Socket for IPC with the helper daemon
    #[clap(short = 's', long, default_value = "/var/run/coentrovpn/helper.sock")]
    helper_socket: PathBuf,

    /// Log level
    #[clap(short, long, default_value = "info")]
    log_level: String,

    /// Run a simple ping test to the helper daemon
    #[clap(long)]
    ping_helper: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Parse command-line arguments
    let args = Args::parse();

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

    info!("CoentroVPN Client starting up");
    debug!("Helper socket path: {}", args.helper_socket.display());

    // If the ping_helper flag is set, just ping the helper and exit
    if args.ping_helper {
        info!("Pinging helper daemon...");
        match helper_comms::ping_helper(&args.helper_socket).await {
            Ok(()) => {
                info!("Helper daemon is responsive");
                return Ok(());
            }
            Err(e) => {
                error!("Failed to ping helper daemon: {}", e);
                return Err(anyhow::anyhow!("Failed to ping helper daemon: {}", e));
            }
        }
    }

    // Create a helper client
    let helper_client = match helper_comms::HelperClient::connect(&args.helper_socket).await {
        Ok(client) => client,
        Err(e) => {
            error!("Failed to connect to helper daemon: {}", e);
            return Err(anyhow::anyhow!("Failed to connect to helper daemon: {}", e));
        }
    };

    // Get the helper status
    match helper_client.get_status().await {
        Ok(status) => {
            info!("Helper daemon status: {:?}", status);
        }
        Err(e) => {
            error!("Failed to get helper daemon status: {}", e);
            return Err(anyhow::anyhow!("Failed to get helper daemon status: {}", e));
        }
    }

    // In Sprint 1, we're just implementing the basic IPC framework
    // Actual VPN functionality will be implemented in later sprints
    info!("Basic IPC framework implemented. Exiting.");

    Ok(())
}
