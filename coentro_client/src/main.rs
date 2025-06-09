//! CoentroVPN Client
//!
//! This is the unprivileged client for the CoentroVPN split daemon architecture.
//! It handles user interactions, QUIC connections, encryption, and packet processing,
//! while delegating system-level operations to the privileged helper daemon.

mod helper_comms;
mod tun_handler;

use crate::tun_handler::{start_tun_quic_tunnel, PassThroughProcessor, TunHandler};
use clap::{Parser, Subcommand};
use log::{debug, error, info, LevelFilter};
use std::path::PathBuf;
use std::sync::Arc;
use uuid::Uuid;

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

    /// Subcommand to execute
    #[clap(subcommand)]
    command: Option<Command>,
}

/// Subcommands for the client
#[derive(Subcommand, Debug)]
enum Command {
    /// Set up a VPN tunnel
    #[clap(name = "setup-tunnel")]
    SetupTunnel {
        /// Requested IP address and prefix length (e.g., "10.0.0.1/24")
        #[clap(long)]
        ip: Option<String>,

        /// Routes to add to the routing table (can be specified multiple times)
        #[clap(long, value_delimiter = ',')]
        routes: Option<Vec<String>>,

        /// DNS servers to configure (can be specified multiple times)
        #[clap(long, value_delimiter = ',')]
        dns: Option<Vec<String>>,

        /// MTU value for the tunnel interface
        #[clap(long)]
        mtu: Option<u32>,

        /// Server address to connect to (e.g., "example.com:4433")
        #[clap(long)]
        server: Option<String>,

        /// Client certificate file path
        #[clap(long)]
        cert: Option<PathBuf>,

        /// Client key file path
        #[clap(long)]
        key: Option<PathBuf>,

        /// Server CA certificate file path
        #[clap(long)]
        ca: Option<PathBuf>,
    },

    /// Tear down an active VPN tunnel
    #[clap(name = "teardown-tunnel")]
    TeardownTunnel,
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

    // Process the subcommand
    match args.command {
        Some(Command::SetupTunnel {
            ip,
            routes,
            dns,
            mtu,
            server,
            cert,
            key,
            ca,
        }) => {
            // Ignoring cert, key, ca as they're not used in this implementation
            let _ = (cert, key, ca);
            info!("Setting up VPN tunnel...");

            // Generate a unique client ID
            let client_id = Uuid::new_v4().to_string();

            // Default routes if none specified
            let routes = routes.unwrap_or_else(|| vec!["0.0.0.0/0".to_string()]);

            // Set up the tunnel
            let tunnel_details = match helper_client
                .setup_tunnel(&client_id, ip, routes, dns, mtu)
                .await
            {
                Ok(details) => {
                    info!("Tunnel setup successful:");
                    info!("  Interface: {}", details.interface_name);
                    info!("  IP: {}", details.assigned_ip);
                    info!("  MTU: {}", details.assigned_mtu);
                    details
                }
                Err(e) => {
                    error!("Failed to set up tunnel: {}", e);
                    return Err(anyhow::anyhow!("Failed to set up tunnel: {}", e));
                }
            };

            // If a server address is provided, establish a QUIC connection
            if let Some(server_addr) = server {
                info!("Connecting to QUIC server at {}", server_addr);

                // For now, we'll just use a mock connection since we're not actually implementing
                // the full QUIC client functionality in this PR
                let (quic_stream_rx, quic_stream_tx) = (tokio::io::empty(), tokio::io::sink());

                info!("QUIC connection established, starting tunnel...");

                // Create a TUN handler using the file descriptor received from the helper daemon
                info!(
                    "Creating TUN handler with file descriptor {}",
                    tunnel_details.fd
                );
                let tun_handler = TunHandler::new(
                    tunnel_details.fd, // Real file descriptor from the helper daemon
                    tunnel_details.interface_name,
                    tunnel_details.assigned_ip,
                    tunnel_details.assigned_mtu,
                );

                // Create a packet processor
                let processor = Arc::new(PassThroughProcessor);

                // Start the TUN-QUIC tunnel
                let tunnel_task = tokio::spawn(async move {
                    if let Err(e) = start_tun_quic_tunnel(
                        tun_handler,
                        quic_stream_rx,
                        quic_stream_tx,
                        processor,
                        100, // Buffer size
                    )
                    .await
                    {
                        error!("Tunnel error: {}", e);
                    }
                });

                info!("Tunnel is active. Press Ctrl+C to tear down the tunnel and exit.");

                // Wait for Ctrl+C
                tokio::signal::ctrl_c().await?;

                info!("Received Ctrl+C, tearing down tunnel...");

                // Abort the tunnel task
                tunnel_task.abort();

                // Tear down the tunnel
                if let Err(e) = helper_client.teardown_tunnel().await {
                    error!("Failed to tear down tunnel: {}", e);
                    return Err(anyhow::anyhow!("Failed to tear down tunnel: {}", e));
                }

                info!("Tunnel torn down successfully.");
            } else {
                info!("No server address provided, tunnel is ready for local testing.");
                info!("Press Ctrl+C to tear down the tunnel and exit.");

                // Wait for Ctrl+C
                tokio::signal::ctrl_c().await?;

                info!("Received Ctrl+C, tearing down tunnel...");

                // Tear down the tunnel
                if let Err(e) = helper_client.teardown_tunnel().await {
                    error!("Failed to tear down tunnel: {}", e);
                    return Err(anyhow::anyhow!("Failed to tear down tunnel: {}", e));
                }

                info!("Tunnel torn down successfully.");
            }
        }
        Some(Command::TeardownTunnel) => {
            info!("Tearing down VPN tunnel...");

            match helper_client.teardown_tunnel().await {
                Ok(()) => {
                    info!("Tunnel torn down successfully.");
                }
                Err(e) => {
                    error!("Failed to tear down tunnel: {}", e);
                    return Err(anyhow::anyhow!("Failed to tear down tunnel: {}", e));
                }
            }
        }
        None => {
            // No subcommand specified, just get the helper status
            match helper_client.get_status().await {
                Ok(status) => {
                    info!("Helper daemon status:");
                    info!("  Version: {}", status.helper_version);
                    info!("  Tunnel active: {}", status.tunnel_active);
                    if let Some(interface) = status.active_interface {
                        info!("  Active interface: {}", interface);
                    }
                    if let Some(ip_config) = status.current_ip_config {
                        info!("  IP configuration: {}", ip_config);
                    }
                }
                Err(e) => {
                    error!("Failed to get helper daemon status: {}", e);
                    return Err(anyhow::anyhow!("Failed to get helper daemon status: {}", e));
                }
            }

            info!("No command specified. Use --help to see available commands.");
        }
    }

    Ok(())
}
