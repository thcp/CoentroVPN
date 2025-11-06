//! CoentroVPN Client
//!
//! This is the unprivileged client for the CoentroVPN split daemon architecture.
//! It handles user interactions, QUIC connections, encryption, and packet processing,
//! while delegating system-level operations to the privileged helper daemon.

mod helper_comms;
mod tun_handler;

use crate::tun_handler::{start_tun_transport_bridge, PassThroughProcessor, TunHandler};
use clap::{Parser, Subcommand};
use shared_utils::logging::{init_logging, LogOptions};
use shared_utils::transport::ClientTransport;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{debug, error, info};
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
#[allow(clippy::large_enum_variant)]
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

        /// Pre-shared key for PSK authentication (hex or base64)
        #[clap(long)]
        psk: Option<String>,

        /// Client certificate file path
        #[clap(long)]
        cert: Option<PathBuf>,

        /// Client key file path
        #[clap(long)]
        key: Option<PathBuf>,

        /// Server CA certificate file path
        #[clap(long)]
        ca: Option<PathBuf>,

        /// Do not wait for Ctrl+C; tear down immediately after setup
        #[clap(long)]
        no_wait: bool,

        /// Use split-default routing (0.0.0.0/1 and 128.0.0.0/1)
        #[clap(long)]
        split_default: bool,

        /// Explicit route mode: "default" or "split" (overrides split-default flag)
        #[clap(long)]
        route_mode: Option<String>,

        /// Additional include routes (comma-separated CIDRs)
        #[clap(long, value_delimiter = ',')]
        include_routes: Option<Vec<String>>,

        /// Routes to exclude (comma-separated CIDRs)
        #[clap(long, value_delimiter = ',')]
        exclude_routes: Option<Vec<String>>,
    },

    /// Tear down an active VPN tunnel
    #[clap(name = "teardown-tunnel")]
    TeardownTunnel,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Parse command-line arguments
    let args = Args::parse();

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
            psk,
            cert: _cert,
            key: _key,
            ca,
            no_wait,
            split_default,
            route_mode,
            include_routes,
            exclude_routes,
        }) => {
            // Note: cert/key handled via QUIC pinned roots when provided (ca used below)
            info!("Setting up VPN tunnel...");

            // Generate a unique client ID
            let client_id = Uuid::new_v4().to_string();

            // Determine route mode and explicit routes
            // If user provided --routes, send them explicitly and leave route_mode None
            // Otherwise set route_mode so helper computes default/split, and leave routes empty
            let (routes, route_mode_opt) = if let Some(r) = routes {
                (r, None)
            } else {
                let rm = match route_mode.as_deref() {
                    Some("split") => Some(coentro_ipc::messages::RouteMode::Split),
                    Some("default") => Some(coentro_ipc::messages::RouteMode::Default),
                    Some(_) => {
                        return Err(anyhow::anyhow!(
                            "Invalid --route-mode. Use 'default' or 'split'"
                        ));
                    }
                    None => {
                        if split_default {
                            Some(coentro_ipc::messages::RouteMode::Split)
                        } else {
                            Some(coentro_ipc::messages::RouteMode::Default)
                        }
                    }
                };
                (Vec::new(), rm)
            };

            // Set up the tunnel
            let tunnel_details = match helper_client
                .setup_tunnel(
                    &client_id,
                    ip,
                    routes,
                    route_mode_opt,
                    include_routes,
                    exclude_routes,
                    dns,
                    mtu,
                )
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

                // Initialize QUIC client (secure-by-default TLS, encryption key for payload)
                // Derive data-plane key from PSK if provided; else generate a random key for local testing
                let key: [u8; 32] = if let Some(psk_str_clone) = psk.clone() {
                    let psk_bytes = match shared_utils::proto::auth::parse_psk(&psk_str_clone) {
                        Ok(b) => b,
                        Err(e) => {
                            error!("Invalid PSK: {}", e);
                            return Err(anyhow::anyhow!("Invalid PSK: {}", e));
                        }
                    };
                    use sha2::{Digest, Sha256};
                    let digest = Sha256::digest(&psk_bytes);
                    let mut out = [0u8; 32];
                    out.copy_from_slice(&digest);
                    out
                } else {
                    shared_utils::AesGcmCipher::generate_key()
                };
                // If a CA is provided, use pinned roots for TLS validation
                let quic_client = if let Some(ca_path) = ca.clone() {
                    use rustls_pemfile::certs;
                    use std::fs::File;
                    use std::io::BufReader;
                    let mut reader = BufReader::new(
                        File::open(&ca_path)
                            .map_err(|e| anyhow::anyhow!("Failed to open CA: {}", e))?,
                    );
                    let chain = certs(&mut reader)
                        .map_err(|e| anyhow::anyhow!("Failed to parse CA PEM: {}", e))?;
                    if chain.is_empty() {
                        return Err(anyhow::anyhow!("No certificates found in CA file"));
                    }
                    let anchors: Vec<rustls::Certificate> =
                        chain.into_iter().map(rustls::Certificate).collect();
                    match shared_utils::QuicClient::new_with_pinned_roots(&key, &anchors) {
                        Ok(c) => c,
                        Err(e) => {
                            error!("Failed to initialize QUIC client with pinned CA: {}", e);
                            return Err(anyhow::anyhow!("Failed to initialize QUIC client: {}", e));
                        }
                    }
                } else {
                    match shared_utils::QuicClient::new(&key) {
                        Ok(c) => c,
                        Err(e) => {
                            error!("Failed to initialize QUIC client: {}", e);
                            return Err(anyhow::anyhow!("Failed to initialize QUIC client: {}", e));
                        }
                    }
                };

                let mut connection = match quic_client.connect(&server_addr).await {
                    Ok(conn) => conn,
                    Err(e) => {
                        error!("Failed to connect to QUIC server {}: {}", server_addr, e);
                        return Err(anyhow::anyhow!("Failed to connect to QUIC server: {}", e));
                    }
                };

                // Perform control-plane authentication (PSK if provided)
                if let Some(psk_str) = psk {
                    info!("Performing PSK authentication with server");
                    match shared_utils::proto::auth::psk_handshake_client(
                        &mut *connection,
                        &psk_str,
                    )
                    .await
                    {
                        Ok(session_id) => {
                            info!("Authenticated. Session: {}", session_id);
                        }
                        Err(e) => {
                            error!("Authentication failed: {}", e);
                            return Err(anyhow::anyhow!("Authentication failed: {}", e));
                        }
                    }
                } else {
                    info!("No PSK provided; proceeding without client auth (server may reject)");
                }

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

                // Start the TUN-to-transport bridge over QUIC
                let tunnel_task = tokio::spawn(async move {
                    if let Err(e) =
                        start_tun_transport_bridge(tun_handler, connection, processor, 100).await
                    {
                        error!("Tunnel error: {}", e);
                    }
                });

                if !no_wait {
                    info!("Tunnel is active. Press Ctrl+C to tear down the tunnel and exit.");
                    // Wait for Ctrl+C
                    tokio::signal::ctrl_c().await?;
                    info!("Received Ctrl+C, tearing down tunnel...");
                } else {
                    info!("--no-wait specified; tearing down tunnel immediately...");
                }

                // Abort the tunnel task
                tunnel_task.abort();

                // Tear down the tunnel
                if let Err(e) = helper_client.teardown_tunnel().await {
                    error!("Failed to tear down tunnel: {}", e);
                    return Err(anyhow::anyhow!("Failed to tear down tunnel: {}", e));
                }

                info!("Tunnel torn down successfully.");
            } else {
                if !no_wait {
                    info!("No server address provided; tunnel is ready for local testing.");
                    info!("Press Ctrl+C to tear down the tunnel and exit.");
                    tokio::signal::ctrl_c().await?;
                    info!("Received Ctrl+C, tearing down tunnel...");
                } else {
                    info!("--no-wait specified; tearing down tunnel immediately...");
                }

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
