mod session;
mod tunnel;

use clap::Parser;
use std::path::Path;
use tracing::{debug, error, info};
use tracing_subscriber::EnvFilter;

use shared_utils::config::ConfigManager;
use shared_utils::tunnel::TunnelManager;

/// CoentroVPN Core Engine
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Path to the configuration file
    #[arg(short, long, value_name = "FILE", default_value = "config.toml")]
    config: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing subscriber
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::from_default_env().add_directive("core_engine=debug".parse().unwrap()),
        )
        .with_file(true)
        .with_line_number(true)
        .with_target(true)
        .init();

    info!("Starting CoentroVPN core engine");
    debug!("Initializing with configuration");

    // Parse command-line arguments
    let cli = Cli::parse();
    debug!("Using configuration file: {}", cli.config);

    // Load configuration
    let config_path = Path::new(&cli.config);
    let config_manager = match ConfigManager::load(config_path) {
        Ok(manager) => manager,
        Err(err) => {
            error!("Failed to load configuration: {}", err);
            return Err(format!("Configuration error: {}", err).into());
        }
    };

    let config = config_manager.config();
    info!("Configuration loaded successfully");
    debug!("Role: {:?}", config.role);

    // Create tunnel manager
    let tunnel_manager = TunnelManager::new();

    // Create tunnel based on configuration
    match tunnel_manager.create_tunnel_from_config(config).await {
        Ok(tunnel_id) => {
            info!("Tunnel created successfully with ID: {}", tunnel_id);

            // Keep the application running
            tokio::signal::ctrl_c().await?;
            info!("Received shutdown signal");
        }
        Err(err) => {
            error!("Failed to create tunnel: {}", err);
            return Err(format!("Tunnel creation failed: {}", err).into());
        }
    }

    info!("CoentroVPN core engine shutting down");
    Ok(())
}
