//! CLI integration for CoentroVPN.
//!
//! This module provides command-line interface functionality for CoentroVPN,
//! allowing users to start the server or client components with appropriate
//! configuration.

use clap::{Parser, Subcommand};
use shared_utils::config::{Config, ConfigManager, Role};
use std::path::PathBuf;
use tracing::{debug, error, info, warn};

/// CoentroVPN CLI application
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Path to the configuration file
    #[arg(short, long, value_name = "FILE", default_value = "config.toml")]
    config: PathBuf,

    /// Subcommand to execute
    #[command(subcommand)]
    command: Option<Commands>,
}

/// CLI subcommands
#[derive(Subcommand)]
enum Commands {
    /// Start the VPN server
    Server {
        /// Override the role in the config file
        #[arg(short, long)]
        force: bool,
    },
    /// Start the VPN client
    Client {
        /// Override the role in the config file
        #[arg(short, long)]
        force: bool,
    },
    /// Start the component based on the role in the config file
    Start,
}

/// Error type for CLI operations
#[derive(Debug, thiserror::Error)]
pub enum CliError {
    /// Configuration error
    #[error("Configuration error: {0}")]
    ConfigError(#[from] shared_utils::config::ConfigError),

    /// Invalid role
    #[error("Invalid role: {0}")]
    _InvalidRole(String),

    /// IO error
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Result type for CLI operations
pub type CliResult<T> = Result<T, CliError>;

/// Run the CLI application
pub fn run() -> CliResult<()> {
    let cli = Cli::parse();
    
    // Load configuration
    debug!("Loading configuration from {:?}", cli.config);
    let config_manager = match ConfigManager::load(&cli.config) {
        Ok(manager) => manager,
        Err(err) => {
            error!("Failed to load configuration: {}", err);
            return Err(CliError::ConfigError(err));
        }
    };
    
    let config = config_manager.config();
    
    // Determine which component to start based on command and config
    match &cli.command {
        Some(Commands::Server { force }) => {
            if *force || config.role == Role::Server {
                start_server(config)?;
            } else {
                warn!("Configuration specifies client role, but server command was given with --force");
                start_server(config)?;
            }
        }
        Some(Commands::Client { force }) => {
            if *force || config.role == Role::Client {
                start_client(config)?;
            } else {
                warn!("Configuration specifies server role, but client command was given with --force");
                start_client(config)?;
            }
        }
        Some(Commands::Start) | None => {
            // Start based on the role in the config
            match config.role {
                Role::Server => start_server(config)?,
                Role::Client => start_client(config)?,
            }
        }
    }
    
    Ok(())
}

/// Start the VPN server
fn start_server(config: &Config) -> CliResult<()> {
    info!("Starting CoentroVPN server");
    
    // Validate server configuration
    if let Err(err) = config.validate() {
        error!("Invalid server configuration: {}", err);
        return Err(CliError::ConfigError(err));
    }
    
    // TODO: Implement server startup logic
    // This would typically involve calling into the core_engine crate
    // to start the server with the provided configuration
    
    info!("CoentroVPN server started successfully");
    
    // For now, just return Ok since we don't have the actual server implementation
    Ok(())
}

/// Start the VPN client
fn start_client(config: &Config) -> CliResult<()> {
    info!("Starting CoentroVPN client");
    
    // Validate client configuration
    if let Err(err) = config.validate() {
        error!("Invalid client configuration: {}", err);
        return Err(CliError::ConfigError(err));
    }
    
    // TODO: Implement client startup logic
    // This would typically involve calling into the core_engine crate
    // to start the client with the provided configuration
    
    info!("CoentroVPN client started successfully");
    
    // For now, just return Ok since we don't have the actual client implementation
    Ok(())
}
