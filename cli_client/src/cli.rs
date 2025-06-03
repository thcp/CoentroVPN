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
                warn!(
                    "Configuration specifies client role, but server command was given with --force"
                );
                start_server(config)?;
            }
        }
        Some(Commands::Client { force }) => {
            if *force || config.role == Role::Client {
                start_client(config)?;
            } else {
                warn!(
                    "Configuration specifies server role, but client command was given with --force"
                );
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

    // Start the server using the core_engine
    // In a real implementation, we would use a proper IPC mechanism
    // For now, we'll just spawn the core_engine process
    let status = std::process::Command::new("cargo")
        .args(["run", "--bin", "core_engine"])
        .status()
        .map_err(CliError::IoError)?;

    if !status.success() {
        error!(
            "Core engine process exited with non-zero status: {:?}",
            status
        );
        return Err(CliError::IoError(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Core engine process failed: {:?}", status),
        )));
    }

    info!("CoentroVPN server started successfully");
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

    // Start the client using the core_engine
    // In a real implementation, we would use a proper IPC mechanism
    // For now, we'll just spawn the core_engine process
    let status = std::process::Command::new("cargo")
        .args(["run", "--bin", "core_engine"])
        .status()
        .map_err(CliError::IoError)?;

    if !status.success() {
        error!(
            "Core engine process exited with non-zero status: {:?}",
            status
        );
        return Err(CliError::IoError(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Core engine process failed: {:?}", status),
        )));
    }

    info!("CoentroVPN client started successfully");
    Ok(())
}
