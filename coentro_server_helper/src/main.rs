#[cfg(not(unix))]
compile_error!("coentro_server_helper is only supported on Unix-like systems");

mod ipc;
mod network;
mod persistence;

use anyhow::Result;
use clap::Parser;
use ipc::ServerIpcServer;
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use shared_utils::config::Config;
use shared_utils::logging::{init_logging, LogOptions};
use std::net::SocketAddr;
use std::path::PathBuf;
use tracing::{debug, error, info, warn};

#[derive(Parser, Debug)]
#[clap(author, version, about)]
struct Args {
    /// Path to the Unix domain socket used for IPC with the server helper
    #[clap(
        long,
        value_name = "PATH",
        default_value = "/var/run/coentrovpn/server_helper.sock"
    )]
    socket_path: PathBuf,

    /// Path to the configuration file
    #[clap(short, long, value_name = "FILE", default_value = "config.toml")]
    config: PathBuf,

    /// Log level (trace|debug|info|warn|error)
    #[clap(short, long, default_value = "info")]
    log_level: String,

    /// Override Prometheus listen address (e.g. 0.0.0.0:9200)
    #[clap(long)]
    metrics_listen: Option<String>,

    /// Enable or disable metrics exporter via CLI
    #[clap(long)]
    metrics_enabled: Option<bool>,

    /// Run in foreground (compatibility flag for future use)
    #[clap(long)]
    foreground: bool,
}

fn is_already_running() -> bool {
    let output = std::process::Command::new("pgrep")
        .arg("-f")
        .arg("coentro_server_helper")
        .output();

    match output {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let pids: Vec<&str> = stdout
                .trim()
                .split('\n')
                .filter(|pid| !pid.is_empty())
                .collect();
            pids.len() > 1
        }
        Err(_) => false,
    }
}

fn init_logger(level_str: &str) -> LogOptions {
    let level = match level_str.to_lowercase().as_str() {
        "trace" => tracing::Level::TRACE,
        "debug" => tracing::Level::DEBUG,
        "info" => tracing::Level::INFO,
        "warn" => tracing::Level::WARN,
        "error" => tracing::Level::ERROR,
        _ => tracing::Level::INFO,
    };

    LogOptions {
        level,
        ..Default::default()
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    if !args.foreground && is_already_running() {
        error!("Another instance of the server helper is already running. Exiting.");
        std::process::exit(1);
    }

    let _guard = init_logging(init_logger(&args.log_level));
    info!("Starting CoentroVPN server helper daemon");
    debug!(socket = %args.socket_path.display(), config = %args.config.display());

    let config = match Config::load(&args.config) {
        Ok(cfg) => cfg,
        Err(err) => {
            warn!(
                "Failed to load configuration from {}: {} — falling back to defaults",
                args.config.display(),
                err
            );
            Config::default()
        }
    };

    let metrics_enabled = args.metrics_enabled.unwrap_or(config.metrics.enabled);
    let metrics_listen = args
        .metrics_listen
        .clone()
        .unwrap_or_else(|| config.metrics.listen_addr.clone());

    let _metrics_handle: Option<PrometheusHandle> = if metrics_enabled {
        let listen_addr: SocketAddr = metrics_listen
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid metrics listen address: {}", e))?;
        info!("Prometheus metrics endpoint listening on {}", listen_addr);
        Some(
            PrometheusBuilder::new()
                .with_http_listener(listen_addr)
                .install_recorder()
                .map_err(|e| anyhow::anyhow!("Failed to install Prometheus recorder: {}", e))?,
        )
    } else {
        None
    };

    let server = ServerIpcServer::bind(&args.socket_path, &config.helper).await?;

    if let Err(err) = server.run().await {
        error!("Server helper terminated with error: {}", err);
        return Err(err);
    }

    info!("Server helper shut down cleanly");
    Ok(())
}
