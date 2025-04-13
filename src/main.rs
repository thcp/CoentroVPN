use crate::observability::{init_metrics, start_metrics_server};
use crate::utils::bind_socket; // Import the centralized binding function
use clap::Parser;
use coentrovpn::client::Client;
use coentrovpn::config::Config;
use coentrovpn::logging::init_logging;
use coentrovpn::observability::{init_metrics, start_health_server, HealthState};
use coentrovpn::packet_utils::ReassemblyBuffer;
use coentrovpn::server::{start_server, Server};
use coentrovpn::tunnel::Tunnel;
use num_cpus;
use std::collections::HashSet;
use std::env;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::runtime::Builder;
use tokio::sync::Mutex;
use tracing::{debug, info};
use uuid::Uuid;

#[derive(Parser, Debug)]
#[command(name = "coentrovpn", version)]
struct Cli {
    /// Path to config file
    #[arg(short, long, default_value = "Config.toml")]
    config: String,
}

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    // Dynamically set the number of worker threads based on available CPU cores
    let worker_threads = num_cpus::get();

    // Create the Tokio runtime manually with the dynamic number of worker threads
    let runtime = Builder::new_multi_thread()
        .worker_threads(worker_threads)
        .enable_all()
        .build()?;

    // Run the async code within the runtime
    runtime.block_on(async {
        // Parse CLI arguments
        let cli = Cli::parse();

        // Load config from file or environment
        info!("Loading config from {}", cli.config);
        let config = Config::from_env_or_file(&cli.config)?;
        info!("Config loaded: {:?}", config);

        // Validate the config
        config.validate()?; // Call the validate method

        // Initialize logging
        let log_level = env::var("LOG_LEVEL").unwrap_or_else(|_| config.logging.log_level.clone());
        let log_format = env::var("LOG_FORMAT").unwrap_or_else(|_| config.logging.format.clone());
        init_logging(&log_level, &log_format);
        debug!("Log level set to: {}", log_level);

        // Initialize metrics
        let metrics_addr = config.observability.metrics_addr.clone();
        let enable_metrics = config.observability.enable_metrics;

        if enable_metrics {
            tokio::spawn(async move {
                init_metrics().await;
                start_metrics_server(&metrics_addr)
                    .await
                    .expect("Failed to start metrics server");
            });
        }

        // Initialize health state and server
        let health_state = Arc::new(HealthState::new());
        let health_addr = config.observability.health_addr.parse()?;
        tokio::spawn(start_health_server(health_addr));
        info!("Metrics available at http://{}/metrics", health_addr);

        // Set the health state to ready after initialization
        health_state.set_ready().await;

        // Debug statement to confirm values
        println!("Starting server on {}:{}", listen_addr, listen_port);

        // Start the server
        let listen_addr = config.listen_addr.clone();
        let listen_port = config.listen_port;
        start_server().expect("Failed to start server");

        Ok(())
    })
}
