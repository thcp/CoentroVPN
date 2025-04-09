use clap::Parser;
use coentrovpn::client::Client;
use coentrovpn::config::Config;
use coentrovpn::logging::init_logging;
use coentrovpn::packet_utils::ReassemblyBuffer;
use coentrovpn::server::Server;
use coentrovpn::tunnel::Tunnel;
use coentrovpn::observability::{HealthState, start_health_server, init_metrics};
use num_cpus;
use std::env;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::runtime::Builder;
use tokio::sync::Mutex;
use tracing::{info, debug};
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
        init_metrics();

        // Initialize health state and server
        let health_state = Arc::new(HealthState::new());
        let health_addr = config.health_addr.parse()?;
        tokio::spawn(start_health_server(health_addr, Arc::clone(&health_state)));
        info!("Metrics available at http://{}/metrics", health_addr);

        // Create a UDP socket and wrap it in an Arc<Mutex>
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let socket = Arc::new(Mutex::new(socket));

        // Set the health state to ready after initialization
        health_state.set_ready().await;

        // Instantiate Client or Server based on mode
        match config.mode.as_str() {
            "server" => {
                let mut server = Server {
                    config,
                    socket: Arc::clone(&socket),
                    session_id: Uuid::new_v4(),
                    reassembly_buffer: Arc::new(Mutex::new(ReassemblyBuffer::new(std::time::Duration::from_secs(10)))),
                };
                server.start().await?;
            }
            "client" => {
                let server_addr = config.server_addr.parse()?;
                let mut client = Client {
                    config,
                    socket: Arc::clone(&socket),
                    server_addr,
                    session_id: Uuid::new_v4(),
                    reassembly_buffer: Arc::new(Mutex::new(ReassemblyBuffer::new(std::time::Duration::from_secs(10)))),
                };
                client.start().await?;
            }
            _ => {
                return Err("Invalid mode in config. Use 'client' or 'server'.".into());
            }
        }

        Ok(())
    })
}