use clap::Parser;
use coentrovpn::client::Client;
use coentrovpn::config::Config;
use coentrovpn::logging::init_logging; // Updated import
use coentrovpn::server::Server;
use coentrovpn::tunnel::Tunnel;
use num_cpus;  // Import the num_cpus crate
use std::env;
use std::sync::Arc; // Add this import for Arc
use tokio::net::UdpSocket; // Add this import for UdpSocket
use tokio::runtime::Builder;  // Import Builder to manually create the runtime
use tokio::sync::Mutex; // Add this import for Mutex
use tracing::{info, debug}; // Updated import
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

        // Log the compression minimum size threshold
        info!("Compression minimum size threshold: {} bytes", config.compression.min_compression_size.unwrap_or(0));

        // Check environment variable `LOG_LEVEL` first, then fallback to Config.toml
        let log_level = if let Ok(val) = env::var("LOG_LEVEL") {
            val.to_lowercase()
        } else {
            config.logging.log_level.to_lowercase()
        };

        // Ensure a valid log level is set
        let log_level = match log_level.as_str() {
            "debug" => "debug",
            "info" => "info",
            "error" => "error",
            _ => "info",  // Default to info if invalid value found
        };

        // Only set RUST_LOG if it's not already set
        if env::var("RUST_LOG").is_err() {
            env::set_var("RUST_LOG", &log_level);
        }
        
        // Debug log to verify the log level

        init_logging(&log_level); // Replaced env_logger::init() with init_logging()
        debug!("Log level set to: {}", log_level);
        debug!("RUST_LOG is set to: {}", env::var("RUST_LOG").unwrap_or_else(|_| "not set".to_string()));        

        // Create a UDP socket and wrap it in an Arc<Mutex>
        let socket = UdpSocket::bind("0.0.0.0:0").await?;  // Bind to a random available port
        let socket = Arc::new(Mutex::new(socket)); // Wrap the socket in Arc<Mutex>

        // Instantiate Client or Server based on mode
        match config.mode.as_str() {
            "server" => {
                let mut server: Server = Server {
                    config,
                    socket: Arc::clone(&socket),
                    session_id: Uuid::new_v4(),
                }; // Declare server as mutable
                server.start().await?;  // Now we can call start() on a mutable reference
            }
            "client" => {
                let server_addr = config.server_addr.parse()?;
                let mut client: Client = Client {
                    config,
                    socket: Arc::clone(&socket),
                    server_addr,
                    session_id: Uuid::new_v4(),
                };
                client.start().await?;  // Now we can call start() on a mutable reference
            }
            _ => {
                return Err("Invalid mode in config. Use 'client' or 'server'.".into());
            }
        }

        Ok(())
    })
}