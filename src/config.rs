use serde::Deserialize;
use std::fs;
use std::env;

#[derive(Debug, Deserialize, Clone)]
pub struct LoggingConfig {
    pub log_level: String,  // Log level (e.g., "debug", "info", "error")
}

#[derive(Debug, Deserialize, Clone)]  // Add Clone derive here
pub struct CompressionConfig {
    pub algorithm: String,  // Compression algorithm choice
}

#[derive(Debug, Deserialize, Clone)]  // Add Clone derive here
pub struct Config {
    pub mode: String,
    pub server_addr: String,
    pub listen_port: u16,
    pub listen_addr: String,
    pub logging: LoggingConfig,  // Added logging configuration

    // New fields for UDP configurations
    pub mtu: Option<u16>,           // Maximum Transmission Unit
    pub buffer_size: Option<usize>, // Buffer size for UDP packets
    pub connection_timeout: Option<u64>, // Connection timeout in seconds
    
    // New field for rate limiting
    pub rate_limit: Option<u64>,    // Rate limit in bytes per second (Optional)

    // New field for compression algorithm
    pub compression: CompressionConfig,  // Compression settings

    // Flow control parameters
    pub flow_control_threshold: Option<u64>, // Flow control threshold in bytes

    // Max packet size for splitting data packets
    pub max_packet_size: Option<usize>,  // Added max_packet_size field

    // New fields for OS-level buffer sizes
    pub recv_buffer_size: Option<usize>, // OS-level receive buffer size
    pub send_buffer_size: Option<usize>, // OS-level send buffer size
}

impl Config {
    pub fn from_file(path: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync + 'static>> {
        let contents = fs::read_to_string(path)?;
        let config: Config = toml::from_str(&contents)?;
        Ok(config)
    }

    pub fn from_env_or_file(path: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync + 'static>> {
        let mut config = Self::from_file(path)?;

        // Override with environment variables if they exist
        if let Ok(mode) = env::var("MODE") {
            config.mode = mode;
        }
        if let Ok(server_addr) = env::var("SERVER_ADDR") {
            config.server_addr = server_addr;
        }
        if let Ok(listen_addr) = env::var("LISTEN_ADDR") {
            config.listen_addr = listen_addr;
        }
        if let Ok(listen_port) = env::var("LISTEN_PORT") {
            config.listen_port = listen_port.parse().unwrap_or(config.listen_port);
        }
        if let Ok(log_level) = env::var("LOG_LEVEL") {
            config.logging.log_level = log_level;
        }

        // Override UDP configuration settings
        if let Ok(mtu) = env::var("MTU") {
            config.mtu = Some(mtu.parse().unwrap_or(config.mtu.unwrap_or(1500)));
        }
        if let Ok(buffer_size) = env::var("BUFFER_SIZE") {
            config.buffer_size = Some(buffer_size.parse().unwrap_or(config.buffer_size.unwrap_or(8192))); // Default to 8 KB if not provided
        }
        if let Ok(timeout) = env::var("CONNECTION_TIMEOUT") {
            config.connection_timeout = Some(timeout.parse().unwrap_or(config.connection_timeout.unwrap_or(30)));
        }

        // Override rate limit configuration
        if let Ok(rate_limit) = env::var("RATE_LIMIT") {
            config.rate_limit = Some(rate_limit.parse().unwrap_or(config.rate_limit.unwrap_or(1024 * 1024))); // Default to 1 MB/s if not provided
        }

        // Override compression algorithm configuration
        if let Ok(algorithm) = env::var("COMPRESSION_ALGORITHM") {
            config.compression.algorithm = algorithm;
        }

        // Override flow control threshold configuration
        if let Ok(flow_control_threshold) = env::var("FLOW_CONTROL_THRESHOLD") {
            config.flow_control_threshold = Some(flow_control_threshold.parse().unwrap_or(config.flow_control_threshold.unwrap_or(1024 * 1024))); // Default to 1 MB if not provided
        }

        // Override max packet size configuration
        if let Ok(max_packet_size) = env::var("MAX_PACKET_SIZE") {
            config.max_packet_size = Some(max_packet_size.parse().unwrap_or(config.max_packet_size.unwrap_or(8192))); // Default to 8 KB if not provided
        }

        // Override OS-level receive buffer size
        if let Ok(recv_buf) = env::var("RECV_BUFFER_SIZE") {
            config.recv_buffer_size = Some(recv_buf.parse().unwrap_or(config.recv_buffer_size.unwrap_or(1048576)));
        }
        // Override OS-level send buffer size
        if let Ok(send_buf) = env::var("SEND_BUFFER_SIZE") {
            config.send_buffer_size = Some(send_buf.parse().unwrap_or(config.send_buffer_size.unwrap_or(1048576)));
        }

        Ok(config)
    }
}