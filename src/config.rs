use serde::Deserialize;
use std::{env, fs};
use tracing::info;

#[async_trait::async_trait]
pub trait Tunnel: Send + Sync {
    async fn start(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
    async fn send_data(
        &self,
        data: &[u8],
        addr: std::net::SocketAddr,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
    async fn receive_data(&self) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>>;
}

#[derive(Debug, Deserialize, Clone)]
pub struct LoggingConfig {
    pub log_level: String, // Log level (e.g., "debug", "info", "error")
    pub format: String,    // "json" or "pretty"
}

#[derive(Debug, Deserialize, Clone)]
pub struct CompressionConfig {
    pub algorithm: String, // Compression algorithm (e.g., "gzip", "zstd")
    pub min_compression_size: Option<usize>, // Minimum size for compression
}

#[derive(Debug, Deserialize, Clone)]
pub struct UdpConfig {
    pub mtu: Option<usize>,
    pub buffer_size: usize,
    pub rate_limit: Option<usize>,
    pub max_packet_size: Option<usize>,
    pub flow_control_threshold: usize,
    pub recv_buffer_size: usize,
    pub send_buffer_size: usize,
    pub enable_mtu_discovery: bool,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ObservabilityConfig {
    pub metrics_addr: String,
    pub health_addr: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub mode: String,
    pub server_addr: String,
    pub listen_port: u16,
    pub listen_addr: String,
    pub logging: LoggingConfig,
    pub compression: CompressionConfig,
    pub udp: UdpConfig,
    pub observability: ObservabilityConfig,
}

impl Config {
    pub fn from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        info!("Loading config from {}", path);
        let contents = fs::read_to_string(path)?;
        let config: Config = toml::from_str(&contents)?;
        Ok(config)
    }

    pub fn from_env_or_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let mut config = Self::from_file(path)?;

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
        if let Ok(min_size) = env::var("COMPRESSION_MIN_SIZE") {
            config.compression.min_compression_size = Some(min_size.parse().unwrap_or(512));
        }
        if let Ok(mtu) = env::var("UDP_MTU") {
            config.udp.mtu = Some(mtu.parse().unwrap_or(1500));
        }
        if let Ok(buffer_size) = env::var("UDP_BUFFER_SIZE") {
            config.udp.buffer_size = buffer_size.parse().unwrap_or(8192);
        }
        if let Ok(rate_limit) = env::var("UDP_RATE_LIMIT") {
            config.udp.rate_limit = Some(rate_limit.parse().unwrap_or(1000));
        }
        if let Ok(max_packet_size) = env::var("UDP_MAX_PACKET_SIZE") {
            config.udp.max_packet_size = Some(max_packet_size.parse().unwrap_or(1400));
        }
        if let Ok(threshold) = env::var("UDP_FLOW_CONTROL_THRESHOLD") {
            config.udp.flow_control_threshold = threshold.parse().unwrap_or(500);
        }
        if let Ok(recv_buf) = env::var("UDP_RECV_BUFFER_SIZE") {
            config.udp.recv_buffer_size = recv_buf.parse().unwrap_or(1048576);
        }
        if let Ok(send_buf) = env::var("UDP_SEND_BUFFER_SIZE") {
            config.udp.send_buffer_size = send_buf.parse().unwrap_or(1048576);
        }
        if let Ok(enable_mtu) = env::var("UDP_ENABLE_MTU_DISCOVERY") {
            config.udp.enable_mtu_discovery = enable_mtu.parse().unwrap_or(true);
        }

        Ok(config)
    }

    pub fn validate(&self) -> Result<(), String> {
        if let Some(size) = self.compression.min_compression_size {
            if size < 64 {
                return Err(format!(
                    "compression.min_compression_size must be >= 64, got {}",
                    size
                ));
            }
        }
        Ok(())
    }
}
