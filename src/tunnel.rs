use async_trait::async_trait;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, RwLock};
use std::sync::Arc;
use std::net::SocketAddr;
use log::{info, error};
use crate::config::Config;
use tokio::time::{sleep, Duration}; // For rate limiting
use crate::net::{calculate_max_payload_size, discover_path_mtu}; // Import for calculating max payload size and discovering MTU
use socket2::Socket;
use std::net::UdpSocket as StdUdpSocket;

// Correct imports for LZ4 and Zstd compression
use lz4::block::{self, CompressionMode};
use zstd::stream;
use crate::packet_utils::{frame_chunks, deframe_chunks}; // Updated imports

use rand::random; // Added import

#[async_trait]
pub trait Tunnel {
    async fn start(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;  // mutable self
    async fn send_data(&self, data: &[u8], addr: SocketAddr) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
    async fn receive_data(&self) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>>;
}

#[derive(Clone)]
pub struct TunnelImpl {
    pub config: Config,
    pub socket: Arc<RwLock<UdpSocket>>,  // Wrap socket in Arc<RwLock> to allow read concurrency
}

impl TunnelImpl {
    pub fn new(config: Config, addr: SocketAddr) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let std_socket = StdUdpSocket::bind(addr)?;
        std_socket.set_nonblocking(true)?;
        let socket2 = Socket::from(std_socket);

        if let Some(recv_buf) = config.udp.recv_buffer_size {
            socket2.set_recv_buffer_size(recv_buf)?;
            info!("Set receive buffer size to {}", recv_buf);
        }

        if let Some(send_buf) = config.udp.send_buffer_size {
            socket2.set_send_buffer_size(send_buf)?;
            info!("Set send buffer size to {}", send_buf);
        }

        let std_socket = socket2.into();
        let socket = UdpSocket::from_std(std_socket)?;

        Ok(TunnelImpl { 
            config, 
            socket: Arc::new(RwLock::new(socket)),  // Wrap in Arc<RwLock> for concurrency
        })
    }

    async fn handle_connection(&self, data: Vec<u8>, addr: SocketAddr) {
        // Process received data
        info!("Received data from {}: {:?}", addr, data);

        // Simulate some processing
        if let Err(e) = self.send_data(&data, addr).await {
            error!("Error sending data: {}", e);
        }
    }
}

pub async fn compress_data(data: &[u8], algorithm: &str) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let data = data.to_vec();
    let algorithm = algorithm.to_string(); // Clone the algorithm to ensure 'static lifetime
    tokio::task::spawn_blocking(move || {
        match algorithm.as_str() {
            "lz4" => {
                let compressed_data = block::compress(&data, Some(CompressionMode::default()), false)?;
                Ok(compressed_data)
            }
            "zstd" => {
                let compressed_data = stream::encode_all(std::io::Cursor::new(&data), 3)?;
                Ok(compressed_data)
            }
            _ => Err("Unsupported compression algorithm!".into()),
        }
    })
    .await?
}

pub async fn decompress_data(data: &[u8], algorithm: &str) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let data = data.to_vec();
    let algorithm = algorithm.to_string(); // Clone the algorithm to ensure 'static lifetime
    tokio::task::spawn_blocking(move || {
        match algorithm.as_str() {
            "lz4" => {
                let decompressed_data = block::decompress(&data, None)?;
                Ok(decompressed_data)
            }
            "zstd" => {
                let decompressed_data = stream::decode_all(std::io::Cursor::new(&data))?;
                Ok(decompressed_data)
            }
            _ => Err("Unsupported compression algorithm!".into()),
        }
    })
    .await?
}

#[async_trait]
impl Tunnel for TunnelImpl {
    async fn start(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> { 
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(32); // Channel for sending data

        // Convert server_addr from String to SocketAddr
        let mut addrs = tokio::net::lookup_host(self.config.server_addr.clone()).await?;
        let server_addr = addrs.next().ok_or("Invalid server address")?;

        // Set the buffer size based on the configuration
        let buffer_size: usize = self.config.udp.buffer_size.unwrap_or(8192);  // Use buffer_size from config or default to 8192 bytes

        // Apply buffer size to the socket (for both receive and send)
        let socket = self.socket.clone();  // Clone the Arc pointer for concurrency
        tokio::spawn(async move {
            loop {
                let mut buf = vec![0u8; buffer_size]; // Dynamic buffer size
                match socket.read().await.recv_from(&mut buf).await {
                    Ok((size, src)) => {
                        info!("Received data from {}", src);
                        let data = buf[..size].to_vec();
                        if let Err(e) = tx.send(data).await {
                            error!("Failed to send data to channel: {}", e);
                        }
                    }
                    Err(e) => {
                        error!("Error receiving UDP packet: {}", e);
                    }
                }
            }
        });

        // Handle the received data
        while let Some(data) = rx.recv().await {
            self.handle_connection(data, server_addr).await;
        }

        Ok(())
    }

    async fn send_data(&self, data: &[u8], addr: SocketAddr) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let socket = self.socket.read().await;  // Lock the socket for sending
        
        // Apply rate limiting based on configuration
        if let Some(rate_limit) = self.config.udp.rate_limit {
            let rate_limit_bytes = rate_limit as f64;

            let sent_data = data.len() as f64;
            let sleep_duration = Duration::from_secs_f64(sent_data / rate_limit_bytes);

            // Sleep to respect the rate limit
            sleep(sleep_duration).await;
        }

        // Discover path MTU
        let configured_mtu = self.config.udp.mtu.unwrap_or(1500);
        let enable_discovery = self.config.udp.enable_mtu_discovery.unwrap_or(false);
        let discovered_mtu = discover_path_mtu(configured_mtu.into(), addr, enable_discovery);
        let max_packet_size = self.config.udp.max_packet_size.unwrap_or_else(|| calculate_max_payload_size(discovered_mtu.into()));
        info!("Using max_packet_size: {}", max_packet_size);

        // Get the selected compression algorithm
        let compression_algorithm = self.config.compression.algorithm.clone();  // Retrieve compression algorithm

        // Compress data based on user selection
        let compressed_data = compress_data(&data, &compression_algorithm).await?;

        // Use frame_chunks to chunk the data
        let msg_id: u32 = random();
        let chunks = frame_chunks(&compressed_data, max_packet_size - 8, msg_id); // Updated line

        // Send each chunk
        for chunk in chunks {
            socket.send_to(&chunk, addr).await?;
        }

        Ok(())
    }

    async fn receive_data(&self) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let socket = self.socket.read().await;  // Lock the socket for receiving
        let mut buf = vec![0u8; self.config.udp.buffer_size.unwrap_or(1024)]; // Use dynamic buffer size
        let (size, _) = socket.recv_from(&mut buf).await?;

        // Use deframe_chunks to reassemble the data
        let reassembled_data = match deframe_chunks(vec![buf[..size].to_vec()]) { // Updated line
            Some(data) => data,
            None => return Err("Failed to reassemble packet".into()),
        };

        // Get the selected compression algorithm
        let compression_algorithm = self.config.compression.algorithm.clone();  // Retrieve compression algorithm

        // Decompress received data based on user selection
        let decompressed_data = decompress_data(&reassembled_data, &compression_algorithm).await?;

        Ok(decompressed_data)
    }
}