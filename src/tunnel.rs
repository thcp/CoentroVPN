use async_trait::async_trait;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, RwLock};
use std::sync::Arc;
use std::net::{SocketAddr, ToSocketAddrs};
use log::{info, error};
use crate::config::Config;
use tokio::time::{sleep, Duration}; // For rate limiting
use crate::net::{calculate_max_payload_size, discover_path_mtu}; // Import for calculating max payload size and discovering MTU
use socket2::Socket;
use std::net::UdpSocket as StdUdpSocket;

// Correct imports for LZ4 and Zstd compression
use lz4::block::{compress as lz4_compress, CompressionMode};
use zstd::stream::encode_all as zstd_compress;

#[async_trait]
pub trait Tunnel {
    async fn start(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;  // mutable self
    async fn send_data(&self, data: &[u8], addr: SocketAddr) -> Result<(), Box<dyn std::error::Error>>;
    async fn receive_data(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>>;
}

#[derive(Clone)]
pub struct TunnelImpl {
    pub config: Config,
    pub socket: Arc<RwLock<UdpSocket>>,  // Wrap socket in Arc<RwLock> to allow read concurrency
}

impl TunnelImpl {
    pub fn new(config: Config, addr: SocketAddr) -> Result<Self, Box<dyn std::error::Error>> {
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

    // Correctly updated compress_data function
    async fn compress_data(data: &[u8], algorithm: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        match algorithm {
            "lz4" => {
                // LZ4 compression with default mode (None) and no prepended size
                let compressed_data = lz4_compress(data, Some(CompressionMode::default()), false)?;
                Ok(compressed_data)
            }
            "zstd" => {
                // Zstd compression with compression level 3
                let compressed_data = zstd_compress(data, 3)?; // Compression level 3 for Zstd
                Ok(compressed_data)
            }
            _ => Err("Unsupported compression algorithm!".into()),
        }
    }

    // Implement packet splitting logic
    fn split_packet(data: &[u8], max_size: usize) -> Vec<Vec<u8>> {
        data.chunks(max_size)
            .map(|chunk| chunk.to_vec())
            .collect()
    }

    // Reassemble the split packets
    fn reassemble_packets(chunks: Vec<Vec<u8>>) -> Vec<u8> {
        chunks.into_iter().flatten().collect()
    }
}

#[async_trait]
impl Tunnel for TunnelImpl {
    async fn start(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> { 
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(32); // Channel for sending data

        // Convert server_addr from String to SocketAddr
        let server_addr: SocketAddr = self.config.server_addr.to_socket_addrs()?.next().ok_or("Invalid server address")?;

        // Set the buffer size based on the configuration
        let buffer_size: usize = self.config.udp.buffer_size.unwrap_or(8192);  // Use buffer_size from config or default to 8192 bytes

        // Apply buffer size to the socket (for both receive and send)
        let socket = self.socket.clone();  // Clone the Arc pointer for concurrency
        tokio::spawn(async move {
            loop {
                let mut buf = vec![0u8; buffer_size]; // Dynamic buffer size
                match socket.write().await.recv_from(&mut buf).await {
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

    async fn send_data(&self, data: &[u8], addr: SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
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
        let compressed_data = TunnelImpl::compress_data(data, &compression_algorithm).await?;

        // Split data into chunks for better handling of large packets
        let chunks = TunnelImpl::split_packet(&compressed_data, max_packet_size);

        // Send each chunk
        for chunk in chunks {
            socket.send_to(&chunk, addr).await?;
        }

        Ok(())
    }

    async fn receive_data(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let socket = self.socket.read().await;  // Lock the socket for receiving
        let mut buf = vec![0u8; self.config.udp.buffer_size.unwrap_or(1024)]; // Use dynamic buffer size
        let (size, _) = socket.recv_from(&mut buf).await?;

        // Assuming the data is chunked, reassemble it before further processing
        let chunks = TunnelImpl::split_packet(&buf[..size], self.config.udp.max_packet_size.unwrap_or(8192));
        let reassembled_data = TunnelImpl::reassemble_packets(chunks);

        // Get the selected compression algorithm
        let compression_algorithm = self.config.compression.algorithm.clone();  // Retrieve compression algorithm

        // Decompress received data based on user selection
        let decompressed_data = TunnelImpl::compress_data(&reassembled_data, &compression_algorithm).await?;

        Ok(decompressed_data)
    }
}