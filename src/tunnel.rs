use tokio::net::UdpSocket;
use tokio::sync::{mpsc, RwLock};
use std::sync::Arc;
use std::net::SocketAddr;
use tracing::{info, error, debug, trace, info_span}; // Updated to use structured logging
use crate::config::Config;
use tokio::time::{sleep, Duration}; // For rate limiting
use crate::net::{calculate_max_payload_size, discover_path_mtu}; // Import for calculating max payload size and discovering MTU
use socket2::Socket;
use std::net::UdpSocket as StdUdpSocket;
use uuid::Uuid;
use lz4::block::{self, CompressionMode};
use zstd::stream;
use crate::packet_utils::{frame_chunks, deframe_chunks};
use rand::random;
use crate::context::{Direction, ChunkContext, MessageContext, MessageType}; // Added MessageContext and MessageType
use async_trait::async_trait;

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
    pub session_id: Uuid, // Added session_id
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
            session_id: Uuid::new_v4(), // Initialize session_id
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
        debug!(session_id = %self.session_id, "Tunnel session started");

        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(32); // Channel for sending data

        // Convert server_addr from String to SocketAddr
        let mut addrs = tokio::net::lookup_host(self.config.server_addr.clone()).await?;
        let server_addr = addrs.next().ok_or("Invalid server address")?;
        info!("Starting tunnel with server address: {}", server_addr);

        // Set the buffer size based on the configuration
        let buffer_size: usize = self.config.udp.buffer_size.unwrap_or(8192);  // Use buffer_size from config or default to 8192 bytes

        // Apply buffer size to the socket (for both receive and send)
        let socket = self.socket.clone();  // Clone the Arc pointer for concurrency
        tokio::spawn(async move {
            loop {
                let socket = socket.read().await;
                let mut buf = vec![0u8; buffer_size]; // Dynamic buffer size
                match socket.recv_from(&mut buf).await {
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
        
        let msg_id: u32 = random();
        let msg_ctx = MessageContext {
            message_id: msg_id as u64,
            session_id: self.session_id,
            size: data.len(),
            message_type: MessageType::Data,
        };

        let span = info_span!(
            "message_send",
            message_id = msg_ctx.message_id,
            session_id = %msg_ctx.session_id,
            message_type = %msg_ctx.message_type,
            size = msg_ctx.size
        );
        let _enter = span.enter();

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
        info!("Using max_packet_size: {}", max_packet_size); // Moved line

        // Get the selected compression algorithm
        let compression_algorithm = self.config.compression.algorithm.clone();  // Retrieve compression algorithm
        trace!("Compressing data with algorithm: {}", compression_algorithm);
        // Compress data based on user selection
        let compressed_data = compress_data(&data, &compression_algorithm).await?;
        let chunks = frame_chunks(&compressed_data, max_packet_size - 8, msg_id);
        let total_chunks = chunks.len() as u32;

        debug!(
            message_id = msg_id,
            total_chunks,
            compressed_size = compressed_data.len(),
            "Prepared message for sending"
        );

        // Send each chunk
        for (chunk_id, chunk) in chunks.into_iter().enumerate() {
            let ctx = ChunkContext {
                message_id: msg_id as u64,
                chunk_id: chunk_id as u32,
                total_chunks: Some(total_chunks),
                direction: Direction::Outbound,
            };

            trace!(
                message_id = ctx.message_id,
                chunk_id = ctx.chunk_id,
                total_chunks = ?ctx.total_chunks,
                size = chunk.len(),
                direction = %ctx.direction, // Rearranged fields
                "Sending chunk"
            );

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
            None => {
                error!("Deframe failed for received packet, discarding");
                return Err("Failed to reassemble packet".into());
            }
        };

        let msg_ctx = MessageContext {
            message_id: 0, // TODO: parse actual message_id from chunk when available
            session_id: self.session_id,
            size: reassembled_data.len(),
            message_type: MessageType::Data,
        };

        let span = info_span!(
            "message_receive",
            session_id = %msg_ctx.session_id,
            message_type = %msg_ctx.message_type,
            size = msg_ctx.size
        );
        let _enter = span.enter();

        // Get the selected compression algorithm
        let compression_algorithm = self.config.compression.algorithm.clone();  // Retrieve compression algorithm

        // Decompress received data based on user selection
        let decompressed_data = decompress_data(&reassembled_data, &compression_algorithm).await?;

        debug!(
            size = decompressed_data.len(),
            "Successfully received and reassembled message"
        );

        trace!(
            direction = %Direction::Inbound,
            size = decompressed_data.len(),
            "Received and decompressed message"
        );

        Ok(decompressed_data)
    }
}