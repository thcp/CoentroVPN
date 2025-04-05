use crate::tunnel::Tunnel;
use crate::config::Config;
use crate::net::{calculate_max_payload_size, discover_path_mtu};
use async_trait::async_trait;
use tracing::{info, error, debug, trace}; // Updated to use structured logging
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use std::sync::Arc;
use std::net::SocketAddr;
use tokio::time::{sleep, Duration}; // For rate limiting
use socket2::Socket;
use std::net::UdpSocket as StdUdpSocket;
use crate::packet_utils::{split_packet, frame_chunks, deframe_chunks};
use crate::context::{Direction, ChunkContext}; // Added imports
use uuid::Uuid; // Add this at the top

pub struct Server {
    pub config: Config,
    pub socket: Arc<Mutex<UdpSocket>>,
    pub session_id: Uuid, // Updated struct
}

#[async_trait]
impl Tunnel for Server {
    async fn start(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.session_id = Uuid::new_v4(); // Inserted line
        debug!(session_id = %self.session_id, "New server session started");

        let addr = format!("{}:{}", self.config.listen_addr, self.config.listen_port);
        info!("Server listening on {}", addr);

        let std_socket = StdUdpSocket::bind(&addr)
            .map_err(|e| format!("Failed to bind UDP socket on {}: {}", addr, e))?;
        std_socket.set_nonblocking(true)
            .map_err(|e| format!("Failed to set non-blocking mode on {}: {}", addr, e))?;
        let socket2 = Socket::from(std_socket);

        if let Some(recv_buf) = self.config.udp.recv_buffer_size {
            socket2.set_recv_buffer_size(recv_buf)?;
            info!("Set receive buffer size to {}", recv_buf);
        }

        if let Some(send_buf) = self.config.udp.send_buffer_size {
            socket2.set_send_buffer_size(send_buf)?;
            info!("Set send buffer size to {}", send_buf);
        }

        let std_socket = socket2.into();
        let socket = UdpSocket::from_std(std_socket)
            .map_err(|e| format!("Failed to create Tokio UdpSocket: {}", e))?;
        let socket = Arc::new(Mutex::new(socket));
        self.socket = socket;

        // Perform MTU discovery once
        let mtu = self.config.udp.mtu.unwrap_or(1500);
        let enable_discovery = self.config.udp.enable_mtu_discovery.unwrap_or(false);
        let discovered_mtu = discover_path_mtu(mtu.into(), addr.parse()?, enable_discovery);
        let max_size = self.config.udp.max_packet_size.unwrap_or_else(|| calculate_max_payload_size(discovered_mtu));

        info!(
            "Server initialized with discovered MTU = {}, max_packet_size = {}",
            discovered_mtu, max_size
        );

        let mut buf = [0u8; 1500];
        loop {
            let (len, peer) = match self.socket.lock().await.recv_from(&mut buf).await {
                Ok(res) => res,
                Err(e) => {
                    error!("Failed to receive data: {}", e);
                    continue;
                }
            };

            info!("Received {} bytes from {}", len, peer);
            trace!("Processing packet: {:?}", &buf[..len]);

            if let Some(rate_limit) = self.config.udp.rate_limit {
                let rate_limit_bytes = rate_limit as f64;
                let sent_data = buf.len() as f64;
                let sleep_duration = if rate_limit_bytes > 0.0 {
                    Duration::from_secs_f64(sent_data / rate_limit_bytes)
                } else {
                    Duration::from_secs(0)
                };
                sleep(sleep_duration).await;
            }

            let chunks = if len <= max_size {
                vec![buf[..len].to_vec()]
            } else {
                split_packet(&buf[..len], max_size)
            };

            let socket_clone = Arc::clone(&self.socket);
            let peer_clone = peer.clone();

            for chunk in chunks {
                let socket_clone = Arc::clone(&socket_clone);
                let chunk_clone = chunk.clone();

                tokio::spawn(async move {
                    let socket = socket_clone.lock().await;
                    if let Err(e) = socket.send_to(&chunk_clone, peer_clone).await {
                        error!("Failed to send data to {}: {}", peer_clone, e);
                    }

                    info!("Echoed {} bytes back to {}", chunk_clone.len(), peer_clone);
                });
            }
        }
    }

    async fn send_data(&self, data: &[u8], addr: SocketAddr) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let socket = self.socket.lock().await;

        if let Some(rate_limit) = self.config.udp.rate_limit {
            let rate_limit_bytes = rate_limit as f64;
            let sent_data = data.len() as f64;
            let sleep_duration = if rate_limit_bytes > 0.0 {
                Duration::from_secs_f64(sent_data / rate_limit_bytes)
            } else {
                Duration::from_secs(0)
            };
            sleep(sleep_duration).await;
        }

        let mtu = self.config.udp.mtu.unwrap_or(1500);
        let enable_discovery = self.config.udp.enable_mtu_discovery.unwrap_or(false);
        let discovered_mtu = discover_path_mtu(mtu.into(), addr, enable_discovery);
        let max_size = self.config.udp.max_packet_size.unwrap_or_else(|| calculate_max_payload_size(discovered_mtu));

        let msg_id: u32 = rand::random(); // Added random message ID
        let chunk_preview = frame_chunks(&data, max_size - 8, msg_id);
        let total_chunks = chunk_preview.len() as u32;

        debug!(
            message_id = msg_id,
            total_chunks,
            compressed_size = data.len(),
            "Prepared message for sending"
        );

        for (chunk_id, chunk) in chunk_preview.into_iter().enumerate() { // Updated for loop
            let ctx = ChunkContext {
                message_id: msg_id as u64,
                chunk_id: chunk_id as u32,
                total_chunks: Some(total_chunks),
                direction: Direction::Outbound,
            };

            trace!( // Added tracing
                message_id = ctx.message_id,
                chunk_id = ctx.chunk_id,
                total_chunks = ?ctx.total_chunks,
                direction = %ctx.direction,
                size = chunk.len(),
                "Sending chunk"
            );

            socket.send_to(&chunk, addr).await?;
        }

        Ok(())
    }

    async fn receive_data(&self) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let socket = self.socket.lock().await;  // Lock the socket for receiving
        let mut buf = vec![0u8; 1024];
        let (size, _) = socket.recv_from(&mut buf).await?;

        let reassembled_data = match deframe_chunks(vec![buf[..size].to_vec()]) { // Updated to use deframe_chunks
            Some(data) => data,
            None => return Err("Failed to reassemble packet".into()),
        };

        trace!( // Added tracing
            direction = %Direction::Inbound,
            size = reassembled_data.len(),
            "Received and decompressed message"
        );

        debug!( // Added debug logging
            size = reassembled_data.len(),
            "Successfully received and reassembled message"
        );

        Ok(reassembled_data) // Use reassembled_data here
    }
}

impl Server {
}