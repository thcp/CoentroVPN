use crate::config::Config;
use crate::context::{
    ChunkContext, ControlPayload, Direction, HandshakePayload, MessageContext, MessageType,
}; // Added ControlPayload and HandshakePayload
use crate::net::{calculate_max_payload_size, discover_path_mtu};
use crate::observability::PACKETS_TOTAL; // Added import for Prometheus counter
use crate::packet_utils::decompress_data;
use crate::packet_utils::{deframe_chunks, frame_chunks, split_packet, ReassemblyBuffer}; // Added ReassemblyBuffer
use crate::tunnel::Tunnel;
use async_trait::async_trait;
use bincode::config::standard; // Added bincode imports
use bincode::serde::decode_from_slice as deserialize; // Added bincode imports
use socket2::Socket;
use std::collections::HashSet; // Added for deduplication
use std::fmt;
use std::net::SocketAddr;
use std::net::UdpSocket as StdUdpSocket;
use std::sync::Arc;
use std::time::Duration; // Included Duration
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::sync::Mutex as TokioMutex;
use tokio::time::sleep; // For rate limiting
use tracing::info_span;
use tracing::{debug, error, info, trace}; // Updated to use structured logging
use uuid::Uuid; // Added for deduplication
use tokio::net::TcpListener;
use tokio::io::AsyncWriteExt;

pub struct Server {
    pub config: Config,
    pub socket: Arc<Mutex<UdpSocket>>,
    pub session_id: Uuid,                                // Updated struct
    pub reassembly_buffer: Arc<Mutex<ReassemblyBuffer>>, // Added reassembly_buffer
    pub received_message_ids: Arc<Mutex<HashSet<u64>>>,  // Added for deduplication
}

impl Server {
    pub async fn start_health_checks(&self, health_addr: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let listener = TcpListener::bind(health_addr).await?;
        info!("Health check server running on {}", health_addr);

        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((mut socket, _)) => {
                        let response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
                        if let Err(e) = socket.write_all(response.as_bytes()).await {
                            error!("Failed to respond to health check: {}", e);
                        }
                    }
                    Err(e) => {
                        error!("Failed to accept health check connection: {}", e);
                    }
                }
            }
        });

        Ok(())
    }
}

#[async_trait]
impl Tunnel for Server {
    async fn start(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.session_id = Uuid::new_v4(); // Inserted line
        let span = info_span!("server_start", session_id = %self.session_id);
        let _enter = span.enter();
        debug!(session_id = %self.session_id, "New server session started");

        let addr = format!("{}:{}", self.config.listen_addr, self.config.listen_port);
        info!("Server listening on {}", addr);

        let std_socket = StdUdpSocket::bind(&addr)
            .map_err(|e| format!("Failed to bind UDP socket on {}: {}", addr, e))?;
        std_socket
            .set_nonblocking(true)
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

        self.reassembly_buffer =
            Arc::new(Mutex::new(ReassemblyBuffer::new(Duration::from_secs(10)))); // Added reassembly_buffer initialization
        self.received_message_ids = Arc::new(Mutex::new(HashSet::new())); // Added for deduplication

        // Perform MTU discovery once
        let mtu = self.config.udp.mtu.unwrap_or(1500);
        let enable_discovery = self.config.udp.enable_mtu_discovery.unwrap_or(false);
        let discovered_mtu = discover_path_mtu(mtu.into(), addr.parse()?, enable_discovery);
        let max_size = self
            .config
            .udp
            .max_packet_size
            .unwrap_or_else(|| calculate_max_payload_size(discovered_mtu));

        info!(
            "Server initialized with discovered MTU = {}, max_packet_size = {}",
            discovered_mtu, max_size
        );

        // Validate and use health_addr from Config.toml
        let health_addr: String = self
            .config
            .observability
            .health_addr
            .clone();


        self.start_health_checks(&health_addr).await?;

        loop {
            let mut buf = [0u8; 1500];
            let (len, peer) = match self.socket.lock().await.recv_from(&mut buf).await {
                Ok(res) => res,
                Err(e) => {
                    error!("Failed to receive data: {}", e);
                    continue;
                }
            };

            let received_data = match self.receive_data().await {
                Ok(data) => data,
                Err(e) => {
                    error!("Failed to receive or process data: {}", e);
                    continue;
                }
            };

            info!(
                "Received {} bytes from {}: {:?}",
                received_data.len(),
                peer,
                String::from_utf8_lossy(&received_data)
            );

            if let Err(e) = self.send_data(&received_data, peer).await {
                error!("Failed to send response to {}: {}", peer, e);
            }
        }
    }

    async fn send_data(
        &self,
        data: &[u8],
        addr: SocketAddr,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let socket = self.socket.lock().await;

        let msg_id: u32 = rand::random(); // Added random message ID
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
        let max_size = self
            .config
            .udp
            .max_packet_size
            .unwrap_or_else(|| calculate_max_payload_size(discovered_mtu));

        info!("Using max_packet_size: {}", max_size); // Moved line here

        let chunks = frame_chunks(&data, max_size - 8, msg_id, msg_ctx.message_type.to_u8());
        PACKETS_TOTAL.inc_by(chunks.len() as u64);
        let total_chunks = chunks.len() as u32;

        debug!(
            message_id = msg_id,
            total_chunks,
            compressed_size = data.len(),
            "Prepared message for sending"
        );

        for (chunk_id, chunk) in chunks.into_iter().enumerate() {
            // Updated for loop
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
                size = chunk.len(),
                direction = %ctx.direction,
                "Sending chunk"
            );

            socket.send_to(&chunk, addr).await?;
        }

        Ok(())
    }

    async fn receive_data(&self) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let socket = self.socket.lock().await; // Lock the socket for receiving
        let mut buf = vec![0u8; 1024];
        let (size, _) = socket.recv_from(&mut buf).await?;

        let mut buffer = self.reassembly_buffer.lock().await; // Updated to use ReassemblyBuffer
        buffer.purge_expired();
        let reassembled_data = match buffer.insert(buf[..size].to_vec()) {
            Some(data) => data,
            None => {
                error!("Reassembly failed: awaiting more chunks");
                return Err("Failed to reassemble packet".into());
            }
        };

        let msg_ctx = MessageContext {
            message_id: buffer.last_msg_id().unwrap_or(0).into(),
            session_id: self.session_id,
            size: reassembled_data.len(),
            message_type: MessageType::Data,
        };
        if msg_ctx.message_type == MessageType::Ack {
            trace!("Received ACK for message_id: {}", msg_ctx.message_id);
            return Ok(vec![]); // Acknowledge and exit early
        }

        let mut seen = self.received_message_ids.lock().await; // Added deduplication check
        if seen.contains(&msg_ctx.message_id) {
            PACKETS_TOTAL.inc(); // Increment total packets
            return Err("Duplicate message_id received".into());
        }
        seen.insert(msg_ctx.message_id); // Insert message_id into the set

        let span = info_span!(
            "message_receive",
            session_id = %msg_ctx.session_id,
            message_type = %msg_ctx.message_type,
            size = msg_ctx.size
        );
        let _enter = span.enter();

        trace!( // Added tracing
            direction = %Direction::Inbound,
            size = reassembled_data.len(),
            "Received and decompressed message"
        );

        debug!(
            // Added debug logging
            size = reassembled_data.len(),
            "Successfully received and reassembled message"
        );

        match msg_ctx.message_type {
            MessageType::Control => {
                match deserialize::<ControlPayload, _>(&reassembled_data, standard()) {
                    Ok((payload, _)) => {
                        trace!("Deserialized ControlPayload: {:?}", payload);
                    }
                    Err(e) => {
                        trace!("Failed to deserialize ControlPayload: {:?}", e);
                    }
                }
            }
            MessageType::Heartbeat => {
                match deserialize::<crate::context::HeartbeatPayload, _>(
                    &reassembled_data,
                    standard(),
                ) {
                    Ok((payload, _)) => {
                        trace!("Deserialized HeartbeatPayload: {:?}", payload);
                    }
                    Err(e) => {
                        trace!("Failed to deserialize HeartbeatPayload: {:?}", e);
                    }
                }
            }
            MessageType::Handshake => {
                match deserialize::<HandshakePayload, _>(&reassembled_data, standard()) {
                    Ok((payload, _)) => {
                        trace!("Deserialized HandshakePayload: {:?}", payload);
                    }
                    Err(e) => {
                        trace!("Failed to deserialize HandshakePayload: {:?}", e);
                    }
                }
            }
            _ => {}
        }

        PACKETS_TOTAL.inc(); // Added metric increment
        Ok(reassembled_data) // Use reassembled_data here
    }
}

impl fmt::Display for MessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MessageType::Control => write!(f, "control"),
            MessageType::Data => write!(f, "data"),
            MessageType::Handshake => write!(f, "handshake"),
            MessageType::Heartbeat => write!(f, "heartbeat"),
            MessageType::Ack => write!(f, "ack"),
            MessageType::Unknown(code) => write!(f, "unknown({})", code),
        }
    }
}
