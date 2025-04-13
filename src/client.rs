use crate::config::Config;
use crate::context::{ControlPayload, HandshakePayload, MessageContext, MessageType};
use crate::net::{calculate_max_payload_size, discover_mtu, discover_path_mtu};
use crate::observability::PACKETS_TOTAL; // Added import for Prometheus counter
use crate::packet_utils::decompress_data;
use crate::packet_utils::{deframe_chunks, frame_chunks, ReassemblyBuffer};
use crate::tunnel::Tunnel;
use crate::utils::bind_socket; // Import the centralized binding function
use async_trait::async_trait;
use bincode::config::standard;
use bincode::serde::encode_to_vec as serialize;
use socket2::Socket;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::net::UdpSocket as StdUdpSocket;
use std::sync::Arc;
use std::time::Duration; // For rate limiting
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::task;
use tokio::time::sleep; // For rate limiting
use tracing::{error, info, info_span, trace};
use uuid::Uuid; // Added import for HashSet

pub struct Client {
    pub config: Config,
    pub socket: Arc<Mutex<UdpSocket>>,
    pub server_addr: SocketAddr,
    pub session_id: Uuid,
    pub reassembly_buffer: Arc<Mutex<ReassemblyBuffer>>,
    pub received_message_ids: Arc<Mutex<HashSet<u64>>>, // Added field for deduplication
}

// Implement Clone for Client
impl Clone for Client {
    fn clone(&self) -> Self {
        Client {
            config: self.config.clone(),
            socket: Arc::clone(&self.socket),
            server_addr: self.server_addr,
            session_id: self.session_id,
            reassembly_buffer: Arc::clone(&self.reassembly_buffer),
            received_message_ids: Arc::clone(&self.received_message_ids), // Cloning the new field
        }
    }
}

#[async_trait]
impl Tunnel for Client {
    async fn start(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // mutable self
        let span = info_span!("client_start", session_id = %self.session_id);
        let _enter = span.enter();
        let local = "0.0.0.0:0"; // Bind to a random port
        let server = format!("{}:{}", self.config.server_addr, self.config.listen_port);

        // Convert server address string to SocketAddr with error handling
        self.server_addr = match server.parse() {
            Ok(addr) => addr,
            Err(e) => {
                error!("Failed to parse server address: {}", e);
                return Err(Box::new(e));
            }
        };

        let std_socket = StdUdpSocket::bind(local)
            .map_err(|e| format!("Failed to bind UDP socket on {}: {}", local, e))?;
        std_socket
            .set_nonblocking(true)
            .map_err(|e| format!("Failed to set non-blocking mode: {}", e))?;
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
        self.socket = Arc::new(Mutex::new(socket));
        info!("Client socket bound to {}", local);

        // Initialize reassembly buffer
        self.reassembly_buffer =
            Arc::new(Mutex::new(ReassemblyBuffer::new(Duration::from_secs(10))));
        self.received_message_ids = Arc::new(Mutex::new(HashSet::new())); // Initialize the deduplication set

        let configured_mtu = self.config.udp.mtu.unwrap_or(1500);
        let enable = self.config.udp.enable_mtu_discovery.unwrap_or(false);
        let target = self.server_addr;
        let discovered_mtu = discover_path_mtu(configured_mtu.into(), target, enable);

        let max_packet_size = self
            .config
            .udp
            .max_packet_size
            .unwrap_or_else(|| calculate_max_payload_size(discovered_mtu));

        let handshake = HandshakePayload {
            session_id: self.session_id,
            client_info: "client-rust".to_string(),
        };

        let handshake_bytes = serialize(&handshake, standard())?;
        let handshake_ctx = MessageContext {
            message_id: rand::random::<u64>(),
            session_id: self.session_id,
            size: handshake_bytes.len(),
            message_type: MessageType::Handshake,
        };

        self.send_data(&handshake_bytes, self.server_addr).await?;

        // Receiving response concurrently
        let response = self.receive_data().await?;
        info!(
            "Received from server: {}",
            String::from_utf8_lossy(&response)
        );

        let heartbeat = b"heartbeat";
        let hb_ctx = MessageContext {
            message_id: rand::random::<u64>(),
            session_id: self.session_id,
            size: heartbeat.len(),
            message_type: MessageType::Heartbeat,
        };
        self.send_data(heartbeat, self.server_addr).await?;

        Ok(())
    }

    // Implementing send_data with rate limiting and packet splitting
    async fn send_data(
        &self,
        data: &[u8],
        addr: SocketAddr,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let configured_mtu = self.config.udp.mtu.unwrap_or(1500);
        let enable = self.config.udp.enable_mtu_discovery.unwrap_or(false);
        let discovered_mtu = discover_path_mtu(configured_mtu.into(), addr, enable);
        let max_packet_size = self
            .config
            .udp
            .max_packet_size
            .unwrap_or_else(|| calculate_max_payload_size(discovered_mtu));

        info!("Using max_packet_size: {}", max_packet_size); // Moved line

        let socket = self.socket.lock().await; // Lock the socket for sending

        let msg_id: u32 = rand::random(); // Updated to generate message ID
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
            let sleep_duration = if rate_limit_bytes > 0.0 {
                Duration::from_secs_f64(sent_data / rate_limit_bytes)
            } else {
                Duration::from_secs(0)
            };

            // Sleep to respect the rate limit
            sleep(sleep_duration).await;
        }

        // Check if data fits within max packet size
        if data.len() <= max_packet_size {
            socket.send_to(data, addr).await?;
        } else {
            // Update MTU-based packet sizing
            let chunks = frame_chunks(
                data,
                max_packet_size - 8,
                msg_id,
                msg_ctx.message_type.to_u8(),
            );
            PACKETS_TOTAL.inc_by(chunks.len() as u64); // Increment metric after preparing chunks
                                                       // Send each chunk
            for chunk in chunks {
                socket.send_to(&chunk, addr).await?;
            }
        }

        Ok(())
    }

    // Implementing receive_data
    async fn receive_data(&self) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let configured_mtu = self.config.udp.mtu.unwrap_or(1500);
        let enable = self.config.udp.enable_mtu_discovery.unwrap_or(false);
        let discovered_mtu = discover_path_mtu(configured_mtu.into(), self.server_addr, enable);
        let max_packet_size = self
            .config
            .udp
            .max_packet_size
            .unwrap_or_else(|| calculate_max_payload_size(discovered_mtu));

        let socket = self.socket.lock().await; // Lock the socket for receiving
        let mut buf = vec![0u8; max_packet_size]; // Buffer for received data
        let (size, _) = socket.recv_from(&mut buf).await?;

        // Sanity check for received data size
        if size > max_packet_size {
            return Err("Received packet exceeds max_packet_size".into());
        }

        let mut buffer = self.reassembly_buffer.lock().await;
        buffer.purge_expired();
        let reassembled_data = match buffer.insert(buf[..size].to_vec()) {
            Some(data) => data,
            None => {
                error!("Reassembly failed: awaiting more chunks");
                return Err("Failed to reassemble packet".into());
            }
        };

        // Decompress if compression is configured
        let decompressed_data =
            decompress_data(&reassembled_data, &self.config.compression.algorithm).await?; // Added decompression

        let msg_ctx = MessageContext {
            message_id: buffer.last_msg_id().unwrap_or(0).into(),
            session_id: self.session_id,
            size: decompressed_data.len(),
            message_type: MessageType::Data,
        };

        // Deduplication check
        let mut seen = self.received_message_ids.lock().await;
        if seen.contains(&msg_ctx.message_id) {
            PACKETS_TOTAL.inc(); // Increment received counter before returning
            return Err("Duplicate message_id received".into());
        }
        seen.insert(msg_ctx.message_id);

        if msg_ctx.message_type == MessageType::Ack {
            trace!("Received ACK for message_id: {}", msg_ctx.message_id);
            return Ok(vec![]); // Acknowledge and exit early
        }

        let span = info_span!(
            "message_receive",
            session_id = %msg_ctx.session_id,
            message_type = %msg_ctx.message_type,  // using Display impl
            size = msg_ctx.size
        );
        let _enter = span.enter();

        match msg_ctx.message_type {
            MessageType::Control => {
                trace!(
                    "Received Control message: {:?}",
                    String::from_utf8_lossy(&reassembled_data)
                );
            }
            MessageType::Heartbeat => {
                trace!(
                    "Received Heartbeat message: {:?}",
                    String::from_utf8_lossy(&reassembled_data)
                );
            }
            _ => {}
        }

        PACKETS_TOTAL.inc(); // Increment received counter before returning
        Ok(decompressed_data) // Updated return value
    }
}

pub fn connect_to_server() {
    let config = Config::builder()
        .add_source(config::File::with_name("Config.toml"))
        .build()
        .expect("Failed to load configuration");

    let mtu = discover_mtu(&config);
    println!("Using MTU: {}", mtu);

    let server_addr = config
        .get_string("server_addr")
        .expect("Missing server_addr");

    let client_socket =
        bind_socket(&format!("{}:0", server_addr)).expect("Failed to bind client socket");

    let mut paused = false;

    // Example client loop
    loop {
        if paused {
            // Wait for a signal from the server to resume
            if check_server_ready_signal() {
                paused = false;
                println!("Resuming data transmission...");
            }
            continue;
        }

        // Prepare data to send
        let data = b"Hello, server!"; // Example payload
        let max_packet_size = config.get_int("udp.max_packet_size").unwrap_or(1400) as usize;

        // Check if data fits within max packet size
        if data.len() <= max_packet_size {
            client_socket
                .send_to(data, server_addr.clone())
                .expect("Failed to send data");
            println!("Sent data: {:?}", String::from_utf8_lossy(data));
        } else {
            // Split data into chunks and send each chunk
            let chunks = frame_chunks(data, max_packet_size - 8, 1, 0); // Example message ID and type
            for chunk in chunks {
                client_socket
                    .send_to(&chunk, server_addr.clone())
                    .expect("Failed to send chunk");
                println!("Sent chunk: {:?}", chunk);
            }
        }

        // Simulate receiving a backpressure signal
        if received_backpressure_signal() {
            paused = true;
            println!("Paused sending due to backpressure signal from server");
        }
    }
}

fn received_backpressure_signal() -> bool {
    // Logic to detect backpressure signal from the server
    // For now, simulate backpressure randomly
    use rand::Rng;
    rand::thread_rng().gen_bool(0.1) // 10% chance of backpressure
}

fn check_server_ready_signal() -> bool {
    // Logic to detect readiness signal from the server
    // For now, simulate readiness randomly
    use rand::Rng;
    rand::thread_rng().gen_bool(0.9) // 90% chance of readiness
}
