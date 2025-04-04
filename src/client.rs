use crate::tunnel::Tunnel;
use crate::config::Config;
use crate::net::{calculate_max_payload_size, discover_path_mtu};
use socket2::Socket;
use std::net::UdpSocket as StdUdpSocket;
use async_trait::async_trait;
use log::{info, error};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::task;
use std::sync::Arc;
use std::net::SocketAddr;
use tokio::time::{sleep, Duration}; // For rate limiting
use crate::packet_utils::{frame_chunks, deframe_chunks}; // Updated import

pub struct Client {
    pub config: Config,
    pub socket: Arc<Mutex<UdpSocket>>,  // Add socket field to Client
    pub server_addr: SocketAddr,
}

// Implement Clone for Client
impl Clone for Client {
    fn clone(&self) -> Self {
        Client {
            config: self.config.clone(),
            socket: Arc::clone(&self.socket),
            server_addr: self.server_addr,
        }
    }
}

#[async_trait]
impl Tunnel for Client {
    async fn start(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {  // mutable self
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
        std_socket.set_nonblocking(true)
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

        let configured_mtu = self.config.udp.mtu.unwrap_or(1500);
        let enable = self.config.udp.enable_mtu_discovery.unwrap_or(false);
        let target = self.server_addr;
        let discovered_mtu = discover_path_mtu(configured_mtu.into(), target, enable);

        let max_packet_size = self.config.udp.max_packet_size.unwrap_or_else(|| calculate_max_payload_size(discovered_mtu));

        let message = b"ping from client";

        // Spawn a task for sending data concurrently
        let socket_clone = Arc::clone(&self.socket); // Clone the Arc pointer
        let client_clone = self.clone(); // Clone the entire client struct

        task::spawn(async move {
            let socket = socket_clone.lock().await; // Lock the socket

            // Apply rate limiting based on configuration
            if let Some(rate_limit) = client_clone.config.udp.rate_limit {
                let rate_limit_bytes = rate_limit as f64;

                let sent_data = message.len() as f64;
                let sleep_duration = Duration::from_secs_f64(sent_data / rate_limit_bytes);

                // Sleep to respect the rate limit
                sleep(sleep_duration).await;
            }

            if message.len() <= max_packet_size {
                match socket.send_to(message, &client_clone.server_addr).await {
                    Ok(_) => {
                        info!("Sent message to server");
                    }
                    Err(e) => {
                        error!("Failed to send message: {}", e);
                    }
                }
            } else {
                error!("Message size {} exceeds max_packet_size {}, dropping", message.len(), max_packet_size);
            }
        });

        // Receiving response concurrently
        let mut buf = [0u8; 1500];
        let len = {
            let socket = self.socket.lock().await; // Lock the socket for receiving
            match socket.recv_from(&mut buf).await {
                Ok((size, _)) => size,
                Err(e) => {
                    error!("Failed to receive data: {}", e);
                    return Err(Box::new(e));
                }
            }
        };
        
        info!("Received from server: {}", String::from_utf8_lossy(&buf[..len]));

        Ok(())
    }

    // Implementing send_data with rate limiting and packet splitting
    async fn send_data(&self, data: &[u8], addr: SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
        let configured_mtu = self.config.udp.mtu.unwrap_or(1500);
        let enable = self.config.udp.enable_mtu_discovery.unwrap_or(false);
        let discovered_mtu = discover_path_mtu(configured_mtu.into(), addr, enable);
        let max_packet_size = self.config.udp.max_packet_size.unwrap_or_else(|| calculate_max_payload_size(discovered_mtu));

        let socket = self.socket.lock().await;  // Lock the socket for sending
        
        // Apply rate limiting based on configuration
        if let Some(rate_limit) = self.config.udp.rate_limit {
            let rate_limit_bytes = rate_limit as f64;

            let sent_data = data.len() as f64;
            let sleep_duration = Duration::from_secs_f64(sent_data / rate_limit_bytes);

            // Sleep to respect the rate limit
            sleep(sleep_duration).await;
        }

        // Check if data fits within max packet size
        if data.len() <= max_packet_size {
            socket.send_to(data, addr).await?;
        } else {
            // Update MTU-based packet sizing
            let msg_id: u32 = rand::random(); // Updated to generate message ID
            let chunks = frame_chunks(data, max_packet_size - 8, msg_id); // Updated to frame chunks

            // Send each chunk
            for chunk in chunks {
                socket.send_to(&chunk, addr).await?;
            }
        }

        Ok(())
    }

    // Implementing receive_data
    async fn receive_data(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let configured_mtu = self.config.udp.mtu.unwrap_or(1500);
        let enable = self.config.udp.enable_mtu_discovery.unwrap_or(false);
        let discovered_mtu = discover_path_mtu(configured_mtu.into(), self.server_addr, enable);
        let max_packet_size = self.config.udp.max_packet_size.unwrap_or_else(|| calculate_max_payload_size(discovered_mtu));

        let socket = self.socket.lock().await;  // Lock the socket for receiving
        let mut buf = vec![0u8; max_packet_size];  // Buffer for received data
        let (size, _) = socket.recv_from(&mut buf).await?;

        // Sanity check for received data size
        if size > max_packet_size {
            return Err("Received packet exceeds max_packet_size".into());
        }

        // Check if received data fits within max packet size
        let reassembled_data = match deframe_chunks(vec![buf[..size].to_vec()]) { // Updated to use deframe_chunks
            Some(data) => data,
            None => return Err("Failed to reassemble packet".into()),
        };

        Ok(reassembled_data)
    }
}