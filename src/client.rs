use crate::tunnel::Tunnel;
use crate::config::Config;
use crate::net::calculate_max_payload_size;
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

pub struct Client {
    pub config: Config,
    pub socket: Arc<Mutex<UdpSocket>>,  // Add socket field to Client
}

// Implement Clone for Client
impl Clone for Client {
    fn clone(&self) -> Self {
        Client {
            config: self.config.clone(),
            socket: Arc::clone(&self.socket),
        }
    }
}

#[async_trait]
impl Tunnel for Client {
    async fn start(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {  // mutable self
        let local = "0.0.0.0:0"; // Bind to a random port
        let server = format!("{}:{}", self.config.server_addr, self.config.listen_port);
        
        // Convert server address string to SocketAddr with error handling
        let server_addr: SocketAddr = match server.parse() {
            Ok(addr) => addr,
            Err(e) => {
                error!("Failed to parse server address: {}", e);
                return Err(Box::new(e));
            }
        };

        let std_socket = StdUdpSocket::bind(local)?;
        std_socket.set_nonblocking(true)?;
        let socket2 = Socket::from(std_socket);

        if let Some(recv_buf) = self.config.recv_buffer_size {
            socket2.set_recv_buffer_size(recv_buf)?;
            info!("Set receive buffer size to {}", recv_buf);
        }

        if let Some(send_buf) = self.config.send_buffer_size {
            socket2.set_send_buffer_size(send_buf)?;
            info!("Set send buffer size to {}", send_buf);
        }

        let std_socket = socket2.into();
        let socket = UdpSocket::from_std(std_socket)?;
        self.socket = Arc::new(Mutex::new(socket));
        info!("Client socket bound to {}", local);

        let message = b"ping from client";

        // Spawn a task for sending data concurrently
        let socket_clone = Arc::clone(&self.socket); // Clone the Arc pointer
        let client_clone = self.clone(); // Clone the entire client struct

        task::spawn(async move {
            let socket = socket_clone.lock().await; // Lock the socket

            // Apply rate limiting based on configuration
            if let Some(rate_limit) = client_clone.config.rate_limit {
                let rate_limit_bytes = rate_limit as f64;

                let sent_data = message.len() as f64;
                let sleep_duration = Duration::from_secs_f64(sent_data / rate_limit_bytes);

                // Sleep to respect the rate limit
                sleep(sleep_duration).await;
            }

            match socket.send_to(message, &server_addr).await {
                Ok(_) => {
                    info!("Sent message to server");
                }
                Err(e) => {
                    error!("Failed to send message: {}", e);
                }
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
        let socket = self.socket.lock().await;  // Lock the socket for sending
        
        // Apply rate limiting based on configuration
        if let Some(rate_limit) = self.config.rate_limit {
            let rate_limit_bytes = rate_limit as f64;

            let sent_data = data.len() as f64;
            let sleep_duration = Duration::from_secs_f64(sent_data / rate_limit_bytes);

            // Sleep to respect the rate limit
            sleep(sleep_duration).await;
        }

        // Update MTU-based packet sizing
        let mtu = self.config.mtu.unwrap_or(1500);
        let max_packet_size = self.config.max_packet_size.unwrap_or_else(|| calculate_max_payload_size(mtu.into()));

        // Split data into chunks based on max packet size
        let chunks = self.split_packet(data, max_packet_size);

        // Send each chunk
        for chunk in chunks {
            socket.send_to(&chunk, addr).await?;
        }

        Ok(())
    }

    // Implementing receive_data
    async fn receive_data(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let socket = self.socket.lock().await;  // Lock the socket for receiving
        let mut buf = vec![0u8; 1024];  // Buffer for received data
        let (size, _) = socket.recv_from(&mut buf).await?;

        // Update MTU-based packet sizing
        let mtu = self.config.mtu.unwrap_or(1500);
        let max_packet_size = self.config.max_packet_size.unwrap_or_else(|| calculate_max_payload_size(mtu.into()));

        // Split the received data if necessary (can be adjusted based on your needs)
        let chunks = self.split_packet(&buf[..size], max_packet_size);

        // Reassemble the chunks into a full packet
        let reassembled_data = self.reassemble_packets(chunks);

        Ok(reassembled_data)
    }
}

impl Client {
    // Function to split large data into smaller chunks
    fn split_packet(&self, data: &[u8], max_size: usize) -> Vec<Vec<u8>> {
        data.chunks(max_size)
            .map(|chunk| chunk.to_vec())
            .collect()
    }

    // Function to reassemble split packets into a complete packet
    fn reassemble_packets(&self, chunks: Vec<Vec<u8>>) -> Vec<u8> {
        chunks.into_iter().flatten().collect()
    }
}