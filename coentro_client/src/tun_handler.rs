//! TUN Interface Handler for the CoentroVPN Client
//!
//! This module handles the TUN interface provided by the helper daemon.
//! It reads packets from the TUN interface and forwards them to the QUIC tunnel,
//! and vice versa.

use log::{debug, error, info, warn};
use std::io::{self, Read, Write};
use std::os::unix::io::{FromRawFd, RawFd};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex};

/// Maximum packet size for TUN interface
const MAX_PACKET_SIZE: usize = 1500;

/// TUN interface handler
#[allow(dead_code)]
pub struct TunHandler {
    /// TUN interface file descriptor
    tun_fd: RawFd,
    /// TUN interface name
    interface_name: String,
    /// TUN interface IP configuration
    ip_config: String,
    /// TUN interface MTU
    mtu: u32,
    /// Packet sender for outgoing packets (to QUIC tunnel)
    packet_tx: Option<mpsc::Sender<Vec<u8>>>,
    /// Packet receiver for incoming packets (from QUIC tunnel)
    packet_rx: Option<mpsc::Receiver<Vec<u8>>>,
}

impl TunHandler {
    /// Create a new TUN handler from the given file descriptor and details
    pub fn new(tun_fd: RawFd, interface_name: String, ip_config: String, mtu: u32) -> Self {
        Self {
            tun_fd,
            interface_name,
            ip_config,
            mtu,
            packet_tx: None,
            packet_rx: None,
        }
    }

    /// Get the TUN interface name
    #[allow(dead_code)]
    pub fn interface_name(&self) -> &str {
        &self.interface_name
    }

    /// Get the TUN interface IP configuration
    #[allow(dead_code)]
    pub fn ip_config(&self) -> &str {
        &self.ip_config
    }

    /// Get the TUN interface MTU
    #[allow(dead_code)]
    pub fn mtu(&self) -> u32 {
        self.mtu
    }

    /// Create packet channels for communication with the QUIC tunnel
    pub fn create_packet_channels(
        &mut self,
        buffer_size: usize,
    ) -> (mpsc::Sender<Vec<u8>>, mpsc::Receiver<Vec<u8>>) {
        // Create channels for packets
        let (tun_to_quic_tx, tun_to_quic_rx) = mpsc::channel(buffer_size);
        let (quic_to_tun_tx, quic_to_tun_rx) = mpsc::channel(buffer_size);

        // Store the channels
        self.packet_tx = Some(tun_to_quic_tx);
        self.packet_rx = Some(quic_to_tun_rx);

        // Return the other ends of the channels
        (quic_to_tun_tx, tun_to_quic_rx)
    }

    /// Start processing packets
    pub async fn start_processing(&mut self) -> io::Result<()> {
        // Make sure we have channels
        if self.packet_tx.is_none() || self.packet_rx.is_none() {
            return Err(io::Error::other(
                "Packet channels not created",
            ));
        }

        // Get the packet channels
        let packet_tx = self.packet_tx.take().unwrap();
        let mut packet_rx = self.packet_rx.take().unwrap();

        // Create a file from the TUN file descriptor
        let tun_file = unsafe { std::fs::File::from_raw_fd(self.tun_fd) };
        let tun_file = Arc::new(Mutex::new(tun_file));

        // Clone for the read task
        let tun_file_read = Arc::clone(&tun_file);

        // Spawn a task to read from the TUN interface and send to the QUIC tunnel
        let read_task = tokio::spawn(async move {
            let mut buffer = vec![0u8; MAX_PACKET_SIZE];
            loop {
                // Read from the TUN interface
                let n = {
                    let mut file = tun_file_read.lock().await;
                    match file.read(&mut buffer) {
                        Ok(n) => n,
                        Err(e) => {
                            error!("Error reading from TUN interface: {}", e);
                            break;
                        }
                    }
                };

                if n == 0 {
                    warn!("TUN interface closed");
                    break;
                }

                debug!("Read {} bytes from TUN interface", n);

                // Send the packet to the QUIC tunnel
                let packet = buffer[..n].to_vec();
                if let Err(e) = packet_tx.send(packet).await {
                    error!("Error sending packet to QUIC tunnel: {}", e);
                    break;
                }
            }
        });

        // Spawn a task to receive from the QUIC tunnel and write to the TUN interface
        let write_task = tokio::spawn(async move {
            while let Some(packet) = packet_rx.recv().await {
                debug!("Received {} bytes from QUIC tunnel", packet.len());

                // Write to the TUN interface
                let result = {
                    let mut file = tun_file.lock().await;
                    file.write_all(&packet)
                };

                if let Err(e) = result {
                    error!("Error writing to TUN interface: {}", e);
                    break;
                }
            }
        });

        // Wait for both tasks to complete
        tokio::select! {
            _ = read_task => {
                warn!("TUN read task completed");
            }
            _ = write_task => {
                warn!("TUN write task completed");
            }
        }

        Ok(())
    }
}

/// Packet processor trait for handling packets between TUN and QUIC
#[async_trait::async_trait]
pub trait PacketProcessor: Send + Sync {
    /// Process a packet from the TUN interface to the QUIC tunnel
    async fn process_tun_to_quic(&self, packet: &[u8]) -> io::Result<Vec<u8>>;

    /// Process a packet from the QUIC tunnel to the TUN interface
    async fn process_quic_to_tun(&self, packet: &[u8]) -> io::Result<Vec<u8>>;
}

/// Start a TUN-to-QUIC tunnel with the given packet processor
pub async fn start_tun_quic_tunnel<P: PacketProcessor + 'static>(
    mut tun_handler: TunHandler,
    quic_stream_rx: impl AsyncRead + Unpin + Send + 'static,
    quic_stream_tx: impl AsyncWrite + Unpin + Send + 'static,
    processor: Arc<P>,
    buffer_size: usize,
) -> io::Result<()> {
    // Create packet channels
    let (quic_to_tun_tx, mut tun_to_quic_rx) = tun_handler.create_packet_channels(buffer_size);

    // Start TUN processing
    let tun_task = tokio::spawn(async move {
        if let Err(e) = tun_handler.start_processing().await {
            error!("TUN processing error: {}", e);
        }
    });

    // Wrap the QUIC stream in a BufReader/BufWriter for efficiency
    let mut quic_reader = tokio::io::BufReader::new(quic_stream_rx);
    let mut quic_writer = tokio::io::BufWriter::new(quic_stream_tx);

    // Spawn a task to read from the QUIC tunnel and send to the TUN interface
    let processor_clone = Arc::clone(&processor);
    let quic_read_task = tokio::spawn(async move {
        let mut buffer = vec![0u8; MAX_PACKET_SIZE];
        loop {
            // Read the packet length
            let mut len_bytes = [0u8; 2];
            if let Err(e) = quic_reader.read_exact(&mut len_bytes).await {
                if e.kind() == io::ErrorKind::UnexpectedEof {
                    info!("QUIC stream closed");
                } else {
                    error!("Error reading packet length from QUIC stream: {}", e);
                }
                break;
            }

            let packet_len = u16::from_be_bytes(len_bytes) as usize;
            if packet_len == 0 || packet_len > MAX_PACKET_SIZE {
                error!("Invalid packet length: {}", packet_len);
                break;
            }

            // Read the packet
            if let Err(e) = quic_reader.read_exact(&mut buffer[..packet_len]).await {
                error!("Error reading packet from QUIC stream: {}", e);
                break;
            }

            debug!("Read {} bytes from QUIC stream", packet_len);

            // Process the packet
            let processed_packet = match processor_clone
                .process_quic_to_tun(&buffer[..packet_len])
                .await
            {
                Ok(packet) => packet,
                Err(e) => {
                    error!("Error processing packet from QUIC to TUN: {}", e);
                    continue;
                }
            };

            // Send the packet to the TUN interface
            if let Err(e) = quic_to_tun_tx.send(processed_packet).await {
                error!("Error sending packet to TUN interface: {}", e);
                break;
            }
        }
    });

    // Spawn a task to read from the TUN interface and send to the QUIC tunnel
    let quic_write_task = tokio::spawn(async move {
        while let Some(packet) = tun_to_quic_rx.recv().await {
            debug!("Received {} bytes from TUN interface", packet.len());

            // Process the packet
            let processed_packet = match processor.process_tun_to_quic(&packet).await {
                Ok(packet) => packet,
                Err(e) => {
                    error!("Error processing packet from TUN to QUIC: {}", e);
                    continue;
                }
            };

            // Write the packet length
            let packet_len = processed_packet.len() as u16;
            if let Err(e) = quic_writer.write_all(&packet_len.to_be_bytes()).await {
                error!("Error writing packet length to QUIC stream: {}", e);
                break;
            }

            // Write the packet
            if let Err(e) = quic_writer.write_all(&processed_packet).await {
                error!("Error writing packet to QUIC stream: {}", e);
                break;
            }

            // Flush the writer
            if let Err(e) = quic_writer.flush().await {
                error!("Error flushing QUIC stream: {}", e);
                break;
            }
        }
    });

    // Wait for all tasks to complete
    tokio::select! {
        _ = tun_task => {
            warn!("TUN task completed");
        }
        _ = quic_read_task => {
            warn!("QUIC read task completed");
        }
        _ = quic_write_task => {
            warn!("QUIC write task completed");
        }
    }

    Ok(())
}

/// A simple pass-through packet processor that doesn't modify packets
pub struct PassThroughProcessor;

#[async_trait::async_trait]
impl PacketProcessor for PassThroughProcessor {
    async fn process_tun_to_quic(&self, packet: &[u8]) -> io::Result<Vec<u8>> {
        Ok(packet.to_vec())
    }

    async fn process_quic_to_tun(&self, packet: &[u8]) -> io::Result<Vec<u8>> {
        Ok(packet.to_vec())
    }
}
