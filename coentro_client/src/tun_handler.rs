//! TUN Interface Handler for the CoentroVPN Client
//!
//! This module handles the TUN interface provided by the helper daemon.
//! It reads packets from the TUN interface and forwards them to the QUIC tunnel,
//! and vice versa.

#[cfg(feature = "tun-metrics")]
use metrics::{counter, histogram};
use shared_utils::transport::Connection as TransportConnection;
use std::io::{self, Read, Write};
use std::os::unix::io::{FromRawFd, RawFd};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{broadcast, mpsc, Mutex};
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

/// Maximum packet size for TUN interface (hard cap)
const MAX_PACKET_SIZE: usize = 1500;
/// Minimum packet size we'll allow for MTU clamping
const MIN_PACKET_SIZE: usize = 576;

#[cfg(feature = "tun-metrics")]
const METRIC_TUN_BYTES: &str = "coentrovpn_client_tun_bytes_total";
#[cfg(feature = "tun-metrics")]
const METRIC_TUN_PACKETS: &str = "coentrovpn_client_tun_packets_total";
#[cfg(feature = "tun-metrics")]
const METRIC_TUN_PACKET_SIZE: &str = "coentrovpn_client_tun_packet_size_bytes";

#[cfg(feature = "tun-metrics")]
fn record_packet_metrics(direction: &'static str, len: usize) {
    counter!(METRIC_TUN_PACKETS, 1, "direction" => direction);
    counter!(METRIC_TUN_BYTES, len as u64, "direction" => direction);
    histogram!(METRIC_TUN_PACKET_SIZE, len as f64, "direction" => direction);
}

#[cfg(not(feature = "tun-metrics"))]
fn record_packet_metrics(_direction: &'static str, _len: usize) {}

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

    /// Bounded maximum frame size used for buffers and validation
    fn max_frame_len(&self) -> usize {
        let mtu = self.mtu as usize;
        mtu.clamp(MIN_PACKET_SIZE, MAX_PACKET_SIZE)
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
            return Err(io::Error::other("Packet channels not created"));
        }

        // Get the packet channels
        let packet_tx = self.packet_tx.take().unwrap();
        let mut packet_rx = self.packet_rx.take().unwrap();
        let max_frame = self.max_frame_len();
        let iface_name = self.interface_name.clone();

        // Create a file from the TUN file descriptor
        let tun_file = unsafe { std::fs::File::from_raw_fd(self.tun_fd) };
        let tun_file = Arc::new(Mutex::new(tun_file));

        // Clone for the read task
        let tun_file_read = Arc::clone(&tun_file);
        let read_iface = iface_name.clone();

        // Spawn a task to read from the TUN interface and send to the QUIC tunnel
        let read_task = tokio::spawn(async move {
            let mut buffer = vec![0u8; max_frame];
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
                record_packet_metrics("tun_to_transport", n);

                // Send the packet to the QUIC tunnel
                let packet = buffer[..n].to_vec();
                if let Err(e) = packet_tx.send(packet).await {
                    error!(
                        iface = %read_iface,
                        "Error sending packet to QUIC tunnel: {}",
                        e
                    );
                    break;
                }
            }
        });

        // Spawn a task to receive from the QUIC tunnel and write to the TUN interface
        let write_task = tokio::spawn(async move {
            while let Some(packet) = packet_rx.recv().await {
                debug!("Received {} bytes from QUIC tunnel", packet.len());

                if packet.len() > max_frame {
                    warn!(
                        iface = %iface_name,
                        size = packet.len(),
                        max = max_frame,
                        "Dropping oversize packet headed to TUN"
                    );
                    continue;
                }
                record_packet_metrics("transport_to_tun", packet.len());

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
#[allow(dead_code)]
pub async fn start_tun_quic_tunnel<P: PacketProcessor + 'static>(
    mut tun_handler: TunHandler,
    quic_stream_rx: impl AsyncRead + Unpin + Send + 'static,
    quic_stream_tx: impl AsyncWrite + Unpin + Send + 'static,
    processor: Arc<P>,
    buffer_size: usize,
) -> io::Result<()> {
    let max_frame = tun_handler.max_frame_len();
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
        let mut buffer = vec![0u8; max_frame];
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
            if packet_len == 0 || packet_len > max_frame {
                warn!(
                    "Dropping oversize or empty packet from QUIC (len={}, max={})",
                    packet_len, max_frame
                );
                // Drain the body to keep stream in sync without allocating unbounded memory
                let mut discard = (&mut quic_reader).take(packet_len as u64);
                let _ = tokio::io::copy(&mut discard, &mut tokio::io::sink()).await;
                continue;
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

            if processed_packet.len() > max_frame {
                warn!(
                    size = processed_packet.len(),
                    max = max_frame,
                    "Dropping processed QUIC packet larger than max frame"
                );
                continue;
            }

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

            if processed_packet.len() > max_frame {
                warn!(
                    size = processed_packet.len(),
                    max = max_frame,
                    "Dropping TUN packet larger than max frame for QUIC stream"
                );
                continue;
            }

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

/// Start a TUN-to-transport bridge using a shared_utils transport Connection
pub async fn start_tun_transport_bridge<P: PacketProcessor + 'static>(
    mut tun_handler: TunHandler,
    connection: Box<dyn TransportConnection + Send + Sync>,
    processor: Arc<P>,
    buffer_size: usize,
) -> io::Result<BridgeHandle> {
    let max_frame = tun_handler.max_frame_len();
    let iface_label = tun_handler.interface_name().to_string();
    // Create packet channels
    let (quic_to_tun_tx, mut tun_to_quic_rx) = tun_handler.create_packet_channels(buffer_size);
    let (shutdown_tx, _) = broadcast::channel::<()>(1);

    // Start TUN processing
    let mut tun_shutdown = shutdown_tx.subscribe();
    let tun_task = tokio::spawn(async move {
        if let Err(e) = tun_handler.start_processing().await {
            error!("TUN processing error: {}", e);
        }
        let _ = tun_shutdown.recv().await;
    });

    // Task: read from transport and forward to TUN
    let processor_clone = Arc::clone(&processor);
    let connection_arc = Arc::new(Mutex::new(connection));
    let conn_reader = Arc::clone(&connection_arc);
    let mut read_shutdown = shutdown_tx.subscribe();
    let max_frame_from_transport = max_frame;
    let iface_from_transport = iface_label.clone();
    let read_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = read_shutdown.recv() => {
                    info!("Transport->TUN reader received shutdown");
                    break;
                }
                result = async {
                    let mut conn = conn_reader.lock().await;
                    conn.recv_data().await
                } => {
                    match result {
                        Ok(Some(data)) => {
                            debug!("Transport->TUN received {} bytes", data.len());
                            if data.len() > max_frame_from_transport {
                                warn!(
                                    iface = %iface_from_transport,
                                    size = data.len(),
                                    max = max_frame_from_transport,
                                    "Dropping oversize packet from transport before TUN"
                                );
                                continue;
                            }
                            match processor_clone.process_quic_to_tun(&data).await {
                                Ok(pkt) => {
                                    if let Err(e) = quic_to_tun_tx.send(pkt).await {
                                        error!("Failed to send packet to TUN: {}", e);
                                        break;
                                    }
                                }
                                Err(e) => {
                                    error!("Error processing transport->TUN packet: {}", e);
                                }
                            }
                        }
                        Ok(None) => {
                            info!("Transport closed by peer");
                            break;
                        }
                        Err(e) => {
                            error!("Transport recv error: {}", e);
                            break;
                        }
                    }
                }
            }
        }
    });

    // Task: read from TUN and send to transport
    let conn_writer = Arc::clone(&connection_arc);
    let mut write_shutdown = shutdown_tx.subscribe();
    let max_frame_to_transport = max_frame;
    let iface_to_transport = iface_label;
    let write_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = write_shutdown.recv() => {
                    info!("TUN->Transport writer received shutdown");
                    break;
                }
                maybe_packet = tun_to_quic_rx.recv() => {
                    let Some(packet) = maybe_packet else { break; };
                    debug!("TUN->Transport sending {} bytes", packet.len());
                    if packet.len() > max_frame_to_transport {
                        warn!(
                            iface = %iface_to_transport,
                            size = packet.len(),
                            max = max_frame_to_transport,
                            "Dropping oversize packet from TUN before transport send"
                        );
                        continue;
                    }
                    match processor.process_tun_to_quic(&packet).await {
                        Ok(pkt) => {
                            let mut conn = conn_writer.lock().await;
                            if let Err(e) = conn.send_data(&pkt).await {
                                error!("Transport send error: {}", e);
                                break;
                            }
                        }
                        Err(e) => {
                            error!("Error processing TUN->transport packet: {}", e);
                        }
                    }
                }
            }
        }
    });

    Ok(BridgeHandle {
        shutdown: shutdown_tx,
        tun_task,
        read_task,
        write_task,
    })
}

/// Handle to cooperatively shut down the TUN<->transport bridge.
pub struct BridgeHandle {
    shutdown: broadcast::Sender<()>,
    tun_task: JoinHandle<()>,
    read_task: JoinHandle<()>,
    write_task: JoinHandle<()>,
}

impl BridgeHandle {
    pub async fn shutdown(self) {
        let _ = self.shutdown.send(());
        let _ = self.tun_task.await;
        let _ = self.read_task.await;
        let _ = self.write_task.await;
    }
}
