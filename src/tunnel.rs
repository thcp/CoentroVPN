use crate::config::Config;
use crate::context::{MessageContext, MessageType, PendingMessage, SlidingWindow};
use crate::crypto::aes_gcm::AesGcmEncryptor;
use crate::observability::{DUPLICATES_TOTAL, PACKETS_TOTAL, REASSEMBLIES_TOTAL, RETRIES_TOTAL};
use crate::observability::{LATENCY_HISTOGRAM, PACKET_LOSS_GAUGE, THROUGHPUT_GAUGE};
use crate::packet_utils::{
    compress_data, decompress_data, frame_chunks, PacketHeader, ReassemblyBuffer,
};
use bincode::config::standard;
use bincode::serde::{decode_from_slice as deserialize, encode_to_vec as serialize};
use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::Mutex as TokioMutex;
use tokio::task;
use tracing::{debug, info, trace};

#[async_trait::async_trait]
pub trait Tunnel: Send + Sync {
    async fn start(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
    async fn send_data(
        &self,
        data: &[u8],
        addr: std::net::SocketAddr,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
    async fn receive_data(&self) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>>;
}

pub struct TunnelImpl {
    pub config: Config,
    encryptor: Option<AesGcmEncryptor>,
    socket: Arc<tokio::sync::Mutex<UdpSocket>>,
    pub reassembly_buffer: Arc<tokio::sync::Mutex<ReassemblyBuffer>>,
    pub pending_messages: Arc<TokioMutex<HashMap<u64, PendingMessage>>>,
    pub sliding_window: Arc<TokioMutex<SlidingWindow>>,
    pub received_message_ids: Arc<TokioMutex<HashSet<u64>>>,
}

impl TunnelImpl {
    async fn maybe_compress_data(
        data: &[u8],
        algorithm: &str,
        min_size: usize,
        message_type: &MessageType,
    ) -> Result<(Vec<u8>, bool), Box<dyn std::error::Error + Send + Sync>> {
        match message_type {
            MessageType::Control | MessageType::Heartbeat | MessageType::Ack => {
                // Skip compression for control-plane messages and acknowledgments
                return Ok((data.to_vec(), false));
            }
            _ => {}
        }

        if data.len() < min_size {
            // Skip compression if the data size is below the minimum threshold
            trace!(
                "Skipping compression: data size {} is below min_compression_size {}",
                data.len(),
                min_size
            );
            return Ok((data.to_vec(), false));
        }

        let compressed = compress_data(data, algorithm).await?;
        trace!(
            "Compression applied: original size = {}, compressed size = {}",
            data.len(),
            compressed.len()
        );
        Ok((compressed, true))
    }

    pub async fn send_data(
        &self,
        data: Vec<u8>,
        msg_ctx: &MessageContext,
        addr: SocketAddr,
    ) -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error + Send + Sync>> {
        let algorithm = &self.config.compression.algorithm; // Use compression algorithm from config
        let min_size = self.config.compression.min_compression_size.unwrap_or(0); // Use min_compression_size from config

        let (mut payload, compressed) =
            Self::maybe_compress_data(&data, algorithm, min_size, &msg_ctx.message_type).await?;

        let mut encrypted = false;

        let mut window = self.sliding_window.lock().await;
        if window.inflight.len() >= window.max_inflight {
            return Err("Sliding window full. Backpressure applied.".into());
        }
        window.inflight.push(msg_ctx.message_id);
        drop(window);

        match msg_ctx.message_type {
            MessageType::Control | MessageType::Heartbeat | MessageType::Handshake => {
                trace!(
                    "Serializing control-plane message: {:?}",
                    msg_ctx.message_type
                );
                payload = serialize(&data, standard())
                    .map_err(|e| format!("Control message serialization failed: {:?}", e))?;
            }
            _ => { /* existing logic */ }
        }

        if let Some(ref encryptor) = self.encryptor {
            if matches!(msg_ctx.message_type, MessageType::Data) {
                let aad = b""; // optionally pass metadata
                let (ciphertext, nonce) = encryptor.encrypt(&payload, aad).map_err(|e| {
                    Box::<dyn std::error::Error + Send + Sync>::from(format!(
                        "Encryption failed: {:?}",
                        e
                    ))
                })?;
                let mut buf = Vec::with_capacity(12 + ciphertext.len());
                buf.extend_from_slice(&nonce);
                buf.extend_from_slice(&ciphertext);
                payload = buf;
                encrypted = true;
            }
        }

        if encrypted {
            debug!(
                "AES-GCM encryption applied: {} -> {} bytes",
                data.len(),
                payload.len()
            );
        }

        if compressed {
            debug!(
                original_size = data.len(),
                compressed_size = payload.len(),
                ratio = format!("{:.2}", payload.len() as f64 / data.len() as f64),
                "Compression applied"
            );
        } else {
            trace!(
                "Compression skipped (type: {:?}, size: {})",
                msg_ctx.message_type,
                data.len()
            );
        }

        let chunks = frame_chunks(
            &payload,
            1400 - 8,
            msg_ctx.message_id as u32,
            msg_ctx.message_type.to_u8(),
        ); // example MTU logic
        PACKETS_TOTAL.inc_by(chunks.len() as u64);

        let mut pending = self.pending_messages.lock().await;
        pending.insert(
            msg_ctx.message_id,
            PendingMessage {
                message_id: msg_ctx.message_id,
                chunks: chunks.clone(),
                destination: addr,
                last_sent: Instant::now(),
                retries: 0,
                backoff: Duration::from_secs(1), // Initialize with a default backoff duration
            },
        );

        Ok(chunks)
    }

    pub async fn decrypt_if_needed(
        &self,
        data: &[u8],
        msg_type: &MessageType,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        if let Some(ref encryptor) = self.encryptor {
            if matches!(msg_type, MessageType::Data) {
                if data.len() < 12 {
                    return Err("Encrypted payload too short (missing nonce)".into());
                }
                let (nonce_bytes, ciphertext) = data.split_at(12);
                let mut nonce_array = [0u8; 12];
                nonce_array.copy_from_slice(nonce_bytes);
                let aad = b""; // optionally bind to metadata
                let plaintext = encryptor
                    .decrypt(ciphertext, &nonce_array, aad)
                    .map_err(|e| {
                        Box::<dyn std::error::Error + Send + Sync>::from(format!(
                            "Decryption failed: {:?}",
                            e
                        ))
                    })?;
                return Ok(plaintext);
            }
        }
        Ok(data.to_vec())
    }

    pub async fn receive_data(&self) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let start_time = Instant::now(); // Start latency timer
        let socket = self.socket.lock().await;
        let mut buf = [0u8; 1500];
        let (len, peer) = socket.recv_from(&mut buf).await?;
        let received_payload = &buf[..len];

        // Update throughput metric
        THROUGHPUT_GAUGE.set(len as i64);

        let (header, payload) =
            PacketHeader::deserialize(received_payload).ok_or("Failed to parse packet header")?;

        let msg_type = match header.message_type {
            0 => MessageType::Data,
            1 => MessageType::Control,
            2 => MessageType::Control,
            3 => MessageType::Heartbeat,
            4 => MessageType::Handshake,
            5 => MessageType::Ack,
            v => MessageType::Unknown(v),
        };

        let mut dedupe_set = self.received_message_ids.lock().await;
        if dedupe_set.contains(&(header.msg_id as u64)) {
            DUPLICATES_TOTAL.inc();
            PACKET_LOSS_GAUGE.inc(); // Increment packet loss gauge for duplicates
            return Err("Duplicate message detected".into());
        }
        dedupe_set.insert(header.msg_id as u64);

        if matches!(msg_type, MessageType::Ack) {
            let mut pending = self.pending_messages.lock().await;
            if pending.remove(&(header.msg_id as u64)).is_some() {
                let mut window = self.sliding_window.lock().await;
                window.inflight.retain(|id| *id != header.msg_id as u64);
                trace!(
                    "ACK received — message_id {} removed from resend queue",
                    header.msg_id
                );
            }
            return Ok(vec![]); // Early return for ACK messages
        }

        let mut buffer = self.reassembly_buffer.lock().await;
        buffer.purge_expired();
        if let Some(assembled) = buffer.insert(received_payload.to_vec()) {
            let decrypted = self.decrypt_if_needed(&assembled, &msg_type).await?;

            let final_payload = if matches!(msg_type, MessageType::Data) {
                let algorithm = &self.config.compression.algorithm;
                match decompress_data(&decrypted, algorithm).await {
                    Ok(decompressed) => decompressed,
                    Err(e) => {
                        tracing::warn!("Decompression failed: {}", e);
                        decrypted
                    }
                }
            } else {
                decrypted
            };

            match msg_type {
                MessageType::Control => {
                    match deserialize::<crate::context::ControlPayload, _>(
                        &final_payload,
                        standard(),
                    ) {
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
                        &final_payload,
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
                    match deserialize::<crate::context::HandshakePayload, _>(
                        &final_payload,
                        standard(),
                    ) {
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

            PACKETS_TOTAL.inc();
            trace!(
                message_id = header.msg_id,
                "Completed reassembly and decryption"
            );
            REASSEMBLIES_TOTAL.inc();

            if matches!(msg_type, MessageType::Data) {
                trace!("Sending ACK for message_id: {}", header.msg_id);
                let ack_header = PacketHeader {
                    message_type: MessageType::Ack.to_u8(),
                    msg_id: header.msg_id,
                    chunk_id: 0,
                    total_chunks: 1,
                };
                let ack_packet = ack_header.serialize();
                let _ = socket.send_to(&ack_packet, peer).await;
            }

            LATENCY_HISTOGRAM.observe(start_time.elapsed().as_secs_f64()); // Record latency
            return Ok(final_payload);
        } else {
            return Err("Incomplete message: awaiting more chunks".into());
        }
    }

    pub async fn start(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Validate compression settings
        if self.config.compression.min_compression_size.is_some() {
            let min_size = self.config.compression.min_compression_size.unwrap();
            if min_size == 0 {
                return Err("min_compression_size must be greater than 0".into());
            }
        }

        if self.config.compression.algorithm.is_empty() {
            return Err("Compression algorithm must be specified".into());
        }

        // ...existing initialization logic...
        Ok(())
    }

    pub async fn start_resend_loop(self: Arc<Self>) {
        let resend_interval = Duration::from_secs(3);
        let max_retries = 5;
        let max_backoff = Duration::from_secs(30); // Maximum backoff duration
        let socket = self.socket.clone();
        let pending_messages = self.pending_messages.clone();

        tokio::spawn(async move {
            loop {
                tokio::time::sleep(resend_interval).await;

                let mut pending = pending_messages.lock().await;
                let now = Instant::now();

                for msg in pending.values_mut() {
                    if now.duration_since(msg.last_sent) > resend_interval
                        && msg.retries < max_retries
                    {
                        let backoff = Duration::from_secs(2u64.pow(msg.retries.min(5) as u32)); // Exponential backoff
                        if now.duration_since(msg.last_sent) >= backoff {
                            let sock = socket.lock().await;
                            for chunk in &msg.chunks {
                                let _ = sock.send_to(chunk, msg.destination).await;
                            }
                            msg.last_sent = now;
                            msg.retries += 1;
                            RETRIES_TOTAL.inc();
                            trace!(
                                "Resent message_id: {} (retry #{}, backoff: {:?})",
                                msg.message_id,
                                msg.retries,
                                backoff
                            );
                        }
                    }
                }

                let mut window = self.sliding_window.lock().await;
                pending.retain(|msg_id, msg| {
                    let keep = msg.retries < max_retries
                        && now.duration_since(msg.last_sent) <= max_backoff;
                    if !keep {
                        window.inflight.retain(|id| id != msg_id);
                        trace!(
                            "Message_id {} removed due to exceeding retries or timeout",
                            msg_id
                        );
                    }
                    keep
                });
            }
        });
    }
}
