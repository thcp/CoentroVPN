use crate::config::Config;
use crate::context::{MessageContext, MessageType};
use crate::packet_utils::{frame_chunks, PacketHeader, ReassemblyBuffer, compress_data, decompress_data};
use crate::crypto::aes_gcm::AesGcmEncryptor;
use tracing::{debug, trace};
use std::io::Read;
use tokio::task;
use tokio::net::UdpSocket;
use std::sync::Arc;
use std::time::Duration;
use bincode::config::standard;
use bincode::serde::{encode_to_vec as serialize, decode_from_slice as deserialize};

#[async_trait::async_trait]
pub trait Tunnel: Send + Sync {
    async fn start(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
    async fn send_data(&self, data: &[u8], addr: std::net::SocketAddr) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
    async fn receive_data(&self) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>>;
}

pub struct TunnelImpl {
    pub config: Config,
    encryptor: Option<AesGcmEncryptor>,
    socket: Arc<tokio::sync::Mutex<UdpSocket>>,
    pub reassembly_buffer: Arc<tokio::sync::Mutex<ReassemblyBuffer>>,
}

impl TunnelImpl {
    async fn maybe_compress_data(
        data: &[u8],
        algorithm: &str,
        min_size: usize,
        message_type: &MessageType,
    ) -> Result<(Vec<u8>, bool), Box<dyn std::error::Error + Send + Sync>> {
        match message_type {
            MessageType::Control | MessageType::Heartbeat => {
                return Ok((data.to_vec(), false));
            }
            _ => {}
        }

        if data.len() < min_size {
            return Ok((data.to_vec(), false));
        }

        let compressed = compress_data(data, algorithm).await?;
        Ok((compressed, true))
    }

    pub async fn send_data(
        &self,
        data: Vec<u8>,
        msg_ctx: &MessageContext,
    ) -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error + Send + Sync>> {
        let algorithm = &self.config.compression.algorithm;
        let min_size = self.config.compression.min_compression_size.unwrap_or(0);

        let (mut payload, compressed) = Self::maybe_compress_data(
            &data,
            algorithm,
            min_size,
            &msg_ctx.message_type,
        )
        .await?;

        let mut encrypted = false;

        match msg_ctx.message_type {
            MessageType::Control | MessageType::Heartbeat | MessageType::Handshake => {
                trace!("Serializing control-plane message: {:?}", msg_ctx.message_type);
                payload = serialize(&data, standard())
                    .map_err(|e| format!("Control message serialization failed: {:?}", e))?;
            }
            _ => { /* existing logic */ }
        }

        if let Some(ref encryptor) = self.encryptor {
            if matches!(msg_ctx.message_type, MessageType::Data) {
                let aad = b""; // optionally pass metadata
                let (ciphertext, nonce) = encryptor.encrypt(&payload, aad)
                    .map_err(|e| Box::<dyn std::error::Error + Send + Sync>::from(format!("Encryption failed: {:?}", e)))?;
                let mut buf = Vec::with_capacity(12 + ciphertext.len());
                buf.extend_from_slice(&nonce);
                buf.extend_from_slice(&ciphertext);
                payload = buf;
                encrypted = true;
            }
        }

        if encrypted {
            debug!("AES-GCM encryption applied: {} -> {} bytes", data.len(), payload.len());
        }

        if compressed {
            debug!(
                original_size = data.len(),
                compressed_size = payload.len(),
                ratio = format!("{:.2}", payload.len() as f64 / data.len() as f64),
                "Compression applied"
            );
        } else {
            trace!("Compression skipped (type: {:?}, size: {})", msg_ctx.message_type, data.len());
        }

        let chunks = frame_chunks(&payload, 1400 - 8, msg_ctx.message_id as u32, msg_ctx.message_type.to_u8()); // example MTU logic
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
                let plaintext = encryptor.decrypt(ciphertext, &nonce_array, aad)
                    .map_err(|e| Box::<dyn std::error::Error + Send + Sync>::from(format!("Decryption failed: {:?}", e)))?;
                return Ok(plaintext);
            }
        }
        Ok(data.to_vec())
    }

    pub async fn receive_data(&self) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let socket = self.socket.lock().await;
        let mut buf = [0u8; 1500];
        let (len, _peer) = socket.recv_from(&mut buf).await?;
        let received_payload = &buf[..len];

        let (header, payload) = PacketHeader::deserialize(received_payload)
            .ok_or("Failed to parse packet header")?;

        let msg_type = match header.message_type {
            0 => MessageType::Data,
            1 => MessageType::Control,
            2 => MessageType::Control,
            3 => MessageType::Heartbeat,
            4 => MessageType::Handshake,
            v => MessageType::Unknown(v),
        };

        let mut buffer = self.reassembly_buffer.lock().await;
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
                    match deserialize::<crate::context::ControlPayload, _>(&final_payload, standard()) {
                        Ok((payload, _)) => {
                            trace!("Deserialized ControlPayload: {:?}", payload);
                        }
                        Err(e) => {
                            trace!("Failed to deserialize ControlPayload: {:?}", e);
                        }
                    }
                }
                MessageType::Heartbeat => {
                    match deserialize::<crate::context::HeartbeatPayload, _>(&final_payload, standard()) {
                        Ok((payload, _)) => {
                            trace!("Deserialized HeartbeatPayload: {:?}", payload);
                        }
                        Err(e) => {
                            trace!("Failed to deserialize HeartbeatPayload: {:?}", e);
                        }
                    }
                }
                MessageType::Handshake => {
                    match deserialize::<crate::context::HandshakePayload, _>(&final_payload, standard()) {
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

            return Ok(final_payload);
        } else {
            return Err("Incomplete message: awaiting more chunks".into());
        }
    }
}