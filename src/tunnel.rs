#[async_trait::async_trait]
pub trait Tunnel: Send + Sync {
    async fn start(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
    async fn send_data(&self, data: &[u8], addr: std::net::SocketAddr) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
    async fn receive_data(&self) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>>;
}

use crate::config::Config;
use crate::context::{MessageContext, MessageType};
use crate::packet_utils::frame_chunks;
use tracing::{debug, trace};
use std::io::Read;
use tokio::task;

pub struct TunnelImpl {
    pub config: Config,
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

        let (payload, compressed) = Self::maybe_compress_data(
            &data,
            algorithm,
            min_size,
            &msg_ctx.message_type,
        )
        .await?;

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

        let chunks = frame_chunks(&payload, 1400 - 8, msg_ctx.message_id as u32); // example MTU logic
        Ok(chunks)
    }
}

async fn compress_data(
    data: &[u8],
    algorithm: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let input = data.to_vec();
    let result = match algorithm {
        "lz4" => {
            task::spawn_blocking(move || {
                let mut encoder = lz4::EncoderBuilder::new().build(Vec::new())?;
                std::io::copy(&mut &input[..], &mut encoder)?;
                let (compressed, result) = encoder.finish();
                result?;
                Ok(compressed)
            })
            .await?
        }
        "zstd" => {
            task::spawn_blocking(move || {
                let compressed = zstd::stream::encode_all(&input[..], 1)?;
                Ok(compressed)
            })
            .await?
        }
        _ => Err(format!("Unsupported compression algorithm: {}", algorithm).into()),
    };
    result
}

pub async fn decompress_data(
    data: &[u8],
    algorithm: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let input = data.to_vec();
    let result = match algorithm {
        "lz4" => {
            task::spawn_blocking(move || {
                let mut decoder = lz4::Decoder::new(&input[..])?;
                let mut decompressed = Vec::new();
                decoder.read_to_end(&mut decompressed)?;
                Ok(decompressed)
            })
            .await?
        }
        "zstd" => {
            task::spawn_blocking(move || {
                let mut decoder = zstd::stream::Decoder::new(&input[..])?;
                let mut decompressed = Vec::new();
                decoder.read_to_end(&mut decompressed)?;
                Ok(decompressed)
            })
            .await?
        }
        _ => Err(format!("Unsupported decompression algorithm: {}", algorithm).into()),
    };
    result
}