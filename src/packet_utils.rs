use std::collections::{BTreeMap, HashMap};
use std::io::Read;
use std::time::{Duration, Instant};
use tokio::task;

pub fn split_packet(data: &[u8], max_size: usize) -> Vec<Vec<u8>> {
    data.chunks(max_size).map(|chunk| chunk.to_vec()).collect()
}

pub fn reassemble_packets(chunks: Vec<Vec<u8>>) -> Vec<u8> {
    chunks.into_iter().flatten().collect()
}

#[derive(Debug, Clone)]
pub struct PacketHeader {
    pub msg_id: u32,
    pub chunk_id: u16,
    pub total_chunks: u16,
    pub message_type: u8,
}

impl PacketHeader {
    pub fn serialize(&self) -> [u8; 9] {
        let mut buf = [0u8; 9];
        buf[..4].copy_from_slice(&self.msg_id.to_be_bytes());
        buf[4..6].copy_from_slice(&self.chunk_id.to_be_bytes());
        buf[6..8].copy_from_slice(&self.total_chunks.to_be_bytes());
        buf[8] = self.message_type;
        buf
    }

    pub fn deserialize(buf: &[u8]) -> Option<(Self, &[u8])> {
        if buf.len() < 9 {
            return None;
        }
        let msg_id = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let chunk_id = u16::from_be_bytes([buf[4], buf[5]]);
        let total_chunks = u16::from_be_bytes([buf[6], buf[7]]);
        let message_type = buf[8];
        let header = PacketHeader {
            msg_id,
            chunk_id,
            total_chunks,
            message_type,
        };
        Some((header, &buf[9..]))
    }
}

pub fn frame_chunks(
    data: &[u8],
    max_chunk_size: usize,
    msg_id: u32,
    message_type: u8,
) -> Vec<Vec<u8>> {
    let chunks = data.chunks(max_chunk_size).collect::<Vec<_>>();
    let total_chunks = chunks.len() as u16;
    chunks
        .into_iter()
        .enumerate()
        .map(|(i, chunk)| {
            let header = PacketHeader {
                msg_id,
                chunk_id: i as u16,
                total_chunks,
                message_type,
            };
            let mut framed = header.serialize().to_vec();
            framed.extend_from_slice(chunk);
            framed
        })
        .collect()
}

pub fn deframe_chunks(packets: Vec<Vec<u8>>) -> Option<Vec<u8>> {
    let mut parts = BTreeMap::new();
    let mut expected_parts = None;
    let mut msg_id = None;

    for packet in packets {
        if let Some((header, payload)) = PacketHeader::deserialize(&packet) {
            if let Some(id) = msg_id {
                if id != header.msg_id {
                    continue; // discard mismatched message
                }
            } else {
                msg_id = Some(header.msg_id);
            }

            expected_parts = Some(header.total_chunks);
            parts.insert(header.chunk_id, payload.to_vec());
        }
    }

    let total = expected_parts?;
    if parts.len() != total as usize {
        return None;
    }

    let mut result = Vec::new();
    for i in 0..total {
        result.extend(parts.get(&i)?);
    }

    Some(result)
}

pub struct ReassemblyBuffer {
    messages: HashMap<u32, MessageChunks>,
    expiration: Duration,
    last_inserted_id: Option<u32>, // Added tracking for latest message ID
}

struct MessageChunks {
    parts: BTreeMap<u16, Vec<u8>>,
    total_chunks: u16,
    last_update: Instant,
}

impl ReassemblyBuffer {
    pub fn new(expiration: Duration) -> Self {
        Self {
            messages: HashMap::new(),
            expiration,
            last_inserted_id: None,
        }
    }

    pub fn last_msg_id(&self) -> Option<u32> {
        self.last_inserted_id
    }

    pub fn insert(&mut self, packet: Vec<u8>) -> Option<Vec<u8>> {
        let (header, payload) = match PacketHeader::deserialize(&packet) {
            Some(hp) => hp,
            None => return None,
        };

        self.last_inserted_id = Some(header.msg_id); // Track the most recent message ID

        let msg = self
            .messages
            .entry(header.msg_id)
            .or_insert_with(|| MessageChunks {
                parts: BTreeMap::new(),
                total_chunks: header.total_chunks,
                last_update: Instant::now(),
            });

        msg.parts.insert(header.chunk_id, payload.to_vec());
        msg.last_update = Instant::now();

        if msg.parts.len() == msg.total_chunks as usize {
            let mut full = Vec::new();
            for i in 0..msg.total_chunks {
                if let Some(chunk) = msg.parts.get(&i) {
                    full.extend_from_slice(chunk);
                } else {
                    return None;
                }
            }
            self.messages.remove(&header.msg_id);
            return Some(full);
        }

        None
    }

    pub fn purge_expired(&mut self) {
        let now = Instant::now();
        let before = self.messages.len();
        self.messages
            .retain(|_, v| now.duration_since(v.last_update) < self.expiration);
        let after = self.messages.len();
        if before != after {
            tracing::debug!("Purged {} expired reassembly entries", before - after);
        }
    }
}

pub async fn compress_data(
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
