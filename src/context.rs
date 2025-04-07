use std::fmt;
use std::net::SocketAddr;
use uuid::Uuid;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum Direction {
    Inbound,
    Outbound,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageContext {
    pub message_id: u64,
    pub session_id: Uuid,
    pub size: usize,
    pub message_type: MessageType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkContext {
    pub message_id: u64,
    pub chunk_id: u32,
    pub total_chunks: Option<u32>,
    pub direction: Direction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageType {
    Control,
    Data,
    Handshake,
    Heartbeat,
    #[allow(dead_code)]
    Unknown(u8),
}

impl MessageType {
    pub fn to_u8(&self) -> u8 {
        match self {
            MessageType::Control => 2,
            MessageType::Data => 0,
            MessageType::Handshake => 4,
            MessageType::Heartbeat => 3,
            MessageType::Unknown(v) => *v,
        }
    }

    pub fn from_u8(value: u8) -> MessageType {
        match value {
            0 => MessageType::Data,
            2 => MessageType::Control,
            3 => MessageType::Heartbeat,
            4 => MessageType::Handshake,
            other => MessageType::Unknown(other),
        }
    }
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Direction::Inbound => write!(f, "inbound"),
            Direction::Outbound => write!(f, "outbound"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ControlPayload {
    Version { version: String },
    Ack { message_id: u64 },
    Disconnect,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakePayload {
    pub session_id: Uuid,
    pub client_info: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatPayload {
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionContext {
    pub session_id: Uuid,
    pub peer_addr: Option<SocketAddr>,
}
