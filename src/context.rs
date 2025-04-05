use std::fmt;
use uuid::Uuid;

#[derive(Debug, Clone, Copy)]
pub enum Direction {
    Inbound,
    Outbound,
}

#[derive(Debug, Clone)]
pub struct MessageContext {
    pub message_id: u64,
    pub session_id: Uuid,
    pub size: usize,
    pub message_type: MessageType,
}

#[derive(Debug, Clone)]
pub struct ChunkContext {
    pub message_id: u64,
    pub chunk_id: u32,
    pub total_chunks: Option<u32>,
    pub direction: Direction,
}

#[derive(Debug, Clone)]
pub enum MessageType {
    Control,
    Data,
    Handshake,
    Heartbeat,
    #[allow(dead_code)]
    Unknown(u8),
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Direction::Inbound => write!(f, "inbound"),
            Direction::Outbound => write!(f, "outbound"),
        }
    }
}


#[derive(Debug, Clone)]
pub struct SessionContext {
    pub session_id: Uuid,
}
