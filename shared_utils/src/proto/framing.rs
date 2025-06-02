//! Stream framing protocol for CoentroVPN.
//!
//! This module implements the message framing protocol used for communication
//! between CoentroVPN components. The framing protocol ensures that messages
//! are properly delimited and can be reliably transmitted and received over
//! a stream-based transport like QUIC.
//!
//! # Frame Format
//!
//! Each frame has the following structure:
//!
//! ```text
//! +----------------+----------------+----------------+----------------+
//! |    Magic (1)   |  Version (1)   |    Type (1)    |   Flags (1)    |
//! +----------------+----------------+----------------+----------------+
//! |                        Length (4 bytes)                           |
//! +----------------+----------------+----------------+----------------+
//! |                        Payload (variable)                         |
//! +----------------+----------------+----------------+----------------+
//! |                        Checksum (4 bytes)                         |
//! +----------------+----------------+----------------+----------------+
//! ```
//!
//! - Magic: A fixed byte (0xC0) that marks the beginning of a frame
//! - Version: Protocol version (currently 0x01)
//! - Type: Message type (data, control, etc.)
//! - Flags: Additional flags for special handling
//! - Length: Length of the payload in bytes (u32, big-endian)
//! - Payload: The actual message data (variable length)
//! - Checksum: CRC32 checksum of the entire frame (header + payload)
//!
//! # Example Usage
//!
//! ```rust
//! use shared_utils::proto::framing::{Frame, FrameType, FrameEncoder, FrameDecoder};
//!
//! // Create a data frame
//! let data = b"Hello, CoentroVPN!".to_vec();
//! let frame = Frame::new_data(data).unwrap();
//!
//! // Encode the frame
//! let encoder = FrameEncoder::new();
//! let encoded = encoder.encode(&frame);
//!
//! // Decode the frame
//! let mut decoder = FrameDecoder::new();
//! let decoded_frames = decoder.decode(&encoded).unwrap();
//! assert_eq!(decoded_frames.len(), 1);
//! assert_eq!(decoded_frames[0], frame);
//! ```

use std::collections::VecDeque;
use std::fmt;
use std::io::{self, Cursor};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use crc32fast::Hasher;
use thiserror::Error;
use tracing::{debug, error, info, instrument, trace, warn};

// Constants for the frame format
const FRAME_MAGIC: u8 = 0xC0;
const FRAME_VERSION: u8 = 0x01;
const HEADER_SIZE: usize = 8; // Magic (1) + Version (1) + Type (1) + Flags (1) + Length (4)
const CHECKSUM_SIZE: usize = 4;
const MIN_FRAME_SIZE: usize = HEADER_SIZE + CHECKSUM_SIZE;
const MAX_PAYLOAD_SIZE: usize = 65_535; // 64KB max payload size

/// Errors that can occur during frame encoding/decoding.
#[derive(Debug, Error)]
pub enum FrameError {
    /// Invalid magic byte in frame header
    #[error("Invalid frame magic: expected 0x{expected:02X}, got 0x{actual:02X}")]
    InvalidMagic { expected: u8, actual: u8 },

    /// Unsupported protocol version
    #[error("Unsupported protocol version: {0}")]
    UnsupportedVersion(u8),

    /// Invalid frame type
    #[error("Invalid frame type: {0}")]
    InvalidFrameType(u8),

    /// Frame payload too large
    #[error("Frame payload too large: {size} bytes (max: {max} bytes)")]
    PayloadTooLarge { size: usize, max: usize },

    /// Checksum verification failed
    #[error("Checksum verification failed: expected 0x{expected:08X}, got 0x{actual:08X}")]
    ChecksumMismatch { expected: u32, actual: u32 },

    /// I/O error during encoding/decoding
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// Incomplete frame data
    #[error("Incomplete frame data: expected at least {expected} bytes, got {actual} bytes")]
    IncompleteFrame { expected: usize, actual: usize },
}

/// Types of frames that can be sent/received.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    /// Data frame containing encrypted payload
    Data = 0x01,
    
    /// Control frame for connection management
    Control = 0x02,
    
    /// Keepalive frame to maintain connection
    Keepalive = 0x03,
    
    /// Configuration frame for exchanging settings
    Config = 0x04,
    
    /// Error frame indicating an issue
    Error = 0x05,
}

impl FrameType {
    /// Convert a u8 to a FrameType
    pub fn from_u8(value: u8) -> Result<Self, FrameError> {
        match value {
            0x01 => Ok(FrameType::Data),
            0x02 => Ok(FrameType::Control),
            0x03 => Ok(FrameType::Keepalive),
            0x04 => Ok(FrameType::Config),
            0x05 => Ok(FrameType::Error),
            _ => Err(FrameError::InvalidFrameType(value)),
        }
    }
    
    /// Convert a FrameType to a u8
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

/// Flags that can be set on a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameFlags(u8);

impl FrameFlags {
    /// Create a new FrameFlags with no flags set
    pub fn new() -> Self {
        FrameFlags(0)
    }
    
    /// Create a FrameFlags from a raw u8 value
    pub fn from_u8(value: u8) -> Self {
        FrameFlags(value)
    }
    
    /// Convert FrameFlags to a u8
    pub fn to_u8(self) -> u8 {
        self.0
    }
    
    /// Set a flag bit
    pub fn set(&mut self, bit: u8) {
        self.0 |= 1 << bit;
    }
    
    /// Clear a flag bit
    pub fn clear(&mut self, bit: u8) {
        self.0 &= !(1 << bit);
    }
    
    /// Check if a flag bit is set
    pub fn is_set(&self, bit: u8) -> bool {
        (self.0 & (1 << bit)) != 0
    }
}

impl Default for FrameFlags {
    fn default() -> Self {
        Self::new()
    }
}

/// A frame in the CoentroVPN protocol.
#[derive(Clone, PartialEq, Eq)]
pub struct Frame {
    /// The type of frame
    pub frame_type: FrameType,
    
    /// Flags for special handling
    pub flags: FrameFlags,
    
    /// The payload data
    pub payload: Vec<u8>,
}

impl Frame {
    /// Create a new frame with the specified type, flags, and payload
    #[instrument(level = "debug", skip(payload), fields(payload_len = payload.len()))]
    pub fn new(frame_type: FrameType, flags: FrameFlags, payload: Vec<u8>) -> Result<Self, FrameError> {
        if payload.len() > MAX_PAYLOAD_SIZE {
            error!(
                size = payload.len(),
                max = MAX_PAYLOAD_SIZE,
                "Frame payload too large"
            );
            return Err(FrameError::PayloadTooLarge {
                size: payload.len(),
                max: MAX_PAYLOAD_SIZE,
            });
        }
        
        debug!(
            frame_type = ?frame_type,
            flags = flags.to_u8(),
            payload_len = payload.len(),
            "Created new frame"
        );
        
        Ok(Frame {
            frame_type,
            flags,
            payload,
        })
    }
    
    /// Create a new data frame with the given payload
    pub fn new_data(payload: Vec<u8>) -> Result<Self, FrameError> {
        Self::new(FrameType::Data, FrameFlags::new(), payload)
    }
    
    /// Create a new control frame with the given payload
    pub fn new_control(payload: Vec<u8>) -> Result<Self, FrameError> {
        Self::new(FrameType::Control, FrameFlags::new(), payload)
    }
    
    /// Create a new keepalive frame
    pub fn new_keepalive() -> Result<Self, FrameError> {
        Self::new(FrameType::Keepalive, FrameFlags::new(), Vec::new())
    }
    
    /// Create a new config frame with the given payload
    pub fn new_config(payload: Vec<u8>) -> Result<Self, FrameError> {
        Self::new(FrameType::Config, FrameFlags::new(), payload)
    }
    
    /// Create a new error frame with the given payload
    pub fn new_error(payload: Vec<u8>) -> Result<Self, FrameError> {
        Self::new(FrameType::Error, FrameFlags::new(), payload)
    }
    
    /// Calculate the total size of the frame when encoded
    pub fn size(&self) -> usize {
        HEADER_SIZE + self.payload.len() + CHECKSUM_SIZE
    }
}

impl fmt::Debug for Frame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Frame")
            .field("type", &self.frame_type)
            .field("flags", &self.flags)
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

/// Encoder for CoentroVPN frames.
#[derive(Debug, Default)]
pub struct FrameEncoder;

impl FrameEncoder {
    /// Create a new frame encoder
    pub fn new() -> Self {
        debug!("Created new frame encoder");
        FrameEncoder
    }
    
    /// Encode a frame into a byte vector
    #[instrument(level = "debug", skip(self, frame), fields(frame_type = ?frame.frame_type, payload_len = frame.payload.len()))]
    pub fn encode(&self, frame: &Frame) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(frame.size());
        
        // Write header
        buffer.push(FRAME_MAGIC);
        buffer.push(FRAME_VERSION);
        buffer.push(frame.frame_type.to_u8());
        buffer.push(frame.flags.to_u8());
        
        // Write payload length (u32, big-endian)
        let payload_len = frame.payload.len() as u32;
        buffer.write_u32::<BigEndian>(payload_len).unwrap();
        
        // Write payload
        buffer.extend_from_slice(&frame.payload);
        
        // Calculate checksum of everything so far
        let mut hasher = Hasher::new();
        hasher.update(&buffer);
        let checksum = hasher.finalize();
        
        // Write checksum (u32, big-endian)
        buffer.write_u32::<BigEndian>(checksum).unwrap();
        
        trace!(
            frame_type = ?frame.frame_type,
            flags = frame.flags.to_u8(),
            payload_len = frame.payload.len(),
            total_size = buffer.len(),
            checksum = format!("0x{:08X}", checksum),
            "Frame encoded successfully"
        );
        
        buffer
    }
}

/// Decoder for CoentroVPN frames.
#[derive(Debug)]
pub struct FrameDecoder {
    /// Buffer for incomplete frame data
    buffer: Vec<u8>,
}

impl FrameDecoder {
    /// Create a new frame decoder
    pub fn new() -> Self {
        debug!("Created new frame decoder");
        FrameDecoder {
            buffer: Vec::new(),
        }
    }
    
    /// Decode frames from a byte slice
    ///
    /// This method appends the input data to the internal buffer and attempts
    /// to decode as many complete frames as possible. Any incomplete frame data
    /// is kept in the buffer for the next call.
    ///
    /// Returns a vector of successfully decoded frames.
    #[instrument(level = "debug", skip(self, data), fields(data_len = data.len(), buffer_len = self.buffer.len()))]
    pub fn decode(&mut self, data: &[u8]) -> Result<Vec<Frame>, FrameError> {
        // Append new data to the buffer
        self.buffer.extend_from_slice(data);
        
        trace!(
            buffer_len = self.buffer.len(),
            "Appended data to buffer"
        );
        
        let mut frames = Vec::new();
        
        // Try to decode frames until we run out of data
        while let Some(frame) = self.try_decode_frame()? {
            debug!(
                frame_type = ?frame.frame_type,
                payload_len = frame.payload.len(),
                "Decoded frame"
            );
            frames.push(frame);
        }
        
        info!(
            frames_decoded = frames.len(),
            remaining_buffer = self.buffer.len(),
            "Decoded frames from buffer"
        );
        
        Ok(frames)
    }
    
    /// Try to decode a single frame from the buffer
    ///
    /// Returns:
    /// - Ok(Some(frame)) if a frame was successfully decoded
    /// - Ok(None) if there's not enough data for a complete frame
    /// - Err(error) if there was an error decoding the frame
    fn try_decode_frame(&mut self) -> Result<Option<Frame>, FrameError> {
        // Check if we have enough data for a minimal frame
        if self.buffer.len() < MIN_FRAME_SIZE {
            return Ok(None);
        }
        
        // Check magic byte
        if self.buffer[0] != FRAME_MAGIC {
            return Err(FrameError::InvalidMagic {
                expected: FRAME_MAGIC,
                actual: self.buffer[0],
            });
        }
        
        // Check version
        if self.buffer[1] != FRAME_VERSION {
            return Err(FrameError::UnsupportedVersion(self.buffer[1]));
        }
        
        // Read frame type
        let frame_type = FrameType::from_u8(self.buffer[2])?;
        
        // Read flags
        let flags = FrameFlags::from_u8(self.buffer[3]);
        
        // Read payload length
        let mut cursor = Cursor::new(&self.buffer[4..8]);
        let payload_len = cursor.read_u32::<BigEndian>()? as usize;
        
        // Check if the payload length is valid
        if payload_len > MAX_PAYLOAD_SIZE {
            return Err(FrameError::PayloadTooLarge {
                size: payload_len,
                max: MAX_PAYLOAD_SIZE,
            });
        }
        
        // Calculate total frame size
        let total_size = HEADER_SIZE + payload_len + CHECKSUM_SIZE;
        
        // Check if we have a complete frame
        if self.buffer.len() < total_size {
            return Ok(None);
        }
        
        // Calculate checksum of header + payload
        let mut hasher = Hasher::new();
        hasher.update(&self.buffer[0..HEADER_SIZE + payload_len]);
        let calculated_checksum = hasher.finalize();
        
        // Read the checksum from the frame
        let mut cursor = Cursor::new(&self.buffer[HEADER_SIZE + payload_len..total_size]);
        let frame_checksum = cursor.read_u32::<BigEndian>()?;
        
        // Verify checksum
        if calculated_checksum != frame_checksum {
            return Err(FrameError::ChecksumMismatch {
                expected: frame_checksum,
                actual: calculated_checksum,
            });
        }
        
        // Extract payload
        let payload = self.buffer[HEADER_SIZE..HEADER_SIZE + payload_len].to_vec();
        
        // Create frame
        let frame = Frame {
            frame_type,
            flags,
            payload,
        };
        
        // Remove the processed frame from the buffer
        self.buffer.drain(0..total_size);
        
        Ok(Some(frame))
    }
    
    /// Clear the internal buffer
    pub fn clear(&mut self) {
        self.buffer.clear();
    }
    
    /// Get the number of bytes currently in the buffer
    pub fn buffered_bytes(&self) -> usize {
        self.buffer.len()
    }
}

impl Default for FrameDecoder {
    fn default() -> Self {
        Self::new()
    }
}

/// A stream framer that handles both encoding and decoding of frames.
#[derive(Debug)]
pub struct StreamFramer {
    /// Encoder for outgoing frames
    encoder: FrameEncoder,
    
    /// Decoder for incoming frames
    decoder: FrameDecoder,
    
    /// Queue of decoded frames
    frame_queue: VecDeque<Frame>,
}

impl StreamFramer {
    /// Create a new stream framer
    pub fn new() -> Self {
        info!("Creating new stream framer");
        StreamFramer {
            encoder: FrameEncoder::new(),
            decoder: FrameDecoder::new(),
            frame_queue: VecDeque::new(),
        }
    }
    
    /// Encode a frame into a byte vector
    #[instrument(level = "debug", skip(self, frame), fields(frame_type = ?frame.frame_type, payload_len = frame.payload.len()))]
    pub fn encode(&self, frame: &Frame) -> Vec<u8> {
        debug!("Encoding frame");
        self.encoder.encode(frame)
    }
    
    /// Process incoming data and decode frames
    ///
    /// Returns the number of frames decoded
    #[instrument(level = "debug", skip(self, data), fields(data_len = data.len()))]
    pub fn process_data(&mut self, data: &[u8]) -> Result<usize, FrameError> {
        debug!("Processing incoming data");
        let frames = self.decoder.decode(data)?;
        let count = frames.len();
        
        for frame in frames {
            debug!(
                frame_type = ?frame.frame_type,
                payload_len = frame.payload.len(),
                "Queuing decoded frame"
            );
            self.frame_queue.push_back(frame);
        }
        
        info!(
            frames_decoded = count,
            queue_size = self.frame_queue.len(),
            "Processed incoming data"
        );
        
        Ok(count)
    }
    
    /// Get the next decoded frame, if available
    #[instrument(level = "debug", skip(self))]
    pub fn next_frame(&mut self) -> Option<Frame> {
        let frame = self.frame_queue.pop_front();
        
        if let Some(ref f) = frame {
            debug!(
                frame_type = ?f.frame_type,
                payload_len = f.payload.len(),
                remaining_frames = self.frame_queue.len(),
                "Retrieved frame from queue"
            );
        } else {
            trace!("No frames available in queue");
        }
        
        frame
    }
    
    /// Check if there are any decoded frames available
    pub fn has_frames(&self) -> bool {
        !self.frame_queue.is_empty()
    }
    
    /// Get the number of decoded frames available
    pub fn frame_count(&self) -> usize {
        self.frame_queue.len()
    }
    
    /// Clear all decoded frames and the decoder buffer
    pub fn clear(&mut self) {
        self.decoder.clear();
        self.frame_queue.clear();
    }
}

impl Default for StreamFramer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_frame_type_conversion() {
        assert_eq!(FrameType::from_u8(0x01).unwrap(), FrameType::Data);
        assert_eq!(FrameType::from_u8(0x02).unwrap(), FrameType::Control);
        assert_eq!(FrameType::from_u8(0x03).unwrap(), FrameType::Keepalive);
        assert_eq!(FrameType::from_u8(0x04).unwrap(), FrameType::Config);
        assert_eq!(FrameType::from_u8(0x05).unwrap(), FrameType::Error);
        
        assert!(FrameType::from_u8(0x00).is_err());
        assert!(FrameType::from_u8(0x06).is_err());
        
        assert_eq!(FrameType::Data.to_u8(), 0x01);
        assert_eq!(FrameType::Control.to_u8(), 0x02);
        assert_eq!(FrameType::Keepalive.to_u8(), 0x03);
        assert_eq!(FrameType::Config.to_u8(), 0x04);
        assert_eq!(FrameType::Error.to_u8(), 0x05);
    }
    
    #[test]
    fn test_frame_flags() {
        let mut flags = FrameFlags::new();
        assert_eq!(flags.to_u8(), 0);
        
        flags.set(0);
        assert_eq!(flags.to_u8(), 1);
        assert!(flags.is_set(0));
        assert!(!flags.is_set(1));
        
        flags.set(1);
        assert_eq!(flags.to_u8(), 3);
        assert!(flags.is_set(0));
        assert!(flags.is_set(1));
        
        flags.clear(0);
        assert_eq!(flags.to_u8(), 2);
        assert!(!flags.is_set(0));
        assert!(flags.is_set(1));
    }
    
    #[test]
    fn test_frame_creation() {
        let data = b"Hello, CoentroVPN!".to_vec();
        
        let frame = Frame::new_data(data.clone()).unwrap();
        assert_eq!(frame.frame_type, FrameType::Data);
        assert_eq!(frame.flags.to_u8(), 0);
        assert_eq!(frame.payload, data.clone());
        
        let frame = Frame::new_control(data.clone()).unwrap();
        assert_eq!(frame.frame_type, FrameType::Control);
        assert_eq!(frame.flags.to_u8(), 0);
        assert_eq!(frame.payload, data.clone());
        
        let frame = Frame::new_keepalive().unwrap();
        assert_eq!(frame.frame_type, FrameType::Keepalive);
        assert_eq!(frame.flags.to_u8(), 0);
        assert_eq!(frame.payload, Vec::<u8>::new());
        
        let frame = Frame::new_config(data.clone()).unwrap();
        assert_eq!(frame.frame_type, FrameType::Config);
        assert_eq!(frame.flags.to_u8(), 0);
        assert_eq!(frame.payload, data.clone());
        
        let frame = Frame::new_error(data.clone()).unwrap();
        assert_eq!(frame.frame_type, FrameType::Error);
        assert_eq!(frame.flags.to_u8(), 0);
        assert_eq!(frame.payload, data);
    }
    
    #[test]
    fn test_encode_decode_roundtrip() {
        let data = b"Hello, CoentroVPN!".to_vec();
        let original_frame = Frame::new_data(data).unwrap();
        
        // Encode
        let encoder = FrameEncoder::new();
        let encoded = encoder.encode(&original_frame);
        
        // Decode
        let mut decoder = FrameDecoder::new();
        let decoded_frames = decoder.decode(&encoded).unwrap();
        
        // Verify
        assert_eq!(decoded_frames.len(), 1);
        assert_eq!(decoded_frames[0], original_frame);
    }
    
    #[test]
    fn test_partial_decode() {
        let data = b"Hello, CoentroVPN!".to_vec();
        let original_frame = Frame::new_data(data).unwrap();
        
        // Encode
        let encoder = FrameEncoder::new();
        let encoded = encoder.encode(&original_frame);
        
        // Split the encoded data
        let part1 = &encoded[0..10];
        let part2 = &encoded[10..];
        
        // Decode part 1
        let mut decoder = FrameDecoder::new();
        let decoded_frames = decoder.decode(part1).unwrap();
        
        // Should not have enough data yet
        assert_eq!(decoded_frames.len(), 0);
        
        // Decode part 2
        let decoded_frames = decoder.decode(part2).unwrap();
        
        // Now we should have the frame
        assert_eq!(decoded_frames.len(), 1);
        assert_eq!(decoded_frames[0], original_frame);
    }
    
    #[test]
    fn test_stream_framer() {
        let data1 = b"Hello".to_vec();
        let data2 = b"CoentroVPN".to_vec();
        
        let frame1 = Frame::new_data(data1).unwrap();
        let frame2 = Frame::new_control(data2).unwrap();
        
        let mut framer = StreamFramer::new();
        
        // Encode frames
        let encoded1 = framer.encode(&frame1);
        let encoded2 = framer.encode(&frame2);
        
        // Combine encoded data
        let mut combined = encoded1;
        combined.extend_from_slice(&encoded2);
        
        // Process the combined data
        let count = framer.process_data(&combined).unwrap();
        assert_eq!(count, 2);
        assert_eq!(framer.frame_count(), 2);
        assert!(framer.has_frames());
        
        // Get the frames back
        let decoded1 = framer.next_frame().unwrap();
        let decoded2 = framer.next_frame().unwrap();
        
        // Verify
        assert_eq!(decoded1, frame1);
        assert_eq!(decoded2, frame2);
        assert!(!framer.has_frames());
    }
    
    #[test]
    fn test_max_payload_size() {
        // Create a payload that's too large
        let large_payload = vec![0; MAX_PAYLOAD_SIZE + 1];
        let result = Frame::new_data(large_payload);
        
        // Should fail with PayloadTooLarge error
        assert!(result.is_err());
        if let Err(FrameError::PayloadTooLarge { size, max }) = result {
            assert_eq!(size, MAX_PAYLOAD_SIZE + 1);
            assert_eq!(max, MAX_PAYLOAD_SIZE);
        } else {
            panic!("Expected PayloadTooLarge error");
        }
    }
}
