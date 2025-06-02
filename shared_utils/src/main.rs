//! Example usage of the shared_utils crate.
//!
//! This file demonstrates how to use the framing protocol
//! implemented in the shared_utils crate.

use shared_utils::proto::framing::{Frame, FrameEncoder, FrameDecoder};

fn main() {
    println!("CoentroVPN Shared Utils Example");
    println!("===============================");
    
    // Create a data frame
    let data = b"Hello, CoentroVPN!".to_vec();
    let frame = Frame::new_data(data).expect("Failed to create data frame");
    
    println!("Created frame: {:?}", frame);
    
    // Encode the frame
    let encoder = FrameEncoder::new();
    let encoded = encoder.encode(&frame);
    
    println!("Encoded frame size: {} bytes", encoded.len());
    println!("Encoded frame (hex): {:02X?}", &encoded[0..16]); // Show first 16 bytes
    
    // Decode the frame
    let mut decoder = FrameDecoder::new();
    let decoded_frames = decoder.decode(&encoded).expect("Failed to decode frame");
    
    println!("Decoded {} frames", decoded_frames.len());
    
    // Verify the decoded frame matches the original
    if decoded_frames.len() == 1 && decoded_frames[0] == frame {
        println!("✅ Roundtrip successful!");
    } else {
        println!("❌ Roundtrip failed!");
    }
}
