//! Example usage of the shared_utils crate.
//!
//! This file demonstrates how to use the framing protocol
//! implemented in the shared_utils crate.

use shared_utils::logging;
use shared_utils::proto::framing::{Frame, FrameDecoder, FrameEncoder};
use tracing::{debug, error, info, trace, warn};

fn main() {
    // Initialize logging with default settings
    let _guard = logging::init_default_logging();

    info!("CoentroVPN Shared Utils Example");
    debug!("===============================");

    // Create a data frame
    let data = b"Hello, CoentroVPN!".to_vec();
    let frame = match Frame::new_data(data) {
        Ok(f) => {
            debug!("Created frame: {:?}", f);
            f
        }
        Err(e) => {
            error!("Failed to create data frame: {}", e);
            return;
        }
    };

    // Encode the frame
    let encoder = FrameEncoder::new();
    let encoded = encoder.encode(&frame);

    info!("Encoded frame size: {} bytes", encoded.len());
    trace!("Encoded frame (hex): {:02X?}", &encoded[0..16]); // Show first 16 bytes

    // Decode the frame
    let mut decoder = FrameDecoder::new();
    let decoded_frames = match decoder.decode(&encoded) {
        Ok(frames) => {
            debug!("Decoded {} frames", frames.len());
            frames
        }
        Err(e) => {
            error!("Failed to decode frame: {}", e);
            return;
        }
    };

    // Verify the decoded frame matches the original
    if decoded_frames.len() == 1 && decoded_frames[0] == frame {
        info!("✅ Roundtrip successful!");
    } else {
        warn!("❌ Roundtrip failed!");
    }
}
