#![no_main]

use libfuzzer_sys::fuzz_target;
use shared_utils::proto::framing::FrameDecoder;

fuzz_target!(|data: &[u8]| {
    // Feed arbitrary bytes into the decoder; we only care that it never panics.
    let mut decoder = FrameDecoder::new();
    let _ = decoder.decode(data);
});
