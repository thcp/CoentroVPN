use proptest::prelude::*;
use shared_utils::proto::framing::{Frame, FrameDecoder, FrameEncoder, FrameFlags, FrameType};

proptest! {
    #[test]
    fn encode_decode_roundtrip(frame_type in prop_oneof![Just(FrameType::Data), Just(FrameType::Control), Just(FrameType::Keepalive), Just(FrameType::Config), Just(FrameType::Error)],
                               payload in proptest::collection::vec(any::<u8>(), 0..1024)) {
        // Build frame
        let frame = Frame::new(frame_type, FrameFlags::new(), payload.clone()).unwrap();
        // Encode
        let enc = FrameEncoder::new().encode(&frame);
        // Decode
        let mut dec = FrameDecoder::new();
        let frames = dec.decode(&enc).unwrap();
        prop_assert_eq!(frames.len(), 1);
        let got = &frames[0];
        prop_assert_eq!(got.frame_type, frame_type);
        prop_assert_eq!(&got.payload, &payload);
    }
}
