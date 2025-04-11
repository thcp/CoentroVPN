use coentrovpn::packet_utils::{deframe_chunks, frame_chunks, PacketHeader, ReassemblyBuffer};
use std::collections::HashSet;
use std::time::Duration;

#[test]
fn test_packet_header_roundtrip() {
    let header = PacketHeader {
        msg_id: 1234,
        chunk_id: 1,
        total_chunks: 3,
        message_type: 0xAB,
    };
    let serialized = header.serialize();
    let (parsed, _) = PacketHeader::deserialize(&serialized).expect("Deserialization failed");
    assert_eq!(header.msg_id, parsed.msg_id);
    assert_eq!(header.chunk_id, parsed.chunk_id);
    assert_eq!(header.total_chunks, parsed.total_chunks);
    assert_eq!(header.message_type, parsed.message_type);
}

#[test]
fn test_frame_and_deframe_chunks() {
    let payload = b"hello world, this is a long payload that will be chunked".to_vec();
    let msg_id = 42;
    let message_type = 0x01;
    let chunks = frame_chunks(&payload, 20, msg_id, message_type);
    assert!(chunks.len() > 1);

    let reassembled = deframe_chunks(chunks).expect("Deframe failed");
    assert_eq!(reassembled, payload);
}

#[test]
fn test_reassembly_buffer_ordered_insert() {
    let mut buffer = ReassemblyBuffer::new(Duration::from_secs(10));
    let payload = b"chunked payload data".to_vec();
    let chunks = frame_chunks(&payload, 8, 100, 0x01);

    let mut assembled = None;
    for chunk in chunks {
        assembled = buffer.insert(chunk);
    }

    assert_eq!(assembled, Some(payload));
}

#[test]
fn test_reassembly_buffer_unordered_insert() {
    let mut buffer = ReassemblyBuffer::new(Duration::from_secs(10));
    let payload = b"unordered chunked payload test".to_vec();
    let mut chunks = frame_chunks(&payload, 10, 200, 0x02);
    let mut inserted: HashSet<Vec<u8>> = HashSet::new();

    // Shuffle order
    chunks.sort_by_key(|_| rand::random::<u8>());

    let mut assembled = None;
    for chunk in chunks {
        inserted.insert(chunk.clone());
        assembled = buffer.insert(chunk);
    }

    assert_eq!(assembled, Some(payload));
}
