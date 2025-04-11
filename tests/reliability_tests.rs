use coentrovpn::context::MessageType;
use coentrovpn::packet_utils::{frame_chunks, PacketHeader, ReassemblyBuffer};
use std::collections::HashSet;
use std::time::Duration;

#[tokio::test]
async fn test_message_reassembly_success() {
    let expiration = Duration::from_secs(10);
    let mut buffer = ReassemblyBuffer::new(expiration);

    let message = b"hello world!";
    let chunks = frame_chunks(message, 6, 42, MessageType::Data.to_u8());
    assert!(chunks.len() > 1);

    let mut assembled = None;
    for chunk in &chunks {
        assembled = buffer.insert(chunk.clone());
    }

    assert_eq!(assembled, Some(message.to_vec()));
}

#[tokio::test]
async fn test_duplicate_chunk_detection() {
    let expiration = Duration::from_secs(10);
    let mut buffer = ReassemblyBuffer::new(expiration);

    let message = b"duplicate test!";
    let chunks = frame_chunks(message, 8, 88, MessageType::Data.to_u8());

    let mut assembled = None;
    let mut seen_chunks: HashSet<Vec<u8>> = HashSet::new();

    for chunk in &chunks {
        let result = buffer.insert(chunk.clone());
        if assembled.is_some() {
            break;
        }
        assembled = result;
        // Try inserting same chunk again to simulate duplicate
        let dup_result = buffer.insert(chunk.clone());
        assert!(
            dup_result.is_none(),
            "duplicate chunk should not reassemble"
        );
    }

    assert_eq!(assembled, Some(message.to_vec()));
}

#[tokio::test]
async fn test_ack_message_is_skipped() {
    use coentrovpn::packet_utils::PacketHeader;

    let header = PacketHeader {
        message_type: MessageType::Ack.to_u8(),
        msg_id: 1,
        chunk_id: 0,
        total_chunks: 1,
    };

    let ack_packet = header.serialize();
    let expiration = Duration::from_secs(10);
    let mut buffer = ReassemblyBuffer::new(expiration);
    let result = buffer.insert(ack_packet.to_vec());

    assert!(
        result.is_none(),
        "ACK message should not trigger reassembly"
    );
}

#[tokio::test]
async fn test_ack_handling() {
    use coentrovpn::packet_utils::PacketHeader;

    let header = PacketHeader {
        message_type: MessageType::Ack.to_u8(),
        msg_id: 2,
        chunk_id: 0,
        total_chunks: 1,
    };

    let ack_packet = header.serialize();
    let expiration = Duration::from_secs(10);
    let mut buffer = ReassemblyBuffer::new(expiration);
    let result = buffer.insert(ack_packet.to_vec());

    assert!(
        result.is_none(),
        "ACK message should not trigger reassembly"
    );
}

#[tokio::test]
async fn test_message_reassembly_with_multiple_chunks() {
    let expiration = Duration::from_secs(10);
    let mut buffer = ReassemblyBuffer::new(expiration);

    let message = b"multiple chunks test!";
    let chunks = frame_chunks(message, 8, 99, MessageType::Data.to_u8());

    let mut assembled = None;
    for chunk in &chunks {
        assembled = buffer.insert(chunk.clone());
    }

    assert_eq!(assembled, Some(message.to_vec()));
}
