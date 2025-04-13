use coentro_vpn::observability::{DUPLICATES_TOTAL, REASSEMBLIES_TOTAL, RETRIES_TOTAL};
use coentro_vpn::packet_utils::{compress_data, decompress_data};
use coentro_vpn::tunnel::{process_packet, TunnelImpl};
use std::sync::Arc;
use tokio::time::Duration;

#[tokio::test]
async fn test_process_packet_no_backpressure() {
    let mut buffer_usage = 0;
    let flow_control_threshold = 500;
    let packet = vec![0u8; 100]; // 100-byte packet

    let result = process_packet(&packet, &mut buffer_usage, flow_control_threshold);

    assert!(result, "Packet should be processed successfully");
    assert_eq!(
        buffer_usage, 0,
        "Buffer usage should return to 0 after processing"
    );
}

#[tokio::test]
async fn test_process_packet_with_backpressure() {
    let mut buffer_usage = 450;
    let flow_control_threshold = 500;
    let packet = vec![0u8; 100]; // 100-byte packet

    let result = process_packet(&packet, &mut buffer_usage, flow_control_threshold);

    assert!(!result, "Packet should trigger backpressure");
    assert_eq!(
        buffer_usage, 550,
        "Buffer usage should reflect the unprocessed packet"
    );
}

#[tokio::test]
async fn test_maybe_compress_data_no_compression() {
    let data = b"Short data";
    let algorithm = "gzip";
    let min_size = 512; // Minimum size for compression

    let (compressed_data, compressed) = TunnelImpl::maybe_compress_data(
        data,
        algorithm,
        min_size,
        &coentro_vpn::context::MessageType::Data,
    )
    .await
    .expect("Compression failed");

    assert_eq!(compressed_data, data, "Data should not be compressed");
    assert!(!compressed, "Compression flag should be false");
}

#[tokio::test]
async fn test_maybe_compress_data_with_compression() {
    let data = b"Long data that exceeds the minimum compression size";
    let algorithm = "gzip";
    let min_size = 10; // Minimum size for compression

    let (compressed_data, compressed) = TunnelImpl::maybe_compress_data(
        data,
        algorithm,
        min_size,
        &coentro_vpn::context::MessageType::Data,
    )
    .await
    .expect("Compression failed");

    assert!(
        compressed_data.len() < data.len(),
        "Compressed data should be smaller than original"
    );
    assert!(compressed, "Compression flag should be true");
}

#[tokio::test]
async fn test_retries_increment() {
    RETRIES_TOTAL.reset();
    let retries_before = RETRIES_TOTAL.get();

    // Simulate a retry scenario
    let tunnel = Arc::new(TunnelImpl::default()); // Assuming a default implementation exists
    tunnel.start_resend_loop().await;

    tokio::time::sleep(Duration::from_secs(5)).await;

    let retries_after = RETRIES_TOTAL.get();
    assert!(
        retries_after > retries_before,
        "Retries metric should increment"
    );
}

#[tokio::test]
async fn test_duplicates_increment() {
    DUPLICATES_TOTAL.reset();
    let duplicates_before = DUPLICATES_TOTAL.get();

    // Simulate receiving a duplicate packet
    let mut buffer_usage = 0;
    let flow_control_threshold = 500;
    let packet = vec![0u8; 100];
    process_packet(&packet, &mut buffer_usage, flow_control_threshold);

    process_packet(&packet, &mut buffer_usage, flow_control_threshold); // Duplicate

    let duplicates_after = DUPLICATES_TOTAL.get();
    assert!(
        duplicates_after > duplicates_before,
        "Duplicates metric should increment"
    );
}

#[tokio::test]
async fn test_reassemblies_increment() {
    REASSEMBLIES_TOTAL.reset();
    let reassemblies_before = REASSEMBLIES_TOTAL.get();

    // Simulate a reassembly scenario
    let tunnel = Arc::new(TunnelImpl::default()); // Assuming a default implementation exists
    tunnel.receive_data().await.unwrap();

    let reassemblies_after = REASSEMBLIES_TOTAL.get();
    assert!(
        reassemblies_after > reassemblies_before,
        "Reassemblies metric should increment"
    );
}

#[tokio::test]
async fn test_start_resend_loop() {
    RETRIES_TOTAL.reset();
    let retries_before = RETRIES_TOTAL.get();

    let tunnel = Arc::new(TunnelImpl::default()); // Assuming a default implementation exists
    tunnel.start_resend_loop().await;

    tokio::time::sleep(Duration::from_secs(5)).await;

    let retries_after = RETRIES_TOTAL.get();
    assert!(
        retries_after > retries_before,
        "Retries metric should increment"
    );
}

#[tokio::test]
async fn test_decrypt_if_needed_no_encryption() {
    let data = b"Plain data";
    let tunnel = TunnelImpl::default(); // Assuming a default implementation exists

    let decrypted_data = tunnel
        .decrypt_if_needed(data, &coentro_vpn::context::MessageType::Data)
        .await
        .expect("Decryption failed");

    assert_eq!(
        decrypted_data, data,
        "Data should remain unchanged without encryption"
    );
}
