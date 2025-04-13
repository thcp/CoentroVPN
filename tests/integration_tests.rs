use crate::observability::{DUPLICATES_TOTAL, REASSEMBLIES_TOTAL, RETRIES_TOTAL};
use crate::tunnel::{process_packet, TunnelImpl};
use tokio::time::Duration;

#[tokio::test]
async fn test_retries_increment() {
    RETRIES_TOTAL.reset();
    let retries_before = RETRIES_TOTAL.get();

    // Simulate a retry scenario
    let mut tunnel = TunnelImpl::default(); // Assuming a default implementation exists
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
    let mut tunnel = TunnelImpl::default(); // Assuming a default implementation exists
    tunnel.receive_data().await.unwrap();

    let reassemblies_after = REASSEMBLIES_TOTAL.get();
    assert!(
        reassemblies_after > reassemblies_before,
        "Reassemblies metric should increment"
    );
}
