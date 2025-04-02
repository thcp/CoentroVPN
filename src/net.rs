pub const IP_HEADER_SIZE: usize = 20;
pub const UDP_HEADER_SIZE: usize = 8;
pub const ENCRYPTION_OVERHEAD: usize = 32; // Adjust if protocol overhead changes

/// Calculates the maximum safe UDP payload size for given MTU
pub fn calculate_max_payload_size(mtu: usize) -> usize {
    mtu.saturating_sub(IP_HEADER_SIZE + UDP_HEADER_SIZE + ENCRYPTION_OVERHEAD)
}
