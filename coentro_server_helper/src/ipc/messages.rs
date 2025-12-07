use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Authentication header carried alongside helper requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthHeader {
    pub token_id: String,
    pub nonce: u64,
    pub signature: Vec<u8>,
}

/// Address assignment for a tunnel endpoint (address + prefix length).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelAddress {
    pub address: IpAddr,
    pub prefix: u8,
}

/// Route configuration pushed to the helper (CIDR and optional next hop).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteSpec {
    pub cidr: String,
    pub via: Option<IpAddr>,
    pub metric: Option<u32>,
}

/// DNS configuration that should be applied while the tunnel is up.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DnsConfig {
    pub servers: Vec<IpAddr>,
    pub search_domains: Vec<String>,
}

/// Request sent by the core engine when provisioning a new tunnel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateTunnelRequest {
    pub session_id: String,
    pub virtual_address: TunnelAddress,
    pub routes: Vec<RouteSpec>,
    pub dns: Option<DnsConfig>,
    pub mtu: Option<u32>,
    pub enable_nat: bool,
}

/// Request to attach an authenticated QUIC connection to an existing tunnel.
///
/// The associated transport file descriptor is delivered via SCM_RIGHTS in the
/// same IPC exchange.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachQuicRequest {
    pub session_id: String,
    /// Optional logical identifier for multiplexed flows.
    pub flow_id: Option<String>,
    /// Hint for the number of meaningful bidirectional streams available.
    pub stream_count: Option<u16>,
}

/// Request to destroy a tunnel and clean up all associated state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DestroyTunnelRequest {
    pub session_id: String,
    /// Optional human-readable teardown reason for logging/metrics.
    pub reason: Option<String>,
}

/// Request a one-shot metrics snapshot from the helper.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MetricsSnapshotRequest {
    /// When true the helper should reset counters after returning the snapshot.
    #[serde(default)]
    pub reset_after_read: bool,
}

/// Server-side IPC requests emitted by the core engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServerRequest {
    Ping,
    CreateTunnel(CreateTunnelRequest),
    AttachQuic(AttachQuicRequest),
    DestroyTunnel(DestroyTunnelRequest),
    MetricsSnapshot(MetricsSnapshotRequest),
}

/// Envelope wrapping a server request with optional authentication metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatedRequest {
    pub auth: Option<AuthHeader>,
    pub request: ServerRequest,
}

/// Helper acknowledgement for tunnel creation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelCreatedResponse {
    pub session_id: String,
    pub interface: String,
    pub virtual_address: TunnelAddress,
}

/// Helper acknowledgement for QUIC attachment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachQuicResponse {
    pub session_id: String,
    /// Number of streams successfully wired into the bridge.
    pub accepted_streams: u16,
}

/// Helper acknowledgement for tunnel teardown, including final counters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DestroyTunnelResponse {
    pub session_id: String,
    pub bytes_ingress: u64,
    pub bytes_egress: u64,
}

/// Per-tunnel metrics exposed in a snapshot response.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TunnelMetrics {
    pub session_id: String,
    pub interface: String,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub packets_in: u64,
    pub packets_out: u64,
    pub start_timestamp_ms: u64,
}

/// Aggregated metrics exported by the helper.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MetricsSnapshotResponse {
    pub generated_at_ms: u64,
    pub total_sessions: u32,
    pub active_sessions: u32,
    pub tunnels: Vec<TunnelMetrics>,
}

/// Generic acknowledgement payload for commands that do not have dedicated data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenericAck {
    pub session_id: Option<String>,
    pub message: Option<String>,
}

/// Error codes returned by the helper.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ErrorCode {
    InvalidRequest,
    Unauthorized,
    NotFound,
    Busy,
    InternalError,
    Unsupported,
}

/// Error response payload returned by the helper.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub session_id: Option<String>,
    pub code: ErrorCode,
    pub message: String,
}

/// Server-side IPC responses produced by the helper.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServerResponse {
    Pong,
    Ack(GenericAck),
    TunnelCreated(TunnelCreatedResponse),
    QuicAttached(AttachQuicResponse),
    TunnelDestroyed(DestroyTunnelResponse),
    Metrics(MetricsSnapshotResponse),
    Error(ErrorResponse),
}
