//! CoentroVPN IPC Protocol Library
//!
//! This crate defines the IPC protocol and transport mechanisms used for communication
//! between the unprivileged client (`coentro_client`) and the privileged helper daemon
//! (`coentro_helper`) in the CoentroVPN split daemon architecture.

pub mod messages;
pub mod transport;

/// Re-export common types for convenience
pub use messages::{ClientRequest, HelperResponse, TunnelReadyDetails, TunnelSetupRequest};
pub use transport::{IpcError, IpcResult, IpcTransport};
