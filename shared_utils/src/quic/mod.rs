//! QUIC transport implementation for CoentroVPN.
//!
//! This module provides QUIC-based transport for secure, reliable
//! communication between CoentroVPN clients and servers.

mod transport;
mod client;
mod server;

pub use transport::{QuicTransport, TransportError, TransportMessage};
pub use client::QuicClient;
pub use server::QuicServer;
