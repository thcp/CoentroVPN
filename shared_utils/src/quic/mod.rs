//! QUIC transport implementation for CoentroVPN.
//!
//! This module provides QUIC-based transport for secure, reliable
//! communication between CoentroVPN clients and servers.

mod client;
mod server;
mod transport;

pub use client::QuicClient;
pub use server::QuicServer;
pub use transport::{QuicTransport, TransportError, TransportMessage};
