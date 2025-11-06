//! Library entry point for the CoentroVPN server helper.
//!
//! Exposes IPC and network management modules so other workspace crates
//! (e.g. the core engine) can reuse the shared types and transport helpers.

pub mod ipc;
pub mod network;
pub mod persistence;
