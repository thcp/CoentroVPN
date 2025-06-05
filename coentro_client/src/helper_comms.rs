//! Helper Communications for the CoentroVPN Client
//!
//! This module handles communication with the helper daemon via IPC.

use coentro_ipc::messages::{ClientRequest, HelperResponse, StatusDetails};
use coentro_ipc::transport::{IpcTransport, UnixSocketTransport};
use log::{debug, error};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Client for communicating with the helper daemon
pub struct HelperClient {
    transport: Arc<Mutex<UnixSocketTransport>>,
}

impl HelperClient {
    /// Connect to the helper daemon
    pub async fn connect<P: AsRef<Path>>(socket_path: P) -> Result<Self, anyhow::Error> {
        let transport = UnixSocketTransport::connect(socket_path)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to connect to helper daemon: {}", e))?;

        Ok(Self {
            transport: Arc::new(Mutex::new(transport)),
        })
    }

    /// Ping the helper daemon
    pub async fn ping(&self) -> Result<(), anyhow::Error> {
        let mut transport = self.transport.lock().await;

        debug!("Sending ping to helper daemon");
        transport
            .send_request(&ClientRequest::Ping)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to send ping request: {}", e))?;

        let response = transport
            .receive_response()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to receive ping response: {}", e))?;

        match response {
            HelperResponse::Pong => {
                debug!("Received pong from helper daemon");
                Ok(())
            }
            _ => {
                error!("Unexpected response to ping: {:?}", response);
                Err(anyhow::anyhow!(
                    "Unexpected response to ping: {:?}",
                    response
                ))
            }
        }
    }

    /// Get the status of the helper daemon
    pub async fn get_status(&self) -> Result<StatusDetails, anyhow::Error> {
        let mut transport = self.transport.lock().await;

        debug!("Sending status request to helper daemon");
        transport
            .send_request(&ClientRequest::GetStatus)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to send status request: {}", e))?;

        let response = transport
            .receive_response()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to receive status response: {}", e))?;

        match response {
            HelperResponse::StatusReport(status) => {
                debug!("Received status from helper daemon: {:?}", status);
                Ok(status)
            }
            HelperResponse::Error(msg) => {
                error!("Helper daemon returned error: {}", msg);
                Err(anyhow::anyhow!("Helper daemon error: {}", msg))
            }
            _ => {
                error!("Unexpected response to status request: {:?}", response);
                Err(anyhow::anyhow!(
                    "Unexpected response to status request: {:?}",
                    response
                ))
            }
        }
    }

    /// Close the connection to the helper daemon
    pub async fn close(&self) -> Result<(), anyhow::Error> {
        let mut transport = self.transport.lock().await;

        debug!("Closing connection to helper daemon");
        transport
            .close()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to close connection: {}", e))?;

        Ok(())
    }
}

/// Ping the helper daemon (convenience function)
pub async fn ping_helper<P: AsRef<Path>>(socket_path: P) -> Result<(), anyhow::Error> {
    let client = HelperClient::connect(socket_path).await?;
    let result = client.ping().await;
    let _ = client.close().await;
    result
}
