//! Helper Communications for the CoentroVPN Client
//!
//! This module handles communication with the helper daemon via IPC.

use coentro_ipc::messages::{ClientRequest, HelperResponse, StatusDetails, TunnelReadyDetails, TunnelSetupRequest};
use coentro_ipc::transport::{IpcTransport, UnixSocketTransport};
use log::{debug, error, info};
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
        let transport = match UnixSocketTransport::connect(socket_path).await {
            Ok(t) => t,
            Err(e) => {
                // Check if this is an authentication error
                if let coentro_ipc::transport::IpcError::Authentication(msg) = &e {
                    return Err(anyhow::anyhow!("Authentication failed: {}. Make sure you are running as the same user that started the helper daemon or as root.", msg));
                } else if let coentro_ipc::transport::IpcError::Connection(msg) = &e {
                    if msg.contains("Permission denied") {
                        return Err(anyhow::anyhow!("Permission denied when connecting to helper daemon. Socket permissions may be too restrictive or you may not have the required permissions."));
                    }
                }
                return Err(anyhow::anyhow!("Failed to connect to helper daemon: {}", e));
            }
        };

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

    /// Set up a VPN tunnel
    pub async fn setup_tunnel(
        &self,
        client_id: &str,
        requested_ip: Option<String>,
        routes: Vec<String>,
        dns_servers: Option<Vec<String>>,
        mtu: Option<u32>,
    ) -> Result<TunnelReadyDetails, anyhow::Error> {
        let mut transport = self.transport.lock().await;

        let request = TunnelSetupRequest {
            client_id: client_id.to_string(),
            requested_ip_config: requested_ip,
            routes_to_add: routes,
            dns_servers,
            mtu,
        };

        info!("Sending tunnel setup request to helper daemon: {:?}", request);
        transport
            .send_request(&ClientRequest::SetupTunnel(request))
            .await
            .map_err(|e| anyhow::anyhow!("Failed to send tunnel setup request: {}", e))?;

        let response = transport
            .receive_response()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to receive tunnel setup response: {}", e))?;

        match response {
            HelperResponse::TunnelReady(details) => {
                info!("Tunnel setup successful: {:?}", details);
                Ok(details)
            }
            HelperResponse::Error(msg) => {
                error!("Helper daemon returned error: {}", msg);
                Err(anyhow::anyhow!("Helper daemon error: {}", msg))
            }
            _ => {
                error!("Unexpected response to tunnel setup request: {:?}", response);
                Err(anyhow::anyhow!(
                    "Unexpected response to tunnel setup request: {:?}",
                    response
                ))
            }
        }
    }

    /// Tear down an active VPN tunnel
    pub async fn teardown_tunnel(&self) -> Result<(), anyhow::Error> {
        let mut transport = self.transport.lock().await;

        info!("Sending tunnel teardown request to helper daemon");
        transport
            .send_request(&ClientRequest::TeardownTunnel)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to send tunnel teardown request: {}", e))?;

        let response = transport
            .receive_response()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to receive tunnel teardown response: {}", e))?;

        match response {
            HelperResponse::Success => {
                info!("Tunnel teardown successful");
                Ok(())
            }
            HelperResponse::Error(msg) => {
                error!("Helper daemon returned error: {}", msg);
                Err(anyhow::anyhow!("Helper daemon error: {}", msg))
            }
            _ => {
                error!("Unexpected response to tunnel teardown request: {:?}", response);
                Err(anyhow::anyhow!(
                    "Unexpected response to tunnel teardown request: {:?}",
                    response
                ))
            }
        }
    }
}

/// Ping the helper daemon (convenience function)
pub async fn ping_helper<P: AsRef<Path>>(socket_path: P) -> Result<(), anyhow::Error> {
    let client = HelperClient::connect(socket_path).await?;
    let result = client.ping().await;
    let _ = client.close().await;
    result
}
