use anyhow::{Result, anyhow};
use coentro_server_helper::ipc::messages::{
    AttachQuicRequest, AttachQuicResponse, AuthenticatedRequest, CreateTunnelRequest,
    DestroyTunnelRequest, ServerRequest, ServerResponse, TunnelCreatedResponse,
};
use coentro_server_helper::ipc::transport::{receive_response, send_request};
use std::os::fd::RawFd;
use std::path::Path;
use tokio::net::UnixStream;

/// Thin async client for talking to the privileged server helper over IPC.
pub struct ServerHelperClient {
    stream: UnixStream,
}

impl ServerHelperClient {
    /// Establish a new IPC session with the helper.
    pub async fn connect<P: AsRef<Path>>(socket_path: P) -> Result<Self> {
        let stream = UnixStream::connect(socket_path)
            .await
            .map_err(|e| anyhow!("failed to connect to server helper: {e}"))?;
        Ok(Self { stream })
    }

    /// Create a tunnel on the helper.
    pub async fn create_tunnel(
        &mut self,
        request: CreateTunnelRequest,
    ) -> Result<TunnelCreatedResponse> {
        let envelope = AuthenticatedRequest {
            auth: None,
            request: ServerRequest::CreateTunnel(request),
        };
        send_request(&mut self.stream, &envelope, None)
            .await
            .map_err(|e| anyhow!("failed to send CreateTunnel request: {e}"))?;

        match receive_response(&mut self.stream)
            .await
            .map_err(|e| anyhow!("failed to receive CreateTunnel response: {e}"))?
        {
            ServerResponse::TunnelCreated(resp) => Ok(resp),
            ServerResponse::Error(err) => Err(anyhow!(
                "helper CreateTunnel error (code={:?}): {}",
                err.code,
                err.message
            )),
            other => Err(anyhow!(
                "unexpected helper response to CreateTunnel: {other:?}"
            )),
        }
    }

    /// Attach a QUIC transport file descriptor to an existing helper tunnel.
    pub async fn attach_quic(
        &mut self,
        request: AttachQuicRequest,
        fd: RawFd,
    ) -> Result<AttachQuicResponse> {
        let envelope = AuthenticatedRequest {
            auth: None,
            request: ServerRequest::AttachQuic(request),
        };
        send_request(&mut self.stream, &envelope, Some(fd))
            .await
            .map_err(|e| anyhow!("failed to send AttachQuic request: {e}"))?;

        match receive_response(&mut self.stream)
            .await
            .map_err(|e| anyhow!("failed to receive AttachQuic response: {e}"))?
        {
            ServerResponse::QuicAttached(resp) => Ok(resp),
            ServerResponse::Error(err) => Err(anyhow!(
                "helper AttachQuic error (code={:?}): {}",
                err.code,
                err.message
            )),
            other => Err(anyhow!(
                "unexpected helper response to AttachQuic: {other:?}"
            )),
        }
    }

    /// Destroy a helper tunnel, ignoring errors during shutdown.
    pub async fn destroy_tunnel(&mut self, session_id: &str, reason: Option<String>) {
        let envelope = AuthenticatedRequest {
            auth: None,
            request: ServerRequest::DestroyTunnel(DestroyTunnelRequest {
                session_id: session_id.to_string(),
                reason,
            }),
        };

        if let Err(err) = send_request(&mut self.stream, &envelope, None).await {
            tracing::warn!(session_id, "failed to send DestroyTunnel request: {err}");
            return;
        }

        match receive_response(&mut self.stream).await {
            Ok(ServerResponse::TunnelDestroyed(_)) => {}
            Ok(ServerResponse::Error(err)) => {
                tracing::warn!(session_id, code = ?err.code, "helper DestroyTunnel error: {}", err.message);
            }
            Ok(other) => {
                tracing::warn!(
                    session_id,
                    "unexpected helper response to DestroyTunnel: {other:?}"
                );
            }
            Err(err) => {
                tracing::warn!(
                    session_id,
                    "failed to receive DestroyTunnel response: {err}"
                );
            }
        }
    }
}
