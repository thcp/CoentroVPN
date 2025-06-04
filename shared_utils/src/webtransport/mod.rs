use crate::transport::{
    ClientTransport, Connection as TraitConnection, Listener as TraitListener, ServerTransport,
    TransportError,
};
use async_trait::async_trait;
use std::net::SocketAddr;
use tracing::warn;

// --- WebTransport Connection Stub ---
pub struct WebTransportConnectionStub {
    // WebTransport typically uses URLs, not direct SocketAddrs for peer,
    // but SocketAddr for local might be available.
    // For a stub, we'll keep it simple.
    local_addr: Option<SocketAddr>,
}

#[async_trait]
impl TraitConnection for WebTransportConnectionStub {
    async fn send_data(&mut self, _data: &[u8]) -> Result<(), TransportError> {
        warn!("WebTransport send_data: Unimplemented");
        Err(TransportError::Generic("Unimplemented".to_string()))
    }

    async fn recv_data(&mut self) -> Result<Option<Vec<u8>>, TransportError> {
        warn!("WebTransport recv_data: Unimplemented");
        Err(TransportError::Generic("Unimplemented".to_string()))
    }

    fn peer_addr(&self) -> Result<SocketAddr, TransportError> {
        warn!("WebTransport peer_addr: Returning placeholder, WebTransport uses URLs.");
        // This is problematic as the trait expects SocketAddr.
        // A real implementation would need to decide how to handle this.
        // For a stub, we might return a loopback address or error.
        "127.0.0.1:0".parse().map_err(TransportError::AddrParse)
    }

    fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        self.local_addr.ok_or_else(|| {
            TransportError::Generic("Local address not available for WebTransport stub".to_string())
        })
    }

    async fn close(self: Box<Self>) -> Result<(), TransportError> {
        warn!("WebTransport close: Unimplemented");
        Ok(())
    }
}

// --- WebTransport Listener Stub ---
pub struct WebTransportListenerStub {
    listen_url: String, // e.g., https://localhost:4433/path
    local_addr: Option<SocketAddr>,
}

#[async_trait]
impl TraitListener for WebTransportListenerStub {
    async fn accept(&mut self) -> Result<Box<dyn TraitConnection>, TransportError> {
        warn!("WebTransport accept on {}: Unimplemented", self.listen_url);
        Err(TransportError::Generic("Unimplemented".to_string()))
    }

    fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        self.local_addr.ok_or_else(|| {
            TransportError::Generic(
                "Local address not available for WebTransport listener stub".to_string(),
            )
        })
    }
}

// --- WebTransport Client Transport Stub ---
pub struct WebTransportClientStub;

#[async_trait]
impl ClientTransport for WebTransportClientStub {
    async fn connect(&self, server_url: &str) -> Result<Box<dyn TraitConnection>, TransportError> {
        warn!("WebTransport connect to {}: Unimplemented", server_url);
        Err(TransportError::Generic("Unimplemented".to_string()))
    }
}

// --- WebTransport Server Transport Stub ---
pub struct WebTransportServerStub;

#[async_trait]
impl ServerTransport for WebTransportServerStub {
    type Listener = WebTransportListenerStub;

    async fn listen(&self, local_url: &str) -> Result<Self::Listener, TransportError> {
        warn!("WebTransport listen on {}: Unimplemented", local_url);
        // A real implementation would parse the URL and start an HTTP/3 server.
        // The SocketAddr might be derived from the URL's host/port.
        let parsed_url = url::Url::parse(local_url)
            .map_err(|e| TransportError::Configuration(format!("Invalid URL: {}", e)))?;
        let host = parsed_url.host_str().unwrap_or("localhost");
        let port = parsed_url.port().unwrap_or(443); // Default HTTPS port

        let socket_addr_str = format!("{}:{}", host, port);
        let socket_addr: Option<SocketAddr> = socket_addr_str.parse().ok();

        Ok(WebTransportListenerStub {
            listen_url: local_url.to_string(),
            local_addr: socket_addr,
        })
    }
}
