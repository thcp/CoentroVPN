use crate::transport::{
    ClientTransport, Connection as TraitConnection, Listener as TraitListener, ServerTransport,
    TransportError,
};
use async_trait::async_trait;
use std::net::SocketAddr;
use tracing::warn;

// --- TCP Connection Stub ---
pub struct TcpConnectionStub {
    peer_addr: SocketAddr,
    local_addr: SocketAddr,
}

#[async_trait]
impl TraitConnection for TcpConnectionStub {
    async fn send_data(&mut self, _data: &[u8]) -> Result<(), TransportError> {
        warn!("TCP send_data: Unimplemented");
        Err(TransportError::Generic("Unimplemented".to_string()))
    }

    async fn recv_data(&mut self) -> Result<Option<Vec<u8>>, TransportError> {
        warn!("TCP recv_data: Unimplemented");
        Err(TransportError::Generic("Unimplemented".to_string()))
    }

    fn peer_addr(&self) -> Result<SocketAddr, TransportError> {
        Ok(self.peer_addr)
    }

    fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        Ok(self.local_addr)
    }

    async fn close(self: Box<Self>) -> Result<(), TransportError> {
        warn!("TCP close: Unimplemented");
        Ok(())
    }
}

// --- TCP Listener Stub ---
pub struct TcpListenerStub {
    local_addr: SocketAddr,
}

#[async_trait]
impl TraitListener for TcpListenerStub {
    async fn accept(&mut self) -> Result<Box<dyn TraitConnection>, TransportError> {
        warn!("TCP accept: Unimplemented");
        // For a stub, we need to return something plausible if we weren't erroring.
        // Let's error out for now.
        Err(TransportError::Generic("Unimplemented".to_string()))
    }

    fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        Ok(self.local_addr)
    }
}

// --- TCP Client Transport Stub ---
pub struct TcpClientStub;

#[async_trait]
impl ClientTransport for TcpClientStub {
    async fn connect(&self, server_address: &str) -> Result<Box<dyn TraitConnection>, TransportError> {
        warn!("TCP connect to {}: Unimplemented", server_address);
        Err(TransportError::Generic("Unimplemented".to_string()))
    }
}

// --- TCP Server Transport Stub ---
pub struct TcpServerStub;

#[async_trait]
impl ServerTransport for TcpServerStub {
    type Listener = TcpListenerStub;

    async fn listen(&self, local_address: &str) -> Result<Self::Listener, TransportError> {
        warn!("TCP listen on {}: Unimplemented", local_address);
        let addr: SocketAddr = local_address
            .parse()
            .map_err(|e| TransportError::AddrParse(e))?;
        Ok(TcpListenerStub { local_addr: addr })
    }
}
