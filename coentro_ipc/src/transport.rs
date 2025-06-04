//! IPC Transport Layer
//!
//! This module defines the transport layer for the IPC protocol, including
//! the error types and the transport trait.

use crate::messages::{ClientRequest, HelperResponse};
use async_trait::async_trait;
use std::io;
use std::path::Path;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use std::os::unix::io::{AsRawFd, RawFd};
use tokio::time::{timeout, Duration};

/// Result type for IPC operations
pub type IpcResult<T> = Result<T, IpcError>;

/// Error type for IPC operations
#[derive(Error, Debug)]
pub enum IpcError {
    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(#[from] bincode::Error),

    /// Authentication error
    #[error("Authentication error: {0}")]
    Authentication(String),

    /// Connection error
    #[error("Connection error: {0}")]
    Connection(String),

    /// Protocol error
    #[error("Protocol error: {0}")]
    Protocol(String),

    /// Timeout error
    #[error("Timeout error: {0}")]
    Timeout(String),
}

/// Trait for IPC transport implementations
#[async_trait]
pub trait IpcTransport: Send + Sync {
    /// Send a request to the helper daemon
    async fn send_request(&mut self, request: &ClientRequest) -> IpcResult<()>;

    /// Receive a response from the helper daemon
    async fn receive_response(&mut self) -> IpcResult<HelperResponse>;

    /// Close the connection
    async fn close(&mut self) -> IpcResult<()>;
}

/// Unix Domain Socket transport implementation
pub struct UnixSocketTransport {
    stream: UnixStream,
}

impl UnixSocketTransport {
    /// Create a new Unix Domain Socket transport by connecting to the given path
    pub async fn connect<P: AsRef<Path>>(path: P) -> IpcResult<Self> {
        let stream = UnixStream::connect(path).await
            .map_err(|e| IpcError::Connection(format!("Failed to connect to socket: {}", e)))?;
        
        // Note: Tokio's UnixStream doesn't support direct timeout setting
        // We'll use the timeout wrapper when performing I/O operations

        Ok(Self { stream })
    }

    /// Helper method to send a message with length prefix
    async fn send_message(&mut self, data: &[u8]) -> IpcResult<()> {
        // Use timeout for the write operation
        let timeout_duration = Duration::from_secs(5);
        
        // Write length prefix (u32)
        let len = data.len() as u32;
        match timeout(timeout_duration, self.stream.write_all(&len.to_le_bytes())).await {
            Ok(result) => result.map_err(|e| IpcError::Io(e))?,
            Err(_) => return Err(IpcError::Timeout("Write operation timed out".to_string())),
        };
        
        // Write data
        match timeout(timeout_duration, self.stream.write_all(data)).await {
            Ok(result) => result.map_err(|e| IpcError::Io(e))?,
            Err(_) => return Err(IpcError::Timeout("Write operation timed out".to_string())),
        };
        
        Ok(())
    }

    /// Helper method to receive a message with length prefix
    async fn receive_message(&mut self) -> IpcResult<Vec<u8>> {
        let timeout_duration = Duration::from_secs(5);
        
        // Read length prefix (u32)
        let mut len_buf = [0u8; 4];
        match timeout(timeout_duration, self.stream.read_exact(&mut len_buf)).await {
            Ok(result) => result.map_err(|e| IpcError::Io(e))?,
            Err(_) => return Err(IpcError::Timeout("Read operation timed out".to_string())),
        };
        
        let len = u32::from_le_bytes(len_buf) as usize;
        
        // Sanity check on message size to prevent OOM
        if len > 10 * 1024 * 1024 { // 10 MB limit
            return Err(IpcError::Protocol(format!("Message too large: {} bytes", len)));
        }
        
        // Read data
        let mut data = vec![0u8; len];
        match timeout(timeout_duration, self.stream.read_exact(&mut data)).await {
            Ok(result) => result.map_err(|e| IpcError::Io(e))?,
            Err(_) => return Err(IpcError::Timeout("Read operation timed out".to_string())),
        };
        
        Ok(data)
    }
}

#[async_trait]
impl IpcTransport for UnixSocketTransport {
    async fn send_request(&mut self, request: &ClientRequest) -> IpcResult<()> {
        let serialized = bincode::serialize(request)
            .map_err(|e| IpcError::Serialization(e))?;
        
        self.send_message(&serialized).await
    }

    async fn receive_response(&mut self) -> IpcResult<HelperResponse> {
        let data = self.receive_message().await?;
        
        let response = bincode::deserialize(&data)
            .map_err(|e| IpcError::Serialization(e))?;
        
        Ok(response)
    }

    async fn close(&mut self) -> IpcResult<()> {
        // UnixStream doesn't have an explicit close method, but we can shut it down
        self.stream.shutdown().await
            .map_err(|e| IpcError::Io(e))?;
        
        Ok(())
    }
}

/// Helper daemon Unix Domain Socket listener
pub struct UnixSocketListener {
    listener: UnixListener,
    socket_path: String,
}

impl UnixSocketListener {
    /// Create a new Unix Domain Socket listener bound to the given path
    pub async fn bind<P: AsRef<Path>>(path: P) -> IpcResult<Self> {
        let path_str = path.as_ref().to_string_lossy().to_string();
        
        // Remove the socket file if it already exists
        if path.as_ref().exists() {
            std::fs::remove_file(path.as_ref())
                .map_err(|e| IpcError::Connection(format!("Failed to remove existing socket: {}", e)))?;
        }
        
        // Create the listener
        let listener = UnixListener::bind(path.as_ref())
            .map_err(|e| IpcError::Connection(format!("Failed to bind to socket: {}", e)))?;
        
        // Set permissive permissions on the socket file for testing
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = std::fs::metadata(path.as_ref())
                .map_err(|e| IpcError::Connection(format!("Failed to get socket metadata: {}", e)))?;
            let mut permissions = metadata.permissions();
            permissions.set_mode(0o777); // rwxrwxrwx
            std::fs::set_permissions(path.as_ref(), permissions)
                .map_err(|e| IpcError::Connection(format!("Failed to set socket permissions: {}", e)))?;
        }
        
        Ok(Self {
            listener,
            socket_path: path_str,
        })
    }

    /// Accept a new connection
    pub async fn accept(&self) -> IpcResult<UnixSocketConnection> {
        let (stream, _) = self.listener.accept().await
            .map_err(|e| IpcError::Connection(format!("Failed to accept connection: {}", e)))?;
        
        // For Sprint 1, we're not implementing authentication
        // This will be added in a future sprint
        
        Ok(UnixSocketConnection { stream })
    }
}

impl Drop for UnixSocketListener {
    fn drop(&mut self) {
        // Clean up the socket file when the listener is dropped
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

/// Unix Domain Socket connection for the helper daemon
pub struct UnixSocketConnection {
    stream: UnixStream,
}

impl UnixSocketConnection {
    /// Helper method to send a message with length prefix
    pub async fn send_response(&mut self, response: &HelperResponse) -> IpcResult<()> {
        let serialized = bincode::serialize(response)
            .map_err(|e| IpcError::Serialization(e))?;
        
        let timeout_duration = Duration::from_secs(5);
        
        // Write length prefix (u32)
        let len = serialized.len() as u32;
        match timeout(timeout_duration, self.stream.write_all(&len.to_le_bytes())).await {
            Ok(result) => result.map_err(|e| IpcError::Io(e))?,
            Err(_) => return Err(IpcError::Timeout("Write operation timed out".to_string())),
        };
        
        // Write data
        match timeout(timeout_duration, self.stream.write_all(&serialized)).await {
            Ok(result) => result.map_err(|e| IpcError::Io(e))?,
            Err(_) => return Err(IpcError::Timeout("Write operation timed out".to_string())),
        };
        
        Ok(())
    }

    /// Helper method to receive a message with length prefix
    pub async fn receive_request(&mut self) -> IpcResult<ClientRequest> {
        let timeout_duration = Duration::from_secs(5);
        
        // Read length prefix (u32)
        let mut len_buf = [0u8; 4];
        match timeout(timeout_duration, self.stream.read_exact(&mut len_buf)).await {
            Ok(result) => result.map_err(|e| IpcError::Io(e))?,
            Err(_) => return Err(IpcError::Timeout("Read operation timed out".to_string())),
        };
        
        let len = u32::from_le_bytes(len_buf) as usize;
        
        // Sanity check on message size to prevent OOM
        if len > 10 * 1024 * 1024 { // 10 MB limit
            return Err(IpcError::Protocol(format!("Message too large: {} bytes", len)));
        }
        
        // Read data
        let mut data = vec![0u8; len];
        match timeout(timeout_duration, self.stream.read_exact(&mut data)).await {
            Ok(result) => result.map_err(|e| IpcError::Io(e))?,
            Err(_) => return Err(IpcError::Timeout("Read operation timed out".to_string())),
        };
        
        // Deserialize
        let request = bincode::deserialize(&data)
            .map_err(|e| IpcError::Serialization(e))?;
        
        Ok(request)
    }

    /// Close the connection
    pub async fn close(&mut self) -> IpcResult<()> {
        self.stream.shutdown().await
            .map_err(|e| IpcError::Io(e))?;
        
        Ok(())
    }

    /// Get the raw file descriptor for the socket
    pub fn as_raw_fd(&self) -> RawFd {
        self.stream.as_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::{ClientRequest, HelperResponse};
    use tokio::runtime::Runtime;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use std::thread;

    #[test]
    fn test_unix_socket_transport() {
        let runtime = Runtime::new().unwrap();
        let temp_dir = std::env::temp_dir();
        let socket_path = temp_dir.join("coentro_test_socket");
        
        // Remove the socket file if it already exists
        if socket_path.exists() {
            std::fs::remove_file(&socket_path).unwrap();
        }
        
        // Shared state for the test
        let request_received = Arc::new(Mutex::new(false));
        let request_received_clone = request_received.clone();
        
        // Start the server in a separate thread
        let socket_path_clone = socket_path.clone();
        let server_thread = thread::spawn(move || {
            let server_runtime = Runtime::new().unwrap();
            
            server_runtime.block_on(async {
                let listener = UnixSocketListener::bind(&socket_path_clone).await.unwrap();
                let mut connection = listener.accept().await.unwrap();
                
                let request = connection.receive_request().await.unwrap();
                match request {
                    ClientRequest::Ping => {
                        *request_received_clone.lock().unwrap() = true;
                        connection.send_response(&HelperResponse::Pong).await.unwrap();
                    },
                    _ => panic!("Unexpected request type"),
                }
                
                connection.close().await.unwrap();
            });
        });
        
        // Give the server a moment to start
        thread::sleep(Duration::from_millis(100));
        
        // Run the client
        runtime.block_on(async {
            let mut client = UnixSocketTransport::connect(&socket_path).await.unwrap();
            
            // Send a ping request
            client.send_request(&ClientRequest::Ping).await.unwrap();
            
            // Receive the response
            let response = client.receive_response().await.unwrap();
            match response {
                HelperResponse::Pong => {},
                _ => panic!("Unexpected response type"),
            }
            
            client.close().await.unwrap();
        });
        
        // Wait for the server to finish
        server_thread.join().unwrap();
        
        // Check that the request was received
        assert!(*request_received.lock().unwrap());
        
        // Clean up
        if socket_path.exists() {
            std::fs::remove_file(&socket_path).unwrap();
        }
    }
}
