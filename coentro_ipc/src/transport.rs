//! IPC Transport Layer
//!
//! This module defines the transport layer for the IPC protocol, including
//! the error types and the transport trait.

use crate::messages::{ClientRequest, HelperResponse};
use async_trait::async_trait;
use std::collections::HashSet;
use std::io::{self, IoSlice, IoSliceMut};
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::Path;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::time::{timeout, Duration};

// Platform-specific imports for peer credentials
#[cfg(target_os = "linux")]
use nix::sys::socket::UnixCredentials;

#[cfg(target_os = "macos")]
use libc::xucred as UnixCredentials;

// Platform-specific imports for file descriptor passing
#[cfg(any(target_os = "linux", target_os = "macos"))]
use nix::sys::socket::{sendmsg, recvmsg, ControlMessage, ControlMessageOwned, MsgFlags};

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

    /// File descriptor error
    #[error("File descriptor error: {0}")]
    FileDescriptor(String),
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
        let stream = UnixStream::connect(path)
            .await
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
            Ok(result) => result.map_err(IpcError::Io)?,
            Err(_) => return Err(IpcError::Timeout("Write operation timed out".to_string())),
        };

        // Write data
        match timeout(timeout_duration, self.stream.write_all(data)).await {
            Ok(result) => result.map_err(IpcError::Io)?,
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
            Ok(result) => result.map_err(IpcError::Io)?,
            Err(_) => return Err(IpcError::Timeout("Read operation timed out".to_string())),
        };

        let len = u32::from_le_bytes(len_buf) as usize;

        // Sanity check on message size to prevent OOM
        if len > 10 * 1024 * 1024 {
            // 10 MB limit
            return Err(IpcError::Protocol(format!(
                "Message too large: {} bytes",
                len
            )));
        }

        // Read data
        let mut data = vec![0u8; len];
        match timeout(timeout_duration, self.stream.read_exact(&mut data)).await {
            Ok(result) => result.map_err(IpcError::Io)?,
            Err(_) => return Err(IpcError::Timeout("Read operation timed out".to_string())),
        };

        Ok(data)
    }

    /// Receive a file descriptor from the Unix socket
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub async fn receive_fd(&mut self) -> IpcResult<RawFd> {
        // Get the raw file descriptor
        let raw_fd = self.stream.as_raw_fd();

        // Create a buffer for the message
        let mut buf = [0u8; 1];
        let mut cmsg_buffer = vec![0u8; 64];

        // Prepare the IO vector
        let mut iovec = [IoSliceMut::new(&mut buf)];

        // Receive the message with the file descriptor
        let msg = recvmsg::<()>(
            raw_fd,
            &mut iovec,
            Some(&mut cmsg_buffer),
            MsgFlags::empty(),
        )
        .map_err(|e| IpcError::FileDescriptor(format!("Failed to receive message: {}", e)))?;

        // Extract the file descriptor from the control message
        for cmsg in msg.cmsgs() {
            if let ControlMessageOwned::ScmRights(fds) = cmsg {
                if !fds.is_empty() {
                    return Ok(fds[0]);
                }
            }
        }

        Err(IpcError::FileDescriptor(
            "No file descriptor received".to_string(),
        ))
    }
}

#[async_trait]
impl IpcTransport for UnixSocketTransport {
    async fn send_request(&mut self, request: &ClientRequest) -> IpcResult<()> {
        let serialized = bincode::serialize(request).map_err(IpcError::Serialization)?;

        self.send_message(&serialized).await
    }

    async fn receive_response(&mut self) -> IpcResult<HelperResponse> {
        let data = self.receive_message().await?;

        let mut response: HelperResponse =
            bincode::deserialize(&data).map_err(IpcError::Serialization)?;

        // If the response is TunnelReady, we need to receive the file descriptor
        if let HelperResponse::TunnelReady(ref mut details) = response {
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            {
                // Receive the file descriptor
                let fd = self.receive_fd().await?;
                details.fd = fd;
            }
        }

        Ok(response)
    }

    async fn close(&mut self) -> IpcResult<()> {
        // UnixStream doesn't have an explicit close method, but we can shut it down
        self.stream.shutdown().await.map_err(IpcError::Io)?;

        Ok(())
    }
}

/// Authentication configuration for the Unix Domain Socket listener
#[derive(Debug, Clone)]
pub struct AuthConfig {
    /// Set of allowed UIDs
    allowed_uids: HashSet<u32>,
    /// Set of allowed GIDs
    allowed_gids: HashSet<u32>,
    /// Whether to allow root (UID 0) by default
    allow_root: bool,
}

impl Default for AuthConfig {
    fn default() -> Self {
        let mut allowed_uids = HashSet::new();
        let mut allowed_gids = HashSet::new();

        // By default, allow the current user
        if let Ok(uid) = std::env::var("SUDO_UID") {
            if let Ok(uid) = uid.parse::<u32>() {
                allowed_uids.insert(uid);
            }
        }

        // Also allow the current user's primary group
        if let Ok(gid) = std::env::var("SUDO_GID") {
            if let Ok(gid) = gid.parse::<u32>() {
                allowed_gids.insert(gid);
            }
        }

        Self {
            allowed_uids,
            allowed_gids,
            allow_root: true,
        }
    }
}

impl AuthConfig {
    /// Create a new authentication configuration
    pub fn new() -> Self {
        Self::default()
    }

    /// Allow a specific UID
    pub fn allow_uid(mut self, uid: u32) -> Self {
        self.allowed_uids.insert(uid);
        self
    }

    /// Allow a specific GID
    pub fn allow_gid(mut self, gid: u32) -> Self {
        self.allowed_gids.insert(gid);
        self
    }

    /// Set whether to allow root (UID 0) by default
    pub fn allow_root(mut self, allow: bool) -> Self {
        self.allow_root = allow;
        self
    }

    /// Check if a user is allowed based on their credentials
    #[cfg(target_os = "linux")]
    pub fn is_allowed(&self, creds: &UnixCredentials) -> bool {
        // Debug print in test mode
        #[cfg(test)]
        println!("Linux is_allowed check - UID: {}, GID: {}, allowed_uids: {:?}, allowed_gids: {:?}, allow_root: {}", 
                 creds.uid(), creds.gid(), self.allowed_uids, self.allowed_gids, self.allow_root);

        // Always allow root if configured to do so
        if self.allow_root && creds.uid() == 0 {
            #[cfg(test)]
            println!("Root access allowed");
            return true;
        }

        // Check if the UID is allowed
        if self.allowed_uids.contains(&creds.uid()) {
            #[cfg(test)]
            println!("UID {} is allowed", creds.uid());
            return true;
        }

        // Check if the GID is allowed
        if self.allowed_gids.contains(&creds.gid()) {
            #[cfg(test)]
            println!("GID {} is allowed", creds.gid());
            return true;
        }

        #[cfg(test)]
        println!(
            "Access denied for UID: {}, GID: {}",
            creds.uid(),
            creds.gid()
        );

        false
    }

    /// Check if a user is allowed based on their credentials
    #[cfg(target_os = "macos")]
    pub fn is_allowed(&self, creds: &UnixCredentials) -> bool {
        let _primary_gid = if creds.cr_ngroups > 0 {
            creds.cr_groups[0]
        } else {
            0
        };

        // Debug print in test mode
        #[cfg(test)]
        println!("macOS is_allowed check - UID: {}, GID: {}, allowed_uids: {:?}, allowed_gids: {:?}, allow_root: {}", 
                 creds.cr_uid, _primary_gid, self.allowed_uids, self.allowed_gids, self.allow_root);

        // Always allow root if configured to do so
        if self.allow_root && creds.cr_uid == 0 {
            #[cfg(test)]
            println!("Root access allowed");
            return true;
        }

        // Check if the UID is allowed
        if self.allowed_uids.contains(&creds.cr_uid) {
            #[cfg(test)]
            println!("UID {} is allowed", creds.cr_uid);
            return true;
        }

        // Check if the GID is allowed (on macOS, cr_groups[0] is the primary group)
        if creds.cr_ngroups > 0 && self.allowed_gids.contains(&creds.cr_groups[0]) {
            #[cfg(test)]
            println!("GID {} is allowed", creds.cr_groups[0]);
            return true;
        }

        #[cfg(test)]
        println!(
            "Access denied for UID: {}, GID: {}",
            creds.cr_uid, _primary_gid
        );

        false
    }
}

/// Helper daemon Unix Domain Socket listener
pub struct UnixSocketListener {
    listener: UnixListener,
    socket_path: String,
    auth_config: AuthConfig,
}

impl UnixSocketListener {
    /// Create a new Unix Domain Socket listener bound to the given path
    pub async fn bind<P: AsRef<Path>>(path: P) -> IpcResult<Self> {
        Self::bind_with_auth(path, AuthConfig::default()).await
    }

    /// Create a new Unix Domain Socket listener with custom authentication config
    pub async fn bind_with_auth<P: AsRef<Path>>(
        path: P,
        auth_config: AuthConfig,
    ) -> IpcResult<Self> {
        let path_str = path.as_ref().to_string_lossy().to_string();

        // Remove the socket file if it already exists
        if path.as_ref().exists() {
            std::fs::remove_file(path.as_ref()).map_err(|e| {
                IpcError::Connection(format!("Failed to remove existing socket: {}", e))
            })?;
        }

        // Create the listener
        let listener = UnixListener::bind(path.as_ref())
            .map_err(|e| IpcError::Connection(format!("Failed to bind to socket: {}", e)))?;

        // Set permissions on the socket file
        // We'll use 660 (rw-rw----) to allow group members to access the socket
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = std::fs::metadata(path.as_ref()).map_err(|e| {
                IpcError::Connection(format!("Failed to get socket metadata: {}", e))
            })?;
            let mut permissions = metadata.permissions();
            permissions.set_mode(0o660); // rw-rw----
            std::fs::set_permissions(path.as_ref(), permissions).map_err(|e| {
                IpcError::Connection(format!("Failed to set socket permissions: {}", e))
            })?;
        }

        Ok(Self {
            listener,
            socket_path: path_str,
            auth_config,
        })
    }

    /// Accept a new connection
    pub async fn accept(&self) -> IpcResult<UnixSocketConnection> {
        let (stream, _) = self
            .listener
            .accept()
            .await
            .map_err(|e| IpcError::Connection(format!("Failed to accept connection: {}", e)))?;

        // Get peer credentials (UID, GID)
        let peer_cred = Self::get_peer_credentials(&stream).map_err(|e| {
            IpcError::Authentication(format!("Failed to get peer credentials: {}", e))
        })?;

        // Authenticate the peer
        if !self.auth_config.is_allowed(&peer_cred) {
            #[cfg(target_os = "linux")]
            return Err(IpcError::Authentication(format!(
                "Connection from unauthorized user: UID={}, GID={}",
                peer_cred.uid(),
                peer_cred.gid()
            )));

            #[cfg(target_os = "macos")]
            return Err(IpcError::Authentication(format!(
                "Connection from unauthorized user: UID={}, GID={}",
                peer_cred.cr_uid, peer_cred.cr_groups[0]
            )));
        }

        Ok(UnixSocketConnection { stream, peer_cred })
    }

    /// Get the credentials of the peer connected to the given socket
    #[cfg(target_os = "linux")]
    fn get_peer_credentials(stream: &UnixStream) -> io::Result<UnixCredentials> {
        // Get the raw file descriptor
        let raw_fd = stream.as_raw_fd();

        // Use nix to get peer credentials
        let creds =
            nix::sys::socket::getsockopt(raw_fd, nix::sys::socket::sockopt::PeerCredentials)
                .map_err(io::Error::other)?;

        // Debug print in test mode
        #[cfg(test)]
        println!(
            "Linux peer credentials - UID: {}, GID: {}",
            creds.uid(),
            creds.gid()
        );

        Ok(creds)
    }

    /// Get the credentials of the peer connected to the given socket
    #[cfg(target_os = "macos")]
    fn get_peer_credentials(stream: &UnixStream) -> io::Result<UnixCredentials> {
        // Get the raw file descriptor
        let raw_fd = stream.as_raw_fd();

        // Use the getsockopt system call to get the peer credentials
        unsafe {
            let mut xucred = std::mem::MaybeUninit::<libc::xucred>::uninit();
            let mut xucred_size = std::mem::size_of::<libc::xucred>() as libc::socklen_t;

            let ret = libc::getsockopt(
                raw_fd,
                libc::SOL_LOCAL,
                libc::LOCAL_PEERCRED,
                xucred.as_mut_ptr() as *mut libc::c_void,
                &mut xucred_size,
            );

            if ret == 0 {
                let creds = xucred.assume_init();

                // Debug print in test mode
                #[cfg(test)]
                {
                    let gid = if creds.cr_ngroups > 0 {
                        creds.cr_groups[0]
                    } else {
                        0
                    };
                    println!(
                        "macOS peer credentials - UID: {}, GID: {}",
                        creds.cr_uid, gid
                    );
                }

                Ok(creds)
            } else {
                Err(io::Error::last_os_error())
            }
        }
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
    peer_cred: UnixCredentials,
}

impl UnixSocketConnection {
    /// Get the peer credentials (UID, GID)
    pub fn peer_credentials(&self) -> &UnixCredentials {
        &self.peer_cred
    }

    /// Get the peer UID
    #[cfg(target_os = "linux")]
    pub fn peer_uid(&self) -> u32 {
        self.peer_cred.uid()
    }

    /// Get the peer GID
    #[cfg(target_os = "linux")]
    pub fn peer_gid(&self) -> u32 {
        self.peer_cred.gid()
    }

    /// Get the peer UID
    #[cfg(target_os = "macos")]
    pub fn peer_uid(&self) -> u32 {
        self.peer_cred.cr_uid
    }

    /// Get the peer GID
    #[cfg(target_os = "macos")]
    pub fn peer_gid(&self) -> u32 {
        if self.peer_cred.cr_ngroups > 0 {
            self.peer_cred.cr_groups[0]
        } else {
            0 // Default to 0 if no groups
        }
    }

    /// Helper method to send a message with length prefix
    pub async fn send_response(&mut self, response: &HelperResponse) -> IpcResult<()> {
        let serialized = bincode::serialize(response).map_err(IpcError::Serialization)?;

        let timeout_duration = Duration::from_secs(5);

        // Write length prefix (u32)
        let len = serialized.len() as u32;
        match timeout(timeout_duration, self.stream.write_all(&len.to_le_bytes())).await {
            Ok(result) => result.map_err(IpcError::Io)?,
            Err(_) => return Err(IpcError::Timeout("Write operation timed out".to_string())),
        };

        // Write data
        match timeout(timeout_duration, self.stream.write_all(&serialized)).await {
            Ok(result) => result.map_err(IpcError::Io)?,
            Err(_) => return Err(IpcError::Timeout("Write operation timed out".to_string())),
        };

        // If the response is TunnelReady, we need to send the file descriptor
        if let HelperResponse::TunnelReady(ref details) = response {
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            {
                // Send the file descriptor
                self.send_fd(details.fd).map_err(|e| {
                    IpcError::FileDescriptor(format!("Failed to send file descriptor: {}", e))
                })?;
            }
        }

        Ok(())
    }

    /// Send a file descriptor over the Unix socket
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn send_fd(&self, fd: RawFd) -> io::Result<()> {
        // Get the raw file descriptor
        let raw_fd = self.stream.as_raw_fd();

        // Create a dummy message to send along with the file descriptor
        let dummy_data = [0u8; 1];
        let iov = [IoSlice::new(&dummy_data)];

        // Create the control message with the file descriptor
        let fd_array = [fd];
        let cmsg = [ControlMessage::ScmRights(&fd_array)];

        // Send the message with the file descriptor
        sendmsg::<()>(raw_fd, &iov, &cmsg, MsgFlags::empty(), None)?;

        Ok(())
    }

    /// Helper method to receive a message with length prefix
    pub async fn receive_request(&mut self) -> IpcResult<ClientRequest> {
        let timeout_duration = Duration::from_secs(5);

        // Read length prefix (u32)
        let mut len_buf = [0u8; 4];
        match timeout(timeout_duration, self.stream.read_exact(&mut len_buf)).await {
            Ok(result) => result.map_err(IpcError::Io)?,
            Err(_) => return Err(IpcError::Timeout("Read operation timed out".to_string())),
        };

        let len = u32::from_le_bytes(len_buf) as usize;

        // Sanity check on message size to prevent OOM
        if len > 10 * 1024 * 1024 {
            // 10 MB limit
            return Err(IpcError::Protocol(format!(
                "Message too large: {} bytes",
                len
            )));
        }

        // Read data
        let mut data = vec![0u8; len];
        match timeout(timeout_duration, self.stream.read_exact(&mut data)).await {
            Ok(result) => result.map_err(IpcError::Io)?,
            Err(_) => return Err(IpcError::Timeout("Read operation timed out".to_string())),
        };

        // Deserialize
        let request = bincode::deserialize(&data).map_err(IpcError::Serialization)?;

        Ok(request)
    }

    /// Close the connection
    pub async fn close(&mut self) -> IpcResult<()> {
        self.stream.shutdown().await.map_err(IpcError::Io)?;

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
    use std::sync::{Arc, Mutex};
    use std::thread;
    use tokio::runtime::Runtime;

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

        // Use a channel to signal when the server is ready
        let (tx, rx) = std::sync::mpsc::channel();

        // Start the server in a separate thread
        let socket_path_clone = socket_path.clone();
        let server_thread = thread::spawn(move || {
            let server_runtime = Runtime::new().unwrap();

            server_runtime.block_on(async {
                // Create an auth config that allows the current user
                let auth_config = AuthConfig::new()
                    .allow_uid(unsafe { libc::getuid() })
                    .allow_gid(unsafe { libc::getgid() });

                let listener = UnixSocketListener::bind_with_auth(&socket_path_clone, auth_config)
                    .await
                    .unwrap();

                // Signal that the server is ready to accept connections
                tx.send(()).unwrap();
                let mut connection = listener.accept().await.unwrap();

                // Verify we got the correct peer credentials
                assert_eq!(connection.peer_uid(), unsafe { libc::getuid() });

                let request = connection.receive_request().await.unwrap();
                match request {
                    ClientRequest::Ping => {
                        *request_received_clone.lock().unwrap() = true;
                        connection
                            .send_response(&HelperResponse::Pong)
                            .await
                            .unwrap();
                    }
                    _ => panic!("Unexpected request type"),
                }

                connection.close().await.unwrap();
            });
        });

        // Wait for the server to be ready before attempting to connect
        rx.recv().unwrap();

        // Run the client
        runtime.block_on(async {
            // Retry connection with exponential backoff (should succeed on first try now)
            let mut client = None;
            let mut retry_count = 0;
            let max_retries = 5;
            let mut delay_ms = 50;

            while retry_count < max_retries {
                match UnixSocketTransport::connect(&socket_path).await {
                    Ok(c) => {
                        client = Some(c);
                        break;
                    }
                    Err(e) => {
                        println!("Connection attempt {} failed: {}", retry_count + 1, e);
                        retry_count += 1;
                        if retry_count >= max_retries {
                            panic!("Failed to connect after {} attempts", max_retries);
                        }
                        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                        delay_ms *= 2; // Exponential backoff
                    }
                }
            }

            let mut client = client.unwrap();

            // Send a ping request
            client.send_request(&ClientRequest::Ping).await.unwrap();

            // Receive the response
            let response = client.receive_response().await.unwrap();
            match response {
                HelperResponse::Pong => {}
                _ => panic!("Unexpected response type"),
            }

            // Don't unwrap here, as the connection might already be closed by the server
            let _ = client.close().await;
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

    #[test]
    fn test_authentication() {
        let runtime = Runtime::new().unwrap();
        let temp_dir = std::env::temp_dir();
        let socket_path = temp_dir.join("coentro_test_auth_socket");

        // Print current user info for debugging
        println!("Current UID: {}", unsafe { libc::getuid() });
        println!("Current GID: {}", unsafe { libc::getgid() });

        // Remove the socket file if it already exists
        if socket_path.exists() {
            std::fs::remove_file(&socket_path).unwrap();
        }

        // Use a channel to signal when the server is ready
        let (tx, rx) = std::sync::mpsc::channel();
        // Use another channel to signal when the server has processed the connection
        let (auth_tx, auth_rx) = std::sync::mpsc::channel();

        // Start the server in a separate thread with restricted auth
        let socket_path_clone = socket_path.clone();
        let server_thread = thread::spawn(move || {
            let server_runtime = Runtime::new().unwrap();

            server_runtime.block_on(async {
                // Create an auth config that only allows a specific UID that's not the current user
                let current_uid = unsafe { libc::getuid() };
                println!("Server thread UID: {}", current_uid);

                // Use a UID that's definitely not the current user
                let disallowed_uid = if current_uid == 12345 { 12346 } else { 12345 };
                println!("Using disallowed UID: {}", disallowed_uid);

                let auth_config = AuthConfig::new()
                    .allow_uid(disallowed_uid) // Some UID that's not the current user
                    .allow_root(false); // Don't allow root

                let listener = UnixSocketListener::bind_with_auth(&socket_path_clone, auth_config)
                    .await
                    .unwrap();

                // Signal that the server is ready to accept connections
                tx.send(()).unwrap();

                // This should fail with an authentication error since we're not using the allowed UID
                match listener.accept().await {
                    Err(IpcError::Authentication(msg)) => {
                        // This is expected
                        println!("Authentication error as expected: {}", msg);
                        auth_tx.send(true).unwrap(); // Signal that auth failed as expected
                    }
                    Ok(conn) => {
                        #[cfg(target_os = "linux")]
                        println!(
                            "Unexpected authentication success. Peer UID: {}, GID: {}",
                            conn.peer_uid(),
                            conn.peer_gid()
                        );

                        #[cfg(target_os = "macos")]
                        println!(
                            "Unexpected authentication success. Peer UID: {}, GID: {}",
                            conn.peer_uid(),
                            conn.peer_gid()
                        );

                        auth_tx.send(false).unwrap(); // Signal that auth succeeded unexpectedly
                        panic!("Authentication should have failed");
                    }
                    Err(e) => {
                        println!("Unexpected error: {:?}", e);
                        auth_tx.send(false).unwrap(); // Signal that there was an unexpected error
                        panic!("Unexpected error: {:?}", e);
                    }
                }
            });
        });

        // Wait for the server to be ready before attempting to connect
        rx.recv().unwrap();

        // Give the server a moment to set up
        std::thread::sleep(std::time::Duration::from_millis(100));

        // Run the client - this should connect but the server should reject the connection
        runtime.block_on(async {
            // Retry connection with exponential backoff (should succeed on first try now)
            let mut client = None;
            let mut retry_count = 0;
            let max_retries = 5;
            let mut delay_ms = 50;

            while retry_count < max_retries {
                match UnixSocketTransport::connect(&socket_path).await {
                    Ok(c) => {
                        client = Some(c);
                        println!("Client connected successfully");
                        break;
                    }
                    Err(e) => {
                        println!("Connection attempt {} failed: {}", retry_count + 1, e);
                        retry_count += 1;
                        if retry_count >= max_retries {
                            panic!("Failed to connect after {} attempts", max_retries);
                        }
                        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                        delay_ms *= 2; // Exponential backoff
                    }
                }
            }

            // The connection itself should succeed
            let mut client = client.unwrap();

            // Wait for the server to process the authentication
            // This ensures the server has time to reject the connection
            match auth_rx.recv_timeout(std::time::Duration::from_secs(2)) {
                Ok(true) => println!("Server rejected connection as expected"),
                Ok(false) => println!("Server unexpectedly accepted connection"),
                Err(_) => println!("Timeout waiting for server authentication result"),
            }

            // Add a small delay to ensure the server has time to close the connection if needed
            tokio::time::sleep(Duration::from_millis(500)).await;

            // But when we try to send a request, it should fail because the server closed the connection
            match client.send_request(&ClientRequest::Ping).await {
                Err(e) => {
                    // This is expected - the server should have closed the connection
                    println!("Request failed as expected: {}", e);
                }
                Ok(_) => {
                    // This is unexpected - the server should have rejected the connection
                    println!("Request succeeded unexpectedly");
                    panic!("Server should have rejected the connection");
                }
            }

            // Clean up
            let _ = client.close().await;
        });

        // Wait for the server to finish
        server_thread.join().unwrap();

        // Clean up
        if socket_path.exists() {
            std::fs::remove_file(&socket_path).unwrap();
        }
    }
}
