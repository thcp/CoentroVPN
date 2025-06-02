//! Session management for CoentroVPN.
//!
//! This module handles client sessions, including authentication,
//! connection state, and session lifecycle management.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::{debug, error, info, instrument, warn};

use crate::tunnel::{Tunnel, TunnelError};
use shared_utils::crypto::aes_gcm::AesGcmCipher;

/// Session state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum SessionState {
    /// Session is being created
    Creating,
    /// Session is authenticating
    Authenticating,
    /// Session is established and active
    Active,
    /// Session is disconnecting
    Disconnecting,
    /// Session has ended
    Ended,
}

/// Session error types
#[derive(Debug, thiserror::Error)]
#[allow(dead_code)]
pub enum SessionError {
    /// Authentication failed
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    /// Session expired
    #[error("Session expired")]
    Expired,

    /// Tunnel error
    #[error("Tunnel error: {0}")]
    Tunnel(#[from] TunnelError),

    /// Session already ended
    #[error("Session already ended")]
    AlreadyEnded,

    /// Other error
    #[error("Session error: {0}")]
    Other(String),
}

/// A client session in CoentroVPN
#[allow(dead_code)]
pub struct Session {
    /// Unique session identifier
    id: String,

    /// Client identifier
    client_id: String,

    /// Client address
    client_addr: SocketAddr,

    /// Session state
    state: SessionState,

    /// When the session was created
    created_at: Instant,

    /// When the session was last active
    last_active: Instant,

    /// Session expiry time
    expires_at: Option<Instant>,

    /// The network tunnel for this session
    tunnel: Option<Arc<Mutex<Tunnel>>>,

    /// Session encryption key
    encryption_key: Option<[u8; 32]>,
}

impl Session {
    /// Create a new session
    #[instrument(level = "info", skip(client_id))]
    pub fn new(id: String, client_id: String, client_addr: SocketAddr) -> Self {
        let now = Instant::now();

        info!(
            session_id = %id,
            client_id = %client_id,
            client_addr = %client_addr,
            "Creating new session"
        );

        Session {
            id,
            client_id,
            client_addr,
            state: SessionState::Creating,
            created_at: now,
            last_active: now,
            expires_at: None,
            tunnel: None,
            encryption_key: None,
        }
    }

    /// Get the session ID
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Get the client ID
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    /// Get the client address
    pub fn client_addr(&self) -> SocketAddr {
        self.client_addr
    }

    /// Get the session state
    pub fn state(&self) -> SessionState {
        self.state
    }

    /// Get the session creation time
    pub fn created_at(&self) -> Instant {
        self.created_at
    }

    /// Get the time the session was last active
    pub fn last_active(&self) -> Instant {
        self.last_active
    }

    /// Set the session expiry time
    #[instrument(level = "debug", skip(self))]
    pub fn set_expiry(&mut self, duration: Duration) {
        let expires_at = self.created_at + duration;
        debug!(
            session_id = %self.id,
            expires_in = ?duration,
            "Setting session expiry"
        );
        self.expires_at = Some(expires_at);
    }

    /// Check if the session has expired
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            Instant::now() > expires_at
        } else {
            false
        }
    }

    /// Set the tunnel for this session
    #[instrument(level = "debug", skip(self, tunnel))]
    pub fn set_tunnel(&mut self, tunnel: Tunnel) {
        debug!(
            session_id = %self.id,
            tunnel_id = %tunnel.id(),
            "Setting tunnel for session"
        );
        self.tunnel = Some(Arc::new(Mutex::new(tunnel)));
    }

    /// Set the encryption key for this session
    #[instrument(level = "debug", skip(self, key))]
    pub fn set_encryption_key(&mut self, key: [u8; 32]) {
        debug!(
            session_id = %self.id,
            "Setting encryption key for session"
        );
        self.encryption_key = Some(key);

        // If we have a tunnel, set up encryption
        if let Some(tunnel) = &self.tunnel {
            if let Some(key) = self.encryption_key {
                debug!(
                    session_id = %self.id,
                    "Configuring tunnel encryption"
                );

                // Create cipher and set it on the tunnel
                match AesGcmCipher::new(&key) {
                    Ok(cipher) => {
                        if let Ok(mut tunnel) = tunnel.lock() {
                            tunnel.set_cipher(cipher);
                        } else {
                            error!(
                                session_id = %self.id,
                                "Failed to lock tunnel mutex"
                            );
                        }
                    }
                    Err(e) => {
                        error!(
                            session_id = %self.id,
                            error = %e,
                            "Failed to create AES-GCM cipher"
                        );
                    }
                }
            }
        }
    }

    /// Authenticate the session
    #[instrument(level = "info", skip(self, _credentials))]
    pub async fn authenticate(&mut self, _credentials: &[u8]) -> Result<(), SessionError> {
        if self.state != SessionState::Creating {
            warn!(
                session_id = %self.id,
                state = ?self.state,
                "Cannot authenticate session in current state"
            );
            return Err(SessionError::Other(
                "Invalid session state for authentication".to_string(),
            ));
        }

        info!(
            session_id = %self.id,
            "Authenticating session"
        );

        self.state = SessionState::Authenticating;

        // TODO: Implement actual authentication logic
        // For now, we'll just simulate authentication

        // Update last active time
        self.last_active = Instant::now();

        // Set session to active
        self.state = SessionState::Active;

        info!(
            session_id = %self.id,
            "Session authenticated successfully"
        );

        Ok(())
    }

    /// Send data through the session tunnel
    #[instrument(level = "debug", skip(self, data), fields(data_len = data.len()))]
    #[allow(clippy::await_holding_lock)]
    pub async fn send_data(&mut self, data: &[u8]) -> Result<(), SessionError> {
        if self.state != SessionState::Active {
            warn!(
                session_id = %self.id,
                state = ?self.state,
                "Cannot send data: session not active"
            );
            return Err(SessionError::Other("Session not active".to_string()));
        }

        // Check if session has expired
        if self.is_expired() {
            warn!(
                session_id = %self.id,
                "Cannot send data: session expired"
            );
            return Err(SessionError::Expired);
        }

        debug!(
            session_id = %self.id,
            data_len = data.len(),
            "Sending data through session"
        );

        // Get the tunnel
        let tunnel = match &self.tunnel {
            Some(tunnel) => tunnel,
            None => {
                error!(
                    session_id = %self.id,
                    "No tunnel available for session"
                );
                return Err(SessionError::Other("No tunnel available".to_string()));
            }
        };

        // Get a clone of the tunnel Arc to avoid holding the lock across await
        let tunnel_clone = Arc::clone(tunnel);
        
        // Get the tunnel ID for logging
        let tunnel_id = {
            let guard = match tunnel_clone.lock() {
                Ok(guard) => guard,
                Err(e) => {
                    error!(
                        session_id = %self.id,
                        error = %e,
                        "Failed to lock tunnel mutex"
                    );
                    return Err(SessionError::Other("Failed to lock tunnel".to_string()));
                }
            };
            guard.id().to_string()
        };
        
        // Now send the data with a new lock
        let result = {
            let guard = match tunnel_clone.lock() {
                Ok(guard) => guard,
                Err(e) => {
                    error!(
                        session_id = %self.id,
                        error = %e,
                        "Failed to lock tunnel mutex"
                    );
                    return Err(SessionError::Other("Failed to lock tunnel".to_string()));
                }
            };
            guard.send(data).await
        };
        
        // Handle the result
        if let Err(e) = result {
            error!(
                session_id = %self.id,
                tunnel_id = %tunnel_id,
                error = %e,
                "Failed to send data through tunnel"
            );
            return Err(SessionError::Tunnel(e));
        }

        // Update last active time
        self.last_active = Instant::now();

        debug!(
            session_id = %self.id,
            "Data sent successfully"
        );

        Ok(())
    }

    /// Receive data from the session tunnel
    #[instrument(level = "debug", skip(self))]
    #[allow(clippy::await_holding_lock)]
    pub async fn receive_data(&mut self) -> Result<Vec<u8>, SessionError> {
        if self.state != SessionState::Active {
            warn!(
                session_id = %self.id,
                state = ?self.state,
                "Cannot receive data: session not active"
            );
            return Err(SessionError::Other("Session not active".to_string()));
        }

        // Check if session has expired
        if self.is_expired() {
            warn!(
                session_id = %self.id,
                "Cannot receive data: session expired"
            );
            return Err(SessionError::Expired);
        }

        debug!(
            session_id = %self.id,
            "Receiving data from session"
        );

        // Get the tunnel
        let tunnel = match &self.tunnel {
            Some(tunnel) => tunnel,
            None => {
                error!(
                    session_id = %self.id,
                    "No tunnel available for session"
                );
                return Err(SessionError::Other("No tunnel available".to_string()));
            }
        };

        // Get a clone of the tunnel Arc to avoid holding the lock across await
        let tunnel_clone = Arc::clone(tunnel);
        
        // Get the tunnel ID for logging
        let tunnel_id = {
            let guard = match tunnel_clone.lock() {
                Ok(guard) => guard,
                Err(e) => {
                    error!(
                        session_id = %self.id,
                        error = %e,
                        "Failed to lock tunnel mutex"
                    );
                    return Err(SessionError::Other("Failed to lock tunnel".to_string()));
                }
            };
            guard.id().to_string()
        };
        
        // Now receive the data with a new lock
        let result = {
            let mut guard = match tunnel_clone.lock() {
                Ok(guard) => guard,
                Err(e) => {
                    error!(
                        session_id = %self.id,
                        error = %e,
                        "Failed to lock tunnel mutex"
                    );
                    return Err(SessionError::Other("Failed to lock tunnel".to_string()));
                }
            };
            guard.receive().await
        };
        
        // Handle the result
        let data = match result {
            Ok(data) => data,
            Err(e) => {
                error!(
                    session_id = %self.id,
                    tunnel_id = %tunnel_id,
                    error = %e,
                    "Failed to receive data from tunnel"
                );
                return Err(SessionError::Tunnel(e));
            }
        };

        // Update last active time
        self.last_active = Instant::now();

        debug!(
            session_id = %self.id,
            data_len = data.len(),
            "Data received successfully"
        );

        Ok(data)
    }

    /// End the session
    #[instrument(level = "info", skip(self))]
    #[allow(clippy::await_holding_lock)]
    pub async fn end(&mut self) -> Result<(), SessionError> {
        if self.state == SessionState::Ended {
            debug!(
                session_id = %self.id,
                "Session already ended"
            );
            return Err(SessionError::AlreadyEnded);
        }

        info!(
            session_id = %self.id,
            state = ?self.state,
            "Ending session"
        );

        self.state = SessionState::Disconnecting;

        // Close the tunnel if we have one
        if let Some(tunnel) = &self.tunnel {
            let tunnel_clone = Arc::clone(tunnel);
            
            // First try to get the tunnel ID for logging
            let tunnel_id = match tunnel_clone.lock() {
                Ok(guard) => guard.id().to_string(),
                Err(e) => {
                    warn!(
                        session_id = %self.id,
                        error = %e,
                        "Failed to lock tunnel mutex for getting ID"
                    );
                    "unknown".to_string()
                }
            };
            
            // Now try to close the tunnel
            match tunnel_clone.lock() {
                Ok(mut guard) => {
                    if let Err(e) = guard.close().await {
                        warn!(
                            session_id = %self.id,
                            tunnel_id = %tunnel_id,
                            error = %e,
                            "Error closing tunnel"
                        );
                    }
                },
                Err(e) => {
                    warn!(
                        session_id = %self.id,
                        error = %e,
                        "Failed to lock tunnel mutex for closing"
                    );
                }
            }
        }

        self.state = SessionState::Ended;

        info!(
            session_id = %self.id,
            "Session ended"
        );

        Ok(())
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        info!(
            session_id = %self.id,
            state = ?self.state,
            "Session being dropped"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_session_creation() {
        let id = "test-session".to_string();
        let client_id = "test-client".to_string();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);

        let session = Session::new(id, client_id, addr);

        assert_eq!(session.id(), "test-session");
        assert_eq!(session.client_id(), "test-client");
        assert_eq!(session.client_addr(), addr);
        assert_eq!(session.state(), SessionState::Creating);
        assert!(!session.is_expired());
    }

    #[test]
    fn test_session_expiry() {
        let id = "test-session".to_string();
        let client_id = "test-client".to_string();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);

        let mut session = Session::new(id, client_id, addr);

        // Set expiry to a negative duration to make it immediately expired
        session.set_expiry(Duration::from_secs(0));

        assert!(session.is_expired());
    }
}
