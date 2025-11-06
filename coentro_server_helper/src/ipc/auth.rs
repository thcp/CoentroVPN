use crate::ipc::messages::{AuthHeader, ServerRequest};
use crate::ipc::transport::message_bincode_config;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use bincode::Options;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use shared_utils::config::HelperToken;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

pub type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
pub struct TokenRegistry {
    require_auth: bool,
    tokens: HashMap<String, Arc<TokenState>>,
}

struct TokenState {
    secret: Vec<u8>,
    used_nonces: Mutex<HashSet<u64>>,
}

impl TokenRegistry {
    pub fn from_tokens(tokens: &[HelperToken]) -> anyhow::Result<Self> {
        let mut map = HashMap::new();
        for token in tokens {
            let secret = STANDARD
                .decode(token.secret.trim())
                .map_err(|e| anyhow::anyhow!("invalid helper token {}: {}", token.id, e))?;
            if secret.is_empty() {
                return Err(anyhow::anyhow!(
                    "helper token {} has empty secret",
                    token.id
                ));
            }
            let state = Arc::new(TokenState {
                secret,
                used_nonces: Mutex::new(HashSet::new()),
            });
            map.insert(token.id.clone(), state);
        }
        Ok(Self {
            require_auth: !map.is_empty(),
            tokens: map,
        })
    }

    pub fn verify(
        &self,
        header: Option<&AuthHeader>,
        request: &ServerRequest,
    ) -> Result<(), AuthError> {
        if !self.require_auth {
            return Ok(());
        }
        match header {
            Some(h) => self.verify_inner(h, request),
            None => Err(AuthError::Missing),
        }
    }

    fn verify_inner(&self, header: &AuthHeader, request: &ServerRequest) -> Result<(), AuthError> {
        let state = self
            .tokens
            .get(&header.token_id)
            .ok_or(AuthError::UnknownToken)?
            .clone();

        let serialized = message_bincode_config()
            .serialize(request)
            .map_err(|e| AuthError::Internal(e.to_string()))?;

        let mut mac = HmacSha256::new_from_slice(&state.secret)
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        mac.update(&header.nonce.to_le_bytes());
        mac.update(&serialized);
        mac.verify_slice(&header.signature)
            .map_err(|_| AuthError::InvalidSignature)?;

        let mut guard = state
            .used_nonces
            .lock()
            .map_err(|_| AuthError::Internal("token nonce lock poisoned".into()))?;
        if !guard.insert(header.nonce) {
            return Err(AuthError::Replay);
        }

        // Optional pruning to avoid unbounded growth.
        if guard.len() > 10_000 {
            guard.clear();
        }

        Ok(())
    }
}

#[derive(Debug)]
pub enum AuthError {
    Missing,
    UnknownToken,
    InvalidSignature,
    Replay,
    Internal(String),
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::Missing => write!(f, "authentication token required"),
            AuthError::UnknownToken => write!(f, "unknown authentication token"),
            AuthError::InvalidSignature => write!(f, "invalid authentication signature"),
            AuthError::Replay => write!(f, "replayed authentication nonce"),
            AuthError::Internal(msg) => write!(f, "authentication internal error: {msg}"),
        }
    }
}

impl std::error::Error for AuthError {}
