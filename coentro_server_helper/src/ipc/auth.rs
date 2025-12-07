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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::messages::{AuthHeader, ServerRequest};
    use crate::ipc::transport::message_bincode_config;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;

    const SECRET: &[u8] = b"phase3-secret-material";

    fn helper_token() -> HelperToken {
        HelperToken {
            id: "token-1".into(),
            secret: STANDARD.encode(SECRET),
        }
    }

    fn registry_with_token() -> TokenRegistry {
        TokenRegistry::from_tokens(&[helper_token()]).expect("token registry")
    }

    fn signed_header(request: &ServerRequest, nonce: u64) -> AuthHeader {
        let serialized = message_bincode_config()
            .serialize(request)
            .expect("serialize request");
        let mut mac =
            HmacSha256::new_from_slice(SECRET).expect("construct hmac with static secret");
        mac.update(&nonce.to_le_bytes());
        mac.update(&serialized);
        let signature = mac.finalize().into_bytes().to_vec();
        AuthHeader {
            token_id: "token-1".into(),
            nonce,
            signature,
        }
    }

    #[test]
    fn allows_requests_when_auth_disabled() {
        let registry = TokenRegistry::from_tokens(&[]).unwrap();
        assert!(registry.verify(None, &ServerRequest::Ping).is_ok());
    }

    #[test]
    fn rejects_missing_auth_when_tokens_required() {
        let registry = registry_with_token();
        let err = registry
            .verify(None, &ServerRequest::Ping)
            .expect_err("missing auth should fail");
        assert!(matches!(err, AuthError::Missing));
    }

    #[test]
    fn rejects_unknown_token_id() {
        let registry = registry_with_token();
        let mut header = signed_header(&ServerRequest::Ping, 42);
        header.token_id = "other".into();
        let err = registry
            .verify(Some(&header), &ServerRequest::Ping)
            .expect_err("unknown token expected");
        assert!(matches!(err, AuthError::UnknownToken));
    }

    #[test]
    fn rejects_invalid_signature() {
        let registry = registry_with_token();
        let mut header = signed_header(&ServerRequest::Ping, 7);
        header.signature.reverse();
        let err = registry
            .verify(Some(&header), &ServerRequest::Ping)
            .expect_err("invalid signature expected");
        assert!(matches!(err, AuthError::InvalidSignature));
    }

    #[test]
    fn rejects_replayed_nonce() {
        let registry = registry_with_token();
        let header = signed_header(&ServerRequest::Ping, 99);
        // First attempt succeeds.
        registry
            .verify(Some(&header), &ServerRequest::Ping)
            .expect("initial verification");
        // Second attempt should be detected as replay.
        let err = registry
            .verify(Some(&header), &ServerRequest::Ping)
            .expect_err("replay must fail");
        assert!(matches!(err, AuthError::Replay));
    }

    #[test]
    fn accepts_valid_signature() {
        let registry = registry_with_token();
        let header = signed_header(&ServerRequest::Ping, 123);
        assert!(registry.verify(Some(&header), &ServerRequest::Ping).is_ok());
    }
}
