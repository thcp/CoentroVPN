//! Control-plane authentication messages and helpers (PSK and mTLS scaffolding).

use crate::proto::framing::{Frame, FrameDecoder, FrameEncoder, FrameType};
use crate::transport::{Connection, TransportError};
use base64::Engine;
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::time::{Duration, SystemTime};
use tracing::{info, warn};

type HmacSha256 = Hmac<Sha256>;

const NONCE_LEN: usize = 32;
const AUTH_VERSION: u8 = 1;
const CHALLENGE_TTL: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ControlAuthMessage {
    ClientHello {
        version: u8,
        features: u32,
        method: AuthMethod,
    },
    AuthChallenge {
        nonce: Vec<u8>,
        issued_at_ms: u64,
    },
    AuthResponse {
        mac: Vec<u8>,
    },
    AuthOk {
        session_id: String,
    },
    AuthReject {
        reason: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AuthMethod {
    Psk,
    Mtls,
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn encode_ctrl(msg: &ControlAuthMessage) -> Result<Vec<u8>, TransportError> {
    let payload = bincode::serialize(msg)
        .map_err(|e| TransportError::Protocol(format!("Serialize auth msg: {}", e)))?;
    let frame = Frame::new(FrameType::Control, Default::default(), payload)
        .map_err(|e| TransportError::Protocol(format!("Frame build: {}", e)))?;
    Ok(FrameEncoder::new().encode(&frame))
}

fn decode_ctrl(bytes: &[u8]) -> Result<ControlAuthMessage, TransportError> {
    let mut decoder = FrameDecoder::new();
    let frames = decoder
        .decode(bytes)
        .map_err(|e| TransportError::Protocol(format!("Decode frames: {}", e)))?;
    if frames.len() != 1 {
        return Err(TransportError::Protocol(
            "Expected single control frame".into(),
        ));
    }
    if frames[0].frame_type != FrameType::Control {
        return Err(TransportError::Protocol("Expected control frame".into()));
    }
    bincode::deserialize(&frames[0].payload)
        .map_err(|e| TransportError::Protocol(format!("Deserialize auth msg: {}", e)))
}

pub fn parse_psk(psk_str: &str) -> Result<Vec<u8>, TransportError> {
    // Try hex, then base64 (RFC4648 standard)
    if let Ok(bytes) = hex::decode(psk_str) {
        return Ok(bytes);
    }
    let engine = base64::engine::general_purpose::STANDARD;
    engine
        .decode(psk_str)
        .map_err(|_| TransportError::Configuration("Invalid PSK (hex or base64 expected)".into()))
}

fn hmac_psk(psk: &[u8], nonce: &[u8]) -> Result<Vec<u8>, TransportError> {
    let mut mac = HmacSha256::new_from_slice(psk)
        .map_err(|e| TransportError::Configuration(format!("HMAC key: {}", e)))?;
    mac.update(nonce);
    Ok(mac.finalize().into_bytes().to_vec())
}

pub async fn psk_handshake_client(
    conn: &mut dyn Connection,
    psk_str: &str,
) -> Result<String, TransportError> {
    let psk = parse_psk(psk_str)?;
    // 1) Send ClientHello
    let hello = ControlAuthMessage::ClientHello {
        version: AUTH_VERSION,
        features: 0,
        method: AuthMethod::Psk,
    };
    conn.send_data(&encode_ctrl(&hello)?).await?;

    // 2) Expect AuthChallenge
    let Some(bytes) = conn.recv_data().await? else {
        return Err(TransportError::Protocol("connection closed".into()));
    };
    let ControlAuthMessage::AuthChallenge {
        nonce,
        issued_at_ms,
    } = decode_ctrl(&bytes)?
    else {
        return Err(TransportError::Protocol("expected AuthChallenge".into()));
    };
    let age = Duration::from_millis(now_millis().saturating_sub(issued_at_ms));
    if age > CHALLENGE_TTL {
        return Err(TransportError::Protocol("stale challenge".into()));
    }

    // 3) Respond with HMAC(nonce)
    let mac = hmac_psk(&psk, &nonce)?;
    let resp = ControlAuthMessage::AuthResponse { mac };
    conn.send_data(&encode_ctrl(&resp)?).await?;

    // 4) Await AuthOk/Reject
    let Some(bytes) = conn.recv_data().await? else {
        return Err(TransportError::Protocol("connection closed".into()));
    };
    match decode_ctrl(&bytes)? {
        ControlAuthMessage::AuthOk { session_id } => Ok(session_id),
        ControlAuthMessage::AuthReject { reason } => Err(TransportError::Protocol(format!(
            "auth rejected: {}",
            reason
        ))),
        _ => Err(TransportError::Protocol(
            "unexpected message after response".into(),
        )),
    }
}

pub struct PskChallenge {
    pub nonce: [u8; NONCE_LEN],
    pub issued_at_ms: u64,
}

impl PskChallenge {
    pub fn new() -> Self {
        let mut nonce = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce);
        Self {
            nonce,
            issued_at_ms: now_millis(),
        }
    }

    pub fn is_fresh(&self) -> bool {
        let age = Duration::from_millis(now_millis().saturating_sub(self.issued_at_ms));
        age <= CHALLENGE_TTL
    }

    pub fn verify(&self, psk: &[u8], mac: &[u8]) -> Result<bool, TransportError> {
        let expected = hmac_psk(psk, &self.nonce)?;
        Ok(subtle::ConstantTimeEq::ct_eq(mac, &expected).into())
    }
}

impl Default for PskChallenge {
    fn default() -> Self {
        Self::new()
    }
}

pub async fn psk_handshake_server<F>(
    conn: &mut dyn Connection,
    get_psk: F,
) -> Result<String, TransportError>
where
    F: Fn() -> Result<Vec<u8>, TransportError>,
{
    // 1) Expect ClientHello
    let Some(bytes) = conn.recv_data().await? else {
        return Err(TransportError::Protocol("connection closed".into()));
    };
    match decode_ctrl(&bytes)? {
        ControlAuthMessage::ClientHello {
            version, method, ..
        } => {
            if version != AUTH_VERSION || method != AuthMethod::Psk {
                return Err(TransportError::Protocol("unsupported auth".into()));
            }
        }
        _ => return Err(TransportError::Protocol("expected ClientHello".into())),
    }

    // 2) Send challenge
    let challenge = PskChallenge::new();
    let challenge_msg = ControlAuthMessage::AuthChallenge {
        nonce: challenge.nonce.to_vec(),
        issued_at_ms: challenge.issued_at_ms,
    };
    conn.send_data(&encode_ctrl(&challenge_msg)?).await?;

    // 3) Receive response and verify
    let Some(bytes) = conn.recv_data().await? else {
        return Err(TransportError::Protocol("connection closed".into()));
    };
    let ControlAuthMessage::AuthResponse { mac } = decode_ctrl(&bytes)? else {
        return Err(TransportError::Protocol("expected AuthResponse".into()));
    };
    if !challenge.is_fresh() {
        let _ = conn
            .send_data(&encode_ctrl(&ControlAuthMessage::AuthReject {
                reason: "stale challenge".into(),
            })?)
            .await;
        return Err(TransportError::Protocol("stale challenge".into()));
    }
    let psk = get_psk()?;
    let ok = challenge.verify(&psk, &mac)?;
    if !ok {
        warn!("PSK MAC verification failed");
        let _ = conn
            .send_data(&encode_ctrl(&ControlAuthMessage::AuthReject {
                reason: "invalid mac".into(),
            })?)
            .await;
        return Err(TransportError::Protocol("invalid mac".into()));
    }

    // 4) Issue session id
    let session_id = uuid::Uuid::new_v4().to_string();
    conn.send_data(&encode_ctrl(&ControlAuthMessage::AuthOk {
        session_id: session_id.clone(),
    })?)
    .await?;
    info!("Client authenticated; session_id={}", session_id);
    Ok(session_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_and_challenge() {
        let psk = b"supersecretkey";
        let chall = PskChallenge::new();
        assert!(chall.is_fresh());
        let mac = hmac_psk(psk, &chall.nonce).unwrap();
        assert!(chall.verify(psk, &mac).unwrap());
        let mut wrong = mac.clone();
        wrong[0] ^= 0xFF;
        assert!(!chall.verify(psk, &wrong).unwrap());
    }
}
