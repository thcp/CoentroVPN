//! Control-plane authentication messages and helpers (PSK and mTLS scaffolding).

use crate::proto::framing::{Frame, FrameDecoder, FrameEncoder, FrameType};
use crate::transport::{Connection, TransportError};
use base64::Engine;
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::VecDeque;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};
use tracing::{info, warn};

type HmacSha256 = Hmac<Sha256>;

const NONCE_LEN: usize = 32;
const AUTH_VERSION: u8 = 1;
const DEFAULT_CHALLENGE_TTL: Duration = Duration::from_secs(60);
const METRIC_REPLAY_CACHE_ENTRIES: &str = "coentrovpn_auth_replay_cache_entries";
const METRIC_REPLAY_REJECT_TOTAL: &str = "coentrovpn_auth_replay_reject_total";

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
    if age > DEFAULT_CHALLENGE_TTL {
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
        self.is_fresh_with(DEFAULT_CHALLENGE_TTL)
    }

    pub fn is_fresh_with(&self, ttl: Duration) -> bool {
        let age = Duration::from_millis(now_millis().saturating_sub(self.issued_at_ms));
        age <= ttl
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
    psk_handshake_server_with_config(conn, get_psk, &ServerAuthConfig::default()).await
}

/// Server-side configuration for the PSK handshake.
#[derive(Clone, Debug)]
pub struct ServerAuthConfig {
    /// Allowed lifetime of a challenge before it is considered stale.
    pub challenge_ttl: Duration,
    /// Optional metrics collector.
    pub metrics: Option<Arc<AuthMetrics>>,
    /// Optional replay cache to detect nonce replays.
    pub replay_cache: Option<Arc<dyn ReplayCacheProvider>>,
}

impl Default for ServerAuthConfig {
    fn default() -> Self {
        Self {
            challenge_ttl: DEFAULT_CHALLENGE_TTL,
            metrics: None,
            replay_cache: None,
        }
    }
}

impl ServerAuthConfig {
    /// Create a new configuration with the provided challenge TTL.
    pub fn new(challenge_ttl: Duration) -> Self {
        Self {
            challenge_ttl,
            metrics: None,
            replay_cache: None,
        }
    }

    /// Attach an [`AuthMetrics`] collector to this configuration.
    pub fn with_metrics(mut self, metrics: Arc<AuthMetrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Attach a replay cache to this configuration.
    pub fn with_replay_cache(mut self, cache: Arc<dyn ReplayCacheProvider>) -> Self {
        self.replay_cache = Some(cache);
        self
    }
}

/// Simple metrics tracker for authentication outcomes.
#[derive(Debug, Default)]
pub struct AuthMetrics {
    attempts: AtomicU64,
    successes: AtomicU64,
    failures: AtomicU64,
}

impl AuthMetrics {
    pub fn record_attempt(&self) {
        self.attempts.fetch_add(1, Ordering::Relaxed);
        metrics::counter!("coentrovpn_auth_attempts_total", 1);
    }

    pub fn record_success(&self) {
        self.successes.fetch_add(1, Ordering::Relaxed);
        metrics::counter!("coentrovpn_auth_successes_total", 1);
    }

    pub fn record_failure(&self) {
        self.failures.fetch_add(1, Ordering::Relaxed);
        metrics::counter!("coentrovpn_auth_failures_total", 1);
    }

    pub fn attempts(&self) -> u64 {
        self.attempts.load(Ordering::Relaxed)
    }

    pub fn successes(&self) -> u64 {
        self.successes.load(Ordering::Relaxed)
    }

    pub fn failures(&self) -> u64 {
        self.failures.load(Ordering::Relaxed)
    }
}

/// Replay cache backend abstraction.
pub trait ReplayCacheProvider: std::fmt::Debug + Send + Sync + 'static {
    fn register(&self, nonce: &[u8], ttl: Duration) -> bool;
    fn len(&self) -> usize {
        0
    }
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Simple in-memory replay cache to detect reused nonces.
#[derive(Debug)]
pub struct ReplayCache {
    entries: Mutex<VecDeque<(Vec<u8>, Instant)>>,
    max_entries: usize,
}

impl ReplayCache {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: Mutex::new(VecDeque::with_capacity(max_entries)),
            max_entries,
        }
    }

    fn insert(&self, nonce: &[u8], ttl: Duration) -> bool {
        let mut guard = self.entries.lock().unwrap();
        let now = Instant::now();
        while let Some((_, timestamp)) = guard.front() {
            if now.duration_since(*timestamp) > ttl {
                guard.pop_front();
            } else {
                break;
            }
        }

        if guard.iter().any(|(entry, _)| entry.as_slice() == nonce) {
            return false;
        }

        if guard.len() >= self.max_entries {
            guard.pop_front();
        }

        guard.push_back((nonce.to_vec(), now));
        true
    }
}

impl ReplayCacheProvider for ReplayCache {
    fn register(&self, nonce: &[u8], ttl: Duration) -> bool {
        let inserted = self.insert(nonce, ttl);
        if inserted {
            metrics::gauge!(METRIC_REPLAY_CACHE_ENTRIES, self.len() as f64);
        }
        inserted
    }

    fn len(&self) -> usize {
        self.entries.lock().unwrap().len()
    }
}

/// File-backed replay cache that persists entries across restarts.
#[derive(Debug)]
pub struct PersistentReplayCache {
    inner: ReplayCache,
    path: PathBuf,
    load_ttl: Duration,
}

impl PersistentReplayCache {
    pub fn new<P: Into<PathBuf>>(path: P, max_entries: usize, load_ttl: Duration) -> Self {
        let path = path.into();
        let inner = ReplayCache::new(max_entries);
        let cache = Self {
            inner,
            path,
            load_ttl,
        };
        cache.load_from_disk();
        cache
    }

    fn load_from_disk(&self) {
        if let Ok(contents) = fs::read(&self.path) {
            if let Ok(entries) = bincode::deserialize::<Vec<(Vec<u8>, u64)>>(&contents) {
                let mut guard = self.inner.entries.lock().unwrap();
                guard.clear();
                let now = SystemTime::now();
                for (nonce, timestamp_ms) in entries {
                    let ts = SystemTime::UNIX_EPOCH + Duration::from_millis(timestamp_ms);
                    let age = now.duration_since(ts).unwrap_or_default();
                    if age <= self.load_ttl {
                        let entry_instant =
                            Instant::now().checked_sub(age).unwrap_or_else(Instant::now);
                        guard.push_back((nonce, entry_instant));
                    }
                }
            }
        }
    }

    fn persist(&self) {
        if let Ok(guard) = self.inner.entries.lock() {
            let now = SystemTime::now();
            let data: Vec<_> = guard
                .iter()
                .map(|(nonce, instant)| {
                    let ts = now
                        .checked_sub(instant.elapsed())
                        .unwrap_or(SystemTime::UNIX_EPOCH);
                    let millis = ts
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64;
                    (nonce.clone(), millis)
                })
                .collect();
            if let Ok(bytes) = bincode::serialize(&data) {
                if let Some(parent) = self.path.parent() {
                    let _ = fs::create_dir_all(parent);
                }
                let _ = fs::write(&self.path, bytes);
            }
        }
    }
}

impl ReplayCacheProvider for PersistentReplayCache {
    fn register(&self, nonce: &[u8], ttl: Duration) -> bool {
        let result = self.inner.insert(nonce, ttl);
        if result {
            self.persist();
            metrics::gauge!(METRIC_REPLAY_CACHE_ENTRIES, self.len() as f64);
        }
        result
    }

    fn len(&self) -> usize {
        self.inner.len()
    }
}

pub async fn psk_handshake_server_with_config<F>(
    conn: &mut dyn Connection,
    get_psk: F,
    config: &ServerAuthConfig,
) -> Result<String, TransportError>
where
    F: Fn() -> Result<Vec<u8>, TransportError>,
{
    if let Some(metrics) = &config.metrics {
        metrics.record_attempt();
    }
    // 1) Expect ClientHello
    let Some(bytes) = conn.recv_data().await? else {
        if let Some(metrics) = &config.metrics {
            metrics.record_failure();
        }
        return Err(TransportError::Protocol("connection closed".into()));
    };
    match decode_ctrl(&bytes)? {
        ControlAuthMessage::ClientHello {
            version, method, ..
        } => {
            if version != AUTH_VERSION || method != AuthMethod::Psk {
                if let Some(metrics) = &config.metrics {
                    metrics.record_failure();
                }
                return Err(TransportError::Protocol("unsupported auth".into()));
            }
        }
        _ => {
            if let Some(metrics) = &config.metrics {
                metrics.record_failure();
            }
            return Err(TransportError::Protocol("expected ClientHello".into()));
        }
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
        if let Some(metrics) = &config.metrics {
            metrics.record_failure();
        }
        return Err(TransportError::Protocol("connection closed".into()));
    };
    let ControlAuthMessage::AuthResponse { mac } = decode_ctrl(&bytes)? else {
        if let Some(metrics) = &config.metrics {
            metrics.record_failure();
        }
        return Err(TransportError::Protocol("expected AuthResponse".into()));
    };
    if !challenge.is_fresh_with(config.challenge_ttl) {
        let _ = conn
            .send_data(&encode_ctrl(&ControlAuthMessage::AuthReject {
                reason: "stale challenge".into(),
            })?)
            .await;
        if let Some(metrics) = &config.metrics {
            metrics.record_failure();
        }
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
        if let Some(metrics) = &config.metrics {
            metrics.record_failure();
        }
        return Err(TransportError::Protocol("invalid mac".into()));
    }
    if let Some(cache) = &config.replay_cache {
        if !cache.register(&challenge.nonce, config.challenge_ttl) {
            warn!("replayed authentication challenge detected");
            let _ = conn
                .send_data(&encode_ctrl(&ControlAuthMessage::AuthReject {
                    reason: "replayed challenge".into(),
                })?)
                .await;
            metrics::counter!(METRIC_REPLAY_REJECT_TOTAL, 1);
            if let Some(metrics) = &config.metrics {
                metrics.record_failure();
            }
            return Err(TransportError::Protocol("replayed challenge".into()));
        }
    }

    // 4) Issue session id
    let session_id = uuid::Uuid::new_v4().to_string();
    conn.send_data(&encode_ctrl(&ControlAuthMessage::AuthOk {
        session_id: session_id.clone(),
    })?)
    .await?;
    info!("Client authenticated; session_id={}", session_id);
    if let Some(metrics) = &config.metrics {
        metrics.record_success();
    }
    Ok(session_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use metrics_exporter_prometheus::PrometheusBuilder;
    use std::sync::OnceLock;
    use tokio::sync::{Mutex, mpsc};

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

    #[test]
    fn test_challenge_staleness() {
        // Construct a stale challenge by setting issued_at in the far past
        let chall = PskChallenge {
            nonce: [0u8; NONCE_LEN],
            issued_at_ms: 0,
        };
        assert!(!chall.is_fresh());
        assert!(!chall.is_fresh_with(Duration::from_millis(1)));
    }

    #[test]
    fn auth_metrics_recording() {
        let metrics = AuthMetrics::default();
        assert_eq!(metrics.attempts(), 0);
        assert_eq!(metrics.successes(), 0);
        assert_eq!(metrics.failures(), 0);
        metrics.record_attempt();
        metrics.record_success();
        metrics.record_failure();
        assert_eq!(metrics.attempts(), 1);
        assert_eq!(metrics.successes(), 1);
        assert_eq!(metrics.failures(), 1);
    }

    #[test]
    fn replay_cache_register() {
        let cache = ReplayCache::new(2);
        let ttl = Duration::from_secs(1);
        assert!(cache.register(&[1, 2, 3], ttl));
        assert!(!cache.register(&[1, 2, 3], ttl));
        assert!(cache.register(&[4, 5, 6], ttl));
        std::thread::sleep(ttl + Duration::from_millis(10));
        assert!(cache.register(&[1, 2, 3], ttl));
    }

    #[derive(Debug)]
    struct DenyReplayCache;
    impl ReplayCacheProvider for DenyReplayCache {
        fn register(&self, _nonce: &[u8], _ttl: Duration) -> bool {
            false
        }
    }

    struct InMemoryConn {
        tx: mpsc::Sender<Vec<u8>>,
        rx: Mutex<mpsc::Receiver<Vec<u8>>>,
    }

    impl InMemoryConn {
        fn pair() -> (Self, Self) {
            let (server_tx, server_rx) = mpsc::channel::<Vec<u8>>(8);
            let (client_tx, client_rx) = mpsc::channel::<Vec<u8>>(8);
            (
                Self {
                    tx: server_tx,
                    rx: Mutex::new(client_rx),
                },
                Self {
                    tx: client_tx,
                    rx: Mutex::new(server_rx),
                },
            )
        }
    }

    fn ensure_metrics_recorder() -> metrics_exporter_prometheus::PrometheusHandle {
        static HANDLE: OnceLock<metrics_exporter_prometheus::PrometheusHandle> = OnceLock::new();
        HANDLE
            .get_or_init(|| {
                PrometheusBuilder::new()
                    .install_recorder()
                    .expect("install recorder")
            })
            .clone()
    }

    #[async_trait]
    impl Connection for InMemoryConn {
        async fn send_data(&mut self, data: &[u8]) -> Result<(), TransportError> {
            self.tx
                .send(data.to_vec())
                .await
                .map_err(|e| TransportError::Send(e.to_string()))
        }

        async fn recv_data(&mut self) -> Result<Option<Vec<u8>>, TransportError> {
            let mut rx = self.rx.lock().await;
            Ok(rx.recv().await)
        }

        fn peer_addr(&self) -> Result<std::net::SocketAddr, TransportError> {
            "127.0.0.1:0".parse().map_err(TransportError::AddrParse)
        }

        fn local_addr(&self) -> Result<std::net::SocketAddr, TransportError> {
            "127.0.0.1:0".parse().map_err(TransportError::AddrParse)
        }

        async fn close(self: Box<Self>) -> Result<(), TransportError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn rejects_replayed_nonce_via_cache() {
        let (mut server_conn, mut client_conn) = InMemoryConn::pair();
        let server_cfg = ServerAuthConfig::new(DEFAULT_CHALLENGE_TTL)
            .with_replay_cache(Arc::new(DenyReplayCache));
        let server = tokio::spawn(async move {
            psk_handshake_server_with_config(&mut server_conn, || parse_psk("YWFh"), &server_cfg)
                .await
        });

        let client_res = psk_handshake_client(&mut client_conn, "YWFh").await;
        assert!(matches!(
            client_res,
            Err(TransportError::Protocol(msg)) if msg.contains("replayed")
        ));

        let server_res = server.await.expect("server task panicked");
        assert!(matches!(
            server_res,
            Err(TransportError::Protocol(msg)) if msg.contains("replayed")
        ));
    }

    #[tokio::test]
    async fn rejects_stale_challenge() {
        let (mut server_conn, mut client_conn) = InMemoryConn::pair();
        let server_cfg = ServerAuthConfig {
            challenge_ttl: Duration::from_millis(1),
            metrics: None,
            replay_cache: None,
        };
        let server = tokio::spawn(async move {
            // Intentionally sleep inside to force staleness
            tokio::time::sleep(Duration::from_millis(5)).await;
            psk_handshake_server_with_config(&mut server_conn, || parse_psk("YWFh"), &server_cfg)
                .await
        });

        // Client runs immediately; server delay makes challenge stale by verification
        let client_res = psk_handshake_client(&mut client_conn, "YWFh").await;
        assert!(matches!(
            client_res,
            Err(TransportError::Protocol(msg)) if msg.contains("stale")
        ));

        let server_res = server.await.expect("server task panicked");
        assert!(matches!(
            server_res,
            Err(TransportError::Protocol(msg)) if msg.contains("stale")
        ));
    }

    #[tokio::test]
    async fn replay_cache_persistence_round_trip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("replay.bin");
        let ttl = Duration::from_secs(60);
        {
            let cache = PersistentReplayCache::new(&path, 8, ttl);
            let nonce = b"nonce-1";
            assert!(cache.register(nonce, ttl));
            // second register should fail
            assert!(!cache.register(nonce, ttl));
        }

        // Re-create cache; it should load the persisted nonce and reject reuse
        let cache = PersistentReplayCache::new(&path, 8, ttl);
        assert!(!cache.register(b"nonce-1", ttl));
        // new nonce still accepted
        assert!(cache.register(b"nonce-2", ttl));
    }

    #[tokio::test]
    async fn replay_counter_metric_increments() {
        let handle = ensure_metrics_recorder();
        let (mut server_conn, mut client_conn) = InMemoryConn::pair();
        let server_cfg = ServerAuthConfig::new(DEFAULT_CHALLENGE_TTL)
            .with_replay_cache(Arc::new(DenyReplayCache));
        let server = tokio::spawn(async move {
            psk_handshake_server_with_config(&mut server_conn, || parse_psk("YWFh"), &server_cfg)
                .await
        });

        let _ = psk_handshake_client(&mut client_conn, "YWFh").await;
        let _ = server.await;

        let metrics = handle.render();
        assert!(
            metrics.contains("coentrovpn_auth_replay_reject_total"),
            "replay metric missing: {metrics}"
        );
    }
}
