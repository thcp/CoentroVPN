pub mod messages;
pub mod transport;

mod auth;

use crate::network::InterfaceError;
use crate::network::{
    build_interface_manager, InterfaceManager, InterfaceResult, PolicyState, TunConfig,
    TunDescriptor,
};
use crate::persistence::Persistence;
use anyhow::{Context, Result};
use auth::{AuthError, TokenRegistry};
use messages::{
    AttachQuicRequest, AttachQuicResponse, AuthHeader, CreateTunnelRequest, DestroyTunnelRequest,
    DestroyTunnelResponse, ErrorCode, ErrorResponse, MetricsSnapshotResponse, ServerRequest,
    ServerResponse, TunnelCreatedResponse, TunnelMetrics,
};
use metrics::{counter, gauge};
use nix::unistd::close;
use shared_utils::config::HelperConfig;
use std::collections::HashMap;
use std::fmt;
use std::fs::File as StdFile;
use std::io::ErrorKind;
use std::os::fd::{FromRawFd, IntoRawFd, OwnedFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::RawFd;
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::SystemTime;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::{broadcast, mpsc, Mutex};
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};
use transport::{receive_request, send_response};

const INTERFACE_PREFIX: &str = "srv";
const MAX_PACKET_SIZE: usize = 2048;
const TUN_WRITE_QUEUE_CAPACITY: usize = 256;
const TUN_BROADCAST_CAPACITY: usize = 256;

const METRIC_ACTIVE_SESSIONS: &str = "coentrovpn_server_helper_sessions";
const METRIC_SESSIONS_CREATED_TOTAL: &str = "coentrovpn_server_helper_sessions_created_total";
const METRIC_SESSIONS_CLOSED_TOTAL: &str = "coentrovpn_server_helper_sessions_closed_total";
const METRIC_BYTES_TOTAL: &str = "coentrovpn_server_helper_bytes_total";
const METRIC_PACKETS_TOTAL: &str = "coentrovpn_server_helper_packets_total";
const METRIC_ERRORS_TOTAL: &str = "coentrovpn_server_helper_errors_total";

#[derive(Debug)]
pub struct ServerIpcServer {
    listener: UnixListener,
    socket_path: PathBuf,
    allowed_uids: Vec<u32>,
    allowed_gids: Vec<u32>,
    state: Arc<HelperState>,
}

impl ServerIpcServer {
    pub async fn bind<P: AsRef<Path>>(socket_path: P, helper_cfg: &HelperConfig) -> Result<Self> {
        let socket_path = socket_path.as_ref().to_path_buf();
        if let Some(parent) = socket_path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("Failed to create socket directory: {}", parent.display())
            })?;
        }

        if socket_path.exists() {
            std::fs::remove_file(&socket_path).with_context(|| {
                format!(
                    "Failed to remove existing socket at {}",
                    socket_path.display()
                )
            })?;
        }

        let listener = UnixListener::bind(&socket_path)
            .with_context(|| format!("Failed to bind IPC socket at {}", socket_path.display()))?;

        if let Ok(metadata) = std::fs::metadata(&socket_path) {
            let mut permissions = metadata.permissions();
            permissions.set_mode(0o660);
            if let Err(e) = std::fs::set_permissions(&socket_path, permissions) {
                warn!(
                    "Failed to adjust permissions on {}: {}",
                    socket_path.display(),
                    e
                );
            }
        }

        let interface_manager = Arc::from(build_interface_manager());
        let token_registry = TokenRegistry::from_tokens(&helper_cfg.session_tokens)?;
        let persistence = Arc::new(Persistence::default());
        persistence.load().await;
        let state = Arc::new(HelperState::new(
            interface_manager,
            token_registry,
            Arc::clone(&persistence),
        ));

        Ok(Self {
            listener,
            socket_path,
            allowed_uids: helper_cfg.allowed_uids.clone(),
            allowed_gids: helper_cfg.allowed_gids.clone(),
            state,
        })
    }

    pub async fn run(self) -> Result<()> {
        info!(
            path = %self.socket_path.display(),
            "Server helper listening for IPC requests"
        );
        if !self.allowed_uids.is_empty() || !self.allowed_gids.is_empty() {
            debug!(
                allowed_uids = ?self.allowed_uids,
                allowed_gids = ?self.allowed_gids,
                "UID/GID allow lists configured"
            );
        }

        self.state.initialize().await?;

        let mut sigint =
            signal(SignalKind::interrupt()).context("Failed to register SIGINT handler")?;
        let mut sigterm =
            signal(SignalKind::terminate()).context("Failed to register SIGTERM handler")?;

        loop {
            tokio::select! {
                accept_result = self.listener.accept() => {
                    match accept_result {
                        Ok((stream, addr)) => {
                            debug!(peer = ?addr, "Accepted IPC connection");
                            let state = self.state.clone();
                            tokio::spawn(async move {
                                if let Err(err) = handle_connection(stream, state).await {
                                    error!("Connection handler error: {err:?}");
                                }
                            });
                        }
                        Err(err) => {
                            error!("IPC accept error: {}", err);
                        }
                    }
                }
                _ = sigint.recv() => {
                    info!("Received SIGINT, shutting down server helper");
                    break;
                }
                _ = sigterm.recv() => {
                    info!("Received SIGTERM, shutting down server helper");
                    break;
                }
            }
        }

        self.state.shutdown().await;

        Ok(())
    }
}

impl Drop for ServerIpcServer {
    fn drop(&mut self) {
        if let Err(e) = std::fs::remove_file(&self.socket_path) {
            if e.kind() != std::io::ErrorKind::NotFound {
                warn!(
                    "Failed to remove IPC socket {} on drop: {}",
                    self.socket_path.display(),
                    e
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::net::{IpAddr, Ipv4Addr};
    use std::os::fd::{FromRawFd, OwnedFd};
    use std::os::unix::net::UnixStream as StdUnixStream;
    use crate::ipc::messages::{DnsConfig, RouteSpec, TunnelAddress};
    use crate::network::NatState;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::{timeout, Duration};

    #[derive(Default)]
    struct MockInterfaceManager {
        peers: Mutex<Vec<StdUnixStream>>,
    }

    impl MockInterfaceManager {
        async fn take_peer(&self) -> Option<StdUnixStream> {
            self.peers.lock().await.pop()
        }
    }

    #[async_trait]
    impl InterfaceManager for MockInterfaceManager {
        async fn ensure_forwarding(&self) -> InterfaceResult<()> {
            Ok(())
        }

        async fn ensure_tun(&self, config: &TunConfig) -> InterfaceResult<TunDescriptor> {
            let (peer, helper) = StdUnixStream::pair().map_err(InterfaceError::Io)?;
            peer.set_nonblocking(true).ok();
            helper.set_nonblocking(true).ok();
            self.peers.lock().await.push(peer);
            let fd = helper.into_raw_fd();
            Ok(TunDescriptor {
                name: config
                    .name_hint
                    .clone()
                    .unwrap_or_else(|| format!("{}0", config.name_prefix)),
                fd: unsafe { OwnedFd::from_raw_fd(fd) },
                mtu: config.mtu,
                ipv4_cidr: config.ipv4_cidr.clone(),
                sysctl_touched: None,
            })
        }

        async fn teardown_tun(&self, _name: &str) -> InterfaceResult<()> {
            Ok(())
        }

        async fn cleanup_stale_interfaces(&self, _prefix: &str) -> InterfaceResult<()> {
            Ok(())
        }

        async fn apply_policy(
            &self,
            _interface: &str,
            _routes: &[RouteSpec],
            _dns: Option<&DnsConfig>,
        ) -> InterfaceResult<PolicyState> {
            Ok(PolicyState::default())
        }

        async fn rollback_policy(&self, _interface: &str, _state: &PolicyState) -> InterfaceResult<()> {
            Ok(())
        }

        async fn apply_nat(&self, _interface: &str, _cidr: &str) -> InterfaceResult<Option<NatState>> {
            Ok(None)
        }

        async fn rollback_nat(&self, _interface: &str, _state: &NatState) -> InterfaceResult<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn transport_and_tun_round_trip() {
        let iface = Arc::new(MockInterfaceManager::default());
        let auth = TokenRegistry::from_tokens(&[]).expect("token registry");
        let persistence = Arc::new(Persistence::default());
        let state = HelperState::new(iface.clone(), auth, persistence);
        state.initialize().await.expect("init");

        let req = CreateTunnelRequest {
            session_id: "sess1".into(),
            virtual_address: TunnelAddress {
                address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                prefix: 24,
            },
            routes: vec![],
            dns: None,
            mtu: Some(1200),
            enable_nat: false,
        };
        state.create_tunnel(req).await.expect("create tunnel");

        let (client_sock, helper_sock) = StdUnixStream::pair().expect("socketpair");
        client_sock.set_nonblocking(true).ok();
        helper_sock.set_nonblocking(true).ok();
        state
            .attach_transport(
                AttachQuicRequest {
                    session_id: "sess1".into(),
                    flow_id: None,
                    stream_count: Some(1),
                },
                Some(helper_sock.into_raw_fd()),
            )
            .await
            .expect("attach");

        let mut client_stream = tokio::net::UnixStream::from_std(client_sock).expect("tokio stream");
        let tun_peer = iface.take_peer().await.expect("tun peer present");
        let mut tun_stream = tokio::net::UnixStream::from_std(tun_peer).expect("tokio tun");
        tokio::time::sleep(Duration::from_millis(25)).await;

        // Transport -> TUN
        let payload = vec![0xAA, 0xBB, 0xCC];
        let len_bytes = (payload.len() as u16).to_be_bytes();
        client_stream.write_all(&len_bytes).await.expect("write len");
        client_stream.write_all(&payload).await.expect("write payload");

        let mut tun_buf = vec![0u8; payload.len()];
        timeout(Duration::from_secs(1), tun_stream.read_exact(&mut tun_buf))
            .await
            .expect("read timeout")
            .expect("tun read");
        assert_eq!(tun_buf, payload);

        // TUN -> Transport
        tokio::time::sleep(Duration::from_millis(25)).await;
        let payload2 = vec![0x01, 0x02, 0x03, 0x04];
        {
            let sessions = state.sessions.lock().await;
            let entry = sessions.get("sess1").expect("session present");
            let _ = entry.tun_bridge.broadcast_tx.send(Arc::new(payload2.clone()));
        }

        let mut len_buf = [0u8; 2];
        tokio::time::sleep(Duration::from_millis(25)).await;
        timeout(Duration::from_secs(1), client_stream.read_exact(&mut len_buf))
            .await
            .expect("client len timeout")
            .expect("client len read");
        let len = u16::from_be_bytes(len_buf) as usize;
        let mut recv_buf = vec![0u8; len];
        timeout(Duration::from_secs(1), client_stream.read_exact(&mut recv_buf))
            .await
            .expect("client payload timeout")
            .expect("client payload read");
        assert_eq!(recv_buf, payload2);
    }
}

#[allow(dead_code)]
#[derive(Debug)]
struct TunnelEntry {
    interface_name: String,
    ipv4_cidr: String,
    mtu: u32,
    sysctl_touched: Option<PathBuf>,
    tun_bridge: TunBridge,
    flows: HashMap<String, TransportBridge>,
    bytes_ingress: Arc<AtomicU64>,
    bytes_egress: Arc<AtomicU64>,
    packets_ingress: Arc<AtomicU64>,
    packets_egress: Arc<AtomicU64>,
    started_at: SystemTime,
    policy_state: PolicyState,
}

impl TunnelEntry {
    fn new(descriptor: TunDescriptor) -> Result<Self, ActionError> {
        let TunDescriptor {
            name,
            fd,
            mtu,
            ipv4_cidr,
            sysctl_touched,
        } = descriptor;

        let bytes_ingress = Arc::new(AtomicU64::new(0));
        let bytes_egress = Arc::new(AtomicU64::new(0));
        let packets_ingress = Arc::new(AtomicU64::new(0));
        let packets_egress = Arc::new(AtomicU64::new(0));
        let tun_bridge = TunBridge::new(
            name.clone(),
            fd,
            Arc::clone(&bytes_ingress),
            Arc::clone(&bytes_egress),
            Arc::clone(&packets_ingress),
            Arc::clone(&packets_egress),
        )?;

        Ok(Self {
            interface_name: name,
            ipv4_cidr,
            mtu,
            sysctl_touched,
            tun_bridge,
            flows: HashMap::new(),
            bytes_ingress,
            bytes_egress,
            packets_ingress,
            packets_egress,
            started_at: SystemTime::now(),
            policy_state: PolicyState::default(),
        })
    }

    fn attach_transport_with_id(&mut self, flow_id: String, fd: RawFd) -> Result<(), ActionError> {
        if self.flows.contains_key(&flow_id) {
            return Err(ActionError::Conflict(format!(
                "flow {} already attached for interface {}",
                flow_id, self.interface_name
            )));
        }

        let receiver = self.tun_bridge.subscribe();
        let writer = self.tun_bridge.writer();
        let bridge = TransportBridge::new(
            flow_id.clone(),
            fd,
            receiver,
            writer,
            Arc::clone(&self.bytes_ingress),
            Arc::clone(&self.bytes_egress),
            Arc::clone(&self.packets_ingress),
            Arc::clone(&self.packets_egress),
        )?;
        self.flows.insert(flow_id, bridge);
        Ok(())
    }

    fn close_transport(&mut self) {
        for bridge in self.flows.values_mut() {
            bridge.shutdown();
        }
        self.flows.clear();
        self.tun_bridge.shutdown();
    }

    fn close_interface(&mut self) {
        self.tun_bridge.close_interface();
    }

    fn metrics(&self, session_id: &str, reset: bool) -> TunnelMetrics {
        let bytes_in = if reset {
            self.bytes_ingress.swap(0, Ordering::Relaxed)
        } else {
            self.bytes_ingress.load(Ordering::Relaxed)
        };
        let bytes_out = if reset {
            self.bytes_egress.swap(0, Ordering::Relaxed)
        } else {
            self.bytes_egress.load(Ordering::Relaxed)
        };
        let packets_in = if reset {
            self.packets_ingress.swap(0, Ordering::Relaxed)
        } else {
            self.packets_ingress.load(Ordering::Relaxed)
        };
        let packets_out = if reset {
            self.packets_egress.swap(0, Ordering::Relaxed)
        } else {
            self.packets_egress.load(Ordering::Relaxed)
        };

        TunnelMetrics {
            session_id: session_id.to_string(),
            interface: self.interface_name.clone(),
            bytes_in,
            bytes_out,
            packets_in,
            packets_out,
            start_timestamp_ms: self
                .started_at
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
        }
    }
}

#[derive(Clone)]
struct HelperState {
    interface_manager: Arc<dyn InterfaceManager>,
    sessions: Arc<Mutex<HashMap<String, TunnelEntry>>>,
    auth: TokenRegistry,
    persistence: Arc<Persistence>,
}

impl HelperState {
    fn new(
        interface_manager: Arc<dyn InterfaceManager>,
        auth: TokenRegistry,
        persistence: Arc<Persistence>,
    ) -> Self {
        Self {
            interface_manager,
            sessions: Arc::new(Mutex::new(HashMap::new())),
            auth,
            persistence,
        }
    }

    async fn initialize(&self) -> InterfaceResult<()> {
        self.persistence.load().await;

        let stale_sessions = self.persistence.drain().await;
        for session in stale_sessions {
            if let Some(nat_state) = session.policy.nat.as_ref() {
                if let Err(err) = self
                    .interface_manager
                    .rollback_nat(&session.interface, nat_state)
                    .await
                {
                    warn!(
                        session = %session.session_id,
                        interface = %session.interface,
                        "failed to rollback persisted NAT: {err}"
                    );
                }
            }

            if let Err(err) = self
                .interface_manager
                .rollback_policy(&session.interface, &session.policy)
                .await
            {
                warn!(
                    session = %session.session_id,
                    interface = %session.interface,
                    "failed to rollback persisted policy: {err}"
                );
            }

            let _ = self
                .interface_manager
                .teardown_tun(&session.interface)
                .await;
        }

        self.interface_manager.ensure_forwarding().await?;
        self.interface_manager
            .cleanup_stale_interfaces(INTERFACE_PREFIX)
            .await?;
        gauge!(METRIC_ACTIVE_SESSIONS, 0.0);
        Ok(())
    }

    async fn shutdown(&self) {
        let drained = {
            let mut sessions = self.sessions.lock().await;
            let drained = sessions
                .drain()
                .map(|(id, entry)| (id, entry))
                .collect::<Vec<_>>();
            gauge!(METRIC_ACTIVE_SESSIONS, 0.0);
            drained
        };

        for (session_id, mut entry) in drained {
            entry.close_transport();
            if let Some(nat_state) = entry.policy_state.nat.as_ref() {
                let _ = self
                    .interface_manager
                    .rollback_nat(&entry.interface_name, nat_state)
                    .await;
            }
            let _ = self
                .interface_manager
                .rollback_policy(&entry.interface_name, &entry.policy_state)
                .await;
            let _ = self
                .interface_manager
                .teardown_tun(&entry.interface_name)
                .await;
            entry.close_interface();
            self.persistence.remove_session(&session_id).await;
        }
    }

    async fn create_tunnel(
        &self,
        request: CreateTunnelRequest,
    ) -> Result<TunnelCreatedResponse, ActionError> {
        {
            let sessions = self.sessions.lock().await;
            if sessions.contains_key(&request.session_id) {
                return Err(ActionError::Conflict(format!(
                    "session {} already exists",
                    request.session_id
                )));
            }
        }

        let cidr = format!(
            "{}/{}",
            request.virtual_address.address, request.virtual_address.prefix
        );

        let tun_config = TunConfig {
            name_hint: None,
            name_prefix: INTERFACE_PREFIX.to_string(),
            ipv4_cidr: cidr,
            mtu: request.mtu.unwrap_or(1500),
            bring_up: true,
        };

        let descriptor = self
            .interface_manager
            .ensure_tun(&tun_config)
            .await
            .map_err(ActionError::from)?;
        let interface_name = descriptor.name.clone();
        let mut entry = match TunnelEntry::new(descriptor) {
            Ok(entry) => entry,
            Err(err) => {
                let _ = self.interface_manager.teardown_tun(&interface_name).await;
                return Err(err);
            }
        };

        let mut policy_state = match self
            .interface_manager
            .apply_policy(&entry.interface_name, &request.routes, request.dns.as_ref())
            .await
        {
            Ok(state) => state,
            Err(err) => {
                let _ = self
                    .interface_manager
                    .teardown_tun(&entry.interface_name)
                    .await;
                return Err(ActionError::Interface(err));
            }
        };

        if request.enable_nat {
            match self
                .interface_manager
                .apply_nat(&entry.interface_name, &entry.ipv4_cidr)
                .await
            {
                Ok(Some(nat_state)) => {
                    policy_state.nat = Some(nat_state);
                }
                Ok(None) => {}
                Err(err) => {
                    let _ = self
                        .interface_manager
                        .rollback_policy(&entry.interface_name, &policy_state)
                        .await;
                    let _ = self
                        .interface_manager
                        .teardown_tun(&entry.interface_name)
                        .await;
                    return Err(ActionError::Interface(err));
                }
            }
        }
        entry.policy_state = policy_state.clone();
        self.persistence
            .register_session(&request.session_id, &entry.interface_name, policy_state)
            .await;

        let response = TunnelCreatedResponse {
            session_id: request.session_id.clone(),
            interface: entry.interface_name.clone(),
            virtual_address: request.virtual_address,
        };

        {
            let mut sessions = self.sessions.lock().await;
            sessions.insert(request.session_id.clone(), entry);
            gauge!(METRIC_ACTIVE_SESSIONS, sessions.len() as f64);
        }
        counter!(METRIC_SESSIONS_CREATED_TOTAL, 1);

        Ok(response)
    }

    async fn attach_transport(
        &self,
        request: AttachQuicRequest,
        fd: Option<RawFd>,
    ) -> Result<AttachQuicResponse, ActionError> {
        let fd = fd.ok_or_else(|| {
            ActionError::Invalid("AttachQuic requires a transport file descriptor".to_string())
        })?;

        let mut sessions = self.sessions.lock().await;
        match sessions.get_mut(&request.session_id) {
            Some(entry) => {
                let flow_id = request
                    .flow_id
                    .clone()
                    .unwrap_or_else(|| format!("flow-{}", entry.flows.len() + 1));
                if let Some(streams) = request.stream_count {
                    if streams > 1 {
                        debug!(
                            session = %request.session_id,
                            %streams,
                            "AttachQuic requested multiple streams; current implementation attaches one fd per request"
                        );
                    }
                }
                let result = entry.attach_transport_with_id(flow_id, fd);
                match result {
                    Ok(()) => Ok(AttachQuicResponse {
                        session_id: request.session_id,
                        accepted_streams: 1,
                    }),
                    Err(err) => {
                        let _ = close(fd);
                        Err(err)
                    }
                }
            }
            None => {
                drop(sessions);
                let _ = close(fd);
                Err(ActionError::NotFound(format!(
                    "session {} not found",
                    request.session_id
                )))
            }
        }
    }

    async fn destroy_tunnel(
        &self,
        request: DestroyTunnelRequest,
    ) -> Result<DestroyTunnelResponse, ActionError> {
        let entry = {
            let mut sessions = self.sessions.lock().await;
            let entry = sessions.remove(&request.session_id);
            gauge!(METRIC_ACTIVE_SESSIONS, sessions.len() as f64);
            entry
        };

        let mut entry = entry.ok_or_else(|| {
            ActionError::NotFound(format!("session {} not found", request.session_id))
        })?;
        counter!(METRIC_SESSIONS_CLOSED_TOTAL, 1);

        entry.close_transport();
        if let Some(nat_state) = entry.policy_state.nat.as_ref() {
            if let Err(err) = self
                .interface_manager
                .rollback_nat(&entry.interface_name, nat_state)
                .await
            {
                warn!(
                    session = %request.session_id,
                    interface = %entry.interface_name,
                    "failed to rollback NAT during destroy: {err}"
                );
            }
        }
        if let Err(err) = self
            .interface_manager
            .rollback_policy(&entry.interface_name, &entry.policy_state)
            .await
        {
            warn!(
                session = %request.session_id,
                interface = %entry.interface_name,
                "failed to rollback policy during destroy: {err}"
            );
        }
        self.interface_manager
            .teardown_tun(&entry.interface_name)
            .await
            .map_err(ActionError::from)?;
        entry.close_interface();
        self.persistence.remove_session(&request.session_id).await;

        Ok(DestroyTunnelResponse {
            session_id: request.session_id,
            bytes_ingress: entry.bytes_ingress.load(Ordering::Relaxed),
            bytes_egress: entry.bytes_egress.load(Ordering::Relaxed),
        })
    }

    async fn metrics_snapshot(&self, reset: bool) -> MetricsSnapshotResponse {
        let sessions = self.sessions.lock().await;
        let tunnels = sessions
            .iter()
            .map(|(session_id, entry)| entry.metrics(session_id, reset))
            .collect::<Vec<_>>();

        MetricsSnapshotResponse {
            generated_at_ms: SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            total_sessions: tunnels.len() as u32,
            active_sessions: tunnels.len() as u32,
            tunnels,
        }
    }

    fn verify_auth(
        &self,
        header: Option<&AuthHeader>,
        request: &ServerRequest,
    ) -> Result<(), ActionError> {
        self.auth.verify(header, request).map_err(ActionError::from)
    }
}

impl fmt::Debug for HelperState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HelperState").finish()
    }
}

#[derive(Debug)]
enum ActionError {
    Invalid(String),
    NotFound(String),
    Conflict(String),
    Unauthorized(String),
    Interface(InterfaceError),
}

impl From<InterfaceError> for ActionError {
    fn from(value: InterfaceError) -> Self {
        ActionError::Interface(value)
    }
}

impl From<AuthError> for ActionError {
    fn from(value: AuthError) -> Self {
        match value {
            AuthError::Missing => ActionError::Unauthorized("authentication required".into()),
            AuthError::UnknownToken => {
                ActionError::Unauthorized("unknown authentication token".into())
            }
            AuthError::InvalidSignature => {
                ActionError::Unauthorized("invalid authentication signature".into())
            }
            AuthError::Replay => ActionError::Unauthorized("replayed authentication nonce".into()),
            AuthError::Internal(msg) => ActionError::Interface(InterfaceError::Platform(msg)),
        }
    }
}

impl ActionError {
    fn into_response(self, session_id: Option<&str>) -> ServerResponse {
        match self {
            ActionError::Invalid(message) => {
                error_response(session_id, ErrorCode::InvalidRequest, message)
            }
            ActionError::NotFound(message) => {
                error_response(session_id, ErrorCode::NotFound, message)
            }
            ActionError::Conflict(message) => error_response(session_id, ErrorCode::Busy, message),
            ActionError::Unauthorized(message) => {
                error_response(session_id, ErrorCode::Unauthorized, message)
            }
            ActionError::Interface(err) => {
                error_response(session_id, map_interface_error_code(&err), err.to_string())
            }
        }
    }
}

fn map_interface_error_code(err: &InterfaceError) -> ErrorCode {
    match err {
        InterfaceError::InvalidConfig(_) => ErrorCode::InvalidRequest,
        InterfaceError::CommandFailure { .. } => ErrorCode::InternalError,
        InterfaceError::Io(_) => ErrorCode::InternalError,
        InterfaceError::Platform(_) => ErrorCode::InternalError,
    }
}

fn error_response(session_id: Option<&str>, code: ErrorCode, message: String) -> ServerResponse {
    ServerResponse::Error(ErrorResponse {
        session_id: session_id.map(|s| s.to_string()),
        code,
        message,
    })
}

fn request_session_id(request: &ServerRequest) -> Option<&str> {
    match request {
        ServerRequest::CreateTunnel(req) => Some(&req.session_id),
        ServerRequest::AttachQuic(req) => Some(&req.session_id),
        ServerRequest::DestroyTunnel(req) => Some(&req.session_id),
        _ => None,
    }
}

#[derive(Debug)]
struct TunBridge {
    interface: String,
    tun_fd: Option<OwnedFd>,
    writer_tx: mpsc::Sender<Vec<u8>>,
    broadcast_tx: broadcast::Sender<Arc<Vec<u8>>>,
    reader_task: JoinHandle<()>,
    writer_task: JoinHandle<()>,
}

impl TunBridge {
    fn new(
        interface: String,
        tun_fd: OwnedFd,
        bytes_in: Arc<AtomicU64>,
        bytes_out: Arc<AtomicU64>,
        packets_in: Arc<AtomicU64>,
        packets_out: Arc<AtomicU64>,
    ) -> Result<Self, ActionError> {
        let (writer_tx, writer_rx) = mpsc::channel::<Vec<u8>>(TUN_WRITE_QUEUE_CAPACITY);
        let (broadcast_tx, _) = broadcast::channel::<Arc<Vec<u8>>>(TUN_BROADCAST_CAPACITY);

        let reader_fd = tun_fd
            .try_clone()
            .map_err(|e| ActionError::Interface(InterfaceError::Io(e)))?;
        let writer_fd = tun_fd
            .try_clone()
            .map_err(|e| ActionError::Interface(InterfaceError::Io(e)))?;

        let reader_interface = interface.clone();
        let broadcast_reader = broadcast_tx.clone();
        let bytes_out_reader = Arc::clone(&bytes_out);
        let packets_out_reader = Arc::clone(&packets_out);
        let reader_task = tokio::spawn(async move {
            let std_reader = unsafe { StdFile::from_raw_fd(reader_fd.into_raw_fd()) };
            let mut reader = File::from_std(std_reader);
            let mut buf = vec![0u8; MAX_PACKET_SIZE];
            loop {
                match reader.read(&mut buf).await {
                    Ok(0) => continue,
                    Ok(n) => {
                        let packet = Arc::new(buf[..n].to_vec());
                        if broadcast_reader.send(packet).is_ok() {
                            bytes_out_reader.fetch_add(n as u64, Ordering::Relaxed);
                            packets_out_reader.fetch_add(1, Ordering::Relaxed);
                            counter!(
                                METRIC_BYTES_TOTAL,
                                n as u64,
                                "direction" => "egress",
                                "interface" => reader_interface.clone()
                            );
                            counter!(
                                METRIC_PACKETS_TOTAL,
                                1,
                                "direction" => "egress",
                                "interface" => reader_interface.clone()
                            );
                        }
                    }
                    Err(ref e) if e.kind() == ErrorKind::Interrupted => continue,
                    Err(e) => {
                        warn!(interface = %reader_interface, "TUN read error: {e}");
                        counter!(
                            METRIC_ERRORS_TOTAL,
                            1,
                            "kind" => "tun_read",
                            "interface" => reader_interface.clone()
                        );
                        break;
                    }
                }
            }
        });

        let bytes_in_writer = Arc::clone(&bytes_in);
        let packets_in_writer = Arc::clone(&packets_in);
        let writer_interface = interface.clone();
        let writer_task = tokio::spawn(async move {
            let std_writer = unsafe { StdFile::from_raw_fd(writer_fd.into_raw_fd()) };
            let mut writer = File::from_std(std_writer);
            let mut rx = writer_rx;
            while let Some(packet) = rx.recv().await {
                let packet_len = packet.len();
                if let Err(e) = writer.write_all(&packet).await {
                    warn!(interface = %writer_interface, "TUN write error: {e}");
                    counter!(
                        METRIC_ERRORS_TOTAL,
                        1,
                        "kind" => "tun_write",
                        "interface" => writer_interface.clone()
                    );
                    break;
                }
                bytes_in_writer.fetch_add(packet_len as u64, Ordering::Relaxed);
                packets_in_writer.fetch_add(1, Ordering::Relaxed);
                counter!(
                    METRIC_BYTES_TOTAL,
                    packet_len as u64,
                    "direction" => "ingress",
                    "interface" => writer_interface.clone()
                );
                counter!(
                    METRIC_PACKETS_TOTAL,
                    1,
                    "direction" => "ingress",
                    "interface" => writer_interface.clone()
                );
            }
        });

        Ok(Self {
            interface,
            tun_fd: Some(tun_fd),
            writer_tx,
            broadcast_tx,
            reader_task,
            writer_task,
        })
    }

    fn subscribe(&self) -> broadcast::Receiver<Arc<Vec<u8>>> {
        self.broadcast_tx.subscribe()
    }

    fn writer(&self) -> mpsc::Sender<Vec<u8>> {
        self.writer_tx.clone()
    }

    fn shutdown(&self) {
        debug!(interface = %self.interface, "shutting down tun bridge tasks");
        self.reader_task.abort();
        self.writer_task.abort();
    }

    fn close_interface(&mut self) {
        if let Some(fd) = self.tun_fd.take() {
            drop(fd);
        }
    }
}

#[derive(Debug)]
struct TransportBridge {
    flow_id: String,
    reader_task: JoinHandle<()>,
    writer_task: JoinHandle<()>,
}

impl TransportBridge {
    fn new(
        flow_id: String,
        fd: RawFd,
        mut broadcast_rx: broadcast::Receiver<Arc<Vec<u8>>>,
        tun_writer: mpsc::Sender<Vec<u8>>,
        bytes_in: Arc<AtomicU64>,
        bytes_out: Arc<AtomicU64>,
        packets_in: Arc<AtomicU64>,
        packets_out: Arc<AtomicU64>,
    ) -> Result<Self, ActionError> {
        let std_stream = unsafe { StdUnixStream::from_raw_fd(fd) };
        std_stream
            .set_nonblocking(true)
            .map_err(|e| ActionError::Interface(InterfaceError::Io(e)))?;
        let transport = UnixStream::from_std(std_stream)
            .map_err(|e| ActionError::Interface(InterfaceError::Io(e)))?;

        let (mut reader, mut writer) = transport.into_split();

        let writer_bytes = Arc::clone(&bytes_out);
        let writer_packets = Arc::clone(&packets_out);
        let flow_for_writer = flow_id.clone();
        let writer_task = tokio::spawn(async move {
            loop {
                match broadcast_rx.recv().await {
                    Ok(packet) => {
                        let packet_len = packet.len();
                        if packet_len > u16::MAX as usize {
                            warn!(
                                flow = %flow_for_writer,
                                len = packet_len,
                                "packet exceeds u16 length, dropping"
                            );
                            counter!(
                                METRIC_ERRORS_TOTAL,
                                1,
                                "kind" => "transport_packet_oversize",
                                "flow" => flow_for_writer.clone()
                            );
                            continue;
                        }

                        let len_bytes = (packet_len as u16).to_be_bytes();
                        if let Err(e) = writer.write_all(&len_bytes).await {
                            warn!(flow = %flow_for_writer, "transport write error (len): {e}");
                            counter!(
                                METRIC_ERRORS_TOTAL,
                                1,
                                "kind" => "transport_write_len",
                                "flow" => flow_for_writer.clone()
                            );
                            break;
                        }
                        if let Err(e) = writer.write_all(&packet).await {
                            warn!(flow = %flow_for_writer, "transport write error (payload): {e}");
                            counter!(
                                METRIC_ERRORS_TOTAL,
                                1,
                                "kind" => "transport_write_payload",
                                "flow" => flow_for_writer.clone()
                            );
                            break;
                        }
                        writer_bytes.fetch_add(packet_len as u64, Ordering::Relaxed);
                        writer_packets.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(broadcast::error::RecvError::Lagged(skipped)) => {
                        warn!(flow = %flow_for_writer, skipped, "transport receiver lagged behind");
                        counter!(
                            METRIC_ERRORS_TOTAL,
                            1,
                            "kind" => "transport_broadcast_lag",
                            "flow" => flow_for_writer.clone()
                        );
                        continue;
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        });

        let tun_writer_clone = tun_writer;
        let reader_bytes = Arc::clone(&bytes_in);
        let reader_packets = Arc::clone(&packets_in);
        let flow_for_reader = flow_id.clone();
        let reader_task = tokio::spawn(async move {
            loop {
                let mut len_buf = [0u8; 2];
                match reader.read_exact(&mut len_buf).await {
                    Ok(_) => {}
                    Err(ref e) if e.kind() == ErrorKind::Interrupted => continue,
                    Err(e) if e.kind() == ErrorKind::UnexpectedEof => break,
                    Err(e) => {
                        warn!(flow = %flow_for_reader, "transport read error (len): {e}");
                        counter!(
                            METRIC_ERRORS_TOTAL,
                            1,
                            "kind" => "transport_read_len",
                            "flow" => flow_for_reader.clone()
                        );
                        break;
                    }
                }

                let packet_len = u16::from_be_bytes(len_buf) as usize;
                if packet_len == 0 {
                    continue;
                }
                if packet_len > MAX_PACKET_SIZE {
                    warn!(
                        flow = %flow_for_reader,
                        packet_len,
                        "declared packet length exceeds max, draining"
                    );
                    counter!(
                        METRIC_ERRORS_TOTAL,
                        1,
                        "kind" => "transport_packet_declared_oversize",
                        "flow" => flow_for_reader.clone()
                    );
                    let mut drain = vec![0u8; packet_len];
                    if let Err(e) = reader.read_exact(&mut drain).await {
                        warn!(flow = %flow_for_reader, "transport read error (oversize drain): {e}");
                        counter!(
                            METRIC_ERRORS_TOTAL,
                            1,
                            "kind" => "transport_read_oversize_drain",
                            "flow" => flow_for_reader.clone()
                        );
                        break;
                    }
                    continue;
                }

                let mut packet = vec![0u8; packet_len];
                match reader.read_exact(&mut packet).await {
                    Ok(_) => match tun_writer_clone.try_send(packet) {
                        Ok(_) => {
                            reader_bytes.fetch_add(packet_len as u64, Ordering::Relaxed);
                            reader_packets.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            warn!(flow = %flow_for_reader, "tun write queue full, dropping packet");
                            counter!(
                                METRIC_ERRORS_TOTAL,
                                1,
                                "kind" => "tun_queue_full",
                                "flow" => flow_for_reader.clone()
                            );
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => break,
                    },
                    Err(e) => {
                        warn!(flow = %flow_for_reader, "transport read error (payload): {e}");
                        counter!(
                            METRIC_ERRORS_TOTAL,
                            1,
                            "kind" => "transport_read_payload",
                            "flow" => flow_for_reader.clone()
                        );
                        break;
                    }
                }
            }
        });

        Ok(Self {
            flow_id,
            reader_task,
            writer_task,
        })
    }

    fn shutdown(&mut self) {
        debug!(flow = %self.flow_id, "shutting down transport bridge tasks");
        self.reader_task.abort();
        self.writer_task.abort();
    }
}

async fn handle_connection(
    stream: UnixStream,
    state: Arc<HelperState>,
) -> Result<(), anyhow::Error> {
    let mut stream = stream;

    loop {
        let (envelope, fd) = match receive_request(&mut stream).await {
            Ok(res) => res,
            Err(err) => {
                debug!("IPC receive error: {err:?}");
                break;
            }
        };

        if let Err(auth_err) = state.verify_auth(envelope.auth.as_ref(), &envelope.request) {
            if let Some(fd) = fd {
                let _ = close(fd);
            }
            let response = auth_err.into_response(request_session_id(&envelope.request));
            if let Err(err) = send_response(&mut stream, &response).await {
                error!("Failed to send response: {err:?}");
                break;
            }
            continue;
        }

        let request = envelope.request;

        let response = match request {
            ServerRequest::Ping => ServerResponse::Pong,
            ServerRequest::CreateTunnel(req) => {
                let session = req.session_id.clone();
                match state.create_tunnel(req).await {
                    Ok(created) => ServerResponse::TunnelCreated(created),
                    Err(err) => err.into_response(Some(&session)),
                }
            }
            ServerRequest::AttachQuic(req) => {
                let session = req.session_id.clone();
                match state.attach_transport(req, fd).await {
                    Ok(attached) => ServerResponse::QuicAttached(attached),
                    Err(err) => err.into_response(Some(&session)),
                }
            }
            ServerRequest::DestroyTunnel(req) => {
                let session = req.session_id.clone();
                match state.destroy_tunnel(req).await {
                    Ok(destroyed) => ServerResponse::TunnelDestroyed(destroyed),
                    Err(err) => err.into_response(Some(&session)),
                }
            }
            ServerRequest::MetricsSnapshot(req) => {
                ServerResponse::Metrics(state.metrics_snapshot(req.reset_after_read).await)
            }
        };

        if let Err(err) = send_response(&mut stream, &response).await {
            error!("Failed to send response: {err:?}");
            break;
        }
    }

    Ok(())
}
