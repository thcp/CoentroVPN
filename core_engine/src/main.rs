mod bridge;
mod helper_client;
mod ipam;

use bridge::spawn_quic_helper_bridge;
use helper_client::ServerHelperClient;
use ipam::IpAllocator;

use anyhow::{Context, Result, anyhow};
use clap::Parser;
use coentro_server_helper::ipc::messages::{
    AttachQuicRequest, CreateTunnelRequest, DnsConfig, RouteSpec, TunnelAddress,
};
use metrics::counter;
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use rustls::server::{
    AllowAnyAnonymousOrAuthenticatedClient, AllowAnyAuthenticatedClient, ClientCertVerifier,
};
use rustls::{Certificate as RustlsCertificate, PrivateKey as RustlsPrivateKey, RootCertStore};
use rustls_pemfile::{certs, pkcs8_private_keys};
use sha2::{Digest, Sha256};
use shared_utils::config::{AuthMode, Config, ConfigManager, Role, SecurityConfig};
use shared_utils::proto::auth::{
    AuthMetrics, PersistentReplayCache, ReplayCache, ReplayCacheProvider, ServerAuthConfig,
    parse_psk, psk_handshake_server_with_config,
};
use shared_utils::quic::QuicServer;
use shared_utils::transport::{Listener, ServerTransport};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::{IpAddr, SocketAddr};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::SystemTime;
use tokio::net::UnixStream;
use tokio::signal;
use tokio::signal::unix::{self as unix_signal, SignalKind};
use tracing::{debug, error, info, warn};
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

/// CoentroVPN Core Engine
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Path to the configuration file
    #[arg(short, long, value_name = "FILE", default_value = "config.toml")]
    config: PathBuf,

    /// Path to the server helper IPC socket
    #[arg(long, value_name = "PATH")]
    helper_socket: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    init_logging();

    let cli = Cli::parse();
    debug!("Using configuration file: {}", cli.config.display());

    let config_manager = ConfigManager::load(&cli.config)
        .map_err(|err| anyhow!("failed to load configuration: {err}"))?;
    let config = Arc::new(config_manager.config().clone());
    info!("Configuration loaded successfully");

    if config.role != Role::Server {
        return Err(anyhow!(
            "core_engine must run with role=server to accept dataplane sessions"
        ));
    }

    let helper_socket = Arc::new(
        cli.helper_socket
            .or_else(|| Some(PathBuf::from(&config.server.helper_socket)))
            .expect("helper socket path must be set"),
    );
    let ip_pool = Arc::new(IpAllocator::new(
        config
            .server
            .virtual_ip_range
            .as_deref()
            .expect("validated server.virtual_ip_range"),
    )?);

    let _metrics_handle = init_metrics(&config)?;

    let tls_state = Arc::new(TlsState::new(&config)?);
    let revocations = Arc::new(RevocationList::from_config(&config));
    let signal_tls = Arc::clone(&tls_state);
    let signal_revocations = Arc::clone(&revocations);
    tokio::spawn(async move {
        match unix_signal::signal(SignalKind::hangup()) {
            Ok(mut hup) => {
                while hup.recv().await.is_some() {
                    let tls_result = signal_tls.reload();
                    let rev_result = signal_revocations.reload_from_disk();
                    match (tls_result, rev_result) {
                        (Ok(_), Ok(_)) => info!("Reloaded TLS material and revocation list"),
                        (Err(err), _) => error!("TLS reload failed: {err}"),
                        (_, Err(err)) => error!("Revocation reload failed: {err}"),
                    }
                }
            }
            Err(err) => warn!("Unable to register SIGHUP handler: {err}"),
        }
    });

    let auth_metrics = Arc::new(AuthMetrics::default());
    let replay_cache: Arc<dyn ReplayCacheProvider> =
        if let Some(path) = &config.security.replay_cache_path {
            Arc::<PersistentReplayCache>::new(PersistentReplayCache::new(
                path.clone(),
                config.security.replay_cache_max_entries,
                config.security.challenge_ttl(),
            )) as Arc<dyn ReplayCacheProvider>
        } else {
            Arc::<ReplayCache>::new(ReplayCache::new(config.security.replay_cache_max_entries))
                as Arc<dyn ReplayCacheProvider>
        };

    let bind_addr = format!("{}:{}", config.network.bind_address, config.network.port);
    let key_material = derive_dataplane_key(&config)?;
    let quic_server =
        build_quic_server(&config, &key_material, &bind_addr, Arc::clone(&revocations))?;
    let mut listener = quic_server
        .listen(&bind_addr)
        .await
        .map_err(|e| anyhow!("failed to listen on {bind_addr}: {e}"))?;

    info!("Core engine listening for QUIC on {}", bind_addr);

    let server_auth_config = Arc::new(
        ServerAuthConfig::new(config.security.challenge_ttl())
            .with_metrics(auth_metrics.clone())
            .with_replay_cache(replay_cache.clone()),
    );

    loop {
        tokio::select! {
            accept = listener.accept() => {
                match accept {
                    Ok(conn) => {
                        let helper_socket = Arc::clone(&helper_socket);
                        let config = Arc::clone(&config);
                        let ip_pool = Arc::clone(&ip_pool);
                        let auth_cfg = Arc::clone(&server_auth_config);
                        tokio::spawn(async move {
                            if let Err(err) = handle_connection(conn, config, helper_socket, ip_pool, auth_cfg).await {
                                error!("session terminated with error: {err}");
                            }
                        });
                    }
                    Err(e) => {
                        error!("Listener accept error: {e}");
                    }
                }
            }
            _ = signal::ctrl_c() => {
                info!("Received Ctrl+C, shutting down core engine");
                break;
            }
        }
    }

    Ok(())
}

fn init_logging() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::from_default_env().add_directive("core_engine=debug".parse().unwrap()),
        )
        .with_file(true)
        .with_line_number(true)
        .with_target(true)
        .try_init();
}

fn init_metrics(config: &Config) -> Result<Option<PrometheusHandle>> {
    if !config.metrics.enabled {
        return Ok(None);
    }
    let listen_addr: SocketAddr = config
        .metrics
        .listen_addr
        .parse()
        .map_err(|e| anyhow!("invalid metrics listen_addr: {e}"))?;
    info!("Starting Prometheus metrics endpoint on {}", listen_addr);
    let handle = PrometheusBuilder::new()
        .with_http_listener(listen_addr)
        .install_recorder()
        .map_err(|e| anyhow!("failed to install Prometheus exporter: {e}"))?;
    Ok(Some(handle))
}

fn derive_dataplane_key(config: &Config) -> Result<[u8; 32]> {
    let key = match (config.security.auth_mode, &config.security.psk) {
        (AuthMode::Psk, Some(psk_str)) => {
            let psk_bytes = parse_psk(psk_str).map_err(|e| anyhow!("invalid PSK: {e}"))?;
            let digest = Sha256::digest(&psk_bytes);
            let mut out = [0u8; 32];
            out.copy_from_slice(&digest);
            out
        }
        _ => shared_utils::AesGcmCipher::generate_key(),
    };
    Ok(key)
}

fn build_quic_server(
    config: &Config,
    key: &[u8; 32],
    bind: &str,
    revocations: Arc<RevocationList>,
) -> Result<QuicServer> {
    let bind_addr = bind
        .parse()
        .map_err(|e| anyhow!("invalid bind address {bind}: {e}"))?;

    if let (Some(cert_path), Some(key_path)) =
        (&config.security.cert_path, &config.security.key_path)
    {
        let cert_chain = load_cert_chain(cert_path)?;
        let mut key_reader =
            BufReader::new(File::open(key_path).map_err(|e| anyhow!("read key: {e}"))?);
        let mut keys =
            pkcs8_private_keys(&mut key_reader).map_err(|e| anyhow!("parse key PEM: {e}"))?;
        if keys.is_empty() {
            return Err(anyhow!("no PKCS8 private keys found in key_path"));
        }
        let key_der = RustlsPrivateKey(keys.remove(0));
        let tls_config =
            build_server_tls_config(&config.security, cert_chain, key_der, revocations)
                .map_err(|e| anyhow!("failed to build server TLS configuration: {e}"))?;
        QuicServer::new_with_tls_config(bind_addr, key, tls_config)
            .map_err(|e| anyhow!("failed to initialise QUIC server (cert): {e}"))
    } else {
        QuicServer::new(bind_addr, key)
            .map_err(|e| anyhow!("failed to initialise QUIC server: {e}"))
    }
}

fn load_cert_chain(path: &str) -> Result<Vec<RustlsCertificate>> {
    let mut reader = BufReader::new(File::open(path).map_err(|e| anyhow!("read cert chain: {e}"))?);
    let der = certs(&mut reader).map_err(|e| anyhow!("parse cert PEM: {e}"))?;
    if der.is_empty() {
        return Err(anyhow!("no certificates found in {path}"));
    }
    Ok(der.into_iter().map(RustlsCertificate).collect())
}

fn load_client_root_store(path: &str) -> Result<RootCertStore> {
    let mut reader = BufReader::new(File::open(path).map_err(|e| anyhow!("read CA bundle: {e}"))?);
    let der = certs(&mut reader).map_err(|e| anyhow!("parse CA PEM: {e}"))?;
    if der.is_empty() {
        return Err(anyhow!("no certificates found in CA bundle {path}"));
    }
    let mut store = RootCertStore::empty();
    for entry in der {
        store
            .add(&RustlsCertificate(entry))
            .map_err(|e| anyhow!("invalid certificate inside CA bundle {path}: {e}"))?;
    }
    Ok(store)
}

fn fingerprint_hex(cert: &RustlsCertificate) -> String {
    let digest = Sha256::digest(&cert.0);
    digest
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>()
}

struct RevocationVerifier<T: ClientCertVerifier> {
    inner: T,
    revoked: Arc<RevocationList>,
}

impl<T: ClientCertVerifier> RevocationVerifier<T> {
    fn new(inner: T, revoked: Arc<RevocationList>) -> Self {
        Self { inner, revoked }
    }
}

impl<T: ClientCertVerifier> ClientCertVerifier for RevocationVerifier<T> {
    fn offer_client_auth(&self) -> bool {
        self.inner.offer_client_auth()
    }

    fn client_auth_mandatory(&self) -> bool {
        self.inner.client_auth_mandatory()
    }

    fn client_auth_root_subjects(&self) -> &[rustls::DistinguishedName] {
        self.inner.client_auth_root_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &rustls::Certificate,
        intermediates: &[rustls::Certificate],
        now: SystemTime,
    ) -> Result<rustls::server::ClientCertVerified, rustls::Error> {
        let result = self
            .inner
            .verify_client_cert(end_entity, intermediates, now)?;
        let fingerprint = fingerprint_hex(&RustlsCertificate(end_entity.0.clone()));
        if self.revoked.is_revoked(&fingerprint) {
            counter!("coentrovpn_auth_failures_total", 1, "reason" => "revoked");
            return Err(rustls::Error::General(
                "client certificate revoked".to_string(),
            ));
        }
        Ok(result)
    }
}

struct RevocationList {
    static_entries: HashSet<String>,
    entries: RwLock<HashSet<String>>,
    file_path: Option<PathBuf>,
}

impl RevocationList {
    fn from_config(cfg: &Config) -> Self {
        let mut static_entries = HashSet::new();
        for entry in &cfg.security.revoked_cert_fingerprints {
            static_entries.insert(Self::normalize(entry));
        }

        let file_path = cfg
            .security
            .revoked_fingerprints_path
            .as_ref()
            .map(PathBuf::from);

        let mut merged = static_entries.clone();
        if let Some(path) = &file_path {
            if let Err(err) = Self::load_file(&mut merged, path) {
                warn!(?path, "Failed to load revocation file: {err}");
            }
        }

        Self {
            static_entries,
            entries: RwLock::new(merged),
            file_path,
        }
    }

    fn reload_from_disk(&self) -> Result<()> {
        let mut merged = self.static_entries.clone();
        if let Some(path) = &self.file_path {
            Self::load_file(&mut merged, path)?;
        }
        let mut guard = self.entries.write().unwrap();
        *guard = merged;
        Ok(())
    }

    fn is_revoked(&self, fingerprint: &str) -> bool {
        let normalized = Self::normalize(fingerprint);
        self.entries.read().unwrap().contains(&normalized)
    }

    fn load_file(set: &mut HashSet<String>, path: &Path) -> Result<()> {
        let file = File::open(path).map_err(|e| {
            anyhow!(
                "unable to read revoked fingerprint file {}: {e}",
                path.display()
            )
        })?;
        for entry in BufReader::new(file)
            .lines()
            .map_while(Result::ok)
        {
            let trimmed = entry.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            set.insert(Self::normalize(trimmed));
        }
        Ok(())
    }

    fn normalize(input: &str) -> String {
        input.trim().to_ascii_lowercase().replace(':', "")
    }
}

fn build_server_tls_config(
    security: &SecurityConfig,
    cert_chain: Vec<RustlsCertificate>,
    key_der: RustlsPrivateKey,
    revocations: Arc<RevocationList>,
) -> Result<Arc<rustls::ServerConfig>> {
    let builder = rustls::ServerConfig::builder().with_safe_defaults();
    let mut server_config = if security.auth_mode == AuthMode::Mtls {
        let ca_path = security
            .ca_bundle_path
            .as_ref()
            .ok_or_else(|| anyhow!("security.ca_bundle_path is required for mTLS"))?;
        let client_roots = load_client_root_store(ca_path)?;
        let verifier: Arc<dyn ClientCertVerifier> = if security.require_client_cert {
            Arc::new(RevocationVerifier::new(
                AllowAnyAuthenticatedClient::new(client_roots),
                Arc::clone(&revocations),
            ))
        } else {
            Arc::new(RevocationVerifier::new(
                AllowAnyAnonymousOrAuthenticatedClient::new(client_roots),
                Arc::clone(&revocations),
            ))
        };
        builder
            .with_client_cert_verifier(verifier)
            .with_single_cert(cert_chain, key_der)?
    } else {
        builder
            .with_no_client_auth()
            .with_single_cert(cert_chain, key_der)?
    };
    server_config.alpn_protocols = vec![b"h3".to_vec()];
    Ok(Arc::new(server_config))
}

async fn handle_connection(
    mut conn: Box<dyn shared_utils::transport::Connection + Send + Sync>,
    config: Arc<Config>,
    helper_socket: Arc<PathBuf>,
    ip_pool: Arc<IpAllocator>,
    server_auth: Arc<ServerAuthConfig>,
) -> Result<()> {
    let peer = conn.peer_addr().ok();
    info!(?peer, "Incoming QUIC stream accepted");

    if config.security.auth_required {
        match config.security.auth_mode {
            AuthMode::Psk => {
                let psk_opt = config.security.psk.clone();
                let get_psk = move || {
                    psk_opt
                        .as_ref()
                        .ok_or_else(|| anyhow!("PSK missing"))
                        .and_then(|s| parse_psk(s).map_err(|e| anyhow!("{e}")))
                        .map_err(|e| {
                            shared_utils::transport::TransportError::Configuration(e.to_string())
                        })
                };
                psk_handshake_server_with_config(&mut *conn, get_psk, &server_auth)
                    .await
                    .map_err(|e| anyhow!("PSK authentication failed: {e}"))?;
                info!(?peer, "Client authenticated via PSK");
            }
            AuthMode::Mtls => {
                info!(?peer, "Client authenticated via mutual TLS");
            }
            AuthMode::None => {
                return Err(anyhow!(
                    "auth_required=true but auth_mode configured as None; refusing session"
                ));
            }
        }
    } else {
        info!(?peer, "Authentication disabled; proceeding insecurely");
    }

    let session_id = Uuid::new_v4().to_string();
    let Some(lease) = ip_pool.allocate().await else {
        return Err(anyhow!("IP pool exhausted; refusing session"));
    };
    let assigned_ip = lease.addr();
    let prefix = ip_pool.prefix_len();

    let mut helper = ServerHelperClient::connect(&*helper_socket).await?;
    let create_request = build_create_tunnel_request(&session_id, assigned_ip, prefix, &config)?;
    helper.create_tunnel(create_request).await?;

    let (engine_sock, helper_sock) = StdUnixStream::pair()
        .map_err(|e| anyhow!("failed to create socketpair for helper bridge: {e}"))?;
    engine_sock
        .set_nonblocking(true)
        .map_err(|e| anyhow!("failed to configure engine socket: {e}"))?;
    helper_sock
        .set_nonblocking(true)
        .map_err(|e| anyhow!("failed to configure helper socket: {e}"))?;

    let mut flows: HashMap<String, bridge::BridgeHandle> = HashMap::new();
    let flow_id = format!("flow-{}", flows.len() + 1);

    if let Err(err) = helper
        .attach_quic(
            AttachQuicRequest {
                session_id: session_id.clone(),
                flow_id: Some(flow_id.clone()),
                stream_count: Some(1),
            },
            helper_sock.as_raw_fd(),
        )
        .await
    {
        let reason = format!("attach_quic failed: {err}");
        let _ = helper.destroy_tunnel(&session_id, Some(reason)).await;
        return Err(err);
    }
    drop(helper_sock);

    let tokio_stream = UnixStream::from_std(engine_sock)
        .map_err(|e| anyhow!("failed to convert engine socket to async: {e}"))?;

    let bridge_handle = spawn_quic_helper_bridge(flow_id.clone(), conn, tokio_stream);
    flows.insert(flow_id.clone(), bridge_handle);

    let bridge_result = flows
        .remove(&flow_id)
        .expect("bridge handle must exist")
        .wait()
        .await;

    helper
        .destroy_tunnel(
            &session_id,
            bridge_result.as_ref().err().map(|e| e.to_string()),
        )
        .await;
    drop(lease);

    bridge_result
}

fn build_create_tunnel_request(
    session_id: &str,
    address: std::net::Ipv4Addr,
    prefix: u8,
    config: &Config,
) -> Result<CreateTunnelRequest> {
    let mut routes = Vec::new();
    for raw in &config.server.routes {
        routes
            .push(parse_route_spec(raw).with_context(|| format!("invalid server route: '{raw}'"))?);
    }

    let mut servers = Vec::new();
    for entry in &config.server.dns_servers {
        servers.push(
            entry
                .parse::<IpAddr>()
                .map_err(|e| anyhow!("invalid DNS server {entry}: {e}"))?,
        );
    }

    let dns = if servers.is_empty() && config.server.dns_search_domains.is_empty() {
        None
    } else {
        Some(DnsConfig {
            servers,
            search_domains: config.server.dns_search_domains.clone(),
        })
    };

    Ok(CreateTunnelRequest {
        session_id: session_id.to_string(),
        virtual_address: TunnelAddress {
            address: IpAddr::V4(address),
            prefix,
        },
        routes,
        dns,
        mtu: Some(1500),
        enable_nat: config.server.enable_nat,
    })
}

fn parse_route_spec(raw: &str) -> Result<RouteSpec> {
    let parts: Vec<&str> = raw.split_whitespace().collect();
    if parts.is_empty() {
        return Err(anyhow!("route string is empty"));
    }

    let cidr = parts[0];
    // basic validation
    if !cidr.contains('/') {
        return Err(anyhow!("route '{}' missing CIDR prefix", raw));
    }

    let mut via: Option<IpAddr> = None;
    let mut metric: Option<u32> = None;

    let mut idx = 1;
    while idx < parts.len() {
        let token = parts[idx];
        let lower = token.to_ascii_lowercase();
        if lower == "via" {
            idx += 1;
            let value = parts
                .get(idx)
                .ok_or_else(|| anyhow!("expected IP after 'via' in route '{raw}'"))?;
            via = Some(
                value
                    .parse::<IpAddr>()
                    .map_err(|e| anyhow!("invalid via IP {value}: {e}"))?,
            );
        } else if lower.starts_with("via=") {
            let value = &token[4..];
            via = Some(
                value
                    .parse::<IpAddr>()
                    .map_err(|e| anyhow!("invalid via IP {value}: {e}"))?,
            );
        } else if lower == "metric" {
            idx += 1;
            let value = parts
                .get(idx)
                .ok_or_else(|| anyhow!("expected value after 'metric' in route '{raw}'"))?;
            metric = Some(
                value
                    .parse::<u32>()
                    .map_err(|e| anyhow!("invalid metric {value}: {e}"))?,
            );
        } else if lower.starts_with("metric=") {
            let value = &token[7..];
            metric = Some(
                value
                    .parse::<u32>()
                    .map_err(|e| anyhow!("invalid metric {value}: {e}"))?,
            );
        } else {
            return Err(anyhow!("unrecognised route token '{}' in '{}'", token, raw));
        }
        idx += 1;
    }

    Ok(RouteSpec {
        cidr: cidr.to_string(),
        via,
        metric,
    })
}
struct TlsState {
    security: SecurityConfig,
    cert_path: Option<PathBuf>,
    key_path: Option<PathBuf>,
}

impl TlsState {
    fn new(cfg: &Config) -> Result<Self> {
        Ok(Self {
            security: cfg.security.clone(),
            cert_path: cfg.security.cert_path.as_ref().map(PathBuf::from),
            key_path: cfg.security.key_path.as_ref().map(PathBuf::from),
        })
    }

    fn reload(&self) -> Result<()> {
        if self.security.auth_mode != AuthMode::Mtls {
            info!("TLS reload skipped (auth_mode != mTLS)");
            return Ok(());
        }

        let cert_path = self
            .cert_path
            .as_ref()
            .ok_or_else(|| anyhow!("cert_path missing for reload"))?;
        let key_path = self
            .key_path
            .as_ref()
            .ok_or_else(|| anyhow!("key_path missing for reload"))?;

        let certs = load_cert_chain(cert_path.to_string_lossy().as_ref())?;
        let mut reader = BufReader::new(File::open(key_path)?);
        let mut keys =
            pkcs8_private_keys(&mut reader).map_err(|e| anyhow!("parse key PEM: {e}"))?;
        if keys.is_empty() {
            return Err(anyhow!(
                "no PKCS8 private keys found in {}",
                key_path.display()
            ));
        }
        let key = RustlsPrivateKey(keys.remove(0));
        // Build a throwaway revocation list from the static config to validate hot reload.
        let revocations = Arc::new(RevocationList::from_config(&Config {
            security: self.security.clone(),
            ..Config::default()
        }));
        let _ = build_server_tls_config(&self.security, certs, key, revocations)?;
        info!("Reloaded server certificates successfully");
        Ok(())
    }
}
