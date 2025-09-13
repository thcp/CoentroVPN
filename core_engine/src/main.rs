mod session;
mod tunnel;

use clap::Parser;
use std::path::Path;
use tracing::{debug, error, info};
use tracing_subscriber::EnvFilter;

use rustls_pemfile::{certs, pkcs8_private_keys};
use sha2::{Digest, Sha256};
use shared_utils::config::ConfigManager;
use shared_utils::proto::auth::{parse_psk, psk_handshake_server};
use shared_utils::quic::QuicServer;
use shared_utils::transport::{Listener, ServerTransport};
use shared_utils::tunnel::TunnelManager;
use std::fs::File;
use std::io::BufReader;

/// CoentroVPN Core Engine
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Path to the configuration file
    #[arg(short, long, value_name = "FILE", default_value = "config.toml")]
    config: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing subscriber
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::from_default_env().add_directive("core_engine=debug".parse().unwrap()),
        )
        .with_file(true)
        .with_line_number(true)
        .with_target(true)
        .init();

    info!("Starting CoentroVPN core engine");
    debug!("Initializing with configuration");

    // Parse command-line arguments
    let cli = Cli::parse();
    debug!("Using configuration file: {}", cli.config);

    // Load configuration
    let config_path = Path::new(&cli.config);
    let config_manager = match ConfigManager::load(config_path) {
        Ok(manager) => manager,
        Err(err) => {
            error!("Failed to load configuration: {}", err);
            return Err(format!("Configuration error: {}", err).into());
        }
    };

    let config = config_manager.config();
    info!("Configuration loaded successfully");
    debug!("Role: {:?}", config.role);

    // Create tunnel manager (not fully wired yet for QUIC data plane)
    let _tunnel_manager = TunnelManager::new();

    // If running as server, start QUIC listener and require auth as per config
    if config.role == shared_utils::config::Role::Server {
        let bind = format!("{}:{}", config.network.bind_address, config.network.port);
        // Derive data-plane key from PSK when using PSK mode; otherwise random
        let key: [u8; 32] = match (config.security.auth_mode, &config.security.psk) {
            (shared_utils::config::AuthMode::Psk, Some(psk_str)) => {
                let psk_bytes = parse_psk(psk_str).map_err(|e| format!("Invalid PSK: {}", e))?;
                let digest = Sha256::digest(&psk_bytes);
                let mut out = [0u8; 32];
                out.copy_from_slice(&digest);
                out
            }
            _ => shared_utils::AesGcmCipher::generate_key(),
        };

        let server = if let (Some(cert_path), Some(key_path)) =
            (&config.security.cert_path, &config.security.key_path)
        {
            // Load provided TLS certificate and PKCS#8 private key
            let mut cert_reader =
                BufReader::new(File::open(cert_path).map_err(|e| format!("Read cert: {}", e))?);
            let mut key_reader =
                BufReader::new(File::open(key_path).map_err(|e| format!("Read key: {}", e))?);
            let cert_chain =
                certs(&mut cert_reader).map_err(|e| format!("Parse cert PEM: {}", e))?;
            if cert_chain.is_empty() {
                return Err("No certificates found in cert_path".into());
            }
            let mut keys = pkcs8_private_keys(&mut key_reader)
                .map_err(|e| format!("Parse key PEM (PKCS8): {}", e))?;
            if keys.is_empty() {
                return Err("No PKCS8 private keys found in key_path".into());
            }
            let cert = rustls::Certificate(cert_chain[0].clone());
            let key_der = rustls::PrivateKey(keys.remove(0));
            QuicServer::new_with_cert(bind.parse().unwrap(), &key, cert, key_der)
                .map_err(|e| format!("Failed to init QUIC server (with cert): {}", e))?
        } else {
            QuicServer::new(bind.parse().unwrap(), &key)
                .map_err(|e| format!("Failed to init QUIC server: {}", e))?
        };
        let mut listener = server
            .listen(&bind)
            .await
            .map_err(|e| format!("Failed to listen on {}: {}", bind, e))?;

        info!("Core engine listening for QUIC on {}", bind);

        loop {
            match listener.accept().await {
                Ok(mut conn) => {
                    info!("Incoming QUIC stream from {}", conn.peer_addr().unwrap());
                    // Only PSK implemented now
                    if config.security.auth_required
                        && config.security.auth_mode == shared_utils::config::AuthMode::Psk
                    {
                        let psk_opt = config.security.psk.clone();
                        let get_psk = move || {
                            psk_opt
                                .as_ref()
                                .ok_or_else(|| {
                                    shared_utils::transport::TransportError::Configuration(
                                        "PSK missing".into(),
                                    )
                                })
                                .and_then(|s| parse_psk(s))
                        };
                        if let Err(e) = psk_handshake_server(&mut *conn, get_psk).await {
                            error!("Auth failed: {}", e);
                            // Close connection and continue
                            let _ = conn.close().await;
                            continue;
                        }
                        info!("Client authenticated");
                    } else if config.security.auth_required {
                        error!("Unsupported auth mode or missing credentials");
                        let _ = conn.close().await;
                        continue;
                    } else {
                        info!("Auth disabled by configuration; allowing connection");
                    }

                    // For Week 1, we just authenticate and then close
                    let _ = conn.close().await;
                }
                Err(e) => {
                    error!("Accept error: {}", e);
                }
            }
        }
    } else {
        // Client role: keep process alive until Ctrl+C
        tokio::signal::ctrl_c().await?;
    }

    info!("CoentroVPN core engine shutting down");
    Ok(())
}
