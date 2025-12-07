use rcgen::CertificateParams;
use shared_utils::crypto::aes_gcm::AesGcmCipher;
use shared_utils::quic::transport::configure_tls;
use shared_utils::quic::{QuicClient, QuicServer};
use shared_utils::transport::{ClientTransport, ServerTransport, TransportError};
use std::net::SocketAddr;
use tokio::time::{timeout, Duration};

fn generate_cert_for(name: &str) -> anyhow::Result<(rustls::Certificate, rustls::PrivateKey)> {
    let mut params = CertificateParams::new(vec![name.to_string()]);
    let cert = rcgen::Certificate::from_params(params)?;
    let key_der = cert.serialize_private_key_der();
    let cert_der = cert.serialize_der()?;
    Ok((rustls::Certificate(cert_der), rustls::PrivateKey(key_der)))
}

fn start_server(port: u16, cert: rustls::Certificate, key: rustls::PrivateKey) -> anyhow::Result<QuicServer> {
    let server_tls = configure_tls(cert, key)?;
    let key_bytes = AesGcmCipher::generate_key();
    let bind: SocketAddr = format!("127.0.0.1:{port}").parse()?;
    QuicServer::new_with_tls_config(bind, &key_bytes, server_tls).map_err(Into::into)
}

#[tokio::test]
async fn hostname_mismatch_fails() {
    let (cert, key) = generate_cert_for("bad.local").expect("cert");
    let port = 48001;
    let server = start_server(port, cert.clone(), key).expect("server");
    let mut listener = server
        .listen(&format!("127.0.0.1:{port}"))
        .await
        .expect("listen");
    let server_task = tokio::spawn(async move {
        if let Ok(mut conn) = listener.accept().await {
            let _ = conn.recv_data().await;
        }
    });

    let key_bytes = AesGcmCipher::generate_key();
    let client = QuicClient::new_with_pinned_roots(&key_bytes, &cert).expect("client");
    let res = timeout(
        Duration::from_secs(2),
        client.connect("localhost:48001"),
    )
    .await;

    assert!(res.is_err() || matches!(res.unwrap(), Err(TransportError::Tls(_)) | Err(TransportError::Connection(_))));
    server_task.abort();
}

#[tokio::test]
async fn invalid_ca_rejected() {
    let (server_cert, server_key) = generate_cert_for("localhost").expect("cert");
    let port = 48002;
    let server = start_server(port, server_cert.clone(), server_key).expect("server");
    let mut listener = server
        .listen(&format!("127.0.0.1:{port}"))
        .await
        .expect("listen");
    let server_task = tokio::spawn(async move {
        if let Ok(mut conn) = listener.accept().await {
            let _ = conn.recv_data().await;
        }
    });

    // Use a different (wrong) root
    let (wrong_cert, _wrong_key) = generate_cert_for("localhost").expect("wrong cert");
    let key_bytes = AesGcmCipher::generate_key();
    let client = QuicClient::new_with_pinned_roots(&key_bytes, &wrong_cert).expect("client");
    let res = timeout(
        Duration::from_secs(2),
        client.connect("localhost:48002"),
    )
    .await;

    assert!(res.is_err() || matches!(res.unwrap(), Err(TransportError::Tls(_)) | Err(TransportError::Connection(_))));
    server_task.abort();
}
