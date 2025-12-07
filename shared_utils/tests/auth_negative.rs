use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use async_trait::async_trait;
use shared_utils::proto::auth::{
    parse_psk, psk_handshake_client, psk_handshake_server, psk_handshake_server_with_config,
    ServerAuthConfig,
};
use shared_utils::transport::{Connection, TransportError};
use tokio::sync::{mpsc, Mutex};
use tokio::time::sleep;
use tracing::warn;

struct InMemoryConn {
    tx: mpsc::Sender<Vec<u8>>,
    rx: Mutex<mpsc::Receiver<Vec<u8>>>,
    send_delay: Option<Duration>,
    local: SocketAddr,
    peer: SocketAddr,
    drop_rate: f32,
    reorder: bool,
}

impl InMemoryConn {
    fn pair(server_delay: Option<Duration>, client_delay: Option<Duration>) -> (Self, Self) {
        Self::pair_with_conditions(server_delay, client_delay, 0.0, false)
    }

    fn pair_with_conditions(
        server_delay: Option<Duration>,
        client_delay: Option<Duration>,
        drop_rate: f32,
        reorder: bool,
    ) -> (Self, Self) {
        let (server_tx, server_rx) = mpsc::channel::<Vec<u8>>(16);
        let (client_tx, client_rx) = mpsc::channel::<Vec<u8>>(16);
        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = Self {
            tx: server_tx,
            rx: Mutex::new(client_rx),
            send_delay: server_delay,
            local,
            peer: local,
            drop_rate,
            reorder,
        };
        let client = Self {
            tx: client_tx,
            rx: Mutex::new(server_rx),
            send_delay: client_delay,
            local,
            peer: local,
            drop_rate,
            reorder,
        };
        (server, client)
    }
}

#[async_trait]
impl Connection for InMemoryConn {
    async fn send_data(&mut self, data: &[u8]) -> Result<(), TransportError> {
        if let Some(delay) = self.send_delay {
            sleep(delay).await;
        }
        if self.drop_rate > 0.0 {
            let roll: f32 = rand::random();
            if roll < self.drop_rate {
                warn!("Simulated drop of outbound packet");
                return Ok(());
            }
        }
        let mut payload = data.to_vec();
        if self.reorder && payload.len() > 1 {
            payload.reverse();
        }
        self.tx.send(payload).await.map_err(|e| TransportError::Send(e.to_string()))
    }

    async fn recv_data(&mut self) -> Result<Option<Vec<u8>>, TransportError> {
        let mut rx = self.rx.lock().await;
        Ok(rx.recv().await)
    }

    fn peer_addr(&self) -> Result<SocketAddr, TransportError> {
        Ok(self.peer)
    }

    fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        Ok(self.local)
    }

    async fn close(self: Box<Self>) -> Result<(), TransportError> {
        Ok(())
    }
}

#[tokio::test]
async fn rejects_invalid_psk() {
    let (mut server_conn, mut client_conn) = InMemoryConn::pair(None, None);
    let server = tokio::spawn(async move {
        psk_handshake_server(&mut server_conn, || parse_psk("Y29ycmVjdC1wc2s=")).await
    });

    let client_res = psk_handshake_client(&mut client_conn, "d3Jvbmc=").await;
    let server_res = server.await.expect("server task panicked");

    match client_res {
        Err(TransportError::Protocol(msg)) => {
            assert!(
                msg.contains("auth rejected") || msg.contains("invalid mac"),
                "unexpected client error: {msg}"
            );
        }
        other => panic!("expected client auth rejection, got {:?}", other),
    }

    match server_res {
        Err(TransportError::Protocol(msg)) => {
            assert!(
                msg.contains("invalid mac"),
                "unexpected server error: {msg}"
            );
        }
        other => panic!("expected server invalid mac, got {:?}", other),
    }
}

#[tokio::test]
async fn rejects_stale_challenge() {
    let (mut server_conn, mut client_conn) =
        InMemoryConn::pair(None, Some(Duration::from_millis(50)));
    let server_cfg = ServerAuthConfig {
        challenge_ttl: Duration::from_millis(10),
        ..Default::default()
    };
    let server = tokio::spawn(async move {
        psk_handshake_server_with_config(
            &mut server_conn,
            || parse_psk("c3RhbGUtcHNr"),
            &server_cfg,
        )
        .await
    });

    let client_res = psk_handshake_client(&mut client_conn, "c3RhbGUtcHNr").await;
    let server_res = server.await.expect("server task panicked");

    match client_res {
        Err(TransportError::Protocol(msg)) => {
            assert!(
                msg.contains("stale"),
                "unexpected client error: {msg}"
            );
        }
        other => panic!("expected client stale challenge, got {:?}", other),
    }

    match server_res {
        Err(TransportError::Protocol(msg)) => {
            assert!(
                msg.contains("stale challenge"),
                "unexpected server error: {msg}"
            );
        }
        other => panic!("expected server stale challenge, got {:?}", other),
    }
}

#[tokio::test]
async fn withstands_loss_and_reorder() {
    // Simulate loss and reordering; handshake should succeed or fail cleanly without hanging.
    let (mut server_conn, mut client_conn) =
        InMemoryConn::pair_with_conditions(None, None, 0.2, true);

    let server = tokio::spawn(async move {
        psk_handshake_server(&mut server_conn, || parse_psk("Y29uc2lzdGVudA==")).await
    });

    let client_res = psk_handshake_client(&mut client_conn, "Y29uc2lzdGVudA==").await;
    let server_res = server.await.expect("server task panicked");

    match (client_res, server_res) {
        (Ok(_), Ok(_)) => {}
        (Err(TransportError::Protocol(_)), Err(TransportError::Protocol(_))) => {}
        other => panic!("unexpected outcome under loss/reorder: {:?}", other),
    }
}
