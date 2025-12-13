use shared_utils::proto::auth::{
    ServerAuthConfig, parse_psk, psk_handshake_client, psk_handshake_server_with_config,
};
use shared_utils::transport::{Connection, TransportError};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::sleep;

struct LossyConn {
    tx: mpsc::Sender<Vec<u8>>,
    rx: mpsc::Receiver<Vec<u8>>,
    drop_every: Option<usize>,
    reorder_window: usize,
    buffer: Vec<Vec<u8>>,
    send_count: usize,
    delay: Duration,
    peer: SocketAddr,
}

impl LossyConn {
    fn pair(drop_every: Option<usize>, reorder_window: usize, delay: Duration) -> (Self, Self) {
        let (tx_a, rx_a) = mpsc::channel(16);
        let (tx_b, rx_b) = mpsc::channel(16);
        let a = LossyConn {
            tx: tx_a,
            rx: rx_b,
            drop_every,
            reorder_window,
            buffer: Vec::new(),
            send_count: 0,
            delay,
            peer: "127.0.0.1:0".parse().unwrap(),
        };
        let b = LossyConn {
            tx: tx_b,
            rx: rx_a,
            drop_every,
            reorder_window,
            buffer: Vec::new(),
            send_count: 0,
            delay,
            peer: "127.0.0.1:0".parse().unwrap(),
        };
        (a, b)
    }

    async fn flush_buffer(&mut self) -> Result<(), TransportError> {
        if self.buffer.is_empty() {
            return Ok(());
        }
        // Reverse to induce reordering
        while let Some(pkt) = self.buffer.pop() {
            let pkt = pkt.clone();
            let tx = self.tx.clone();
            let delay = self.delay;
            // Apply per-packet delay/jitter
            sleep(delay).await;
            tx.send(pkt)
                .await
                .map_err(|e| TransportError::Send(format!("send failed: {}", e)))?;
        }
        Ok(())
    }
}

impl Drop for LossyConn {
    fn drop(&mut self) {
        // Best-effort flush of any buffered packets so tests don't hang or lose tail packets.
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let mut pending = Vec::new();
            pending.append(&mut self.buffer);
            let tx = self.tx.clone();
            handle.spawn(async move {
                for pkt in pending.into_iter().rev() {
                    let _ = tx.send(pkt).await;
                }
            });
        } else {
            while let Some(pkt) = self.buffer.pop() {
                let _ = self.tx.blocking_send(pkt);
            }
        }
    }
}

#[async_trait::async_trait]
impl Connection for LossyConn {
    async fn send_data(&mut self, data: &[u8]) -> Result<(), TransportError> {
        self.send_count += 1;
        if let Some(n) = self.drop_every {
            if n > 0 && self.send_count % n == 0 {
                // Drop this packet
                return Ok(());
            }
        }

        self.buffer.push(data.to_vec());
        if self.buffer.len() >= self.reorder_window.max(1) {
            self.flush_buffer().await?;
        }
        Ok(())
    }

    async fn recv_data(&mut self) -> Result<Option<Vec<u8>>, TransportError> {
        // If nothing flushed yet, flush what we have (e.g., tail packets)
        if !self.buffer.is_empty() {
            self.flush_buffer().await?;
        }
        match self.rx.recv().await {
            Some(d) => Ok(Some(d)),
            None => Ok(None),
        }
    }

    fn peer_addr(&self) -> Result<SocketAddr, TransportError> {
        Ok(self.peer)
    }

    fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        Ok(self.peer)
    }

    async fn close(self: Box<Self>) -> Result<(), TransportError> {
        Ok(())
    }
}

#[tokio::test]
async fn reorder_only_delivers_all_packets() {
    let (mut a, mut b) = LossyConn::pair(None, 3, Duration::from_millis(1));
    let messages: Vec<_> = (0..5).map(|i| format!("msg-{i}").into_bytes()).collect();
    for m in &messages {
        a.send_data(m).await.unwrap();
    }
    drop(a);

    let mut received = Vec::new();
    while let Some(pkt) = b.recv_data().await.unwrap() {
        received.push(pkt);
        if received.len() == messages.len() {
            break;
        }
    }
    // Ordering may differ; compare sets
    let mut expected = messages;
    expected.sort();
    received.sort();
    assert_eq!(received, expected);
}

#[tokio::test]
async fn moderate_loss_still_runs_without_panic() {
    let (mut a, mut b) = LossyConn::pair(Some(3), 2, Duration::from_millis(0));
    let messages: Vec<_> = (0..10).map(|i| format!("pkt-{i}").into_bytes()).collect();
    for m in &messages {
        a.send_data(m).await.unwrap();
    }
    drop(a);

    let mut received = Vec::new();
    while let Some(pkt) = b.recv_data().await.unwrap() {
        received.push(pkt);
    }
    // With drop_every=3 we expect some loss; ensure at least some delivery
    assert!(
        !received.is_empty(),
        "all packets were dropped unexpectedly"
    );
    assert!(
        received.len() < messages.len(),
        "loss simulation did not drop any packets"
    );
}

#[tokio::test]
async fn psk_handshake_tolerates_reorder_no_loss() {
    let (mut server_conn, mut client_conn) = LossyConn::pair(None, 3, Duration::from_millis(1));
    let server = tokio::spawn(async move {
        psk_handshake_server_with_config(
            &mut server_conn,
            || parse_psk("YWFh"),
            &ServerAuthConfig::default(),
        )
        .await
    });

    let client = tokio::spawn(async move { psk_handshake_client(&mut client_conn, "YWFh").await });

    let sid = client
        .await
        .expect("client task panicked")
        .expect("client should succeed");
    let srv = server
        .await
        .expect("server task panicked")
        .expect("server should succeed");
    assert_eq!(sid, srv);
}

#[tokio::test]
async fn psk_handshake_fails_under_consistent_loss() {
    let (mut server_conn, mut client_conn) = LossyConn::pair(Some(2), 1, Duration::from_millis(0));
    let server = tokio::spawn(async move {
        psk_handshake_server_with_config(
            &mut server_conn,
            || parse_psk("YWFh"),
            &ServerAuthConfig::default(),
        )
        .await
    });

    let client = tokio::spawn(async move { psk_handshake_client(&mut client_conn, "YWFh").await });

    // Ensure the test never hangs under extreme loss; a timeout is considered an expected failure.
    tokio::select! {
        res = client => {
            let client_res = res.expect("client task panicked");
            assert!(
                client_res.is_err(),
                "handshake unexpectedly succeeded under loss"
            );
        }
        _ = tokio::time::sleep(Duration::from_secs(2)) => {
            server.abort();
            let _ = server.await;
            return;
        }
    }

    tokio::select! {
        res = server => {
            let server_res = res.expect("server task panicked");
            assert!(
                server_res.is_err(),
                "server unexpectedly succeeded under loss"
            );
        }
        _ = tokio::time::sleep(Duration::from_secs(2)) => {
            // Timeout is acceptable under heavy loss; abort to clean up.
            // This should not hang the test.
        }
    }
}
