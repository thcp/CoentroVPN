use anyhow::{Result, anyhow};
use shared_utils::transport::Connection;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

const PIPE_CAPACITY: usize = 64;

pub struct BridgeHandle {
    flow_id: String,
    join: JoinHandle<Result<()>>,
}

impl BridgeHandle {
    pub async fn wait(self) -> Result<()> {
        let flow = self.flow_id;
        match self.join.await {
            Ok(res) => res.map_err(|e| anyhow!("flow {flow}: {e}")),
            Err(err) => Err(anyhow!("flow {flow} bridge task join error: {err}")),
        }
    }
}

pub fn spawn_quic_helper_bridge(
    flow_id: String,
    connection: Box<dyn Connection + Send + Sync>,
    stream: UnixStream,
) -> BridgeHandle {
    let join = tokio::spawn(run_bridge(flow_id.clone(), connection, stream));
    BridgeHandle { flow_id, join }
}

async fn run_bridge(
    flow_id: String,
    connection: Box<dyn Connection + Send + Sync>,
    stream: UnixStream,
) -> Result<()> {
    let connection = Arc::new(Mutex::new(connection));
    let (mut helper_reader, mut helper_writer) = stream.into_split();

    let (h2q_tx, mut h2q_rx) = mpsc::channel::<Vec<u8>>(PIPE_CAPACITY);
    let (q2h_tx, mut q2h_rx) = mpsc::channel::<Vec<u8>>(PIPE_CAPACITY);

    let helper_reader_task = {
        let flow = flow_id.clone();
        let h2q_tx = h2q_tx.clone();
        tokio::spawn(async move {
            loop {
                let mut len_buf = [0u8; 2];
                match helper_reader.read_exact(&mut len_buf).await {
                    Ok(_) => {}
                    Err(e) => {
                        info!(flow = %flow, "helper stream closed/read error: {e}");
                        break;
                    }
                }
                let packet_len = u16::from_be_bytes(len_buf) as usize;
                if packet_len == 0 {
                    continue;
                }
                let mut packet = vec![0u8; packet_len];
                if let Err(e) = helper_reader.read_exact(&mut packet).await {
                    warn!(flow = %flow, "helper payload read error: {e}");
                    break;
                }
                if h2q_tx.send(packet).await.is_err() {
                    break;
                }
            }
            drop(h2q_tx);
            Ok::<(), anyhow::Error>(())
        })
    };

    let quic_writer_task = {
        let flow = flow_id.clone();
        let connection = Arc::clone(&connection);
        tokio::spawn(async move {
            while let Some(packet) = h2q_rx.recv().await {
                let mut conn = connection.lock().await;
                if let Err(e) = conn
                    .send_data(&packet)
                    .await
                    .map_err(|e| anyhow!("send_data failed: {e}"))
                {
                    warn!(flow = %flow, "send_data error: {e}");
                    return Err(e);
                }
            }
            Ok::<(), anyhow::Error>(())
        })
    };

    let quic_reader_task = {
        let flow = flow_id.clone();
        let connection = Arc::clone(&connection);
        let q2h_tx = q2h_tx.clone();
        tokio::spawn(async move {
            loop {
                let packet = {
                    let mut conn = connection.lock().await;
                    conn.recv_data()
                        .await
                        .map_err(|e| anyhow!("recv_data failed: {e}"))?
                };
                match packet {
                    Some(data) => {
                        if q2h_tx.send(data).await.is_err() {
                            break;
                        }
                    }
                    None => {
                        debug!(flow = %flow, "QUIC stream closed by peer");
                        break;
                    }
                }
            }
            drop(q2h_tx);
            Ok::<(), anyhow::Error>(())
        })
    };

    let helper_writer_task = {
        let flow = flow_id.clone();
        tokio::spawn(async move {
            while let Some(packet) = q2h_rx.recv().await {
                if packet.len() > u16::MAX as usize {
                    warn!(flow = %flow, len = packet.len(), "dropping oversized packet");
                    continue;
                }
                let len_bytes = (packet.len() as u16).to_be_bytes();
                helper_writer
                    .write_all(&len_bytes)
                    .await
                    .map_err(|e| anyhow!("helper write len failed: {e}"))?;
                helper_writer
                    .write_all(&packet)
                    .await
                    .map_err(|e| anyhow!("helper write payload failed: {e}"))?;
            }
            Ok::<(), anyhow::Error>(())
        })
    };

    drop(h2q_tx);
    drop(q2h_tx);

    let mut first_err: Option<anyhow::Error> = None;

    for task in [
        helper_reader_task,
        quic_writer_task,
        quic_reader_task,
        helper_writer_task,
    ] {
        match task.await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                first_err.get_or_insert(err);
            }
            Err(join_err) => {
                first_err.get_or_insert(anyhow!("bridge subtask join error: {join_err}"));
            }
        }
    }

    if let Some(err) = first_err {
        Err(err)
    } else {
        Ok(())
    }
}
