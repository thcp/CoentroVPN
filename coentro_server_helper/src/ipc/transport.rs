use crate::ipc::messages::{AuthenticatedRequest, ServerRequest, ServerResponse};
use anyhow::{anyhow, bail, Context, Result};
use bincode::Options;
use nix::sys::socket::{recvmsg, sendmsg, ControlMessage, ControlMessageOwned, MsgFlags};
use std::io::{IoSlice, IoSliceMut};
use std::os::unix::io::{AsRawFd, RawFd};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

const MESSAGE_LEN_LIMIT: usize = 16 * 1024; // 16 KB

pub(crate) fn message_bincode_config() -> impl Options {
    bincode::options()
        .with_limit(MESSAGE_LEN_LIMIT as u64)
        .with_fixint_encoding()
}

/// Send a request over the IPC channel. When the request is `AttachQuic`, the
/// caller must provide a file descriptor that will be delivered via SCM_RIGHTS.
pub async fn send_request(
    stream: &mut UnixStream,
    envelope: &AuthenticatedRequest,
    fd: Option<RawFd>,
) -> Result<()> {
    if matches!(envelope.request, ServerRequest::AttachQuic(_)) && fd.is_none() {
        bail!("AttachQuic request requires a QUIC transport file descriptor");
    }
    if !matches!(envelope.request, ServerRequest::AttachQuic(_)) && fd.is_some() {
        bail!("Only AttachQuic requests may include a file descriptor");
    }

    let payload = message_bincode_config().serialize(envelope)?;
    write_length_prefixed(stream, &payload).await?;

    if let Some(raw_fd) = fd {
        send_fd(stream, raw_fd)?;
    }

    Ok(())
}

/// Receive the next request from the IPC channel, returning the payload and an
/// optional SCM_RIGHTS descriptor when present.
pub async fn receive_request(
    stream: &mut UnixStream,
) -> Result<(AuthenticatedRequest, Option<RawFd>)> {
    let payload = read_length_prefixed(stream).await?;
    let envelope: AuthenticatedRequest = message_bincode_config().deserialize(&payload)?;

    let fd = if matches!(envelope.request, ServerRequest::AttachQuic(_)) {
        Some(recv_fd(stream)?)
    } else {
        None
    };

    Ok((envelope, fd))
}

/// Send a response payload to the peer.
pub async fn send_response(stream: &mut UnixStream, response: &ServerResponse) -> Result<()> {
    let payload = message_bincode_config().serialize(response)?;
    write_length_prefixed(stream, &payload).await?;
    Ok(())
}

/// Receive a response payload from the peer.
pub async fn receive_response(stream: &mut UnixStream) -> Result<ServerResponse> {
    let payload = read_length_prefixed(stream).await?;
    let response = message_bincode_config().deserialize(&payload)?;
    Ok(response)
}

async fn write_length_prefixed(stream: &mut UnixStream, payload: &[u8]) -> Result<()> {
    if payload.len() > MESSAGE_LEN_LIMIT {
        bail!(
            "Attempted to send IPC payload larger than limit ({} bytes)",
            payload.len()
        );
    }

    let length = (payload.len() as u32).to_le_bytes();
    stream.write_all(&length).await?;
    stream.write_all(payload).await?;
    stream.flush().await?;
    Ok(())
}

async fn read_length_prefixed(stream: &mut UnixStream) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .context("Failed to read IPC length prefix")?;

    let len = u32::from_le_bytes(len_buf) as usize;
    if len > MESSAGE_LEN_LIMIT {
        bail!("Received IPC payload exceeding limit ({} bytes)", len);
    }

    let mut buf = vec![0u8; len];
    stream
        .read_exact(&mut buf)
        .await
        .context("Failed to read IPC payload body")?;
    Ok(buf)
}

fn send_fd(stream: &UnixStream, fd: RawFd) -> Result<()> {
    if fd < 0 {
        bail!("Invalid file descriptor: {}", fd);
    }

    let sock_fd = stream.as_raw_fd();
    let dummy = [0u8; 1];
    let iov = [IoSlice::new(&dummy)];
    let fd_array = [fd];

    sendmsg::<()>(
        sock_fd,
        &iov,
        &[ControlMessage::ScmRights(&fd_array)],
        MsgFlags::empty(),
        None,
    )
    .context("Failed to send SCM_RIGHTS payload")?;

    Ok(())
}

fn recv_fd(stream: &UnixStream) -> Result<RawFd> {
    let sock_fd = stream.as_raw_fd();
    let mut buf = [0u8; 1];
    let mut cmsg_buffer = vec![0u8; 64];
    let mut iov = [IoSliceMut::new(&mut buf)];

    let msg = recvmsg::<()>(sock_fd, &mut iov, Some(&mut cmsg_buffer), MsgFlags::empty())
        .context("Failed to receive SCM_RIGHTS payload")?;

    for cmsg in msg.cmsgs() {
        if let ControlMessageOwned::ScmRights(fds) = cmsg {
            if let Some(fd) = fds.first() {
                if *fd < 0 {
                    bail!("Received invalid file descriptor: {}", fd);
                }
                return Ok(*fd);
            }
        }
    }

    Err(anyhow!(
        "AttachQuic request missing SCM_RIGHTS descriptor from peer"
    ))
}
