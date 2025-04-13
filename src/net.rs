use crate::config::Config; // Use the Config type from your project
use std::net::SocketAddr;

pub const IP_HEADER_SIZE: usize = 20;
pub const UDP_HEADER_SIZE: usize = 8;
pub const ENCRYPTION_OVERHEAD: usize = 32; // Adjust if protocol overhead changes

/// Calculates the maximum safe UDP payload size for given MTU
pub fn calculate_max_payload_size(mtu: usize) -> usize {
    mtu.saturating_sub(IP_HEADER_SIZE + UDP_HEADER_SIZE + ENCRYPTION_OVERHEAD)
}

pub fn discover_mtu(config: &Config) -> usize {
    if config.udp.enable_mtu_discovery {
        // Perform dynamic MTU discovery logic here
        // For simplicity, return a discovered MTU (e.g., 1400 bytes)
        1400
    } else {
        // Use the static MTU value from the configuration
        config.udp.mtu.unwrap_or(1500)
    }
}

/// Linux-specific implementation for MTU probing.
#[allow(unused_variables)]
pub fn discover_path_mtu(configured_mtu: usize, target: SocketAddr, enable: bool) -> usize {
    if !enable {
        return configured_mtu;
    }

    // Linux only for now
    #[cfg(target_os = "linux")]
    {
        use nix::libc::{setsockopt, IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DO};
        use socket2::{Domain, Protocol, Socket, Type};
        use std::io;
        use std::net::UdpSocket;
        use std::os::unix::io::AsRawFd;

        const PROBE_SIZE: usize = 1472; // Typical MTU (1500 - IP/UDP header)

        let sock = match Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)) {
            Ok(s) => s,
            Err(_) => return configured_mtu,
        };

        let std_sock: UdpSocket = sock.into();
        if std_sock.set_nonblocking(true).is_err() {
            return configured_mtu;
        }

        let fd = std_sock.as_raw_fd();
        unsafe {
            let val: i32 = IP_PMTUDISC_DO;
            if setsockopt(
                fd,
                IPPROTO_IP,
                IP_MTU_DISCOVER,
                &val as *const _ as *const _,
                std::mem::size_of_val(&val) as u32,
            ) != 0
            {
                return configured_mtu;
            }
        }

        let buf = vec![0u8; PROBE_SIZE];
        match std_sock.send_to(&buf, target) {
            Ok(_) => {
                log::info!("Discovered MTU: {}", PROBE_SIZE);
                PROBE_SIZE
            }
            Err(e) => {
                if e.kind() == io::ErrorKind::Other {
                    log::warn!("MTU probe failed, falling back: {}", e);
                    log::info!("Using fallback MTU: {}", configured_mtu.saturating_sub(100));
                    return configured_mtu.saturating_sub(100);
                }
                configured_mtu
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        log::info!("MTU discovery not implemented on this OS.");
        configured_mtu
    }
}
