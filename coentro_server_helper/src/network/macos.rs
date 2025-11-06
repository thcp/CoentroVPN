use super::{
    DnsRollback, InterfaceError, InterfaceManager, InterfaceResult, PolicyState, TunConfig,
    TunDescriptor,
};
use crate::ipc::messages::{DnsConfig, RouteSpec};
use async_trait::async_trait;
use libc::c_void;
use std::ffi::{CStr, CString};
use std::mem;
use std::net::Ipv4Addr;
use std::os::fd::{FromRawFd, OwnedFd};
use tokio::process::Command as TokioCommand;
use tracing::{debug, info, warn};

const UTUN_CONTROL_NAME: &str = "com.apple.net.utun_control";
const SYSCTL_FORWARDING_KEY: &str = "net.inet.ip.forwarding";
const MAX_AUTO_INDEX: usize = 64;

#[derive(Default)]
pub struct MacOsInterfaceManager;

impl MacOsInterfaceManager {
    async fn run_command(&self, command: &str, args: &[&str]) -> InterfaceResult<String> {
        debug!(cmd = command, ?args, "running network command");
        let output = TokioCommand::new(command)
            .args(args)
            .output()
            .await
            .map_err(InterfaceError::from)?;
        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
        } else {
            Err(InterfaceError::CommandFailure {
                command: format!("{} {:?}", command, args),
                stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
            })
        }
    }

    async fn interface_exists(&self, name: &str) -> InterfaceResult<bool> {
        let status = TokioCommand::new("ifconfig")
            .arg(name)
            .status()
            .await
            .map_err(InterfaceError::from)?;
        Ok(status.success())
    }

    async fn choose_name(&self, config: &TunConfig) -> InterfaceResult<String> {
        if let Some(hint) = &config.name_hint {
            return Ok(hint.clone());
        }

        for idx in 0..MAX_AUTO_INDEX {
            let candidate = format!("coentrovpn-{}{}", config.name_prefix, idx);
            if !self.interface_exists(&candidate).await? {
                return Ok(candidate);
            }
        }

        Err(InterfaceError::Platform(format!(
            "Unable to allocate interface name with prefix {}",
            config.name_prefix
        )))
    }

    fn open_utun(&self) -> InterfaceResult<(OwnedFd, String)> {
        unsafe {
            let fd = libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL);
            if fd < 0 {
                return Err(InterfaceError::Platform(format!(
                    "utun socket creation failed: {}",
                    std::io::Error::last_os_error()
                )));
            }

            let mut info: libc::ctl_info = mem::zeroed();
            let name_c = CString::new(UTUN_CONTROL_NAME).unwrap();
            let src = name_c.as_bytes_with_nul();
            let dst = info.ctl_name.as_mut_ptr() as *mut u8;
            ptr_copy(src, dst, info.ctl_name.len());

            if libc::ioctl(fd, libc::CTLIOCGINFO, &mut info) < 0 {
                let err = std::io::Error::last_os_error();
                libc::close(fd);
                return Err(InterfaceError::Platform(format!(
                    "utun ioctl CTLIOCGINFO failed: {}",
                    err
                )));
            }

            let mut addr: libc::sockaddr_ctl = mem::zeroed();
            addr.sc_len = mem::size_of::<libc::sockaddr_ctl>() as u8;
            addr.sc_family = libc::AF_SYSTEM as u8;
            addr.ss_sysaddr = libc::AF_SYSTEM as u16;
            addr.sc_id = info.ctl_id;
            addr.sc_unit = 0;

            let ret = libc::connect(
                fd,
                &addr as *const _ as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_ctl>() as libc::socklen_t,
            );
            if ret < 0 {
                let err = std::io::Error::last_os_error();
                libc::close(fd);
                return Err(InterfaceError::Platform(format!(
                    "utun connect failed: {}",
                    err
                )));
            }

            let mut ifname = [0u8; libc::IFNAMSIZ];
            let mut ifname_len = ifname.len() as libc::socklen_t;
            let gso = libc::getsockopt(
                fd,
                libc::SYSPROTO_CONTROL,
                2, // UTUN_OPT_IFNAME
                ifname.as_mut_ptr() as *mut c_void,
                &mut ifname_len,
            );
            if gso < 0 {
                let err = std::io::Error::last_os_error();
                libc::close(fd);
                return Err(InterfaceError::Platform(format!(
                    "utun getsockopt(UTUN_OPT_IFNAME) failed: {}",
                    err
                )));
            }

            let name_cstr = CStr::from_ptr(ifname.as_ptr() as *const libc::c_char);
            let native_name = name_cstr.to_string_lossy().into_owned();
            info!(native = %native_name, fd, "created utun device");

            Ok((OwnedFd::from_raw_fd(fd), native_name))
        }
    }

    async fn rename_interface(&self, current: &str, desired: &str) -> InterfaceResult<String> {
        if current == desired {
            return Ok(desired.to_string());
        }

        match self
            .run_command("ifconfig", &[current, "name", desired])
            .await
        {
            Ok(_) => {
                info!(old = current, new = desired, "renamed utun interface");
                Ok(desired.to_string())
            }
            Err(err) => {
                warn!(old = current, "failed to rename interface: {err}");
                Ok(current.to_string())
            }
        }
    }

    async fn configure_interface(&self, name: &str, config: &TunConfig) -> InterfaceResult<()> {
        let (ip, prefix) = parse_ipv4_cidr(&config.ipv4_cidr)?;
        let netmask = prefix_len_to_netmask(prefix)?;
        let peer = derive_peer(ip);

        self.run_command(
            "ifconfig",
            &[
                name,
                "inet",
                &ip.to_string(),
                &peer.to_string(),
                "netmask",
                &netmask,
            ],
        )
        .await?;

        self.run_command("ifconfig", &[name, "mtu", &config.mtu.to_string()])
            .await?;

        if config.bring_up {
            self.run_command("ifconfig", &[name, "up"]).await?;
        }

        Ok(())
    }

    async fn sysctl_value(&self, key: &str) -> InterfaceResult<String> {
        self.run_command("sysctl", &["-n", key]).await
    }

    async fn sysctl_set(&self, key: &str, value: &str) -> InterfaceResult<()> {
        self.run_command("sysctl", &["-w", &format!("{}={}", key, value)])
            .await
            .map(|_| ())
    }

    async fn teardown_inner(&self, name: &str) -> InterfaceResult<()> {
        if !self.interface_exists(name).await? {
            return Ok(());
        }

        let _ = self
            .run_command("ifconfig", &[name, "-alias", "0.0.0.0"])
            .await;
        let _ = self.run_command("ifconfig", &[name, "down"]).await;
        Ok(())
    }

    async fn cleanup_matching(&self, prefix: &str) -> InterfaceResult<Vec<String>> {
        let listing = self.run_command("ifconfig", &["-l"]).await?;
        let mut matches = Vec::new();
        for token in listing.split_whitespace() {
            if token.starts_with(prefix) {
                matches.push(token.to_string());
            }
        }
        Ok(matches)
    }

    async fn run_networksetup(&self, args: &[&str]) -> InterfaceResult<String> {
        self.run_command("/usr/sbin/networksetup", args).await
    }

    async fn route_command(&self, args: &[&str]) -> InterfaceResult<String> {
        self.run_command("/usr/sbin/route", args).await
    }

    async fn find_service_for_interface(&self, interface: &str) -> InterfaceResult<String> {
        let output = self.run_networksetup(&["-listallhardwareports"]).await?;

        let mut current_port: Option<String> = None;
        for line in output.lines() {
            let trimmed = line.trim();
            if let Some(port) = trimmed.strip_prefix("Hardware Port: ") {
                current_port = Some(port.trim().to_string());
            } else if let Some(device) = trimmed.strip_prefix("Device: ") {
                if device.trim() == interface {
                    if let Some(port) = current_port.clone() {
                        return Ok(port);
                    }
                }
            }
        }

        // Fallback: default to first listed network service
        let listing = self.run_networksetup(&["-listnetworkservices"]).await?;
        for line in listing.lines() {
            let name = line.trim();
            if name.is_empty() || name.starts_with("An asterisk (") {
                continue;
            }
            return Ok(name.to_string());
        }

        Err(InterfaceError::Platform(format!(
            "unable to determine network service for interface {}",
            interface
        )))
    }

    async fn get_dns_servers(&self, service: &str) -> InterfaceResult<Vec<String>> {
        let output = self.run_networksetup(&["-getdnsservers", service]).await?;
        if output.contains("There aren't any DNS Servers set") {
            return Ok(Vec::new());
        }
        Ok(output
            .lines()
            .filter_map(|line| {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed.to_string())
                }
            })
            .collect())
    }

    async fn get_search_domains(&self, service: &str) -> InterfaceResult<Vec<String>> {
        let output = self
            .run_networksetup(&["-getsearchdomains", service])
            .await?;
        if output.contains("There aren't any Search Domains set") {
            return Ok(Vec::new());
        }
        Ok(output
            .lines()
            .filter_map(|line| {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed.to_string())
                }
            })
            .collect())
    }

    async fn set_dns_servers(&self, service: &str, servers: &[String]) -> InterfaceResult<()> {
        let mut args: Vec<String> = vec!["-setdnsservers".into(), service.to_string()];
        if servers.is_empty() {
            args.push("Empty".to_string());
        } else {
            args.extend(servers.iter().cloned());
        }
        let refs = args.iter().map(|s| s.as_str()).collect::<Vec<_>>();
        self.run_networksetup(&refs).await.map(|_| ())
    }

    async fn set_search_domains(&self, service: &str, domains: &[String]) -> InterfaceResult<()> {
        let mut args: Vec<String> = vec!["-setsearchdomains".into(), service.to_string()];
        if domains.is_empty() {
            args.push("Empty".to_string());
        } else {
            args.extend(domains.iter().cloned());
        }
        let refs = args.iter().map(|s| s.as_str()).collect::<Vec<_>>();
        self.run_networksetup(&refs).await.map(|_| ())
    }

    fn compute_network_and_mask(cidr: &str) -> InterfaceResult<(Ipv4Addr, Ipv4Addr)> {
        let (ip, prefix) = parse_ipv4_cidr(cidr)?;
        let mask_str = prefix_len_to_netmask(prefix)?;
        let mask = mask_str.parse::<Ipv4Addr>().map_err(|e| {
            InterfaceError::InvalidConfig(format!(
                "invalid netmask {} for {}: {}",
                mask_str, cidr, e
            ))
        })?;
        let network = Ipv4Addr::from(u32::from(ip) & u32::from(mask));
        Ok((network, mask))
    }
}

#[async_trait]
impl InterfaceManager for MacOsInterfaceManager {
    async fn ensure_forwarding(&self) -> InterfaceResult<()> {
        let value = self.sysctl_value(SYSCTL_FORWARDING_KEY).await?;
        if value.trim() != "1" {
            self.sysctl_set(SYSCTL_FORWARDING_KEY, "1").await?;
            info!(key = SYSCTL_FORWARDING_KEY, "enabled IPv4 forwarding");
        }
        Ok(())
    }

    async fn ensure_tun(&self, config: &TunConfig) -> InterfaceResult<TunDescriptor> {
        let target_name = self.choose_name(config).await?;
        self.teardown_inner(&target_name).await?;

        let (fd_owned, native_name) = self.open_utun()?;

        let active_name = self.rename_interface(&native_name, &target_name).await?;
        self.configure_interface(&active_name, config).await?;

        Ok(TunDescriptor {
            name: active_name,
            fd: fd_owned,
            mtu: config.mtu,
            ipv4_cidr: config.ipv4_cidr.clone(),
            sysctl_touched: None,
        })
    }

    async fn teardown_tun(&self, name: &str) -> InterfaceResult<()> {
        self.teardown_inner(name).await
    }

    async fn cleanup_stale_interfaces(&self, prefix: &str) -> InterfaceResult<()> {
        let matches = self.cleanup_matching(prefix).await.unwrap_or_default();
        for iface in matches {
            self.teardown_inner(&iface).await?;
        }
        Ok(())
    }

    async fn apply_policy(
        &self,
        interface: &str,
        routes: &[RouteSpec],
        dns: Option<&DnsConfig>,
    ) -> InterfaceResult<PolicyState> {
        let mut state = PolicyState::default();

        if !routes.is_empty() {
            state.routes = self.apply_routes(interface, routes).await?;
        }

        if let Some(cfg) = dns {
            match self.apply_dns(interface, cfg).await {
                Ok(dns_state) => {
                    state.dns = dns_state;
                }
                Err(err) => {
                    if !state.routes.is_empty() {
                        let _ = self.remove_routes(interface, &state.routes).await;
                    }
                    return Err(err);
                }
            }
        }

        Ok(state)
    }

    async fn rollback_policy(&self, interface: &str, state: &PolicyState) -> InterfaceResult<()> {
        let mut first_err: Option<InterfaceError> = None;

        if let Some(dns_state) = state.dns.as_ref() {
            if let Err(err) = self.restore_dns(dns_state).await {
                warn!(interface, "failed to restore DNS: {err}");
                first_err.get_or_insert(err);
            }
        }

        if let Err(err) = self.remove_routes(interface, &state.routes).await {
            warn!(interface, "failed to remove routes: {err}");
            first_err.get_or_insert(err);
        }

        if let Some(err) = first_err {
            Err(err)
        } else {
            Ok(())
        }
    }
}

impl MacOsInterfaceManager {
    async fn apply_routes(
        &self,
        interface: &str,
        routes: &[RouteSpec],
    ) -> InterfaceResult<Vec<RouteSpec>> {
        let mut applied = Vec::new();
        for route in routes {
            let (network, mask) = Self::compute_network_and_mask(&route.cidr)?;
            let mut args = vec![
                "-n".to_string(),
                "add".to_string(),
                "-net".to_string(),
                network.to_string(),
                "-netmask".to_string(),
                mask.to_string(),
            ];
            if let Some(gw) = route.via {
                args.push(gw.to_string());
                args.push("-ifscope".to_string());
                args.push(interface.to_string());
            } else {
                args.push("-interface".to_string());
                args.push(interface.to_string());
            }
            let refs = args.iter().map(|s| s.as_str()).collect::<Vec<_>>();
            match self.route_command(&refs).await {
                Ok(_) => applied.push(route.clone()),
                Err(err) => {
                    warn!(
                        interface,
                        route = %route.cidr,
                        "failed to apply route: {err}"
                    );
                }
            }
        }
        Ok(applied)
    }

    async fn remove_routes(&self, interface: &str, routes: &[RouteSpec]) -> InterfaceResult<()> {
        for route in routes {
            let (network, mask) = Self::compute_network_and_mask(&route.cidr)?;
            let mut args = vec![
                "-n".to_string(),
                "delete".to_string(),
                "-net".to_string(),
                network.to_string(),
                "-netmask".to_string(),
                mask.to_string(),
            ];
            if let Some(gw) = route.via {
                args.push(gw.to_string());
                args.push("-ifscope".to_string());
                args.push(interface.to_string());
            } else {
                args.push("-interface".to_string());
                args.push(interface.to_string());
            }
            let refs = args.iter().map(|s| s.as_str()).collect::<Vec<_>>();
            if let Err(err) = self.route_command(&refs).await {
                warn!(interface, route = %route.cidr, "failed to remove route: {err}");
            }
        }
        Ok(())
    }

    async fn apply_dns(
        &self,
        interface: &str,
        config: &DnsConfig,
    ) -> InterfaceResult<Option<DnsRollback>> {
        if config.servers.is_empty() && config.search_domains.is_empty() {
            return Ok(None);
        }

        let service = self.find_service_for_interface(interface).await?;
        let original_servers = self.get_dns_servers(&service).await?;
        let original_search = self.get_search_domains(&service).await?;

        let servers: Vec<String> = config.servers.iter().map(|ip| ip.to_string()).collect();
        self.set_dns_servers(&service, &servers).await?;
        self.set_search_domains(&service, &config.search_domains)
            .await?;

        Ok(Some(DnsRollback::Macos {
            service,
            servers: original_servers,
            search_domains: original_search,
        }))
    }

    async fn restore_dns(&self, record: &DnsRollback) -> InterfaceResult<()> {
        match record {
            DnsRollback::Macos {
                service,
                servers,
                search_domains,
            } => {
                self.set_dns_servers(service, servers).await?;
                self.set_search_domains(service, search_domains).await?;
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

fn prefix_len_to_netmask(prefix: u32) -> InterfaceResult<String> {
    if prefix > 32 {
        return Err(InterfaceError::InvalidConfig(format!(
            "invalid prefix length {}",
            prefix
        )));
    }
    let mask = if prefix == 0 {
        0
    } else {
        (!0u32).checked_shl(32 - prefix).unwrap_or(!0)
    };
    Ok(Ipv4Addr::from(mask).to_string())
}

fn derive_peer(address: Ipv4Addr) -> Ipv4Addr {
    let octets = address.octets();
    let mut last = octets[3];
    last = if last == 255 {
        last.saturating_sub(1)
    } else {
        last.saturating_add(1)
    };
    Ipv4Addr::new(octets[0], octets[1], octets[2], last)
}

fn parse_ipv4_cidr(cidr: &str) -> InterfaceResult<(Ipv4Addr, u32)> {
    let mut parts = cidr.split('/');
    let ip_part = parts
        .next()
        .ok_or_else(|| InterfaceError::InvalidConfig(format!("invalid CIDR: {}", cidr)))?;
    let prefix_str = parts
        .next()
        .ok_or_else(|| InterfaceError::InvalidConfig(format!("invalid CIDR: {}", cidr)))?;

    let ip = ip_part.parse::<Ipv4Addr>().map_err(|e| {
        InterfaceError::InvalidConfig(format!("invalid IPv4 address {}: {}", ip_part, e))
    })?;
    let prefix = prefix_str.parse::<u32>().map_err(|e| {
        InterfaceError::InvalidConfig(format!("invalid prefix length {}: {}", prefix_str, e))
    })?;

    Ok((ip, prefix))
}

unsafe fn ptr_copy(src: &[u8], dst: *mut u8, dst_len: usize) {
    let len = std::cmp::min(src.len(), dst_len);
    std::ptr::copy_nonoverlapping(src.as_ptr(), dst, len);
}
