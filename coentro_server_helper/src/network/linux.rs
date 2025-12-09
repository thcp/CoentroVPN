use super::{
    DnsRollback, InterfaceError, InterfaceManager, InterfaceResult, NatState, PolicyState,
    TunConfig, TunDescriptor,
};
use async_trait::async_trait;
use std::collections::HashMap;
use std::ffi::OsString;
use std::io::ErrorKind;
use std::os::fd::{FromRawFd, IntoRawFd, OwnedFd};
use tokio::fs;
use tokio::process::Command as TokioCommand;
use tokio::sync::Mutex as AsyncMutex;
use tracing::{debug, info, warn};
use tun::{Configuration, Layer};

use crate::ipc::messages::{DnsConfig, RouteSpec};

const SYSCTL_IPV4_FORWARD: &str = "/proc/sys/net/ipv4/ip_forward";
const SYSCTL_IPV6_FORWARD: &str = "/proc/sys/net/ipv6/conf/all/forwarding";
const MAX_AUTO_INDEX: usize = 64;

#[derive(Default)]
pub struct LinuxInterfaceManager {
    dns_state: AsyncMutex<HashMap<String, LinuxDnsState>>,
}

impl LinuxInterfaceManager {
    async fn interface_exists(&self, name: &str) -> InterfaceResult<bool> {
        let status = TokioCommand::new("ip")
            .args(["link", "show", "dev", name])
            .status()
            .await
            .map_err(InterfaceError::from)?;
        Ok(status.success())
    }

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

    async fn ensure_sysctl(path: &str) -> InterfaceResult<Option<String>> {
        match fs::read_to_string(path).await {
            Ok(existing) => {
                if existing.trim() == "1" {
                    return Ok(None);
                }
            }
            Err(err) if err.kind() == ErrorKind::NotFound => {
                return Ok(None);
            }
            Err(err) => return Err(InterfaceError::Io(err)),
        }

        fs::write(path, b"1\n").await?;
        Ok(Some(path.to_string()))
    }

    async fn configure_interface(&self, name: &str, config: &TunConfig) -> InterfaceResult<()> {
        let _ = self
            .run_command("ip", &["addr", "flush", "dev", name])
            .await;

        self.run_command("ip", &["addr", "add", &config.ipv4_cidr, "dev", name])
            .await?;

        self.run_command(
            "ip",
            &["link", "set", "dev", name, "mtu", &config.mtu.to_string()],
        )
        .await?;

        if config.bring_up {
            self.run_command("ip", &["link", "set", "dev", name, "up"])
                .await?;
        }

        Ok(())
    }

    async fn destroy_interface(&self, name: &str) -> InterfaceResult<()> {
        if !self.interface_exists(name).await? {
            return Ok(());
        }

        let _ = self
            .run_command("ip", &["link", "set", "dev", name, "down"])
            .await;
        let _ = self
            .run_command("ip", &["addr", "flush", "dev", name])
            .await;

        match self
            .run_command("ip", &["link", "delete", "dev", name])
            .await
        {
            Ok(_) => Ok(()),
            Err(err) => {
                warn!(
                    interface = name,
                    "failed to delete interface cleanly: {err}"
                );
                Ok(())
            }
        }
    }

    async fn cleanup_dir(prefix: &str) -> InterfaceResult<Vec<String>> {
        let mut removed = Vec::new();
        let mut dir = match fs::read_dir("/sys/class/net").await {
            Ok(dir) => dir,
            Err(err) => return Err(InterfaceError::Io(err)),
        };

        while let Some(entry) = dir.next_entry().await.map_err(InterfaceError::from)? {
            let name = entry.file_name();
            if let Some(name_str) = name.to_str() {
                if name_str.starts_with(prefix) {
                    removed.push(name_str.to_string());
                }
            }
        }

        Ok(removed)
    }

    async fn has_resolvectl() -> bool {
        TokioCommand::new("sh")
            .arg("-c")
            .arg("command -v resolvectl >/dev/null 2>&1")
            .status()
            .await
            .map(|s| s.success())
            .unwrap_or(false)
    }

    async fn iptables_rule_exists(&self, cidr: &str) -> InterfaceResult<bool> {
        let output = TokioCommand::new("iptables")
            .args([
                "-t",
                "nat",
                "-C",
                "POSTROUTING",
                "-s",
                cidr,
                "-j",
                "MASQUERADE",
            ])
            .output()
            .await
            .map_err(InterfaceError::Io)?;

        if output.status.success() {
            return Ok(true);
        }

        if output.status.code() == Some(1) {
            return Ok(false);
        }

        Err(InterfaceError::CommandFailure {
            command: format!("iptables -t nat -C POSTROUTING -s {cidr} -j MASQUERADE"),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        })
    }

    async fn run_iptables(&self, args: &[&str]) -> InterfaceResult<()> {
        let output = TokioCommand::new("iptables")
            .args(args)
            .output()
            .await
            .map_err(InterfaceError::Io)?;

        if output.status.success() {
            return Ok(());
        }

        Err(InterfaceError::CommandFailure {
            command: format!("iptables {:?}", args),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        })
    }

    async fn apply_routes(
        &self,
        interface: &str,
        routes: &[RouteSpec],
    ) -> InterfaceResult<Vec<RouteSpec>> {
        let mut applied = Vec::new();
        for route in routes {
            let mut args = vec![
                "route".to_string(),
                "replace".to_string(),
                route.cidr.clone(),
                "dev".to_string(),
                interface.to_string(),
            ];
            if let Some(gw) = route.via {
                args.push("via".into());
                args.push(gw.to_string());
            }
            if let Some(metric) = route.metric {
                args.push("metric".into());
                args.push(metric.to_string());
            }
            let refs = args.iter().map(|s| s.as_str()).collect::<Vec<_>>();
            match self.run_command("ip", &refs).await {
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
            let mut args = vec![
                "route".to_string(),
                "delete".to_string(),
                route.cidr.clone(),
                "dev".to_string(),
                interface.to_string(),
            ];
            if let Some(gw) = route.via {
                args.push("via".into());
                args.push(gw.to_string());
            }
            if let Some(metric) = route.metric {
                args.push("metric".into());
                args.push(metric.to_string());
            }
            let refs = args.iter().map(|s| s.as_str()).collect::<Vec<_>>();
            if let Err(err) = self.run_command("ip", &refs).await {
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
        let mut guard = self.dns_state.lock().await;
        if guard.contains_key(interface) {
            drop(guard);
            self.clear_dns(interface, None).await?;
            guard = self.dns_state.lock().await;
        }

        if config.servers.is_empty() && config.search_domains.is_empty() {
            return Ok(None);
        }

        if Self::has_resolvectl().await {
            let mut dns_args = vec!["dns".to_string(), interface.to_string()];
            dns_args.extend(config.servers.iter().map(|s| s.to_string()));
            if dns_args.len() == 2 {
                dns_args.push(String::from(""));
            }
            let dns_refs = dns_args.iter().map(|s| s.as_str()).collect::<Vec<_>>();
            self.run_command("resolvectl", &dns_refs).await?;

            if !config.search_domains.is_empty() {
                let mut domain_args = vec!["domain".to_string(), interface.to_string()];
                domain_args.extend(config.search_domains.iter().cloned());
                let domain_refs = domain_args.iter().map(|s| s.as_str()).collect::<Vec<_>>();
                self.run_command("resolvectl", &domain_refs).await?;
            }

            guard.insert(interface.to_string(), LinuxDnsState::Resolvectl);
            return Ok(Some(DnsRollback::LinuxResolvectl));
        }

        let original = fs::read_to_string("/etc/resolv.conf")
            .await
            .ok()
            .filter(|s| !s.is_empty());
        let original_clone = original.clone();

        let mut content = String::from("# Generated by CoentroVPN\n");
        for server in &config.servers {
            content.push_str(&format!("nameserver {}\n", server));
        }
        if !config.search_domains.is_empty() {
            content.push_str("search ");
            content.push_str(&config.search_domains.join(" "));
            content.push('\n');
        }

        fs::write("/etc/resolv.conf", content).await?;
        guard.insert(
            interface.to_string(),
            LinuxDnsState::ResolvConf {
                original: original_clone,
            },
        );
        Ok(Some(DnsRollback::LinuxResolvConf { original }))
    }

    async fn clear_dns(
        &self,
        interface: &str,
        record: Option<&DnsRollback>,
    ) -> InterfaceResult<()> {
        let mut guard = self.dns_state.lock().await;
        let state = guard.remove(interface);
        drop(guard);
        let source = record.cloned().or_else(|| match state {
            Some(LinuxDnsState::Resolvectl) => Some(DnsRollback::LinuxResolvectl),
            Some(LinuxDnsState::ResolvConf { original }) => {
                Some(DnsRollback::LinuxResolvConf { original })
            }
            None => None,
        });

        if let Some(state) = source {
            match state {
                DnsRollback::LinuxResolvectl => {
                    if let Err(err) = self.run_command("resolvectl", &["revert", interface]).await {
                        warn!(interface, "failed to revert dns via resolvectl: {err}");
                    }
                }
                DnsRollback::LinuxResolvConf { original } => {
                    if let Some(content) = original {
                        if let Err(err) = fs::write("/etc/resolv.conf", content).await {
                            warn!(interface, "failed to restore /etc/resolv.conf: {err}");
                        }
                    } else if let Err(err) =
                        fs::write("/etc/resolv.conf", "# Restored by CoentroVPN\n").await
                    {
                        warn!(interface, "failed to reset /etc/resolv.conf: {err}");
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }
}

#[async_trait]
impl InterfaceManager for LinuxInterfaceManager {
    async fn ensure_forwarding(&self) -> InterfaceResult<()> {
        let touched_ipv4 = Self::ensure_sysctl(SYSCTL_IPV4_FORWARD).await?;
        if let Some(path) = touched_ipv4 {
            info!(path, "enabled IPv4 forwarding");
        }

        let touched_ipv6 = Self::ensure_sysctl(SYSCTL_IPV6_FORWARD).await?;
        if let Some(path) = touched_ipv6 {
            info!(path, "enabled IPv6 forwarding");
        }

        Ok(())
    }

    async fn ensure_tun(&self, config: &TunConfig) -> InterfaceResult<TunDescriptor> {
        let name = self.choose_name(config).await?;

        self.destroy_interface(&name).await?;

        let mut tun_config = Configuration::default();
        tun_config.layer(Layer::L3);
        tun_config.mtu(config.mtu as i32);
        tun_config.up();
        tun_config.platform(|platform| {
            platform.packet_information(false);
        });
        tun_config.name(&name);

        let device = tun::create(&tun_config).map_err(|e| {
            InterfaceError::Platform(format!("failed to create TUN device {name}: {e}"))
        })?;

        let fd = unsafe { OwnedFd::from_raw_fd(device.into_raw_fd()) };
        self.configure_interface(&name, config).await?;

        Ok(TunDescriptor {
            name,
            fd,
            mtu: config.mtu,
            ipv4_cidr: config.ipv4_cidr.clone(),
            sysctl_touched: None,
        })
    }

    async fn teardown_tun(&self, name: &str) -> InterfaceResult<()> {
        self.destroy_interface(name).await
    }

    async fn cleanup_stale_interfaces(&self, prefix: &str) -> InterfaceResult<()> {
        let candidates = Self::cleanup_dir(prefix).await?;
        for iface in candidates {
            self.destroy_interface(&iface).await?;
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
            if let Err(err) = self.clear_dns(interface, Some(dns_state)).await {
                warn!(interface, "failed to revert DNS: {err}");
                first_err.get_or_insert(err);
            }
        } else if let Err(err) = self.clear_dns(interface, None).await {
            warn!(interface, "failed to clear DNS state: {err}");
            first_err.get_or_insert(err);
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

    async fn apply_nat(&self, _interface: &str, cidr: &str) -> InterfaceResult<Option<NatState>> {
        if self.iptables_rule_exists(cidr).await? {
            return Ok(None);
        }

        self.run_iptables(&[
            "-t",
            "nat",
            "-A",
            "POSTROUTING",
            "-s",
            cidr,
            "-j",
            "MASQUERADE",
        ])
        .await?;

        Ok(Some(NatState::LinuxMasquerade {
            cidr: cidr.to_string(),
        }))
    }

    async fn rollback_nat(&self, _interface: &str, state: &NatState) -> InterfaceResult<()> {
        match state {
            NatState::LinuxMasquerade { cidr } => {
                if let Err(err) = self
                    .run_iptables(&[
                        "-t",
                        "nat",
                        "-D",
                        "POSTROUTING",
                        "-s",
                        cidr,
                        "-j",
                        "MASQUERADE",
                    ])
                    .await
                {
                    warn!(%cidr, "failed to remove MASQUERADE rule: {err}");
                    return Err(err);
                }
            }
        }
        Ok(())
    }
}

impl From<std::ffi::OsString> for InterfaceError {
    fn from(value: OsString) -> Self {
        InterfaceError::Platform(format!("invalid unicode: {:?}", value))
    }
}

enum LinuxDnsState {
    Resolvectl,
    ResolvConf { original: Option<String> },
}
