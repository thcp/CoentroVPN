//! macOS Network Manager Implementation
//!
//! This module provides the macOS-specific implementation of the NetworkManager trait.
//! It handles TUN interface creation, routing table modifications, and DNS configuration.

use super::{NetworkError, NetworkManager, NetworkResult, TunConfig, TunDetails};
use async_trait::async_trait;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{Read, Write};
use std::mem;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::process::Command;
use std::ptr;
use tokio::process::Command as TokioCommand;
use tracing::{debug, error, info, warn};

/// macOS Network Manager
#[derive(Debug)]
pub struct MacOsNetworkManager {
    /// Original DNS configuration (for restoration)
    original_dns: Option<Vec<String>>,
    /// Path to the resolv.conf file
    resolv_conf_path: String,
    /// Network Service name whose DNS we modified (for restore)
    dns_service_name: Option<String>,
}

impl MacOsNetworkManager {
    /// Create a new macOS Network Manager
    pub fn new() -> Self {
        Self {
            original_dns: None,
            resolv_conf_path: "/etc/resolv.conf".to_string(),
            dns_service_name: None,
        }
    }

    /// Run a system command and return the output
    async fn run_command(command: &str, args: &[&str], error_msg: &str) -> NetworkResult<String> {
        debug!("Running command: {} {:?}", command, args);

        let output = TokioCommand::new(command)
            .args(args)
            .output()
            .await
            .map_err(|e| NetworkError::SystemCommand(format!("{}: {}", error_msg, e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(NetworkError::SystemCommand(format!(
                "{}: {} (exit code: {:?})",
                error_msg,
                stderr.trim(),
                output.status.code()
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(stdout.trim().to_string())
    }

    /// Open a new utun device and return its file descriptor and name.
    ///
    /// Uses PF_SYSTEM/SYSPROTO_CONTROL to create a fresh `utunX` device.
    fn open_tun_device(&self) -> NetworkResult<(File, String)> {
        // Constants not exposed in libc on all versions
        const AF_SYS_CONTROL: libc::c_uchar = 2; // AF_SYS_CONTROL
        const UTUN_OPT_IFNAME: libc::c_int = 2; // getsockopt option to fetch interface name
        const UTUN_CONTROL_NAME: &str = "com.apple.net.utun_control";

        unsafe {
            // Create control socket
            let fd = libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL);
            if fd < 0 {
                let e = std::io::Error::last_os_error();
                error!(
                    "utun: socket(PF_SYSTEM,SOCK_DGRAM,SYSPROTO_CONTROL) failed: {}",
                    e
                );
                return Err(NetworkError::TunDevice(format!(
                    "Failed to create control socket: {}",
                    e
                )));
            }

            // Resolve control id for utun
            let mut info: libc::ctl_info = mem::zeroed();
            let name_c = CString::new(UTUN_CONTROL_NAME).unwrap();
            // Copy name into ctl_name (bounded)
            let src = name_c.as_bytes_with_nul();
            let dst = info.ctl_name.as_mut_ptr() as *mut u8;
            ptr::copy_nonoverlapping(src.as_ptr(), dst, src.len().min(info.ctl_name.len()));

            if libc::ioctl(fd, libc::CTLIOCGINFO, &mut info) < 0 {
                let e = std::io::Error::last_os_error();
                let _ = libc::close(fd);
                error!("utun: ioctl(CTLIOCGINFO) failed: {}", e);
                return Err(NetworkError::TunDevice(format!(
                    "Failed to resolve utun control id: {}",
                    e
                )));
            }

            // Build sockaddr_ctl for connect
            let mut addr: libc::sockaddr_ctl = mem::zeroed();
            addr.sc_len = mem::size_of::<libc::sockaddr_ctl>() as u8;
            addr.sc_family = libc::AF_SYSTEM as u8;
            addr.ss_sysaddr = AF_SYS_CONTROL as u16;
            addr.sc_id = info.ctl_id;
            addr.sc_unit = 0; // 0 means allocate next available utunX

            let ret = libc::connect(
                fd,
                &addr as *const _ as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_ctl>() as libc::socklen_t,
            );
            if ret < 0 {
                let e = std::io::Error::last_os_error();
                let _ = libc::close(fd);
                error!("utun: connect() failed: {}", e);
                return Err(NetworkError::TunDevice(format!(
                    "Failed to connect utun control socket: {}",
                    e
                )));
            }

            // Retrieve interface name via getsockopt
            let mut ifname = [0u8; libc::IFNAMSIZ];
            let mut ifname_len = ifname.len() as libc::socklen_t;
            let gso = libc::getsockopt(
                fd,
                libc::SYSPROTO_CONTROL,
                UTUN_OPT_IFNAME,
                ifname.as_mut_ptr() as *mut libc::c_void,
                &mut ifname_len,
            );
            if gso < 0 {
                let e = std::io::Error::last_os_error();
                let _ = libc::close(fd);
                error!("utun: getsockopt(UTUN_OPT_IFNAME) failed: {}", e);
                return Err(NetworkError::TunDevice(format!(
                    "Failed to get utun interface name: {}",
                    e
                )));
            }

            // Convert C string to Rust String
            let name_cstr = CStr::from_ptr(ifname.as_ptr() as *const libc::c_char);
            let if_name = name_cstr.to_string_lossy().into_owned();

            info!("Created utun device: {} (fd {})", if_name, fd);

            // Wrap fd in File to manage lifetime (will be leaked later intentionally)
            let file = File::from_raw_fd(fd);
            Ok((file, if_name))
        }
    }

    /// Configure the TUN interface using ifconfig
    async fn configure_tun_interface(
        &self,
        interface_name: &str,
        ip_config: &str,
        mtu: u32,
    ) -> NetworkResult<()> {
        // Parse the IP address and prefix length
        let parts: Vec<&str> = ip_config.split('/').collect();
        if parts.len() != 2 {
            return Err(NetworkError::TunDevice(format!(
                "Invalid IP configuration: {}",
                ip_config
            )));
        }

        let ip_address = parts[0];
        let prefix_len = parts[1]
            .parse::<u32>()
            .map_err(|e| NetworkError::TunDevice(format!("Invalid prefix length: {}", e)))?;

        // Calculate the netmask from the prefix length
        let netmask = Self::prefix_len_to_netmask(prefix_len)?;

        // For a point-to-point interface, we need different IPs for source and destination
        // If the source IP is 10.0.0.1, we'll use 10.0.0.2 for the destination
        let dest_ip = if ip_address.starts_with("10.0.0.1") {
            "10.0.0.2".to_string()
        } else {
            // For other IP addresses, we'll increment the last octet
            let octets: Vec<&str> = ip_address.split('.').collect();
            if octets.len() == 4 {
                let last_octet = octets[3].parse::<u8>().unwrap_or(1);
                let new_last_octet = if last_octet < 255 {
                    last_octet + 1
                } else {
                    last_octet - 1
                };
                format!(
                    "{}.{}.{}.{}",
                    octets[0], octets[1], octets[2], new_last_octet
                )
            } else {
                // Fallback to a default destination IP
                "10.0.0.2".to_string()
            }
        };
        info!(
            "Using source IP {} and destination IP {}",
            ip_address, dest_ip
        );

        // First, bring the interface up
        Self::run_command(
            "ifconfig",
            &[interface_name, "up", "mtu", &mtu.to_string()],
            "Failed to bring up TUN interface",
        )
        .await?;

        // Then, configure the IP address
        // On macOS, for point-to-point interfaces, we need to specify both source and destination IPs
        info!(
            "Configuring IP address for {}: {} -> {}",
            interface_name, ip_address, dest_ip
        );

        // Use the approach that worked in our tests
        Self::run_command(
            "ifconfig",
            &[
                interface_name,
                "inet",
                ip_address,
                &dest_ip,
                "netmask",
                &netmask,
            ],
            "Failed to configure TUN interface",
        )
        .await?;

        // Verify the interface configuration
        let output = Self::run_command(
            "ifconfig",
            &[interface_name],
            "Failed to get interface configuration",
        )
        .await?;

        info!("Interface configuration: {}", output);

        // Check if the IP address was configured correctly
        let mtu_token = format!("mtu {}", mtu);
        let missing_ip = !output.contains(ip_address);
        let missing_mtu = !output.contains(&mtu_token);
        if missing_ip || missing_mtu {
            let mut reasons = Vec::new();
            if missing_ip {
                reasons.push("ip");
            }
            if missing_mtu {
                reasons.push("mtu");
            }
            warn!(
                "Interface {} missing {:?} after configuration",
                interface_name, reasons
            );
            return Err(NetworkError::TunDevice(format!(
                "Failed to configure {}: missing {:?} in interface configuration output",
                interface_name, reasons
            )));
        }

        Ok(())
    }

    /// Convert a prefix length to a netmask string (e.g., 24 -> "255.255.255.0")
    fn prefix_len_to_netmask(prefix_len: u32) -> NetworkResult<String> {
        if prefix_len > 32 {
            return Err(NetworkError::TunDevice(format!(
                "Invalid prefix length: {}",
                prefix_len
            )));
        }

        let netmask_bits = 0xffffffff_u32 << (32 - prefix_len);
        let octet1 = (netmask_bits >> 24) & 0xff;
        let octet2 = (netmask_bits >> 16) & 0xff;
        let octet3 = (netmask_bits >> 8) & 0xff;
        let octet4 = netmask_bits & 0xff;

        Ok(format!("{}.{}.{}.{}", octet1, octet2, octet3, octet4))
    }

    /// Read the current DNS configuration
    fn read_dns_config(&self) -> NetworkResult<Vec<String>> {
        let mut file = File::open(&self.resolv_conf_path)
            .map_err(|e| NetworkError::DnsConfig(format!("Failed to open resolv.conf: {}", e)))?;

        let mut content = String::new();
        file.read_to_string(&mut content)
            .map_err(|e| NetworkError::DnsConfig(format!("Failed to read resolv.conf: {}", e)))?;

        let mut nameservers = Vec::new();
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with("nameserver ") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    nameservers.push(parts[1].to_string());
                }
            }
        }

        Ok(nameservers)
    }

    /// Write a new DNS configuration
    fn write_dns_config(&self, nameservers: &[String]) -> NetworkResult<()> {
        let mut content = String::new();
        content.push_str("# Generated by CoentroVPN\n");
        for ns in nameservers {
            content.push_str(&format!("nameserver {}\n", ns));
        }

        let mut file = File::create(&self.resolv_conf_path)
            .map_err(|e| NetworkError::DnsConfig(format!("Failed to create resolv.conf: {}", e)))?;

        file.write_all(content.as_bytes())
            .map_err(|e| NetworkError::DnsConfig(format!("Failed to write resolv.conf: {}", e)))?;

        Ok(())
    }

    /// Detect the primary outbound device (e.g., en0) from the default route
    async fn detect_primary_device() -> Option<String> {
        let out = TokioCommand::new("/usr/sbin/route")
            .args(["-n", "get", "default"])
            .output()
            .await
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let s = String::from_utf8_lossy(&out.stdout);
        for line in s.lines() {
            let line = line.trim();
            if line.starts_with("interface: ") {
                return Some(line.trim_start_matches("interface: ").trim().to_string());
            }
        }
        None
    }

    /// Map a device (e.g., en0) to a Network Service name (e.g., "Wi-Fi")
    async fn map_device_to_service(device: &str) -> Option<String> {
        let out = TokioCommand::new("/usr/sbin/networksetup")
            .arg("-listnetworkserviceorder")
            .output()
            .await
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let s = String::from_utf8_lossy(&out.stdout);
        for line in s.lines() {
            let line = line.trim();
            if line.starts_with("(Hardware Port: ") {
                // Example: (Hardware Port: Wi-Fi, Device: en0)
                let candidate = line
                    .strip_prefix("(Hardware Port: ")
                    .and_then(|rest| rest.split(',').next())
                    .map(|name| name.trim().to_string());
                if line.contains(&format!("Device: {}", device)) {
                    return candidate;
                }
            }
        }
        // Fallback: pick the first enabled service name from listnetworkservices
        let out2 = TokioCommand::new("/usr/sbin/networksetup")
            .arg("-listnetworkservices")
            .output()
            .await
            .ok()?;
        if !out2.status.success() {
            return None;
        }
        let s2 = String::from_utf8_lossy(&out2.stdout);
        for line in s2.lines() {
            let name = line.trim();
            if name.is_empty() || name.starts_with("An asterisk (") {
                continue;
            }
            return Some(name.to_string());
        }
        None
    }

    async fn get_dns_for_service(service: &str) -> NetworkResult<Vec<String>> {
        let out = TokioCommand::new("/usr/sbin/networksetup")
            .args(["-getdnsservers", service])
            .output()
            .await
            .map_err(|e| {
                NetworkError::DnsConfig(format!("Failed to run networksetup -getdnsservers: {}", e))
            })?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            return Err(NetworkError::DnsConfig(format!(
                "networksetup -getdnsservers failed: {}",
                stderr.trim()
            )));
        }
        let stdout = String::from_utf8_lossy(&out.stdout);
        let msg = stdout.trim();
        if msg.contains("aren't any DNS Servers set") {
            return Ok(Vec::new());
        }
        let mut servers = Vec::new();
        for line in stdout.lines() {
            let val = line.trim();
            if !val.is_empty() {
                servers.push(val.to_string());
            }
        }
        Ok(servers)
    }

    async fn set_dns_for_service(service: &str, servers: &[String]) -> NetworkResult<()> {
        let mut cmd = TokioCommand::new("/usr/sbin/networksetup");
        cmd.arg("-setdnsservers").arg(service);
        if servers.is_empty() {
            cmd.arg("empty");
        } else {
            for s in servers {
                cmd.arg(s);
            }
        }
        let out = cmd.output().await.map_err(|e| {
            NetworkError::DnsConfig(format!("Failed to run networksetup -setdnsservers: {}", e))
        })?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            return Err(NetworkError::DnsConfig(format!(
                "networksetup -setdnsservers failed: {}",
                stderr.trim()
            )));
        }
        Ok(())
    }
}

#[async_trait]
impl NetworkManager for MacOsNetworkManager {
    /// Create a TUN interface
    async fn create_tun(&self, config: TunConfig) -> NetworkResult<TunDetails> {
        info!("Creating TUN interface with config: {:?}", config);

        // Open the TUN device
        let (tun_file, interface_name) = self.open_tun_device()?;
        let fd = tun_file.as_raw_fd();

        // We need to keep the file open, so we'll leak it
        // The file descriptor will be passed to the client
        std::mem::forget(tun_file);

        // Configure the interface
        self.configure_tun_interface(&interface_name, &config.ip_config, config.mtu)
            .await?;

        // Return the TUN details
        Ok(TunDetails {
            name: interface_name,
            ip_config: config.ip_config,
            mtu: config.mtu,
            fd,
        })
    }

    /// Destroy a TUN interface
    async fn destroy_tun(&self, name: &str) -> NetworkResult<()> {
        info!("Destroying TUN interface: {}", name);

        // Attempt to drop any configured addresses; ignore if none are present
        if let Err(e) = Self::run_command(
            "ifconfig",
            &[name, "-alias", "0.0.0.0"],
            &format!("Failed to clear IP aliases on {}", name),
        )
        .await
        {
            let emsg = e.to_string();
            if emsg.contains("Cannot assign requested address")
                || emsg.contains("not found")
                || emsg.contains("does not exist")
            {
                info!(
                    "Interface {} had no aliases to clear; continuing teardown",
                    name
                );
            } else {
                warn!("Error clearing aliases on {}: {}", name, emsg);
            }
        }

        // On macOS, we can just bring the interface down
        match Self::run_command(
            "ifconfig",
            &[name, "down"],
            &format!("Failed to bring down TUN interface {}", name),
        )
        .await
        {
            Ok(_) => {}
            Err(e) => {
                let emsg = e.to_string();
                // Treat already-absent interfaces as success (idempotent teardown)
                if emsg.contains("does not exist")
                    || emsg.contains("No such")
                    || emsg.contains("not found")
                {
                    info!(
                        "Interface {} already absent when bringing down; treating as success",
                        name
                    );
                } else {
                    return Err(e);
                }
            }
        }

        Ok(())
    }

    /// Add a route to the routing table
    async fn add_route(
        &self,
        destination: &str,
        gateway: Option<&str>,
        interface: &str,
    ) -> NetworkResult<()> {
        info!(
            "Adding route: destination={}, gateway={:?}, interface={}",
            destination, gateway, interface
        );
        // Special-case default route on macOS: try default first, then split default as fallback
        if gateway.is_none() && (destination == "0.0.0.0/0" || destination == "default") {
            // Try to add default route via interface
            let try_default = Self::run_command(
                "route",
                &["-n", "add", "-inet", "default", "-interface", interface],
                "Failed to add default route via interface",
            )
            .await;

            match try_default {
                Ok(_) => return Ok(()),
                Err(e) => {
                    if e.to_string().contains("File exists") {
                        info!("Default route already exists; considering it a success");
                        return Ok(());
                    }
                }
            }

            {
                warn!(
                    "Default route via interface failed; falling back to split default (0.0.0.0/1 and 128.0.0.0/1)"
                );
                // Add two covering routes to avoid replacing existing default
                for cidr in ["0.0.0.0/1", "128.0.0.0/1"].iter() {
                    let res = Self::run_command(
                        "route",
                        &["-n", "add", "-net", cidr, "-interface", interface],
                        &format!(
                            "Failed to add split default route {} via interface {}",
                            cidr, interface
                        ),
                    )
                    .await;
                    if let Err(e) = res {
                        if e.to_string().contains("File exists") {
                            info!("Split default {} already exists; continuing", cidr);
                            continue;
                        } else {
                            return Err(e);
                        }
                    }
                }
                return Ok(());
            }
        }

        // Build the generic command arguments
        let mut args = vec!["-n", "add", "-net", destination];

        if let Some(gw) = gateway {
            args.push(gw);
        } else {
            args.push("-interface");
            args.push(interface);
        }

        // Run the route command
        let res = Self::run_command(
            "route",
            &args,
            &format!("Failed to add route to {}", destination),
        )
        .await;
        if let Err(e) = res {
            if e.to_string().contains("File exists") {
                info!(
                    "Route {} already exists; considering it a success",
                    destination
                );
            } else {
                return Err(e);
            }
        }

        Ok(())
    }

    /// Remove a route from the routing table
    async fn remove_route(
        &self,
        destination: &str,
        gateway: Option<&str>,
        interface: &str,
    ) -> NetworkResult<()> {
        info!(
            "Removing route: destination={}, gateway={:?}, interface={}",
            destination, gateway, interface
        );

        // Default route handling: remove both default and split-default to stay idempotent
        if gateway.is_none() && (destination == "0.0.0.0/0" || destination == "default") {
            let targets = [
                (
                    "default",
                    vec!["-n", "delete", "-inet", "default", "-interface", interface],
                ),
                (
                    "0.0.0.0/1",
                    vec!["-n", "delete", "-net", "0.0.0.0/1", "-interface", interface],
                ),
                (
                    "128.0.0.0/1",
                    vec![
                        "-n",
                        "delete",
                        "-net",
                        "128.0.0.0/1",
                        "-interface",
                        interface,
                    ],
                ),
            ];

            for (label, args) in targets {
                if let Err(e) = Self::run_command("route", &args, "Failed to remove route").await {
                    let emsg = e.to_string();
                    if emsg.contains("not in table")
                        || emsg.contains("not found")
                        || emsg.contains("No such")
                    {
                        info!("Route {} already absent; continuing", label);
                        continue;
                    }
                    return Err(NetworkError::Routing(format!(
                        "Failed to remove {} route: {}",
                        label, e
                    )));
                }
            }
            return Ok(());
        }

        // Build the command arguments
        let mut args = vec!["-n", "delete", "-net", destination];

        if let Some(gw) = gateway {
            args.push(gw);
        } else {
            args.push("-interface");
            args.push(interface);
        }

        // Run the route command
        let res = Self::run_command(
            "route",
            &args,
            &format!("Failed to remove route to {}", destination),
        )
        .await;

        if let Err(e) = res {
            let emsg = e.to_string();
            if emsg.contains("not in table")
                || emsg.contains("not found")
                || emsg.contains("No such")
            {
                info!("Route {} already absent; treating as success", destination);
            } else {
                return Err(e);
            }
        }

        Ok(())
    }

    /// Configure DNS servers
    async fn configure_dns(&self, servers: &[String]) -> NetworkResult<()> {
        info!("Configuring DNS servers: {:?}", servers);

        // Prefer networksetup per-service DNS configuration
        if let Some(dev) = Self::detect_primary_device().await {
            info!("Detected primary device: {}", dev);
            if let Some(service) = Self::map_device_to_service(&dev).await {
                info!("Mapped device {} to service '{}'", dev, service);
                // Save original DNS once
                if self.original_dns.is_none() {
                    match Self::get_dns_for_service(&service).await {
                        Ok(orig) => {
                            info!("Saved original DNS for service '{}': {:?}", service, orig);
                            let this = self as *const Self as *mut Self;
                            unsafe {
                                (*this).original_dns = Some(orig);
                                (*this).dns_service_name = Some(service.clone());
                            }
                        }
                        Err(e) => warn!("Failed to read original DNS for '{}': {}", service, e),
                    }
                }

                if let Err(e) = Self::set_dns_for_service(&service, servers).await {
                    warn!(
                        "networksetup failed to set DNS for '{}': {} — falling back to resolv.conf",
                        service, e
                    );
                } else {
                    // Flush DNS cache
                    let _ = Command::new("dscacheutil").args(["-flushcache"]).output();
                    let _ = Command::new("killall")
                        .args(["-HUP", "mDNSResponder"])
                        .output();
                    return Ok(());
                }
            } else {
                warn!(
                    "Could not map device {} to a network service; falling back",
                    dev
                );
            }
        } else {
            warn!("Could not detect primary device; falling back to resolv.conf");
        }

        // Fallback to resolv.conf if networksetup path is unavailable
        if self.original_dns.is_none() {
            let original = self.read_dns_config()?;
            info!("Saved original DNS (resolv.conf fallback): {:?}", original);
            let this = self as *const Self as *mut Self;
            unsafe {
                (*this).original_dns = Some(original);
            }
        }
        self.write_dns_config(servers)?;
        let _ = Command::new("dscacheutil").args(["-flushcache"]).output();
        Ok(())
    }

    /// Restore original DNS configuration
    async fn restore_dns(&self) -> NetworkResult<()> {
        info!("Restoring original DNS configuration");

        // Try to restore via networksetup if we modified a service
        if let Some(service) = &self.dns_service_name {
            if let Some(ref original) = self.original_dns {
                info!("Restoring DNS for service '{}': {:?}", service, original);
                // If original is empty, pass 'empty' to clear
                if let Err(e) = Self::set_dns_for_service(service, original).await {
                    warn!(
                        "Failed to restore DNS for service '{}' via networksetup: {}",
                        service, e
                    );
                } else {
                    let _ = Command::new("dscacheutil").args(["-flushcache"]).output();
                    let _ = Command::new("killall")
                        .args(["-HUP", "mDNSResponder"])
                        .output();
                    // Clear saved state
                    let this = self as *const Self as *mut Self;
                    unsafe {
                        (*this).original_dns = None;
                        (*this).dns_service_name = None;
                    }
                    return Ok(());
                }
            }
        }

        // Fallback: restore resolv.conf if we have it saved
        if let Some(ref original) = self.original_dns {
            info!("Restoring resolv.conf DNS servers: {:?}", original);
            self.write_dns_config(original)?;
            let _ = Command::new("dscacheutil").args(["-flushcache"]).output();
            let this = self as *const Self as *mut Self;
            unsafe {
                (*this).original_dns = None;
                (*this).dns_service_name = None;
            }
        } else {
            warn!("No original DNS configuration to restore");
        }

        Ok(())
    }
}
