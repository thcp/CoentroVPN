//! macOS Network Manager Implementation
//!
//! This module provides the macOS-specific implementation of the NetworkManager trait.
//! It handles TUN interface creation, routing table modifications, and DNS configuration.

use super::{NetworkError, NetworkManager, NetworkResult, TunConfig, TunDetails};
use async_trait::async_trait;
use log::{debug, error, info, warn};
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::process::Command;
use tokio::process::Command as TokioCommand;
use std::ffi::{CStr, CString};
use std::mem;
use std::ptr;

/// macOS Network Manager
#[derive(Debug)]
pub struct MacOsNetworkManager {
    /// Original DNS configuration (for restoration)
    original_dns: Option<Vec<String>>,
    /// Path to the resolv.conf file
    resolv_conf_path: String,
}

impl MacOsNetworkManager {
    /// Create a new macOS Network Manager
    pub fn new() -> Self {
        Self {
            original_dns: None,
            resolv_conf_path: "/etc/resolv.conf".to_string(),
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
                error!("utun: socket(PF_SYSTEM,SOCK_DGRAM,SYSPROTO_CONTROL) failed: {}", e);
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
        if !output.contains(ip_address) {
            warn!(
                "IP address {} not found in interface configuration",
                ip_address
            );
            return Err(NetworkError::TunDevice(format!(
                "Failed to configure IP address for {}: IP address not found in interface configuration",
                interface_name
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

        // On macOS, we can just bring the interface down
        Self::run_command(
            "ifconfig",
            &[name, "down"],
            &format!("Failed to bring down TUN interface {}", name),
        )
        .await?;

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
                        &format!("Failed to add split default route {} via interface {}", cidr, interface),
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
                info!("Route {} already exists; considering it a success", destination);
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

        // Build the command arguments
        let mut args = vec!["-n", "delete", "-net", destination];

        if let Some(gw) = gateway {
            args.push(gw);
        } else {
            args.push("-interface");
            args.push(interface);
        }

        // Run the route command
        Self::run_command(
            "route",
            &args,
            &format!("Failed to remove route to {}", destination),
        )
        .await?;

        Ok(())
    }

    /// Configure DNS servers
    async fn configure_dns(&self, servers: &[String]) -> NetworkResult<()> {
        info!("Configuring DNS servers: {:?}", servers);

        // Save the original DNS configuration if we haven't already
        if self.original_dns.is_none() {
            let original = self.read_dns_config()?;
            info!("Saved original DNS configuration: {:?}", original);
            let this = self as *const Self as *mut Self;
            unsafe {
                (*this).original_dns = Some(original);
            }
        }

        // Write the new DNS configuration
        self.write_dns_config(servers)?;

        // Flush the DNS cache
        let _ = Command::new("dscacheutil").args(["-flushcache"]).output();

        Ok(())
    }

    /// Restore original DNS configuration
    async fn restore_dns(&self) -> NetworkResult<()> {
        info!("Restoring original DNS configuration");

        if let Some(ref original) = self.original_dns {
            info!("Restoring DNS servers: {:?}", original);
            self.write_dns_config(original)?;

            // Flush the DNS cache
            let _ = Command::new("dscacheutil").args(["-flushcache"]).output();

            // Clear the saved original DNS configuration
            let this = self as *const Self as *mut Self;
            unsafe {
                (*this).original_dns = None;
            }
        } else {
            warn!("No original DNS configuration to restore");
        }

        Ok(())
    }
}
