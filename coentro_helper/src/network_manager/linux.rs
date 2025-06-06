//! Linux-specific implementation of the Network Manager
//!
//! This module implements the NetworkManager trait for Linux systems.

use super::{NetworkError, NetworkManager, NetworkResult, TunConfig, TunDetails};
use async_trait::async_trait;
use log::{debug, error, info};
use std::net::Ipv4Addr;
use std::os::unix::io::AsRawFd;
use std::process::Command;
use std::str::FromStr;
use tokio::process::Command as TokioCommand;
use tun::{Configuration, Device, Layer};

/// Linux Network Manager implementation
pub struct LinuxNetworkManager {
    /// Original DNS configuration, saved for restoration
    original_dns: Option<Vec<String>>,
    /// TUN device name, used to track the active TUN device
    tun_name: Option<String>,
}

impl LinuxNetworkManager {
    /// Create a new Linux Network Manager
    pub fn new() -> Self {
        Self {
            original_dns: None,
            tun_name: None,
        }
    }

    /// Run a system command and return the output
    async fn run_command(&self, cmd: &str, args: &[&str]) -> NetworkResult<String> {
        debug!("Running command: {} {:?}", cmd, args);

        let output = TokioCommand::new(cmd)
            .args(args)
            .output()
            .await
            .map_err(|e| {
                NetworkError::SystemCommand(format!("Failed to execute command: {}", e))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            error!("Command failed: {} {}", output.status, stderr);
            return Err(NetworkError::SystemCommand(format!(
                "Command failed with status {}: {}",
                output.status, stderr
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        debug!("Command output: {}", stdout);

        Ok(stdout)
    }

    /// Parse an IP address and prefix length from a string (e.g., "10.0.0.1/24")
    fn parse_ip_config(&self, ip_config: &str) -> NetworkResult<(Ipv4Addr, u8)> {
        let parts: Vec<&str> = ip_config.split('/').collect();
        if parts.len() != 2 {
            return Err(NetworkError::Other(format!(
                "Invalid IP configuration: {}",
                ip_config
            )));
        }

        let ip = Ipv4Addr::from_str(parts[0])
            .map_err(|e| NetworkError::Other(format!("Invalid IP address {}: {}", parts[0], e)))?;

        let prefix_len = parts[1].parse::<u8>().map_err(|e| {
            NetworkError::Other(format!("Invalid prefix length {}: {}", parts[1], e))
        })?;

        if prefix_len > 32 {
            return Err(NetworkError::Other(format!(
                "Invalid prefix length: {}",
                prefix_len
            )));
        }

        Ok((ip, prefix_len))
    }
}

#[async_trait]
impl NetworkManager for LinuxNetworkManager {
    async fn create_tun(&self, config: TunConfig) -> NetworkResult<TunDetails> {
        info!("Creating TUN interface with config: {:?}", config);

        // Parse the IP configuration
        let (ip, prefix_len) = self.parse_ip_config(&config.ip_config)?;

        // Create a TUN device configuration
        let mut tun_config = Configuration::default();

        // Set the name if provided
        if let Some(name) = &config.name {
            tun_config.name(name);
        }

        // Set the layer to IP (Layer 3)
        tun_config.layer(Layer::L3);

        // Set the MTU
        tun_config.mtu(config.mtu as i32);

        // Create the TUN device
        let device = tun::create(&tun_config)
            .map_err(|e| NetworkError::TunDevice(format!("Failed to create TUN device: {}", e)))?;

        // Get the name of the created device
        let name = device.name().to_string();
        info!("Created TUN device: {}", name);

        // Get the file descriptor
        let fd = device.as_raw_fd();
        debug!("TUN device file descriptor: {}", fd);

        // Store the TUN device name
        let this = self as *const _ as *mut Self;
        unsafe {
            (*this).tun_name = Some(name.clone());
        }

        // We need to leak the device to prevent it from being dropped
        // This is a memory leak, but it's acceptable in this context
        // since we only create one TUN device per process
        std::mem::forget(device);

        // Configure the IP address
        let ip_cmd = format!("{}/{}", ip, prefix_len);
        self.run_command("ip", &["addr", "add", &ip_cmd, "dev", &name])
            .await
            .map_err(|e| NetworkError::SystemCommand(format!("Failed to set IP address: {}", e)))?;

        // Bring the interface up
        self.run_command("ip", &["link", "set", "dev", &name, "up"])
            .await
            .map_err(|e| {
                NetworkError::SystemCommand(format!("Failed to bring interface up: {}", e))
            })?;
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        // Return the TUN details
        Ok(TunDetails {
            name,
            ip_config: config.ip_config,
            mtu: config.mtu,
            fd,
        })
    }

    async fn destroy_tun(&self, name: &str) -> NetworkResult<()> {
        info!("Destroying TUN interface: {}", name);

        // Check if the interface exists
        let exists = match self.run_command("ip", &["link", "show", "dev", name]).await {
            Ok(_) => {
                info!("TUN interface {} exists, proceeding with cleanup", name);
                true
            }
            Err(e) => {
                info!(
                    "TUN interface {} does not exist or cannot be accessed: {}",
                    name, e
                );
                false
            }
        };

        if exists {
            // Bring the interface down
            info!("Bringing down TUN interface: {}", name);
            match self
                .run_command("ip", &["link", "set", "dev", name, "down"])
                .await
            {
                Ok(_) => info!("Successfully brought down TUN interface: {}", name),
                Err(e) => {
                    error!("Failed to bring down TUN interface {}: {}", name, e);
                    // Continue with deletion even if bringing down fails
                }
            }

            // Delete the interface
            info!("Deleting TUN interface: {}", name);
            match self
                .run_command("ip", &["link", "delete", "dev", name])
                .await
            {
                Ok(_) => info!("Successfully deleted TUN interface: {}", name),
                Err(e) => {
                    error!("Failed to delete TUN interface {}: {}", name, e);
                    // Try a different approach if the first one fails
                    info!(
                        "Attempting alternative method to delete TUN interface: {}",
                        name
                    );
                    match self
                        .run_command("ip", &["tuntap", "del", "dev", name, "mode", "tun"])
                        .await
                    {
                        Ok(_) => info!(
                            "Successfully deleted TUN interface using alternative method: {}",
                            name
                        ),
                        Err(e2) => {
                            error!(
                                "Failed to delete TUN interface {} using alternative method: {}",
                                name, e2
                            );
                            return Err(NetworkError::SystemCommand(format!(
                                "Failed to delete interface: {} (alternative method: {})",
                                e, e2
                            )));
                        }
                    }
                }
            }
        }

        // Clear the TUN device name
        let this = self as *const _ as *mut Self;
        unsafe {
            (*this).tun_name = None;
        }

        info!("TUN interface cleanup completed for: {}", name);
        Ok(())
    }

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

        // First, verify that the interface exists
        let output = self
            .run_command("ip", &["link", "show", interface])
            .await
            .map_err(|e| {
                NetworkError::Routing(format!("Failed to verify interface exists: {}", e))
            })?;

        if output.is_empty() {
            return Err(NetworkError::Routing(format!(
                "Interface {} does not exist",
                interface
            )));
        }

        // Add a small delay to ensure the interface is fully ready
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        let mut args = vec!["route", "add", destination];

        if let Some(gw) = gateway {
            args.push("via");
            args.push(gw);
        }

        args.push("dev");
        args.push(interface);

        // Try to add the route, but don't fail if it already exists
        match self.run_command("ip", &args).await {
            Ok(_) => Ok(()),
            Err(e) => {
                // Check if the error is "File exists", which means the route already exists
                if e.to_string().contains("File exists") {
                    info!("Route already exists, considering it a success");
                    Ok(())
                } else {
                    Err(e)
                }
            }
        }?;

        Ok(())
    }

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

        let mut args = vec!["route", "del", destination];

        if let Some(gw) = gateway {
            args.push("via");
            args.push(gw);
        }

        args.push("dev");
        args.push(interface);

        self.run_command("ip", &args)
            .await
            .map_err(|e| NetworkError::Routing(format!("Failed to remove route: {}", e)))?;

        Ok(())
    }

    async fn configure_dns(&self, servers: &[String]) -> NetworkResult<()> {
        info!("Configuring DNS servers: {:?}", servers);

        // Save the original DNS configuration for later restoration
        if self.original_dns.is_none() {
            // Read the current DNS configuration from /etc/resolv.conf
            let output = Command::new("cat")
                .arg("/etc/resolv.conf")
                .output()
                .map_err(|e| {
                    NetworkError::DnsConfig(format!("Failed to read /etc/resolv.conf: {}", e))
                })?;

            let content = String::from_utf8_lossy(&output.stdout);
            let mut dns_servers = Vec::new();

            for line in content.lines() {
                if line.starts_with("nameserver ") {
                    let server = line.trim_start_matches("nameserver ").trim().to_string();
                    dns_servers.push(server);
                }
            }

            // Store the original DNS servers
            let original_dns = if dns_servers.is_empty() {
                None
            } else {
                Some(dns_servers)
            };

            // Update the original_dns field
            let this = self as *const _ as *mut Self;
            unsafe {
                (*this).original_dns = original_dns;
            }
        }

        // Create a new resolv.conf content
        let mut content = String::new();
        content.push_str("# Generated by CoentroVPN\n");

        for server in servers {
            content.push_str(&format!("nameserver {}\n", server));
        }

        // Write the new resolv.conf
        std::fs::write("/etc/resolv.conf", content).map_err(|e| {
            NetworkError::DnsConfig(format!("Failed to write /etc/resolv.conf: {}", e))
        })?;

        Ok(())
    }

    async fn restore_dns(&self) -> NetworkResult<()> {
        info!("Restoring original DNS configuration");

        if let Some(servers) = &self.original_dns {
            // Create a new resolv.conf content
            let mut content = String::new();
            content.push_str("# Restored by CoentroVPN\n");

            for server in servers {
                content.push_str(&format!("nameserver {}\n", server));
            }

            // Write the new resolv.conf
            std::fs::write("/etc/resolv.conf", content).map_err(|e| {
                NetworkError::DnsConfig(format!("Failed to write /etc/resolv.conf: {}", e))
            })?;

            // Clear the original_dns field
            let this = self as *const _ as *mut Self;
            unsafe {
                (*this).original_dns = None;
            }
        }

        Ok(())
    }
}
