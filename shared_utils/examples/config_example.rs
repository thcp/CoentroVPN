//! Example demonstrating how to use the configuration module.

use shared_utils::config::{Config, ConfigManager, Role};
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load configuration from a file
    println!("Loading configuration from file...");
    let config_path = Path::new("config.toml");

    if config_path.exists() {
        // Load existing configuration
        let config = Config::load(config_path)?;
        println!("Configuration loaded successfully!");

        // Print configuration details
        print_config(&config);

        // Use ConfigManager for more advanced operations
        let mut manager = ConfigManager::load(config_path)?;
        println!("\nUsing ConfigManager...");
        println!("Config path: {:?}", manager.config_path());

        // Modify configuration
        println!("\nModifying configuration...");
        manager.config_mut().log_level = "debug".to_string();
        println!("Log level changed to: {}", manager.config().log_level);

        // Save to a different file to avoid overwriting the original
        let modified_path = Path::new("config.modified.toml");
        println!("Saving modified configuration to {:?}...", modified_path);
        manager.save_as(modified_path)?;
        println!("Modified configuration saved successfully!");
    } else {
        // Create a new configuration
        println!("Configuration file not found, creating a new one...");

        // Create a server configuration
        let mut config = Config::new();
        config.role = Role::Server;
        config.log_level = "debug".to_string();
        config.network.port = 9090;
        config.network.bind_address = "0.0.0.0".to_string();
        config.security.psk = Some("example-psk".to_string());
        config.server.virtual_ip_range = Some("10.0.0.0/24".to_string());
        config.server.dns_servers = vec!["8.8.8.8".to_string(), "1.1.1.1".to_string()];

        // Save the configuration
        let new_config_path = Path::new("config.example.toml");
        println!("Saving new configuration to {:?}...", new_config_path);
        config.save(new_config_path)?;
        println!("New configuration saved successfully!");

        // Print configuration details
        print_config(&config);
    }

    Ok(())
}

/// Print configuration details
fn print_config(config: &Config) {
    println!("\nConfiguration Details:");
    println!("---------------------");
    println!("Role: {:?}", config.role);
    println!("Log Level: {}", config.log_level);
    println!("Network:");
    println!("  Port: {}", config.network.port);
    println!("  Bind Address: {}", config.network.bind_address);
    println!("  Max Connections: {}", config.network.max_connections);

    println!("Security:");
    println!(
        "  PSK: {}",
        config.security.psk.as_deref().unwrap_or("<not set>")
    );
    println!(
        "  Cert Path: {}",
        config.security.cert_path.as_deref().unwrap_or("<not set>")
    );
    println!(
        "  Key Path: {}",
        config.security.key_path.as_deref().unwrap_or("<not set>")
    );
    println!("  Verify TLS: {}", config.security.verify_tls);

    match config.role {
        Role::Client => {
            println!("Client Configuration:");
            println!(
                "  Server Address: {}",
                config
                    .client
                    .server_address
                    .as_deref()
                    .unwrap_or("<not set>")
            );
            println!("  Auto Reconnect: {}", config.client.auto_reconnect);
            println!(
                "  Reconnect Interval: {} seconds",
                config.client.reconnect_interval
            );
        }
        Role::Server => {
            println!("Server Configuration:");
            println!(
                "  Virtual IP Range: {}",
                config
                    .server
                    .virtual_ip_range
                    .as_deref()
                    .unwrap_or("<not set>")
            );
            println!("  DNS Servers: {:?}", config.server.dns_servers);
            println!("  Routes: {:?}", config.server.routes);
        }
    }
}
