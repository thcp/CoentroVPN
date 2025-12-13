#![cfg(target_os = "linux")]

use coentro_helper::network_manager::{create_network_manager, TunConfig};
use std::process::Command;

fn ip_cmd(args: &[&str]) -> anyhow::Result<String> {
    let out = Command::new("ip").args(args).output()?;
    if !out.status.success() {
        anyhow::bail!(
            "ip {:?} failed: {:?}",
            args,
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

#[tokio::test]
async fn create_route_destroy_tun() -> anyhow::Result<()> {
    let mgr = create_network_manager();
    // Linux TUN device names have a small length limit (typically 15/16 chars); keep it short.
    let pid_suffix = std::process::id() % 10_000;
    let name = format!("cot{:04}", pid_suffix);
    let ip_cidr = "10.8.9.1/30";

    let tun = mgr
        .create_tun(TunConfig {
            name: Some(name.clone()),
            ip_config: ip_cidr.to_string(),
            mtu: 1400,
        })
        .await?;

    // Verify link exists and MTU set
    let link_info = ip_cmd(&["link", "show", "dev", &name])?;
    assert!(
        link_info.contains("mtu 1400"),
        "mtu not applied: {link_info}"
    );

    // Verify address is configured
    let addr_info = ip_cmd(&["-4", "addr", "show", "dev", &name])?;
    assert!(
        addr_info.contains("10.8.9.1/30"),
        "ip not configured: {addr_info}"
    );

    // Add and remove a dummy route to confirm path works
    mgr.add_route("203.0.113.0/24", None, &tun.name).await?;
    let routes = ip_cmd(&["route", "show", "dev", &name])?;
    assert!(
        routes.contains("203.0.113.0/24"),
        "route not present: {routes}"
    );
    mgr.remove_route("203.0.113.0/24", None, &tun.name).await?;

    // Destroy TUN and ensure link is gone
    mgr.destroy_tun(&tun.name).await?;
    let down = Command::new("ip")
        .args(["link", "show", "dev", &name])
        .output()?;
    assert!(
        !down.status.success(),
        "link still exists after destroy: {}",
        String::from_utf8_lossy(&down.stdout)
    );

    Ok(())
}
