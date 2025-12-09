#![cfg(target_os = "linux")]

use coentro_helper::network_manager::{create_network_manager, TunConfig};
use std::fs;
use tempfile::tempdir;

#[tokio::test]
async fn dns_configure_and_restore_uses_override_path() -> anyhow::Result<()> {
    // Prepare temp resolv.conf
    let dir = tempdir()?;
    let resolv_path = dir.path().join("resolv.conf");
    fs::write(&resolv_path, "nameserver 8.8.8.8\nnameserver 1.1.1.1\n")?;
    std::env::set_var(
        "COENTROVPN_LINUX_RESOLV_CONF",
        resolv_path.to_string_lossy().to_string(),
    );

    let mgr = create_network_manager();

    // Configure DNS to a new set
    mgr.configure_dns(&["9.9.9.9".into(), "149.112.112.112".into()])
        .await?;

    let written = fs::read_to_string(&resolv_path)?;
    assert!(
        written.contains("9.9.9.9") && written.contains("149.112.112.112"),
        "new DNS not written: {written}"
    );

    // Restore original
    mgr.restore_dns().await?;
    let restored = fs::read_to_string(&resolv_path)?;
    assert!(
        restored.contains("8.8.8.8") && restored.contains("1.1.1.1"),
        "original DNS not restored: {restored}"
    );

    Ok(())
}
