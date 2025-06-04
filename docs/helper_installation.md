# CoentroVPN Helper Installation Guide

This document provides instructions for installing and troubleshooting the CoentroVPN helper daemon on macOS.

## Installation

The helper daemon can be installed using one of the following methods:

### Method 1: Using launchd (Recommended for Production)

```bash
sudo ./scripts/install_helper_macos.sh
```

This method installs the helper daemon as a launchd service, which will automatically start at boot and restart if it crashes.

### Method 2: Direct Run (Recommended for Development)

```bash
sudo ./scripts/install_helper_macos_direct.sh
```

This method installs the helper daemon and runs it directly in the background. It will not automatically restart if it crashes or if the system is rebooted.

## Troubleshooting

### Socket Permission Issues

If you encounter permission issues when connecting to the helper daemon, it may be due to the socket file permissions. The helper daemon creates a Unix domain socket at `/var/run/coentrovpn/helper.sock` for IPC communication.

By default, the socket directory and socket file have the following permissions:
- Socket directory: `drwxrwxrwx` (777)
- Socket file: `srwxrwxrwx` (777)

These permissive permissions are necessary for non-root users to connect to the socket. If you're still experiencing permission issues, you can check the permissions with:

```bash
ls -la /var/run/coentrovpn/
```

### Launchd Service Issues

If the launchd service fails to load with an "Input/output error", it may be due to a Rust ABI mismatch. This can happen if the helper daemon was built with a different Rust version than the one installed on the system.

To fix this issue, you can try the following:

1. Clean the build artifacts and rebuild the helper daemon:

```bash
sudo cargo clean
cargo build --release --package coentro_helper
```

2. If that doesn't work, use the direct run method instead:

```bash
sudo ./scripts/install_helper_macos_direct.sh
```

### Verifying the Helper Daemon is Running

You can verify that the helper daemon is running with:

```bash
ps aux | grep coentro_helper
```

You should see at least one process running as root.

You can also check the log file at `/var/log/coentrovpn-helper.log` for any error messages:

```bash
cat /var/log/coentrovpn-helper.log
```

### Testing the Helper Daemon

You can test the helper daemon by pinging it from the client:

```bash
cargo run --package coentro_client -- --ping-helper
```

If the helper daemon is running and accessible, you should see:

```
[INFO  coentro_client] CoentroVPN Client starting up
[INFO  coentro_client] Pinging helper daemon...
[INFO  coentro_client] Helper daemon is responsive
```

## Uninstallation

To uninstall the helper daemon, run:

```bash
sudo ./scripts/install_helper_macos.sh --uninstall
```

or

```bash
sudo ./scripts/install_helper_macos_direct.sh --uninstall
```

depending on which installation method you used.
