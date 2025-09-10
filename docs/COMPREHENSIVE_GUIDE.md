# CoentroVPN: Comprehensive Developer Guide

This guide provides a consolidated overview of the CoentroVPN project, including its architecture, development setup, and testing procedures for all supported platforms.

---

## 1. Architecture Overview

CoentroVPN utilizes a **Split Daemon Architecture** to enhance security by minimizing the amount of code that runs with elevated privileges.

-   **`coentro_client` (Unprivileged):** This is the user-facing component that handles the user interface, establishes the secure QUIC connection, and manages packet encryption/decryption. It runs with standard user permissions.
-   **`coentro_helper` (Privileged):** This is a lightweight background daemon that runs as root. Its sole responsibility is to perform system-level operations that require elevated privileges, such as:
    -   Creating virtual network interfaces (TUN/utun).
    -   Configuring IP addresses.
    -   Modifying the system's routing table.
    -   Setting DNS servers.
-   **`coentro_ipc` (Shared Library):** This crate defines the communication protocol between the client and the helper. They communicate over a secure Unix Domain Socket, with the helper authenticating the client based on its UID/GID. The most critical part of this communication is the secure passing of the TUN interface's file descriptor from the helper to the client.

This design ensures that the complex logic of the VPN protocol and user interaction is isolated from the high-privilege operations, significantly reducing the system's attack surface.

---

## 2. Development Setup

### Prerequisites

-   **Rust:** Install from [rust-lang.org](https://www.rust-lang.org/tools/install).
-   **Node.js and npm:** Required for the web dashboard. Install from [nodejs.org](https://nodejs.org/).
-   **Docker & Docker Compose:** Required for running the Linux test environment. Install from [docker.com](https://www.docker.com/get-started).
-   **VSCode (Recommended):** With the `rust-analyzer` extension.

### Building the Project

The project is a Cargo workspace. To build all Rust components from the project root:

```bash
cargo build --workspace
```

To build the web dashboard:

```bash
cd dashboard
npm install
npm run build
```

---

## 3. Platform Guide: macOS

This section covers the installation and testing procedures specific to macOS.

### 3.1. Helper Daemon Installation

-   **Development (Recommended):** Run the helper directly. It will not restart automatically.
    ```bash
    sudo ./scripts/install_helper_macos_direct.sh
    ```
-   **Production:** Install as a `launchd` service to ensure it starts at boot.
    ```bash
    sudo ./scripts/install_helper_macos.sh
    ```
-   **Uninstallation:** To uninstall, run the same script you used for installation with the `--uninstall` flag.
    ```bash
    # Example for direct run installation
    sudo ./scripts/install_helper_macos_direct.sh --uninstall
    ```

### 3.2. Testing on macOS

-   **Automated Test:** An automated script is provided to test file descriptor passing. **Note:** This script uses `dtruss`, which may require disabling System Integrity Protection (SIP) for developer tools.
    ```bash
    # Navigate to the scripts directory and run the test
    cd scripts
    ./test_fd_passing_macos.sh
    ```
-   **Manual Test:**
    1.  **Terminal 1: Start the Helper Daemon:**
        ```bash
        sudo ./target/debug/coentro_helper
        ```
    2.  **Terminal 2: Run the Client:**
        -   Setup Tunnel: `./target/debug/coentro_client setup-tunnel`
        -   Verify `utun` device: `ifconfig | grep utun`
        -   Verify IP address: `ifconfig utunX` (replace `utunX` with the actual device)
        -   Teardown Tunnel: `./target/debug/coentro_client teardown-tunnel`

For a step-by-step macOS validation guide (helper install, IPC ping, utun setup, QUIC examples), see `CoentroVPN-Docs/docs/MACOS_TESTING.md`.

---

## 4. Platform Guide: Linux & Docker

This section covers the installation and testing procedures for a native Linux environment, which is most easily managed via Docker.

### 4.1. Helper Daemon Installation (Native Linux)

-   Use the unified installation script:
    ```bash
    sudo ./scripts/install_helper.sh
    ```
-   To uninstall, run the same script with the `--uninstall` flag.

### 4.2. Testing on Linux (via Docker)

The most reliable way to test the full Linux implementation is by using the provided Docker Compose environment.

-   **Automated Test:** This script validates the entire process, including file descriptor passing.
    1.  Navigate to the test directory: `cd docker/test`
    2.  Run the test script: `./test_fd_passing_docker.sh`
-   **Manual Test:**
    1.  Start the containers: `cd docker/test && docker-compose up -d`
    2.  Get the client container ID: `CLIENT_CONTAINER=$(docker-compose ps -q client)`
    3.  Execute commands inside the client container:
        -   Setup Tunnel: `docker exec $CLIENT_CONTAINER /app/coentro_client setup-tunnel`
        -   Verify TUN device: `docker exec $CLIENT_CONTAINER ip link show | grep tun`
        -   Verify IP address: `docker exec $CLIENT_CONTAINER ip addr show dev tun0`
        -   Teardown Tunnel: `docker exec $CLIENT_CONTAINER /app/coentro_client teardown-tunnel`
    4.  Stop the containers when finished: `docker-compose down`

---

## 5. General Troubleshooting

### Helper Authentication

-   The helper authenticates the client using its **UID and GID**.
-   By default, `root` and the user who ran the installation script (via `sudo`) are allowed to connect.
-   You can allow additional UIDs in `config.toml`:
    ```toml
    [helper]
    allowed_uids = [501, 1000]
    ```

### Socket Permissions

-   The IPC socket is located at `/var/run/coentrovpn/helper.sock`.
-   Permissions are `660` (`srw-rw----`), meaning only `root` and members of the socket's group can connect.
-   For development, if you face permission errors, you can temporarily open up permissions:
    ```bash
    sudo chmod 666 /var/run/coentrovpn/helper.sock
    ```

### Verifying the Helper is Running

-   Use `ps` to check for the process:
    ```bash
    ps aux | grep coentro_helper
    ```
-   Check the logs (path may vary based on installation method):
    -   **macOS `launchd`:** `/var/log/coentrovpn-helper.log`
    -   **Docker:** `docker exec <helper_container_id> cat /var/log/coentro_helper.log`

### Pinging the Helper

The quickest way to test the connection between the client and helper is to use the `--ping-helper` command:

```bash
cargo run --package coentro_client -- --ping-helper
```

A successful response confirms that the helper is running and the client has the necessary permissions to connect to its socket.
