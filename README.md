# CoentroVPN

CoentroVPN is a Rust-based, multi-protocol VPN (QUIC, OpenVPN, WireGuard, IPsec) designed as a modern alternative to OpenVPN and Pritunl, with a scalable Kubernetes-native architecture and a React-based management dashboard.

---

## 🚀 Getting Started & Developer Guide

This guide provides a quick overview for getting started. For detailed instructions on architecture, development setup, and platform-specific testing, please see our **[Comprehensive Developer Guide](docs/COMPREHENSIVE_GUIDE.md)**.

### 1. Prerequisites

-   **Rust:** Install via [rust-lang.org](https://www.rust-lang.org/tools/install).
-   **Node.js & npm:** Install via [nodejs.org](https://nodejs.org/).
-   **Docker & Docker Compose:** Install via [docs.docker.com](https://docs.docker.com/get-docker/).

### 2. Build the Project

-   **Build all Rust components:**
    ```bash
    cargo build --workspace
    ```
-   **Build the Web Dashboard:**
    ```bash
    cd dashboard
    npm install
    npm run build
    ```

---

## 📦 Project Structure

-   **`core_engine/`**: The core VPN server engine.
-   **`management_api/`**: The backend REST API for management.
-   **`dashboard/`**: The React-based web dashboard.
-   **`shared_utils/`**: Shared Rust libraries (crypto, logging, etc.).
-   **`coentro_client/`**: The unprivileged VPN client.
-   **`coentro_helper/`**: The privileged helper daemon.
-   **`coentro_ipc/`**: The shared IPC library for client-helper communication.
-   **`cli_client/`**: The legacy command-line client.
-   **`gui_client/`**: A placeholder for the future GUI client.

---

## 🔧 Platform-Specific Features

### macOS Integration

CoentroVPN integrates with macOS's `launchd` service management system to provide a robust, secure, and reliable helper daemon experience. This integration includes:

- **Socket Activation**: The helper daemon is launched on-demand when a client connects
- **Automatic Startup**: The helper daemon starts automatically at system boot
- **Crash Recovery**: The daemon restarts automatically if it crashes
- **Proper Permissions**: Socket and file permissions are managed securely

For detailed information, see our [macOS launchd Integration Guide](docs/MACOS_LAUNCHD_INTEGRATION.md).

To install the helper daemon on macOS:

```bash
sudo ./scripts/install_helper_macos.sh
```

---

## ✨ Contributions

We welcome contributions! Please follow our contribution guidelines (coming soon) and open issues or pull requests.
