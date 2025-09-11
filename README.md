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

CoentroVPN includes a privileged helper daemon that runs with least privilege to create and manage a TUN (utun) interface. On macOS we support:

- **Real utun creation** via PF_SYSTEM/SYSPROTO_CONTROL with secure FD passing to the client
- **`launchd` Socket Activation** (production) and a **direct/dev mode** (local testing)
- **Proper Permissions**: UDS socket at `/var/run/coentrovpn/helper.sock` with 0660 perms; group-based access via `coentrovpn`

Quick paths:
- One‑shot smoke test (helper → IPC ping → utun setup → QUIC echo → teardown):
  ```bash
  bash ./CoentroVPN/scripts/macos_smoke_test.sh
  ```
- Install as launchd service (production‑style):
  ```bash
  sudo ./scripts/install_helper_macos.sh
  ```
- Dev mode (run helper directly; easiest for local iteration):
  ```bash
  sudo ./scripts/install_helper_macos_direct.sh
  ```

Docs:
- Step‑by‑step macOS validation: `CoentroVPN-Docs/docs/MACOS_TESTING.md`
- Launchd details and troubleshooting: `docs/MACOS_LAUNCHD_INTEGRATION.md`

---

## ✨ Contributions

We welcome contributions! Please follow our contribution guidelines (coming soon) and open issues or pull requests.

---

## 🔒 TLS & Tests (Developers)

- The QUIC client is **secure‑by‑default** and validates server certificates using system roots.
- For local examples/tests that use a self‑signed cert, use the dev‑only feature flag:
  ```bash
  cargo run -p shared_utils --features insecure-tls --example quic_example
  ```
- A pinned‑CA path is available for tests (no insecure flag required); several E2E tests already use it. Bootstrap‑based E2E tests still run under `--features insecure-tls` until PSK/mTLS is wired in.

See also:
- `CoentroVPN-Docs/docs/SECURITY_HARDENING_STATUS.md`
- `CoentroVPN-Docs/docs/SECURITY_TICKETS_SPRINT4.md`
