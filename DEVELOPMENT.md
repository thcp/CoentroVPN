# Development Setup

This document provides instructions for setting up the development environment and bootstrapping the CoentroVPN project.

## Prerequisites

Before you begin, ensure you have the following installed:

*   **Rust:** Follow the official installation guide at [rust-lang.org](https://www.rust-lang.org/tools/install).
*   **Node.js and npm:** Required for the dashboard. Download from [nodejs.org](https://nodejs.org/).
*   **Docker:** (Optional) For running services in containers. Install from [docker.com](https://www.docker.com/get-started).
*   **VSCode (Recommended):** With the `rust-analyzer` and `lldb` extensions for Rust development.

## Cloning the Repository

```bash
git clone https://github.com/your-username/CoentroVPN.git
cd CoentroVPN
```

## Building the Project

The project is a monorepo containing several Rust crates and a web dashboard.

### Core Engine, CLI Client, GUI Client, Management API

These are Rust crates. To build them, navigate to their respective directories or use Cargo workspace commands from the root.

To build all Rust components:

```bash
cargo build --all-targets
```

To build a specific component (e.g., `cli_client`):

```bash
cargo build --package cli_client
```

### Dashboard (Web UI)

The dashboard is a React application built with Vite.

1.  Navigate to the `dashboard` directory:
    ```bash
    cd dashboard
    ```
2.  Install dependencies:
    ```bash
    npm install
    ```
3.  Build for production:
    ```bash
    npm run build
    ```

## Running the Components

### Running the Core Engine (Server)

The core engine acts as the VPN server.

1.  Ensure you have a `config.server.toml` file (or a custom one).
2.  From the project root:
    ```bash
    cargo run --package core_engine -- --config config.server.toml
    ```
    Or, if you are in the `core_engine` directory:
    ```bash
    cargo run -- --config ../config.server.toml
    ```

### Running the CLI Client

The CLI client connects to the VPN server.

1.  Ensure you have a `config.toml` or `config.custom.toml` for the client.
2.  From the project root:
    ```bash
    cargo run --package cli_client -- --config config.toml client connect --server-addr 127.0.0.1:7890
    ```
    Replace `127.0.0.1:7890` with your server's address and port if different.
    Refer to `cli_client/src/cli.rs` for all available commands and options.

### Running the Dashboard

1.  Navigate to the `dashboard` directory:
    ```bash
    cd dashboard
    ```
2.  Start the development server:
    ```bash
    npm run dev
    ```
    This will typically open the dashboard in your browser at `http://localhost:5173`.

### Running the Management API

The Management API provides an interface to manage the VPN server.

1.  From the project root:
    ```bash
    cargo run --package management_api
    ```
    Or, if you are in the `management_api` directory:
    ```bash
    cargo run
    ```
    Check the `management_api/Cargo.toml` or its configuration for the default port.

## Debugging

### Rust Components

Use the `.vscode/launch.json` configurations created for debugging in VSCode.
Select "Debug CLI Client" or "Debug Core Engine" from the Run and Debug view.

### Dashboard

Use your browser's developer tools for debugging the React application.

## Contributing

Please follow the coding style and conventions used in the project.
Ensure your changes pass any linting and testing steps before submitting a pull request.
(Details on testing and linting to be added)
