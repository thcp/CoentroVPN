# CoentroVPN
CoentroVPN is a Rust-based, multi-protocol VPN (QUIC, OpenVPN, WireGuard, IPsec) designed as a modern alternative to OpenVPN and Pritunl, with a scalable Kubernetes-native architecture and a React-based management dashboard.

---

## 📦 Project Structure

- **core_engine/** → Rust core VPN engine (QUIC, AES-GCM, compression)  
- **management_api/** → Rust Axum-based REST API backend  
- **cli_client/** → Rust CLI client  
- **gui_client/** → Rust + Tauri/Electron GUI client  
- **shared_utils/** → Shared Rust utilities (crypto, config, logging)  
- **dashboard/** → React + Vite frontend management dashboard  
- **coentro_ipc/** → IPC protocol for split daemon architecture
- **coentro_helper/** → Privileged helper daemon for system-level operations
- **coentro_client/** → Unprivileged client for split daemon architecture

---

## ⚙ Prerequisites

- Rust (`cargo`) — install via https://www.rust-lang.org/tools/install  
- Node.js + npm — install via Homebrew:
  ```bash
  brew install node
  ```
- Docker + Docker Compose — install via https://docs.docker.com/get-docker/  
- GitHub CLI (optional) — install via Homebrew:
  ```bash
  brew install gh
  ```

---

## 🛠 Local Development Setup

### 1️⃣ Backend (Rust)
```bash
cargo build --workspace
```

### 2️⃣ Frontend (React + Vite)
```bash
cd dashboard
npm install
npm run dev
```

### 3️⃣ Local Docker Setup (Backend + Postgres)
```bash
docker-compose up --build
```

This spins up:
- Rust backend (`management_api`)
- Postgres database
- Frontend React dashboard

### 4️⃣ Run Tests
```bash
cargo test --workspace
cd dashboard && npm run test
```

---

## 🚀 Split Daemon Architecture

CoentroVPN uses a split daemon architecture to enhance security and provide full VPN functionality:

1. **Unprivileged Client (`coentro_client`)**: Handles user interactions, QUIC connections, encryption, and packet processing.
2. **Privileged Helper (`coentro_helper`)**: Manages system-level operations requiring elevated privileges (TUN interfaces, routing, DNS).

These components communicate via a secure IPC channel defined in the `coentro_ipc` library.

### Benefits

- **Enhanced Security**: Minimizes code running with elevated privileges
- **Full VPN Functionality**: Enables TUN interface creation, routing table modifications, and DNS configuration
- **Platform Abstraction**: Consistent client experience across operating systems
- **Improved User Experience**: No need to run the entire client as administrator/root

### Installation

The helper daemon requires elevated privileges. Installation scripts are provided for Linux and macOS:

```bash
# Linux
sudo ./scripts/install_helper.sh

# macOS
sudo ./scripts/install_helper_macos.sh
```

See [Helper Installation Guide](docs/helper_installation.md) for more details.

## 🚀 Running the Demo

### Complete System Demo (Docker Compose)
The easiest way to run a complete demo of CoentroVPN with all components:

```bash
docker-compose up --build
```

This will start:
- The VPN core engine
- Management API backend
- PostgreSQL database
- React dashboard frontend

Access the dashboard at: http://localhost:3000

### Manual Component Setup

#### 1. Build All Components
```bash
cargo build --release --workspace
```

#### 2. Start the Core VPN Engine
```bash
cd core_engine
cargo run --release
```

You can also start the server using the CLI client:
```bash
# First, create a server configuration
cp config.toml config.server.toml
# Edit the configuration to set role = "server"
# Then run the server
cd cli_client
cargo run --release -- --config ../config.server.toml server
```

#### 3. Start the Management API
```bash
cd management_api
cargo run --release
```

#### 4. Launch the Dashboard
```bash
cd dashboard
npm install
npm run dev
```

#### 5. Connect with CLI Client
```bash
cd cli_client
cargo run --release
```

You can also specify a custom configuration file:
```bash
cd cli_client
cargo run --release -- --config config.custom.toml
```

#### 6. Connect with GUI Client
```bash
cd gui_client
cargo run --release
```

#### 7. Run the Unprivileged Client with Helper Daemon
```bash
# First, ensure the helper daemon is installed and running
sudo ./scripts/install_helper.sh

# Then run the unprivileged client
cd coentro_client
cargo run --release

# Or, to test the connection to the helper daemon
cargo run --release -- --ping-helper
```

### Running E2E Tests
```bash
cargo run --example e2e_test
```

The E2E tests demonstrate the full functionality of CoentroVPN by:
1. Starting a server in a separate task
2. Connecting a client to the server
3. Exchanging encrypted, framed packets
4. Verifying message integrity and encryption

The tests also verify tamper resistance by attempting to decrypt messages with incorrect keys.

### Demo Configuration
You can customize the demo by editing the `config.toml` file:

```bash
# View the default configuration
cat config.toml

# Make a custom configuration
cp config.toml config.custom.toml
nano config.custom.toml

# Run with custom configuration (specify which binary to run)
cargo run --release --bin cli_client -- --config config.custom.toml
```

---

## 📦 Docker Deployment Options

### Standard Docker Compose Example

```yaml
version: '3.8'
services:
  backend:
    build: ./management_api
    ports:
      - "8080:8080"

  postgres:
    image: postgres:15
    environment:
      POSTGRES_USER: coentro
      POSTGRES_PASSWORD: vpnpassword
      POSTGRES_DB: coentrovpn
    ports:
      - "5432:5432"

  dashboard:
    build: ./dashboard
    ports:
      - "3000:3000"
```

### Distroless Deployment (Enhanced Security)

For production environments, we provide distroless Docker images that offer enhanced security and minimal footprint:

```bash
# Using the deployment script
./scripts/docker-deploy.sh build
./scripts/docker-deploy.sh up
```

See [Docker Deployment Guide](DOCKER.md) for detailed instructions on deploying CoentroVPN using distroless containers.

---

## 🚀 CI/CD Pipeline

We use GitHub Actions for build pipelines. See `.github/workflows/ci.yml`.

---

## 📅 Sprint 1 Focus

- Initialize Rust workspace + crates  
- Setup React + Vite dashboard  
- Add Docker Compose  
- Set up GitHub Actions CI build  
- Validate local builds  
- Implement split daemon architecture foundation:
  - Create IPC protocol for client-helper communication
  - Implement basic helper daemon for privileged operations
  - Implement unprivileged client
  - Add installation scripts and documentation

---

## ✨ Contributions

We welcome contributions! Please follow our contribution guidelines (coming soon) and open issues or pull requests.

---

Maintained by the CoentroVPN team.
