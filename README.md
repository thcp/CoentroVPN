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

## 📦 Docker Compose Example

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

---

## ✨ Contributions

We welcome contributions! Please follow our contribution guidelines (coming soon) and open issues or pull requests.

---

Maintained by the CoentroVPN team.