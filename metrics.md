# CoentroVPN – Phase 8: Observability & DevOps

This phase introduces metrics, health endpoints, and structured logging to improve system visibility, reliability, and integration with modern operations tooling.

## Objectives

- Expose Prometheus-compatible `/metrics` endpoint for real-time monitoring
- Add HTTP `/healthz` and `/ready` endpoints for Kubernetes liveness/readiness probes
- Support structured logging output (JSON vs human-readable)
- Prepare log routing for per-session or per-peer tracing
- Foundation for Docker/Helm deployment

## Components

### 1. Metrics Endpoint

- Use `metrics` or `prometheus` crate to define and expose:
  - Packets sent/received
  - Bytes sent/received
  - Encryption success/failure counts
  - Compression ratios (optional)
  - Chunk reassembly successes/failures
- Host on an HTTP server (e.g., using `hyper` or `axum`) on a configurable port

### 2. Health Checks

- Add `/healthz` (always returns 200 if process is alive)
- Add `/ready` (returns 200 once tunnel is ready and bound)
- Host on same metrics HTTP server

### 3. Structured Logging

- Add `Config.logging.format = "pretty" | "json"` in `config.toml`
- Use `tracing_subscriber` layers to support both formats
- Ensure logs include fields:
  - Session ID
  - Message ID
  - MessageType
  - Peer address

### 4. Log Routing (Optional Extension)

- Add per-session file log rotation support (via `tracing_appender`)
- Store logs in directory defined in config

### 5. Docker / Helm (Optional Extension)

- Add multi-stage Dockerfile with minimal final image
- Prepare Kubernetes deployment manifest or Helm chart

## Implementation Order

1. Set up a lightweight HTTP server for metrics and health endpoints
2. Integrate `metrics` crate and start emitting internal counters
3. Add `/healthz` and `/ready` routes
4. Extend logging initialization with JSON/pretty switch
5. Optional: implement file-based per-session log routing
6. Optional: containerization with Docker and Helm

## Timeline

| Week | Task                                                 |
|------|------------------------------------------------------|
| 1    | Metrics + health HTTP server scaffolding             |
| 1    | Emit basic metrics (packets, errors)                 |
| 2    | Structured logging toggle                            |
| 2    | Optional: log routing to per-session files           |
| 3    | Dockerfile + deployment YAML/Helm setup              |
| 3    | Final validation and readiness                       |

## Phase 8: Observability & DevOps – File Update Plan

| File                            | Purpose                                             | Status |
|---------------------------------|-----------------------------------------------------|--------|
| `src/metrics.rs`                | Define and register Prometheus metrics              | TODO   |
| `src/health.rs` (or inline)     | Serve `/healthz` and `/ready` endpoints             | TODO   |
| `src/main.rs`                   | Launch metrics HTTP server                          | TODO   |
| `src/config.rs`                 | Add logging format field to config struct           | TODO   |
| `config.toml`                   | Add `logging.format = "pretty" \| "json"`           | TODO   |
| `src/logging.rs` (optional)     | Configure `tracing_subscriber` layers               | TODO   |
| `Dockerfile`                    | Add multi-stage container build                     | TODO   |
| `helm/`                         | Add Kubernetes manifest or Helm chart               | TODO   |
