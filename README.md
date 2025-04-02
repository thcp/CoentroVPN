# 🌀 CoentroVPN – Roadmap & Vision

## 🔍 What is CoentroVPN?

CoentroVPN is a next-generation VPN engine built from scratch in Rust, designed to overcome the performance, customization, and architectural limitations of traditional VPN solutions like OpenVPN and WireGuard. With a strong emphasis on performance, CoentroVPN is aimed at power users, developers, streamers, and businesses that need ultra-responsive, secure, and customizable networking solutions.

## 📜 Project History

The project began with a vision to build a modern, flexible VPN with a modular and performance-optimized design. Early milestones included:
- Fully async tunnel logic using `tokio` and `socket2`
- Dynamic MTU and buffer tuning
- Custom packet splitting and reassembly
- Compression with LZ4/Zstd
- Flow control and early rate limiting

## 🚀 Goals & Potential

- High-throughput networking optimized for gaming, streaming, and file transfer
- Dynamically switchable compression
- Custom congestion/flow control mechanisms
- Fine-grained packet inspection and reassembly
- High observability and telemetry support
- Secure handshake & authentication systems
- Multi-node server deployments with sticky sessions and horizontal scalability

---

## ✅ Unified Progress Summary

| **Component / Feature**          | **Description**                                                                 | **Status**     | **Notes** |
|----------------------------------|---------------------------------------------------------------------------------|----------------|-----------|
| `tunnel.rs`                      | Core tunneling logic, concurrency, UDP socket optimization                      | ✅ Done        | Performance testing still pending |
| `client.rs`                      | Client-side UDP handling, retry logic, integration with tunnel                  | ✅ Done        | Socket2 + MTU support complete |
| `server.rs`                      | UDP listener, response logic, multi-client concurrency                          | ✅ Done        | Uses buffer and MTU tuning |
| `config.rs`                      | Expose UDP-related config (MTU, buffer sizes, etc.)                             | ✅ Done        | TOML + env var overrides supported |
| `main.rs`                        | Load config and pass to client/server                                           | ✅ Done        | Minimal, just `mod net;` added |
| Rate Limiting                    | Throttle data transmission rate to avoid overwhelming the network               | ✅ Done        | Implemented with config controls |
| Flow Control                     | Prevent sender from sending too fast for receiver                               | ✅ Done        | Core logic in tunnel/server/client |
| Sliding Window Protocol          | Windowed packet delivery model                                                  | ⚠️ Partial     | Mentioned but no full ACK logic yet |
| Packet Splitting                 | Split large packets into chunks with headers for indexing and ID                | ✅ Done        | Implemented in tunnel/client/server |
| Chunk Reassembly                 | Reassemble received chunks in correct order                                     | ✅ Done        | Logic in place for reordering and combining |
| Configurable Packet Size         | Max size for splitting packets                                                  | ✅ Done        | Config.toml + config.rs support |
| Configurable Buffer Size         | Set logical buffer limits                                                       | ✅ Done        | In config + applied in server/client |
| Flow Control Thresholds          | Control how full a buffer can get before triggering backpressure                | ✅ Done        | Part of config.rs and respected in code |
| MTU Tuning                       | Adjust payloads to avoid fragmentation                                          | ✅ Done        | Uses `calculate_max_payload_size()` |
| Socket Buffer Tuning             | Apply system-level buffer tuning with `socket2`                                 | ✅ Done        | Cross-platform safe |
| Compression (LZ4/Zstd)           | Use LZ4/Zstd for efficient payload handling                                     | ✅ Done        | Seamlessly integrated |
| Selective Compression            | Only compress large payloads or specific types                                  | ❌ Not yet     | All data currently compressed |
| Socket Timeouts                  | Use timeouts to prevent hangs                                                   | ⚠️ Not yet     | Needs `tokio::time::timeout` wrapping |
| Retry Mechanism                  | Exponential backoff for failed transmissions                                    | ⚠️ Not yet     | Code example exists, not yet wired |
| Backpressure Signaling           | Server signals client to pause/resume based on buffer state                     | ❌ Not started | Planned but no signaling yet |
| Key Exchange (e.g. DH)           | Secure key agreement between client and server                                  | ❌ Not started | Placeholder only |
| Client Authentication            | Auth mechanism to allow only trusted clients                                    | ❌ Not started | Not yet implemented |
| Metrics (latency, loss, etc.)    | Telemetry and monitoring of network performance                                 | ❌ Not started | No metrics layer yet |
| Health Checks                    | Liveness/readiness probes                                                       | ❌ Not started | No periodic health check implemented |
| Horizontal Scaling               | Deploy server across multiple nodes/clusters                                    | ❌ Not started | Architecture not yet cluster-aware |
| Sticky Sessions                  | Ensure session consistency across load-balanced instances                       | ❌ Not started | Would require session persistence logic |

## 📊 CoentroVPN vs. Traditional VPNs

| **Feature**                          | **CoentroVPN**       | **OpenVPN**         | **WireGuard**       |
|-------------------------------------|----------------------|---------------------|---------------------|
| Language                            | Rust (safe & async)  | C                   | C                   |
| Compression                         | LZ4/Zstd, planned selective | Optional (slow)     | None                |
| Packet Splitting/Reassembly         | ✅ Custom             | ❌ Fragmentation only| ❌ Kernel handled    |
| MTU Auto-Tuning                     | ✅ Yes               | ❌ Manual            | ⚠️ Partial           |
| Flow/Rate Control                   | ✅ Custom Logic       | ❌ None              | ❌ None              |
| Buffer Tuning                       | ✅ socket2-based      | ❌ System default    | ❌ System default    |
| Async Runtime                       | ✅ Tokio              | ❌ Blocking          | ⚠️ Kernel-based      |
| Horizontal Scalability              | ⚠️ In design          | ❌ Hard              | ⚠️ In practice       |
| Telemetry & Observability           | ⚠️ Planned            | ❌ Minimal           | ❌ Minimal           |
| Extensibility/Modularity            | ✅ High               | ❌ Low               | ❌ Medium            |

---

> 🧠 *This document is meant to serve as a living map of where CoentroVPN has been, where it's going, and what sets it apart. Update as milestones are completed or the roadmap evolves.*
> 