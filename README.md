<p align="center">
    <img src="coentrovpn.jpeg" alt="CoentroVPN Logo" width="200"/>
</p>
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

| **Feature**                          | **CoentroVPN**                         | **OpenVPN**                                                                 | **WireGuard**                                                             |
|-------------------------------------|----------------------------------------|------------------------------------------------------------------------------|---------------------------------------------------------------------------|
| Language                            | Rust (safe, async, zero-cost abstractions) | C (manual memory mgmt, single-threaded core)                               | C (minimalist, kernel-integrated)                                         |
| Compression                         | LZ4/Zstd, planned selective compression | LZO (legacy), optional and slower                                            | ❌ None built-in                                                           |
| Packet Splitting/Reassembly         | ✅ Custom chunking with headers        | ❌ Relies on IP fragmentation                                                 | ❌ Relies on kernel stack                                                  |
| MTU Auto-Tuning                     | ✅ Dynamic at runtime                  | ❌ Manual tuning required                                                     | ⚠️ Static at start, needs user config                                     |
| Flow/Rate Control                   | ✅ Sliding window, thresholds, backpressure (planned signaling) | ❌ None                                                | ❌ None                                                                    |
| Buffer Tuning                       | ✅ socket2-based user & kernel buffer tuning | ❌ System default, needs OS tuning manually                  | ❌ System default                                                           |
| Async Runtime                       | ✅ Tokio (fully async I/O model)       | ❌ Blocking I/O, threading not scalable                                       | ⚠️ Kernel threads                                                          |
| Horizontal Scalability              | ⚠️ Planned with session stickiness     | ❌ Not natively supported, needs 3rd party orchestration                     | ⚠️ Possible with stateless design, but not automatic                       |
| Telemetry & Observability           | ⚠️ Planned (metrics, tracing)          | ❌ Minimal: only logs, limited plugins                                       | ❌ Limited kernel logging                                                  |
| Extensibility/Modularity            | ✅ High, modular architecture          | ❌ Monolithic codebase                                                        | ❌ Medium (lean code, less extensible)                                     |
| Protocol Flexibility                | ✅ Custom packet format planned        | ✅ Supports multiple transports (TCP/UDP), tun/tap                          | ❌ Only UDP, fixed transport                                                |
| Auth & Crypto Agility              | ⚠️ Not yet implemented, pluggable planned | ✅ Supports mTLS, static keys, PKI, LDAP, PAM, plugins    | ⚠️ Limited: static key or short Curve25519 handshake only                  |
| Key Exchange                        | ⚠️ Planned (e.g., ECDH)                | ✅ SSL/TLS-based with many cipher options                                    | ✅ Noise protocol (Curve25519, ChaCha20, Poly1305)                         |
| NAT Traversal                       | ✅ UDP hole punching planned           | ✅ Uses TCP/UDP, can traverse NAT with config                                | ✅ NAT traversal via UDP                                                   |
| Plugin Ecosystem                    | ⚠️ Planned via modular runtime         | ✅ Extensive plugin and script support                                       | ❌ No plugin system                                                        |
| Platform Support                    | ✅ Cross-platform via Rust             | ✅ Extensive (Linux, Windows, macOS, BSD, Android)                           | ✅ Good (Linux native, user-space implementations elsewhere)              |
| Security Audits                     | ⚠️ To be conducted                     | ✅ Repeated third-party audits, mature                                      | ✅ Audited by multiple third parties                                       |
| Licensing                           | MIT                                    | GPLv2                                                                       | GPLv2                                                                     |

### 🧩 Key Observations & Improvement Targets

- **Compression:** OpenVPN’s LZO is outdated and suboptimal. CoentroVPN already uses Zstd/LZ4 and plans *selective compression based on payload type*.
- **MTU/Packet Handling:** CoentroVPN supports *automatic MTU tuning* and *custom chunking*, which allows better performance over unstable links compared to IP fragmentation in OpenVPN or kernel reliance in WireGuard.
- **Flow Control:** Neither OpenVPN nor WireGuard implement dynamic flow or rate control — this is a major area for CoentroVPN to innovate via *sliding window + adaptive backpressure*.
- **Observability:** CoentroVPN aims to surpass minimal logging with *integrated metrics, spans, and live telemetry endpoints* for debugging and performance analysis.
- **Scalability:** Both OpenVPN and WireGuard lack horizontal scalability out of the box. CoentroVPN targets *cluster-aware deployment with sticky sessions and state sync*.
- **Security Layer:** OpenVPN supports a wide range of ciphers and auth backends, but is complex. WireGuard is simpler but rigid. CoentroVPN will aim for *pluggable cryptographic primitives* and *modern, auditable default choices*.

> 🧠 *This document is meant to serve as a living map of where CoentroVPN has been, where it's going, and what sets it apart. Update as milestones are completed or the roadmap evolves.*