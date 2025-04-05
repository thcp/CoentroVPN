# Recommended Books for CoentroVPN Development

These books cover async programming, logging, protocol design, performance, and security.

| Experience Level          | Book / Resource                                 | Key Topics                                                                                       | Why It’s Relevant to CoentroVPN                         |
|--------------------------|--------------------------------------------------|---------------------------------------------------------------------------------------------------|----------------------------------------------------------|
| 🟢 Beginner → Intermediate | Rust Programming by Example (2nd Ed, 2023)     | Real-world examples, file I/O, networking basics, simple threading                              | Great for building confidence with sockets, packet work  |
| 🟡 Intermediate            | Command-Line Rust                               | CLI tooling, `clap`, configuration, I/O pipelines                                                | Useful to polish your CLI tool entrypoint               |
| 🟡 Intermediate → Advanced | Zero To Production in Rust                     | Telemetry with `tracing`, layered config, structured app design, error handling                 | Aligns well with your logging, config, testing systems   |
| 🟡 Intermediate → Advanced | Async Programming in Rust with Tokio           | `UdpSocket`, `RwLock`, tasks, backpressure, cancellation                                         | Core to how your tunnel/server/client works              |
| 🔵 Advanced                | Rust for Rustaceans                            | Traits, lifetimes, APIs, memory layout, idiomatic patterns                                       | Helps with architecture and tight trait-driven design    |
| 🔵 Advanced                | Rust Atomics and Locks (2nd Ed)                | Low-level concurrency, atomics, `Arc`, `Mutex`, memory models                                    | Critical for safe high-perf shared buffer/socket logic   |
| 🔐 Advanced → Security     | Rust Security Cookbook (RustSec Drafts) *(2025, draft)* | Crypto (AES, HMAC, TLS), fuzzing, constant-time ops, secure network patterns                     | Future-proofing for encryption, auth, DH key exchange    |
| 🔬 Advanced                | The Rust Performance Book                       | Cache locality, inlining, memory layout, benchmarks                                              | Perfect for your future low-latency/tuning needs         |
| 🧠 Reference               | The Tracing Book                               | Layers, filters, spans, field value injection                                                    | Deep dive on structured logging (`tracing`)              |
