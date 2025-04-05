## 05/04 – Structured Logging and Chunk Context Integration
- ✅ Introduced `Chunk` struct for per-chunk metadata (message_id, chunk_id, total_chunks)
- ✅ Implemented `MessageContext` and `ChunkContext` for structured tracing
- ✅ Added `info_span!`, `trace!`, and `debug!` across tunnel, client, and server flows
- ✅ Traced rate-limiting events with delay duration per message
- ✅ Added per-connection and per-chunk spans with consistent field ordering
- ✅ Applied consistent log terminology (decoded, decompressed, etc.)
- ✅ Removed legacy `deframe_chunks` and unified chunk handling

## 16/03 – Initial Scaffolding & Core Setup
- ✅ Project initialized with modular Rust structure
- ✅ `Tunnel` trait defined with `start`, `send_data`, and `receive_data`
- ✅ `Client`, `Server`, and `TunnelImpl` skeletons created
- ✅ Config loader supporting both TOML and environment variables
- ✅ Basic UDP socket binding via `tokio::net::UdpSocket`

---

## 23/03 – Framing, MTU Handling, and Compression
- ✅ Introduced packet framing and chunking using `msg_id`, `chunk_id`, `total_chunks`
- ✅ `frame_chunks` and `deframe_chunks` added to `packet_utils.rs`
- ✅ Implemented MTU discovery logic (with Linux support)
- ✅ Added dynamic max packet size based on MTU and protocol overhead
- ✅ Integrated LZ4 and Zstd compression (using `spawn_blocking`)

---

## 30/03 – Packet Reassembly and Rate Limiting
- ✅ Introduced `ReassemblyBuffer` with timeout-based cleanup
- ✅ Integrated reassembly into `receive_data` flow
- ✅ Applied byte-rate throttling using `tokio::time::sleep` in `send_data`
- ✅ Cleaned up unused imports and removed duplicate type definitions
- ✅ Tuned buffer allocations to be MTU-aware and dynamic

---

## 06/03 – Error Handling and Code Polish
- ✅ Standardized all async function errors as `Box<dyn Error + Send + Sync>`
- ✅ Replaced `to_socket_addrs` with async-safe `tokio::net::lookup_host`
- ✅ Moved `compress_data`/`decompress_data` to shared module scope
- ✅ Refined `UdpSocket` locking strategy (`RwLock` vs `Mutex`)
- ✅ Removed all dead code, unused imports, and improved logging messages

---

## Next Up
- [ ] Add AES-GCM encryption support
- [ ] Add HMAC or CRC integrity checks for UDP frames
- [ ] Unit and integration test coverage
- [ ] Feature gating for optional compression/encryption
- [ ] Flow control / congestion feedback mechanism

---