# CoentroVPN Shared Utilities

This crate provides shared utilities for the CoentroVPN project, including protocol definitions, cryptographic utilities, and other common functionality.

## Stream Framing Protocol

The Stream Framing protocol is implemented in `src/proto/framing.rs`. It provides a reliable way to transmit and receive messages over a stream-based transport like QUIC.

### Frame Format

Each frame has the following structure:

```
+----------------+----------------+----------------+----------------+
|    Magic (1)   |  Version (1)   |    Type (1)    |   Flags (1)    |
+----------------+----------------+----------------+----------------+
|                        Length (4 bytes)                           |
+----------------+----------------+----------------+----------------+
|                        Payload (variable)                         |
+----------------+----------------+----------------+----------------+
|                        Checksum (4 bytes)                         |
+----------------+----------------+----------------+----------------+
```

- Magic: A fixed byte (0xC0) that marks the beginning of a frame
- Version: Protocol version (currently 0x01)
- Type: Message type (data, control, etc.)
- Flags: Additional flags for special handling
- Length: Length of the payload in bytes (u32, big-endian)
- Payload: The actual message data (variable length)
- Checksum: CRC32 checksum of the entire frame (header + payload)

### Frame Types

The following frame types are supported:

- Data (0x01): Contains encrypted payload data
- Control (0x02): Used for connection management
- Keepalive (0x03): Used to maintain the connection
- Config (0x04): Used for exchanging configuration settings
- Error (0x05): Indicates an error condition

## Testing the Stream Framing Implementation

There are several ways to test the Stream Framing implementation:

### 1. Running the Unit Tests

The implementation includes comprehensive unit tests that verify the functionality of the framing protocol. To run the tests:

```bash
cd CoentroVPN
cargo test -p shared_utils
```

### 2. Running the Basic Example

A simple example is provided that demonstrates the basic usage of the framing protocol:

```bash
cd CoentroVPN
cargo run -p shared_utils
```

This example creates a data frame, encodes it, decodes it, and verifies that the roundtrip was successful.

### 3. Running the Client-Server Example

A more comprehensive example is provided that demonstrates the framing protocol in a client-server scenario:

```bash
cd CoentroVPN
cargo run --example framing_test
```

This example:
- Starts a TCP server that listens for connections
- Connects a client to the server
- Sends frames of different types from the client to the server
- Processes the frames on the server and sends responses
- Processes the responses on the client

The output shows the entire process, including:
- Frame creation and encoding
- Frame transmission and reception
- Frame decoding and processing
- Response generation and handling

### 4. Using the API in Your Code

To use the Stream Framing protocol in your own code:

```rust
use shared_utils::proto::framing::{Frame, FrameType, StreamFramer};

// Create a frame
let data = b"Hello, CoentroVPN!".to_vec();
let frame = Frame::new_data(data).unwrap();

// Create a stream framer
let mut framer = StreamFramer::new();

// Encode the frame
let encoded = framer.encode(&frame);

// Send the encoded data over your transport...

// When receiving data:
let received_data = /* ... */;
framer.process_data(&received_data).unwrap();

// Process decoded frames
while let Some(decoded_frame) = framer.next_frame() {
    // Handle the frame based on its type
    match decoded_frame.frame_type {
        FrameType::Data => { /* ... */ },
        FrameType::Control => { /* ... */ },
        // ...
    }
}
```

## Integration with QUIC

The Stream Framing protocol is designed to work with QUIC transport. In the next sprint tasks, it will be integrated with the QUIC transport layer and the encryption layer to provide a secure and reliable communication channel for CoentroVPN.
