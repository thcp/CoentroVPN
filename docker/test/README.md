# CoentroVPN Docker Test Environment

This directory contains Docker files for testing the CoentroVPN split daemon architecture on Linux, even when developing on macOS or Windows.

## Directory Structure

```
docker/
├── production/         # Production Docker files
│   ├── Dockerfile.client
│   └── Dockerfile.server
└── test/               # Testing Docker files
    ├── Dockerfile.helper
    ├── Dockerfile.client
    ├── docker-compose.yml
    ├── test_tunnel.sh
    ├── test_advanced.sh
    ├── test_fd_passing.sh
    └── README.md
```

## Testing Environment

The testing environment consists of three containers:

1. **Helper Container**: Runs the `coentro_helper` daemon with privileged access to create TUN devices and modify routing tables.
2. **Client Container**: Runs the `coentro_client` which communicates with the helper via a Unix Domain Socket.
3. **Test Runner Container**: A container for running test scripts that can interact with both the helper and client.

Both containers share the same network namespace, allowing the client to use the TUN interface created by the helper.

### TUN Interface Management

The testing environment now supports full TUN interface management:

- **Creation**: The helper daemon can create TUN interfaces with specified IP addresses, MTU values, and routing tables.
- **Configuration**: The helper daemon can configure DNS servers for the TUN interface.
- **Teardown**: The helper daemon can tear down TUN interfaces and restore the original network configuration.

The test scripts verify all these operations, ensuring that:

1. The TUN interface is created with the correct parameters
2. Routes are properly added to the routing table
3. DNS servers are correctly configured
4. The TUN interface is properly torn down when requested
5. The original DNS configuration is restored after teardown

### File Descriptor Passing

The split daemon architecture now supports file descriptor passing between the helper daemon and the client. This allows the helper daemon to create a TUN interface and pass the file descriptor to the client, which can then use it to read and write packets directly to the TUN interface.

The `test_fd_passing.sh` script verifies this functionality by:

1. Starting the helper daemon
2. Running the client with strace to trace file descriptor operations
3. Verifying that file descriptor passing occurs via SCM_RIGHTS
4. Checking that the TUN device is properly created and configured
5. Verifying proper cleanup when the client disconnects

## Build Context

The Docker Compose file specifies the project root as the build context, ensuring that the Dockerfiles have access to all project files during the build process, despite being in a subdirectory.

## Usage

### Building the Containers

```bash
docker-compose -f docker/test/docker-compose.yml build
```

### Starting the Testing Environment

```bash
docker-compose -f docker/test/docker-compose.yml up
```

This will start both containers. The helper container will automatically run the `coentro_helper` daemon, while the client container will just sleep, allowing you to exec into it and run tests manually.

### Running Tests

To run the basic tunnel test in the client container:

```bash
docker exec -it coentro-client-test /app/docker/test/test_tunnel.sh
```

To run the advanced tunnel test (requires root privileges):

```bash
docker exec -it coentro-test-runner /app/docker/test/test_advanced.sh
```

To run the file descriptor passing test:

```bash
docker exec -it coentro-test-runner /app/docker/test/test_fd_passing.sh
```

The test scripts perform the following tests:

1. **Authentication Test**: Verifies that the socket has the correct permissions and that authorized users can connect to the helper daemon.
2. **Unauthorized Access Test**: Verifies that unauthorized users are properly rejected by the authentication system.
3. **TUN Interface Creation Test**: Creates a TUN interface with specific parameters and verifies that it's correctly configured.
4. **Routing Test**: Verifies that routes are correctly added to the routing table.
5. **DNS Configuration Test**: Verifies that DNS servers are correctly configured.
6. **File Descriptor Passing Test**: Verifies that file descriptors are properly passed from the helper to the client.
7. **Teardown Test**: Verifies that the TUN interface is properly torn down and the original configuration is restored.

### Inspecting the Environment

To exec into the client container:

```bash
docker exec -it coentro-client-test bash
```

To exec into the helper container:

```bash
docker exec -it coentro-helper-test bash
```

To exec into the test runner container:

```bash
docker exec -it coentro-test-runner bash
```

### Stopping the Testing Environment

```bash
docker-compose -f docker/test/docker-compose.yml down
```

## Troubleshooting

### Socket Permissions

If you encounter permission issues with the Unix Domain Socket, make sure the socket directory has the correct permissions:

```bash
docker exec -it coentro-helper-test chmod 777 /var/run/coentrovpn
```

### TUN Device Creation

If the TUN device creation fails, check the helper logs:

```bash
docker logs coentro-helper-test
```

Make sure the helper container is running with the `--privileged` flag and has the `NET_ADMIN` capability.

### Client Commands

The client now supports the following commands:

```bash
# Set up a tunnel with default parameters
./target/debug/coentro_client setup-tunnel

# Set up a tunnel with specific parameters
./target/debug/coentro_client setup-tunnel --ip 10.8.0.1/24 --routes 0.0.0.0/0,192.168.0.0/16 --dns 8.8.8.8,1.1.1.1 --mtu 1400

# Tear down an active tunnel
./target/debug/coentro_client teardown-tunnel

# Get the status of the helper daemon
./target/debug/coentro_client

# Ping the helper daemon
./target/debug/coentro_client --ping-helper
```

### Authentication

The helper daemon now enforces authentication based on the UID of the connecting client. Only the following users are allowed to connect:

1. The user that started the helper daemon
2. The root user
3. Users explicitly allowed in the configuration

If you encounter authentication issues, make sure you're running the client as an authorized user or as root.

### Platform Support

The split daemon architecture now supports both Linux and macOS platforms:

- **Linux**: Uses the standard TUN/TAP driver and standard network configuration tools.
- **macOS**: Uses the utun driver and macOS-specific network configuration tools.

The appropriate implementation is automatically selected based on the platform.
