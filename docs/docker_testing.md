# Testing CoentroVPN in Docker

This document provides instructions for testing the CoentroVPN split daemon architecture in Docker containers.

## Prerequisites

- Docker installed
- Docker Compose installed
- Basic understanding of Docker and containerization

## Docker Test Environment

The Docker test environment consists of two containers:

1. **Helper Container**: Runs the privileged helper daemon that creates TUN interfaces and manages network configuration.
2. **Client Container**: Runs the unprivileged client that communicates with the helper daemon.

Both containers share a common network namespace, allowing them to communicate with each other and share network interfaces.

## Building the Docker Images

```bash
# Navigate to the Docker test directory
cd docker/test

# Build the Docker images
docker-compose build
```

## Running the Tests

### Automated Testing

We provide a script to automate the testing of file descriptor passing in Docker:

```bash
# Make the script executable if needed
chmod +x docker/test/test_fd_passing_docker.sh

# Run the test script
./docker/test/test_fd_passing_docker.sh
```

The script will:
1. Build the Docker images
2. Start the containers
3. Run the client with `strace` to trace system calls
4. Verify that a TUN device is created with the correct configuration
5. Test cleanup when the client disconnects
6. Check logs for proper operation

### Manual Testing

If you prefer to test manually or if the automated script doesn't work for your environment:

1. Start the Docker containers:
   ```bash
   cd docker/test
   docker-compose up -d
   ```

2. Get the container IDs:
   ```bash
   HELPER_CONTAINER=$(docker-compose ps -q helper)
   CLIENT_CONTAINER=$(docker-compose ps -q client)
   ```

3. Run the client in the client container:
   ```bash
   docker exec $CLIENT_CONTAINER /app/coentro_client setup-tunnel
   ```

4. Verify that a TUN device is created:
   ```bash
   docker exec $CLIENT_CONTAINER ip link show | grep tun
   ```

5. Check the IP address and status of the TUN device:
   ```bash
   docker exec $CLIENT_CONTAINER ip addr show dev tun0  # Replace tun0 with the actual device name
   ```

6. Test routing by adding a route:
   ```bash
   docker exec $CLIENT_CONTAINER /app/coentro_client setup-tunnel --routes 192.168.1.0/24
   ```

7. Verify the route was added:
   ```bash
   docker exec $CLIENT_CONTAINER ip route | grep 192.168.1
   ```

8. Tear down the tunnel:
   ```bash
   docker exec $CLIENT_CONTAINER /app/coentro_client teardown-tunnel
   ```

9. Verify the TUN device is removed:
   ```bash
   docker exec $CLIENT_CONTAINER ip link show | grep tun
   ```

10. Stop the containers:
    ```bash
    docker-compose down
    ```

## Troubleshooting

### Common Issues

1. **Permission Denied**: Make sure the helper container is running with the necessary capabilities:
   ```yaml
   # In docker-compose.yml
   helper:
     cap_add:
       - NET_ADMIN
       - SYS_MODULE
   ```

2. **Socket Connection Failed**: Check if the socket directory exists and has the correct permissions:
   ```bash
   docker exec $HELPER_CONTAINER ls -la /var/run/coentrovpn
   ```

3. **TUN Device Creation Failed**: Ensure the helper container has the necessary privileges:
   ```bash
   docker exec $HELPER_CONTAINER ls -la /dev/net/tun
   ```

4. **Container Communication Issues**: Make sure both containers are on the same network:
   ```bash
   docker network inspect $(docker-compose ps -q helper | xargs docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{end}}')
   ```

### Logs

Check the logs for more detailed information:

- Helper daemon logs:
  ```bash
  docker exec $HELPER_CONTAINER cat /var/log/coentro_helper.log
  ```

- Client logs:
  ```bash
  docker exec $CLIENT_CONTAINER cat /tmp/client.log
  ```

- Strace logs (if using the automated test script):
  ```bash
  docker exec $CLIENT_CONTAINER cat /tmp/strace.log
  ```

## Advanced Debugging

For advanced debugging of file descriptor passing:

1. Use `strace` to trace system calls:
   ```bash
   docker exec $CLIENT_CONTAINER strace -e trace=network,desc -f /app/coentro_client setup-tunnel
   ```

2. Look for `recvmsg` calls with `SCM_RIGHTS` control messages, which indicate file descriptor passing.

3. Check the file descriptors in use by the client:
   ```bash
   docker exec $CLIENT_CONTAINER ls -la /proc/$(pgrep coentro_client)/fd
   ```

4. Monitor network interfaces in real-time:
   ```bash
   docker exec $CLIENT_CONTAINER watch -n 1 'ip link show | grep tun'
   ```

## Docker Compose Configuration

Here's an example `docker-compose.yml` configuration for testing:

```yaml
version: '3'

services:
  helper:
    build:
      context: ../../
      dockerfile: docker/test/Dockerfile.helper
    privileged: true
    cap_add:
      - NET_ADMIN
      - SYS_MODULE
    volumes:
      - /dev/net/tun:/dev/net/tun
    networks:
      - coentro_net

  client:
    build:
      context: ../../
      dockerfile: docker/test/Dockerfile.client
    depends_on:
      - helper
    cap_add:
      - NET_ADMIN  # Needed to configure the TUN interface
    networks:
      - coentro_net

networks:
  coentro_net:
    driver: bridge
```

This configuration creates two containers with the necessary privileges to create and manage TUN interfaces, and places them on the same network for communication.
