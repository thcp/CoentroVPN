# Docker Deployment for CoentroVPN

This document provides instructions for deploying CoentroVPN using Docker with distroless containers for enhanced security and minimal footprint.

## Overview

The Docker deployment consists of two main components:

1. **Server Container**: Runs the core VPN engine, management API, and helper daemon
2. **Client Container**: Runs the CLI client and client daemon

Both containers are built using:
- Rust 1.87.0 for compilation in the builder stage
- Distroless images for the runtime stage, which provide several advantages:
  - Minimal attack surface (no shell, package manager, or unnecessary utilities)
  - Smaller image size
  - Improved security posture

## Prerequisites

- Docker 20.10.0 or newer
- Docker Compose v2.0.0 or newer
- Git (to clone the repository)

## Building and Running

### Using the Deployment Script (Recommended)

The easiest way to deploy CoentroVPN is using the provided deployment script:

```bash
# Make the script executable (if not already)
chmod +x scripts/docker-deploy.sh

# Build the Docker images
./scripts/docker-deploy.sh build

# Start the containers
./scripts/docker-deploy.sh up

# View logs
./scripts/docker-deploy.sh logs

# Check container status
./scripts/docker-deploy.sh status

# Stop the containers
./scripts/docker-deploy.sh down

# Clean up (remove containers and images)
./scripts/docker-deploy.sh clean
```

### Using Docker Compose Directly

You can also use Docker Compose commands directly:

```bash
# Build and start both containers
docker compose -f docker-compose.distroless.yml up -d

# View logs
docker compose -f docker-compose.distroless.yml logs -f

# Stop the containers
docker compose -f docker-compose.distroless.yml down
```

### Building and Running Containers Separately

If you prefer to build and run the containers separately:

#### Server Container

```bash
# Build the server image
docker build -t coentrovpn-server -f Dockerfile.server .

# Run the server container
docker run -d --name coentrovpn-server \
  --cap-add=NET_ADMIN \
  -p 8080:8080 -p 51820:51820 \
  -v "$(pwd)/config:/app/config" \
  -v "$(pwd)/data:/app/data" \
  -e LOG_LEVEL=info \
  -e CONFIG_PATH=/app/config/config.toml \
  coentrovpn-server
```

#### Client Container

```bash
# Build the client image
docker build -t coentrovpn-client -f Dockerfile.client .

# Run the client container
docker run -d --name coentrovpn-client \
  -v "$(pwd)/config:/app/config" \
  -e LOG_LEVEL=info \
  -e SERVER_HOST=coentrovpn-server \
  -e CONFIG_PATH=/app/config/config.toml \
  --network=container:coentrovpn-server \
  coentrovpn-client
```

## Configuration

Before running the containers, ensure you have a valid configuration file at `./config/config.toml`. This file will be mounted into both containers.

Example minimal configuration:

```toml
[server]
listen_addr = "0.0.0.0:51820"
management_addr = "0.0.0.0:8080"

[client]
server_addr = "coentro-server:51820"
```

## Security Considerations

1. **Privileged Operations**: The server container requires the `NET_ADMIN` capability to create and manage network interfaces. This is a security-sensitive permission, so ensure your server container is properly secured.

2. **Volume Mounts**: Configuration and data are mounted as volumes. Ensure these directories have appropriate permissions.

3. **Network Isolation**: The Docker Compose setup creates a dedicated network for communication between the server and client containers.

4. **Distroless Benefits**: The use of distroless containers significantly reduces the attack surface by eliminating shells, package managers, and other utilities that could be exploited.

## Troubleshooting

If you encounter issues:

1. Check the container logs:
   ```bash
   docker logs coentrovpn-server
   docker logs coentrovpn-client
   ```

2. Verify the configuration file is correctly mounted and formatted.

3. Ensure the required ports are not already in use on your host system.

4. For networking issues, verify that the `NET_ADMIN` capability is properly set for the server container.

## Production Deployment Recommendations

For production deployments, consider:

1. Using Docker Swarm or Kubernetes for orchestration
2. Implementing proper secrets management for sensitive configuration
3. Setting up monitoring and alerting
4. Configuring proper log rotation and aggregation
5. Using a reverse proxy (like Traefik or Nginx) for the management API
6. Implementing proper backup strategies for configuration and data
