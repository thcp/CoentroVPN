#!/bin/bash
# Docker deployment script for CoentroVPN
# This script helps with building and running the distroless Docker containers

set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Print header
echo -e "${GREEN}CoentroVPN Docker Deployment${NC}"
echo "==============================="
echo

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo -e "${RED}Error: Docker is not installed or not in PATH${NC}"
    echo "Please install Docker and try again."
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker compose &> /dev/null; then
    echo -e "${YELLOW}Warning: Docker Compose v2 not found${NC}"
    echo "Using legacy docker-compose if available..."
    COMPOSE_CMD="docker-compose"
    
    if ! command -v docker-compose &> /dev/null; then
        echo -e "${RED}Error: Neither Docker Compose v2 nor legacy docker-compose found${NC}"
        echo "Please install Docker Compose and try again."
        exit 1
    fi
else
    COMPOSE_CMD="docker compose"
fi

# Function to show usage
show_usage() {
    echo "Usage: $0 [COMMAND]"
    echo
    echo "Commands:"
    echo "  build       Build the Docker images"
    echo "  up          Start the containers"
    echo "  down        Stop the containers"
    echo "  logs        Show container logs"
    echo "  status      Show container status"
    echo "  clean       Remove all containers and images"
    echo "  help        Show this help message"
    echo
    echo "Examples:"
    echo "  $0 build    # Build the Docker images"
    echo "  $0 up       # Start the containers"
    echo "  $0 logs     # Show logs from all containers"
}

# Function to build the Docker images
build() {
    echo -e "${GREEN}Building Docker images...${NC}"
    
    # Create config directory if it doesn't exist
    mkdir -p config
    
    # Check if config.toml exists, create a sample if not
    if [ ! -f "config/config.toml" ]; then
        echo -e "${YELLOW}Creating sample config.toml...${NC}"
        cat > config/config.toml << EOF
[server]
listen_addr = "0.0.0.0:51820"
management_addr = "0.0.0.0:8080"

[client]
server_addr = "coentro-server:51820"
EOF
    fi
    
    # Build the images
    $COMPOSE_CMD -f docker-compose.distroless.yml build
    
    echo -e "${GREEN}Build completed successfully!${NC}"
}

# Function to start the containers
up() {
    echo -e "${GREEN}Starting containers...${NC}"
    $COMPOSE_CMD -f docker-compose.distroless.yml up -d
    echo -e "${GREEN}Containers started successfully!${NC}"
    
    # Show container status
    status
}

# Function to stop the containers
down() {
    echo -e "${YELLOW}Stopping containers...${NC}"
    $COMPOSE_CMD -f docker-compose.distroless.yml down
    echo -e "${GREEN}Containers stopped successfully!${NC}"
}

# Function to show container logs
logs() {
    echo -e "${GREEN}Showing container logs (press Ctrl+C to exit)...${NC}"
    $COMPOSE_CMD -f docker-compose.distroless.yml logs -f
}

# Function to show container status
status() {
    echo -e "${GREEN}Container status:${NC}"
    $COMPOSE_CMD -f docker-compose.distroless.yml ps
}

# Function to clean up containers and images
clean() {
    echo -e "${YELLOW}Cleaning up containers and images...${NC}"
    
    # Stop and remove containers
    $COMPOSE_CMD -f docker-compose.distroless.yml down
    
    # Remove images
    echo -e "${YELLOW}Removing Docker images...${NC}"
    docker rmi -f $(docker images | grep 'coentrovpn' | awk '{print $3}') 2>/dev/null || true
    
    echo -e "${GREEN}Cleanup completed!${NC}"
}

# Main logic
case "$1" in
    build)
        build
        ;;
    up)
        up
        ;;
    down)
        down
        ;;
    logs)
        logs
        ;;
    status)
        status
        ;;
    clean)
        clean
        ;;
    help)
        show_usage
        ;;
    *)
        show_usage
        exit 1
        ;;
esac

exit 0
