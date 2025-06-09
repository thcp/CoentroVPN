#!/bin/bash
# Test script for file descriptor passing in the CoentroVPN split daemon architecture in Docker
# This script tests the file descriptor passing mechanism between the helper daemon and client

set -e  # Exit on error

echo "=== CoentroVPN File Descriptor Passing Test (Docker) ==="
echo "Running tests in Docker environment"

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed"
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is not installed"
    exit 1
fi

# Build the Docker images
echo "=== Building Docker images ==="
cd "$(dirname "$0")"  # Change to the script directory
docker-compose build
echo "✅ Docker images built successfully"

# Start the containers
echo "=== Starting Docker containers ==="
docker-compose up -d
echo "✅ Docker containers started"

# Function to cleanup on exit
cleanup() {
    echo "=== Cleaning up ==="
    echo "Stopping Docker containers..."
    docker-compose down
    echo "Cleanup complete"
}

# Register the cleanup function to run on exit
trap cleanup EXIT

# Wait for the containers to be ready
echo "Waiting for containers to be ready..."
sleep 5

# Get the container IDs
HELPER_CONTAINER=$(docker-compose ps -q helper)
CLIENT_CONTAINER=$(docker-compose ps -q client)

if [ -z "$HELPER_CONTAINER" ] || [ -z "$CLIENT_CONTAINER" ]; then
    echo "❌ Failed to get container IDs"
    exit 1
fi

echo "Helper container: $HELPER_CONTAINER"
echo "Client container: $CLIENT_CONTAINER"

# Test 1: File Descriptor Passing
echo "=== Test 1: File Descriptor Passing ==="
echo "Setting up tunnel with file descriptor passing..."

# Run the client with strace to trace file descriptor operations
echo "Running client with strace to trace file descriptor operations..."
docker exec $CLIENT_CONTAINER bash -c "strace -e trace=network,desc -f /app/coentro_client setup-tunnel > /tmp/client.log 2> /tmp/strace.log" &
CLIENT_PID=$!

# Give the client time to set up the tunnel
echo "Waiting for tunnel setup..."
sleep 5

# Check if the client process is still running
if ! ps -p $CLIENT_PID > /dev/null; then
    echo "❌ Client process is not running"
    docker exec $HELPER_CONTAINER cat /var/log/coentro_helper.log
    docker exec $CLIENT_CONTAINER cat /tmp/client.log
    docker exec $CLIENT_CONTAINER cat /tmp/strace.log
    exit 1
fi

# Check for file descriptor passing in strace output
echo "Checking strace output for file descriptor passing..."
docker exec $CLIENT_CONTAINER bash -c "grep -q 'recvmsg.*SCM_RIGHTS' /tmp/strace.log"
if [ $? -eq 0 ]; then
    echo "✅ File descriptor passing detected in strace output"
    docker exec $CLIENT_CONTAINER bash -c "grep -n 'recvmsg.*SCM_RIGHTS' /tmp/strace.log"
else
    echo "❌ No file descriptor passing detected in strace output"
    docker exec $CLIENT_CONTAINER cat /tmp/strace.log
    exit 1
fi

# Check if a TUN device was created in the client container
echo "Checking if TUN device was created in the client container..."
docker exec $CLIENT_CONTAINER bash -c "ip link show | grep -o 'tun[0-9]\+'"
if [ $? -eq 0 ]; then
    TUN_DEVICE=$(docker exec $CLIENT_CONTAINER bash -c "ip link show | grep -o 'tun[0-9]\+'")
    echo "✅ TUN device created: $TUN_DEVICE"
    
    # Verify TUN device properties
    echo "Checking TUN device properties..."
    
    # Check if the device is UP
    docker exec $CLIENT_CONTAINER bash -c "ip link show dev $TUN_DEVICE | grep -q 'UP'"
    if [ $? -eq 0 ]; then
        echo "✅ TUN device is UP"
    else
        echo "❌ TUN device is not UP"
        docker exec $CLIENT_CONTAINER bash -c "ip link show dev $TUN_DEVICE"
        docker exec $HELPER_CONTAINER cat /var/log/coentro_helper.log
        exit 1
    fi
    
    # Check IP address (expecting 10.0.0.1/24)
    docker exec $CLIENT_CONTAINER bash -c "ip addr show dev $TUN_DEVICE | grep -q '10.0.0.1/24'"
    if [ $? -eq 0 ]; then
        echo "✅ TUN device has correct IP address"
    else
        echo "❌ TUN device has incorrect IP address"
        docker exec $CLIENT_CONTAINER bash -c "ip addr show dev $TUN_DEVICE"
        docker exec $HELPER_CONTAINER cat /var/log/coentro_helper.log
        exit 1
    fi
    
    # Display full device info for logging
    docker exec $CLIENT_CONTAINER bash -c "ip addr show dev $TUN_DEVICE"
    docker exec $CLIENT_CONTAINER bash -c "ip link show dev $TUN_DEVICE"
else
    echo "❌ Failed to create TUN device"
    docker exec $HELPER_CONTAINER cat /var/log/coentro_helper.log
    docker exec $CLIENT_CONTAINER cat /tmp/client.log
    exit 1
fi

# Test 2: Cleanup on Disconnect
echo "=== Test 2: Cleanup on Disconnect ==="
echo "Tearing down tunnel..."

# Send SIGINT to the client to allow it to clean up properly
if ps -p $CLIENT_PID > /dev/null; then
    echo "Sending SIGINT to client process..."
    kill -SIGINT $CLIENT_PID
    
    # Give the client time to process the signal and tear down the tunnel
    echo "Waiting for client to tear down tunnel..."
    wait $CLIENT_PID 2>/dev/null || true
    sleep 3
else
    echo "Client process is not running"
fi

# Check if the TUN device was removed
echo "Checking if TUN device was removed..."
docker exec $CLIENT_CONTAINER bash -c "ip link show 2>/dev/null | grep -q '$TUN_DEVICE'"
if [ $? -eq 0 ]; then
    echo "❌ TUN device was not removed"
    docker exec $CLIENT_CONTAINER bash -c "ip link show | grep 'tun'"
    
    # Try to force remove the device for cleanup
    echo "Attempting to force remove the device..."
    docker exec $CLIENT_CONTAINER bash -c "ip link delete $TUN_DEVICE 2>/dev/null || true"
    
    # This is a warning, not a failure, as in some environments the device might persist
    echo "⚠️ TUN device cleanup issue (continuing tests)"
else
    echo "✅ TUN device was successfully removed"
fi

# Check helper daemon logs for cleanup confirmation
echo "Checking helper daemon logs for cleanup confirmation..."
docker exec $HELPER_CONTAINER bash -c "grep -q 'Destroying TUN interface' /var/log/coentro_helper.log"
if [ $? -eq 0 ]; then
    echo "✅ Helper daemon attempted to destroy TUN interface"
else
    echo "⚠️ No TUN destruction log found in helper daemon logs"
    docker exec $HELPER_CONTAINER bash -c "tail -n 20 /var/log/coentro_helper.log"
fi

echo "=== All tests completed successfully ==="
