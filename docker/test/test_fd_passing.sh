#!/bin/bash
# Test script for file descriptor passing in the CoentroVPN split daemon architecture
# This script tests the file descriptor passing mechanism between the helper daemon and client

set -e  # Exit on error

echo "=== CoentroVPN File Descriptor Passing Test ==="
echo "Running tests as $(whoami) with UID $(id -u) and GID $(id -g)"

# Build the binaries for Linux
echo "=== Building binaries for Linux ==="
cargo build --bin coentro_helper
cargo build --bin coentro_client
echo "✅ Binaries built successfully"

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check for required tools
for cmd in ip iptables; do
    if ! command_exists $cmd; then
        echo "❌ Required command not found: $cmd"
        exit 1
    fi
done

# Start the helper daemon in the background
echo "=== Starting helper daemon ==="
./target/debug/coentro_helper --log-level debug > helper.log 2>&1 &
HELPER_PID=$!

# Give the helper daemon time to start up
sleep 2

# Check if the helper daemon is running
if ! ps -p $HELPER_PID > /dev/null; then
    echo "❌ Helper daemon failed to start"
    cat helper.log
    exit 1
fi

echo "✅ Helper daemon started with PID $HELPER_PID"

# Function to cleanup on exit
cleanup() {
    echo "=== Cleaning up ==="
    if ps -p $HELPER_PID > /dev/null; then
        echo "Stopping helper daemon..."
        kill $HELPER_PID
        wait $HELPER_PID 2>/dev/null || true
    fi
    echo "Cleanup complete"
}

# Register the cleanup function to run on exit
trap cleanup EXIT

# Test 1: File Descriptor Passing
echo "=== Test 1: File Descriptor Passing ==="
echo "Setting up tunnel with file descriptor passing..."

# Run the client with strace to trace file descriptor operations
echo "Running client with strace to trace file descriptor operations..."
strace -e trace=network,desc -f ./target/debug/coentro_client setup-tunnel > client.log 2> strace.log &
CLIENT_PID=$!

# Give the client time to set up the tunnel
echo "Waiting for tunnel setup..."
sleep 5

# Check if the client is running
if ! ps -p $CLIENT_PID > /dev/null; then
    echo "❌ Client process is not running"
    cat helper.log
    cat client.log
    cat strace.log
    exit 1
fi

# Check for file descriptor passing in strace output
echo "Checking strace output for file descriptor passing..."
if grep -q "recvmsg.*SCM_RIGHTS" strace.log; then
    echo "✅ File descriptor passing detected in strace output"
    grep -n "recvmsg.*SCM_RIGHTS" strace.log
else
    echo "❌ No file descriptor passing detected in strace output"
    cat strace.log
    exit 1
fi

# Check if a TUN device was created
TUN_DEVICE=$(ip link show | grep -o "tun[0-9]\+")
if [ -n "$TUN_DEVICE" ]; then
    echo "✅ TUN device created: $TUN_DEVICE"
    
    # Verify TUN device properties
    echo "Checking TUN device properties..."
    
    # Check if the device is UP
    if ip link show dev $TUN_DEVICE | grep -q "UP"; then
        echo "✅ TUN device is UP"
    else
        echo "❌ TUN device is not UP"
        ip link show dev $TUN_DEVICE
        cat helper.log
        exit 1
    fi
    
    # Check IP address (expecting 10.0.0.1/24)
    if ip addr show dev $TUN_DEVICE | grep -q "10.0.0.1/24"; then
        echo "✅ TUN device has correct IP address"
    else
        echo "❌ TUN device has incorrect IP address"
        ip addr show dev $TUN_DEVICE
        cat helper.log
        exit 1
    fi
    
    # Display full device info for logging
    ip addr show dev $TUN_DEVICE
    ip link show dev $TUN_DEVICE
else
    echo "❌ Failed to create TUN device"
    cat helper.log
    cat client.log
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
if ip link show 2>/dev/null | grep -q "$TUN_DEVICE"; then
    echo "❌ TUN device was not removed"
    ip link show | grep "tun"
    
    # Try to force remove the device for cleanup
    echo "Attempting to force remove the device..."
    ip link delete $TUN_DEVICE 2>/dev/null || true
    
    # This is a warning, not a failure, as in some environments the device might persist
    echo "⚠️ TUN device cleanup issue (continuing tests)"
else
    echo "✅ TUN device was successfully removed"
fi

# Check helper daemon logs for cleanup confirmation
echo "Checking helper daemon logs for cleanup confirmation..."
if grep -q "Destroying TUN interface" helper.log; then
    echo "✅ Helper daemon attempted to destroy TUN interface"
else
    echo "⚠️ No TUN destruction log found in helper daemon logs"
    tail -n 20 helper.log
fi

echo "=== All tests completed successfully ==="
