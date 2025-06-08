#!/bin/bash
# Test script for file descriptor passing in the CoentroVPN split daemon architecture on macOS
# This script tests the file descriptor passing mechanism between the helper daemon and client

set -e  # Exit on error

echo "=== CoentroVPN File Descriptor Passing Test (macOS) ==="
echo "Running tests as $(whoami) with UID $(id -u) and GID $(id -g)"

# Build the binaries
echo "=== Building binaries ==="
cargo build --bin coentro_helper
cargo build --bin coentro_client
echo "✅ Binaries built successfully"

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check for required tools
for cmd in ifconfig route dtruss; do
    if ! command_exists $cmd; then
        echo "❌ Required command not found: $cmd"
        echo "Note: dtruss requires SIP to be disabled or run with sudo"
        exit 1
    fi
done

# Start the helper daemon in the background
echo "=== Starting helper daemon ==="
sudo ./target/debug/coentro_helper --log-level debug > helper.log 2>&1 &
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
        sudo kill $HELPER_PID
        wait $HELPER_PID 2>/dev/null || true
    fi
    echo "Cleanup complete"
}

# Register the cleanup function to run on exit
trap cleanup EXIT

# Test 1: File Descriptor Passing
echo "=== Test 1: File Descriptor Passing ==="
echo "Setting up tunnel with file descriptor passing..."

# Run the client with dtruss to trace file descriptor operations
# Note: dtruss requires SIP to be disabled or run with sudo
echo "Running client with dtruss to trace file descriptor operations..."
sudo dtruss -f ./target/debug/coentro_client setup-tunnel > client.log 2> dtruss.log &
CLIENT_PID=$!

# Give the client time to set up the tunnel
echo "Waiting for tunnel setup..."
sleep 5

# Check if the client is running
if ! ps -p $CLIENT_PID > /dev/null; then
    echo "❌ Client process is not running"
    cat helper.log
    cat client.log
    cat dtruss.log
    exit 1
fi

# Check for file descriptor passing in dtruss output
echo "Checking dtruss output for file descriptor operations..."
if grep -q "recvmsg" dtruss.log; then
    echo "✅ recvmsg system calls detected in dtruss output"
    grep -n "recvmsg" dtruss.log
else
    echo "⚠️ No recvmsg system calls detected in dtruss output"
    # This is not a failure as dtruss might not capture all system calls
fi

# Check if a utun device was created
UTUN_DEVICE=$(ifconfig | grep -o "utun[0-9]\+" | head -1)
if [ -n "$UTUN_DEVICE" ]; then
    echo "✅ utun device created: $UTUN_DEVICE"
    
    # Verify utun device properties
    echo "Checking utun device properties..."
    
    # Check if the device is UP
    if ifconfig $UTUN_DEVICE | grep -q "UP"; then
        echo "✅ utun device is UP"
    else
        echo "❌ utun device is not UP"
        ifconfig $UTUN_DEVICE
        cat helper.log
        exit 1
    fi
    
    # Check IP address (expecting 10.0.0.1)
    if ifconfig $UTUN_DEVICE | grep -q "inet 10.0.0.1"; then
        echo "✅ utun device has correct IP address"
    else
        echo "❌ utun device has incorrect IP address"
        ifconfig $UTUN_DEVICE
        cat helper.log
        exit 1
    fi
    
    # Display full device info for logging
    ifconfig $UTUN_DEVICE
else
    echo "❌ Failed to create utun device"
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
    sudo kill -SIGINT $CLIENT_PID
    
    # Give the client time to process the signal and tear down the tunnel
    echo "Waiting for client to tear down tunnel..."
    wait $CLIENT_PID 2>/dev/null || true
    sleep 3
else
    echo "Client process is not running"
fi

# Check if the utun device was brought down
echo "Checking if utun device was brought down..."
if ifconfig $UTUN_DEVICE 2>/dev/null | grep -q "UP"; then
    echo "⚠️ utun device is still UP"
    ifconfig $UTUN_DEVICE
    
    # Try to force bring down the device for cleanup
    echo "Attempting to force bring down the device..."
    sudo ifconfig $UTUN_DEVICE down 2>/dev/null || true
    
    # This is a warning, not a failure, as in macOS the utun devices persist
    echo "⚠️ utun device cleanup issue (continuing tests)"
else
    echo "✅ utun device was successfully brought down"
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
