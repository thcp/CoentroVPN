#!/bin/bash
# Test script for CoentroVPN tunnel functionality
# This script is meant to be run inside the client container

set -e  # Exit on error

echo "=== CoentroVPN Tunnel Test ==="

# Test 1: Authentication
echo "=== Test 1: Authentication ==="
echo "Checking socket permissions..."
ls -la /var/run/coentrovpn
echo "Socket should have permissions 600 (rw-------)"

echo "Testing connection to helper daemon..."
echo "Sending ping request to helper daemon..."
./target/debug/coentro_client --ping-helper
if [ $? -eq 0 ]; then
    echo "✅ Successfully connected to helper daemon"
else
    echo "❌ Failed to connect to helper daemon"
    exit 1
fi

# Test 2: Authentication with wrong user (skipped in Docker container)
echo "=== Test 2: Authentication with wrong user ==="
echo "Skipping test in Docker container (requires root privileges)"

# Test 3: Normal operation (skipped in Docker container)
echo "=== Test 3: Normal operation ==="
echo "Skipping test in Docker container (requires system modifications)"

echo "=== Test completed ==="
