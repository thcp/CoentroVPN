#!/bin/bash
# CoentroVPN Helper IPC Test Script
# This script tests the basic IPC functionality between the client and helper daemon.

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}CoentroVPN Helper IPC Test${NC}"
echo "This script tests the basic IPC functionality between the client and helper daemon."
echo

# Check if the helper daemon is installed
if [ ! -f "/usr/local/bin/coentro_helper" ]; then
    echo -e "${RED}Error: Helper daemon not installed${NC}"
    echo "Please run: sudo ./scripts/install_helper_macos_direct.sh"
    exit 1
fi

# Check if the helper daemon is running
if ! ps aux | grep -q "[c]oentro_helper"; then
    echo -e "${YELLOW}Warning: Helper daemon not running${NC}"
    echo "Installing helper daemon..."
    sudo ./scripts/install_helper_macos_direct.sh
fi

# Check if the socket exists
if [ ! -S "/var/run/coentrovpn/helper.sock" ]; then
    echo -e "${RED}Error: Helper socket not found${NC}"
    echo "Please check the helper daemon installation."
    exit 1
fi

# Check socket permissions
SOCKET_PERMS=$(ls -la /var/run/coentrovpn/helper.sock | awk '{print $1}')
if [[ "$SOCKET_PERMS" != "srwxrwxrwx"* ]]; then
    echo -e "${YELLOW}Warning: Socket permissions are not world-writable${NC}"
    echo "Current permissions: $SOCKET_PERMS"
    echo "This may cause permission issues when connecting to the helper daemon."
    echo "Fixing permissions..."
    sudo chmod 777 /var/run/coentrovpn/helper.sock
fi

echo -e "${YELLOW}Testing client-helper communication...${NC}"

# Run the client with ping-helper option
echo "Running: cargo run --package coentro_client -- --ping-helper"
OUTPUT=$(cargo run --package coentro_client -- --ping-helper 2>&1)

# Check if the ping was successful
if echo "$OUTPUT" | grep -q "Helper daemon is responsive"; then
    echo -e "${GREEN}Success: Client-helper communication is working${NC}"
    echo "Output:"
    echo "$OUTPUT"
    exit 0
else
    echo -e "${RED}Error: Client-helper communication failed${NC}"
    echo "Output:"
    echo "$OUTPUT"
    exit 1
fi
