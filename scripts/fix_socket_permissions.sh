#!/bin/bash
# CoentroVPN Socket Permissions Fix Script for macOS
# This script fixes the permissions of the CoentroVPN helper socket.

set -e

# Configuration
SOCKET_PATH="/var/run/coentrovpn/helper.sock"
SOCKET_DIR="/var/run/coentrovpn"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Error: This script must be run as root${NC}"
  echo "Please run with sudo: sudo $0"
  exit 1
fi

echo -e "${BLUE}=== CoentroVPN Socket Permissions Fix ===${NC}"

# Check if the helper daemon is running
echo -e "${YELLOW}Checking if helper daemon is running...${NC}"
if ! launchctl list | grep -q "co.coentrovpn.helper"; then
  echo -e "${RED}Error: Helper daemon is not running${NC}"
  echo "Please install and start the helper daemon first"
  exit 1
fi

echo -e "${GREEN}Helper daemon is running${NC}"

# Check if the socket exists
echo -e "${YELLOW}Checking if socket exists...${NC}"
if [ ! -S "$SOCKET_PATH" ]; then
  echo -e "${RED}Error: Socket does not exist at $SOCKET_PATH${NC}"
  echo "Please check the helper daemon logs"
  exit 1
fi

echo -e "${GREEN}Socket exists at $SOCKET_PATH${NC}"

# Check socket permissions
echo -e "${YELLOW}Checking socket permissions...${NC}"
PERMS=$(stat -f "%Lp" "$SOCKET_PATH")
OWNER=$(stat -f "%u:%g" "$SOCKET_PATH")
echo "Socket permissions: $PERMS"
echo "Socket owner: $OWNER"

# Check if the coentrovpn group exists
echo -e "${YELLOW}Checking if coentrovpn group exists...${NC}"
if ! dseditgroup -o read coentrovpn &>/dev/null; then
  echo -e "${YELLOW}Creating 'coentrovpn' group for socket access control${NC}"
  dseditgroup -o create -r "CoentroVPN Users" coentrovpn
  if [ $? -eq 0 ]; then
    echo -e "${GREEN}Successfully created 'coentrovpn' group${NC}"
  else
    echo -e "${RED}Failed to create 'coentrovpn' group${NC}"
    exit 1
  fi
else
  echo -e "${GREEN}coentrovpn group exists${NC}"
fi

# Fix socket permissions
echo -e "${YELLOW}Setting socket permissions to 660 (rw-rw----)${NC}"
chmod 660 "$SOCKET_PATH"

# Set socket group ownership
echo -e "${YELLOW}Setting socket group ownership to coentrovpn${NC}"
chown root:coentrovpn "$SOCKET_PATH"

# Set socket directory group ownership
echo -e "${YELLOW}Setting socket directory group ownership to coentrovpn${NC}"
chown root:coentrovpn "$SOCKET_DIR"

# Verify the changes
PERMS=$(stat -f "%Lp" "$SOCKET_PATH")
OWNER=$(stat -f "%u:%g" "$SOCKET_PATH")
echo -e "${GREEN}Socket permissions updated:${NC}"
echo "New permissions: $PERMS"
echo "New owner: $OWNER"

echo -e "${BLUE}=== Socket permissions fixed successfully ===${NC}"
echo -e "${YELLOW}Note: Users must be in the 'coentrovpn' group to access the socket${NC}"
echo "To add a user to the group, run:"
echo "sudo dseditgroup -o edit -a USERNAME -t user coentrovpn"
