#!/bin/bash
# Test script for macOS launchd integration
# This script tests the installation, operation, and uninstallation of the helper daemon with launchd

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}CoentroVPN Helper Daemon launchd Integration Test${NC}"
echo "This script will test the installation, operation, and uninstallation of the helper daemon with launchd."
echo "It requires sudo privileges to install and uninstall the helper daemon."

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Error: This script must be run as root${NC}"
  echo "Please run with sudo: sudo $0"
  exit 1
fi

# Configuration
HELPER_SOCKET="/var/run/coentrovpn/helper.sock"
LAUNCHD_PLIST="/Library/LaunchDaemons/co.coentrovpn.helper.plist"
LOG_FILE="/var/log/coentrovpn/helper.log"

# Function to clean up in case of failure
cleanup() {
  echo -e "${YELLOW}Cleaning up...${NC}"
  
  # Uninstall the helper daemon
  echo "Uninstalling helper daemon..."
  ./scripts/install_helper_macos.sh --uninstall
  
  echo -e "${RED}Test failed!${NC}"
  exit 1
}

# Set up trap to clean up on script exit due to error
trap cleanup ERR

echo -e "${YELLOW}Step 1: Building and installing the helper daemon...${NC}"
./scripts/install_helper_macos.sh

echo -e "${YELLOW}Step 2: Verifying launchd service is running...${NC}"
if launchctl list | grep -q "co.coentrovpn.helper"; then
  echo -e "${GREEN}launchd service is running.${NC}"
else
  echo -e "${RED}Error: launchd service is not running!${NC}"
  echo "Check the service status with: launchctl list | grep co.coentrovpn.helper"
  echo "Check the logs at: $LOG_FILE"
  cleanup
fi

echo -e "${YELLOW}Step 3: Checking if the socket file exists...${NC}"
if [ -S "$HELPER_SOCKET" ]; then
  echo -e "${GREEN}Socket file exists.${NC}"
else
  echo -e "${RED}Error: Socket file does not exist!${NC}"
  echo "Expected socket at: $HELPER_SOCKET"
  cleanup
fi

echo -e "${YELLOW}Step 4: Testing connection to the helper daemon...${NC}"
echo "Building client..."
cargo build --package coentro_client

echo "Pinging helper daemon..."
if sudo ./target/debug/coentro_client --ping-helper; then
  echo -e "${GREEN}Successfully connected to helper daemon.${NC}"
else
  echo -e "${RED}Error: Failed to connect to helper daemon!${NC}"
  echo "Check the logs at: $LOG_FILE"
  cleanup
fi

echo -e "${YELLOW}Step 5: Getting helper daemon status...${NC}"
if sudo ./target/debug/coentro_client; then
  echo -e "${GREEN}Successfully retrieved helper daemon status.${NC}"
else
  echo -e "${RED}Error: Failed to get helper daemon status!${NC}"
  echo "Check the logs at: $LOG_FILE"
  cleanup
fi

echo -e "${YELLOW}Step 6: Uninstalling the helper daemon...${NC}"
./scripts/install_helper_macos.sh --uninstall

echo -e "${YELLOW}Step 7: Verifying launchd service is stopped...${NC}"
if launchctl list | grep -q "co.coentrovpn.helper"; then
  echo -e "${RED}Error: launchd service is still running!${NC}"
  echo "Check the service status with: launchctl list | grep co.coentrovpn.helper"
  exit 1
else
  echo -e "${GREEN}launchd service is stopped.${NC}"
fi

echo -e "${YELLOW}Step 8: Checking if the socket file is removed...${NC}"
if [ -S "$HELPER_SOCKET" ]; then
  echo -e "${RED}Error: Socket file still exists!${NC}"
  echo "Socket file: $HELPER_SOCKET"
  exit 1
else
  echo -e "${GREEN}Socket file is removed.${NC}"
fi

echo -e "${GREEN}All tests passed successfully!${NC}"
echo "The helper daemon has been successfully integrated with launchd."
