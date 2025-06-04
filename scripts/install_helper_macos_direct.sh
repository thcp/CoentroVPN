#!/bin/bash
# CoentroVPN Helper Daemon Installation Script for macOS (Direct Run Version)
# This script installs the CoentroVPN helper daemon and runs it directly without launchd.

set -e

# Configuration
HELPER_NAME="coentro_helper"
INSTALL_DIR="/usr/local/bin"
SOCKET_DIR="/var/run/coentrovpn"
LOG_FILE="/var/log/coentrovpn-helper.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Error: This script must be run as root${NC}"
  echo "Please run with sudo: sudo $0"
  exit 1
fi

# Parse command line arguments
UNINSTALL=false
DEBUG=false

while [[ $# -gt 0 ]]; do
  case $1 in
    --uninstall)
      UNINSTALL=true
      shift
      ;;
    --debug)
      DEBUG=true
      shift
      ;;
    *)
      echo -e "${RED}Unknown option: $1${NC}"
      echo "Usage: $0 [--uninstall] [--debug]"
      exit 1
      ;;
  esac
done

# Function to uninstall the helper daemon
uninstall() {
  echo -e "${YELLOW}Uninstalling CoentroVPN helper daemon...${NC}"
  
  # Kill any running helper daemon
  echo "Stopping any running helper daemon..."
  pkill -f "${INSTALL_DIR}/${HELPER_NAME}" || true
  
  # Remove the binary
  if [ -f "${INSTALL_DIR}/${HELPER_NAME}" ]; then
    echo "Removing helper binary..."
    rm -f "${INSTALL_DIR}/${HELPER_NAME}"
  fi
  
  # Remove the socket directory
  if [ -d "${SOCKET_DIR}" ]; then
    echo "Removing socket directory..."
    rm -rf "${SOCKET_DIR}"
  fi
  
  echo -e "${GREEN}CoentroVPN helper daemon uninstalled successfully${NC}"
  exit 0
}

# Uninstall if requested
if [ "$UNINSTALL" = true ]; then
  uninstall
fi

# Build the helper daemon
echo -e "${YELLOW}Building CoentroVPN helper daemon...${NC}"
cd "$(dirname "$0")/.."

if [ "$DEBUG" = true ]; then
  cargo build --package coentro_helper
  HELPER_PATH="./target/debug/${HELPER_NAME}"
else
  cargo build --release --package coentro_helper
  HELPER_PATH="./target/release/${HELPER_NAME}"
fi

if [ ! -f "$HELPER_PATH" ]; then
  echo -e "${RED}Error: Failed to build helper daemon${NC}"
  exit 1
fi

# Create the socket directory
echo "Creating socket directory: ${SOCKET_DIR}"
mkdir -p "${SOCKET_DIR}"
chmod 777 "${SOCKET_DIR}"  # Make it world-writable for testing

# Install the helper daemon
echo "Installing helper daemon to ${INSTALL_DIR}"
cp "$HELPER_PATH" "${INSTALL_DIR}/"
chmod 755 "${INSTALL_DIR}/${HELPER_NAME}"

# Kill any existing helper daemon
echo "Stopping any existing helper daemon..."
pkill -f "${INSTALL_DIR}/${HELPER_NAME}" || true

# Run the helper daemon directly in the background
echo "Starting helper daemon directly..."
nohup "${INSTALL_DIR}/${HELPER_NAME}" --socket-path "${SOCKET_DIR}/helper.sock" --foreground > "${LOG_FILE}" 2>&1 &
HELPER_PID=$!

# Wait a moment for the daemon to start
sleep 2

# Check if the daemon is running
if ps -p $HELPER_PID > /dev/null; then
  echo -e "${GREEN}CoentroVPN helper daemon started successfully with PID ${HELPER_PID}${NC}"
else
  echo -e "${RED}Error: Failed to start helper daemon${NC}"
  echo "Check the logs at: ${LOG_FILE}"
  exit 1
fi

echo -e "${YELLOW}Note: The helper daemon is now running with elevated privileges${NC}"
echo "Socket path: ${SOCKET_DIR}/helper.sock"
echo "Log file: ${LOG_FILE}"
echo -e "${GREEN}Installation complete!${NC}"

echo -e "${YELLOW}Important: On macOS, you may need to approve the helper in System Preferences > Security & Privacy${NC}"
echo "This is required for the helper to create network interfaces and modify routing tables."
echo ""
echo -e "${YELLOW}Note: This script runs the helper daemon directly without launchd.${NC}"
echo "The daemon will not automatically restart if it crashes or if the system is rebooted."
echo "To stop the daemon, run: sudo pkill -f ${INSTALL_DIR}/${HELPER_NAME}"
