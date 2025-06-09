#!/bin/bash
# CoentroVPN Helper Daemon Installation Script for macOS
# This script installs the CoentroVPN helper daemon and sets up the necessary permissions on macOS.

set -e

# Configuration
HELPER_NAME="coentro_helper"
INSTALL_DIR="/usr/local/bin"
SOCKET_DIR="/var/run/coentrovpn"
LAUNCHD_DIR="/Library/LaunchDaemons"
PLIST_NAME="co.coentrovpn.helper.plist"
LOG_DIR="/var/log/coentrovpn"

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
CONFIG_FILE="$(pwd)/config.toml"

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
    -c|--config)
      CONFIG_FILE="$2"
      shift 2
      ;;
    *)
      echo -e "${RED}Unknown option: $1${NC}"
      echo "Usage: $0 [--uninstall] [--debug] [-c|--config CONFIG_FILE]"
      exit 1
      ;;
  esac
done

# Function to uninstall the helper daemon
uninstall() {
  echo -e "${YELLOW}Uninstalling CoentroVPN helper daemon...${NC}"

  # Stop and unload the launchd service
  if [ -f "${LAUNCHD_DIR}/${PLIST_NAME}" ]; then
    echo "Stopping and unloading launchd service..."
    # Use bootout instead of unload for more complete removal
    launchctl bootout system "${LAUNCHD_DIR}/${PLIST_NAME}" 2>/dev/null || true
    rm -f "${LAUNCHD_DIR}/${PLIST_NAME}"
  else
    # Even if the plist file doesn't exist, try to bootout the service by label
    echo "Attempting to remove any existing service..."
    launchctl bootout system/co.coentrovpn.helper 2>/dev/null || true
  fi

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

# Clean up any existing installation first
echo -e "${YELLOW}Cleaning up any existing installation...${NC}"
# Try to bootout the service by label (don't exit on error)
launchctl bootout system/co.coentrovpn.helper 2>/dev/null || true
# Remove the plist file if it exists
if [ -f "${LAUNCHD_DIR}/${PLIST_NAME}" ]; then
  rm -f "${LAUNCHD_DIR}/${PLIST_NAME}"
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
chmod 755 "${SOCKET_DIR}"  # rwxr-xr-x - Executable by all, but only writable by owner

# Check if the coentrovpn group exists, create it if it doesn't
if ! dseditgroup -o read coentrovpn &>/dev/null; then
  echo -e "${YELLOW}Creating 'coentrovpn' group for socket access control${NC}"
  dseditgroup -o create -r "CoentroVPN Users" coentrovpn
  if [ $? -eq 0 ]; then
    echo -e "${GREEN}Successfully created 'coentrovpn' group${NC}"
  else
    echo -e "${YELLOW}Failed to create 'coentrovpn' group, socket will use default permissions${NC}"
  fi
else
  echo -e "${GREEN}Using existing 'coentrovpn' group for socket access control${NC}"
fi

# Set the socket directory group ownership to coentrovpn if the group exists
if dseditgroup -o read coentrovpn &>/dev/null; then
  echo "Setting socket directory group ownership to 'coentrovpn'"
  chown root:coentrovpn "${SOCKET_DIR}"
fi

# Create the log directory
echo "Creating log directory: ${LOG_DIR}"
mkdir -p "${LOG_DIR}"
chmod 755 "${LOG_DIR}"  # rwxr-xr-x - Executable by all, but only writable by owner

# Install the helper daemon
echo "Installing helper daemon to ${INSTALL_DIR}"
cp "$HELPER_PATH" "${INSTALL_DIR}/"
chmod 755 "${INSTALL_DIR}/${HELPER_NAME}"

# Copy the launchd plist file
echo "Installing launchd plist file"
echo "Using configuration file: ${CONFIG_FILE}"

# Copy the plist file from the scripts directory
cp "$(dirname "$0")/co.coentrovpn.helper.plist" "${LAUNCHD_DIR}/${PLIST_NAME}"

# Update the plist file with the correct paths
# First, fix the ProgramArguments array
sed -i '' "s|<string>/usr/local/bin/coentro_helper</string>|<string>${INSTALL_DIR}/${HELPER_NAME}</string>|g" "${LAUNCHD_DIR}/${PLIST_NAME}"
sed -i '' "s|<string>--socket-activation</string>|<string>--socket-activation</string>\n        <string>--config</string>\n        <string>${CONFIG_FILE}</string>|g" "${LAUNCHD_DIR}/${PLIST_NAME}"

# Update other paths
sed -i '' "s|/var/run/coentrovpn/helper.sock|${SOCKET_DIR}/helper.sock|g" "${LAUNCHD_DIR}/${PLIST_NAME}"
sed -i '' "s|/var/log/coentrovpn/helper.log|${LOG_DIR}/helper.log|g" "${LAUNCHD_DIR}/${PLIST_NAME}"

# Set the correct permissions for the plist file
chmod 644 "${LAUNCHD_DIR}/${PLIST_NAME}"

# Load and start the service
echo "Loading and starting launchd service"
# Use bootstrap without fallback to ensure clean state
launchctl bootstrap system "${LAUNCHD_DIR}/${PLIST_NAME}"

# Wait a moment for the service to start and create the socket
echo "Waiting for socket to be created..."
sleep 2

# Verify the socket was created with the correct permissions
if [ -S "${SOCKET_DIR}/helper.sock" ]; then
  PERMS=$(stat -f "%Lp" "${SOCKET_DIR}/helper.sock")
  if [ "$PERMS" != "660" ]; then
    echo -e "${YELLOW}Warning: Socket permissions are not 660 (rw-rw----)${NC}"
    echo "Current permissions: $PERMS"
    echo "Fixing socket permissions..."
    chmod 660 "${SOCKET_DIR}/helper.sock"
    
    # If the coentrovpn group exists, set the group ownership
    if dseditgroup -o read coentrovpn &>/dev/null; then
      echo "Setting socket group ownership to 'coentrovpn'"
      chown root:coentrovpn "${SOCKET_DIR}/helper.sock"
    fi
  fi
else
  echo -e "${YELLOW}Warning: Socket was not created at ${SOCKET_DIR}/helper.sock${NC}"
  echo "Check the helper daemon logs for errors"
fi

# Verify the service is running
if launchctl list | grep -q "co.coentrovpn.helper"; then
  echo -e "${GREEN}CoentroVPN helper daemon installed and running successfully${NC}"
else
  echo -e "${RED}Error: Failed to start helper daemon service${NC}"
  echo "Check the service status with: launchctl list | grep co.coentrovpn.helper"
  echo "Check the logs at: ${LOG_DIR}/helper.log"
  exit 1
fi

echo -e "${YELLOW}Note: The helper daemon is now running with elevated privileges${NC}"
echo "Socket path: ${SOCKET_DIR}/helper.sock (managed by launchd)"
echo -e "${GREEN}Installation complete!${NC}"

echo -e "${YELLOW}Important: On macOS, you may need to approve the helper in System Preferences > Security & Privacy${NC}"
echo "This is required for the helper to create network interfaces and modify routing tables."
