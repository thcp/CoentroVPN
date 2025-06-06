#!/bin/bash
# CoentroVPN Helper Daemon Installation Script for macOS
# This script installs the CoentroVPN helper daemon and sets up the necessary permissions on macOS.

set -e

# Configuration
HELPER_NAME="coentro_helper"
INSTALL_DIR="/usr/local/bin"
SOCKET_DIR="/var/run/coentrovpn"
LAUNCHD_DIR="/Library/LaunchDaemons"
PLIST_NAME="com.coentrovpn.helper.plist"

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
    launchctl unload "${LAUNCHD_DIR}/${PLIST_NAME}" || true
    rm -f "${LAUNCHD_DIR}/${PLIST_NAME}"
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

# Install the helper daemon
echo "Installing helper daemon to ${INSTALL_DIR}"
cp "$HELPER_PATH" "${INSTALL_DIR}/"
chmod 755 "${INSTALL_DIR}/${HELPER_NAME}"

# Create the launchd plist file
echo "Creating launchd plist file"
echo "Using configuration file: ${CONFIG_FILE}"
cat > "${LAUNCHD_DIR}/${PLIST_NAME}" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.coentrovpn.helper</string>
    <key>ProgramArguments</key>
    <array>
        <string>${INSTALL_DIR}/${HELPER_NAME}</string>
        <string>--socket-path</string>
        <string>${SOCKET_DIR}/helper.sock</string>
        <string>--foreground</string>
        <string>--config</string>
        <string>${CONFIG_FILE}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>/var/log/coentrovpn-helper.log</string>
    <key>StandardOutPath</key>
    <string>/var/log/coentrovpn-helper.log</string>
    <key>ProcessType</key>
    <string>Interactive</string>
    <key>WorkingDirectory</key>
    <string>/</string>
</dict>
</plist>
EOF

# Set the correct permissions for the plist file
chmod 644 "${LAUNCHD_DIR}/${PLIST_NAME}"

# Load and start the service
echo "Loading and starting launchd service"
launchctl bootstrap system "${LAUNCHD_DIR}/${PLIST_NAME}" || launchctl load "${LAUNCHD_DIR}/${PLIST_NAME}"

# Verify the service is running
if launchctl list | grep -q "com.coentrovpn.helper"; then
  echo -e "${GREEN}CoentroVPN helper daemon installed and running successfully${NC}"
else
  echo -e "${RED}Error: Failed to start helper daemon service${NC}"
  echo "Check the service status with: launchctl list | grep com.coentrovpn.helper"
  echo "Check the logs at: /var/log/coentrovpn-helper.log"
  exit 1
fi

echo -e "${YELLOW}Note: The helper daemon is now running with elevated privileges${NC}"
echo "Socket path: ${SOCKET_DIR}/helper.sock"
echo -e "${GREEN}Installation complete!${NC}"

echo -e "${YELLOW}Important: On macOS, you may need to approve the helper in System Preferences > Security & Privacy${NC}"
echo "This is required for the helper to create network interfaces and modify routing tables."
