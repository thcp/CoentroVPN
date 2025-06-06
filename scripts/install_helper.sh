#!/bin/bash
# CoentroVPN Helper Daemon Installation Script
# This script installs the CoentroVPN helper daemon and sets up the necessary permissions.

set -e

# Configuration
HELPER_NAME="coentro_helper"
INSTALL_DIR="/usr/local/bin"
SOCKET_DIR="/var/run/coentrovpn"
SYSTEMD_DIR="/etc/systemd/system"
SERVICE_NAME="coentrovpn-helper.service"

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
  
  # Stop and disable the systemd service
  if [ -f "${SYSTEMD_DIR}/${SERVICE_NAME}" ]; then
    echo "Stopping and disabling systemd service..."
    systemctl stop ${SERVICE_NAME} || true
    systemctl disable ${SERVICE_NAME} || true
    rm -f "${SYSTEMD_DIR}/${SERVICE_NAME}"
    systemctl daemon-reload
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
chmod 755 "${SOCKET_DIR}"

# Install the helper daemon
echo "Installing helper daemon to ${INSTALL_DIR}"
cp "$HELPER_PATH" "${INSTALL_DIR}/"
chmod 755 "${INSTALL_DIR}/${HELPER_NAME}"

# Create the systemd service file
echo "Creating systemd service file"
cat > "${SYSTEMD_DIR}/${SERVICE_NAME}" << EOF
[Unit]
Description=CoentroVPN Helper Daemon
After=network.target

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/${HELPER_NAME} --socket-path ${SOCKET_DIR}/helper.sock --foreground
Restart=on-failure
RestartSec=5
# Security settings
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=true
NoNewPrivileges=false  # The helper needs to create TUN interfaces
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
# Allow the helper to write to its socket directory
ReadWritePaths=${SOCKET_DIR}

[Install]
WantedBy=multi-user.target
EOF

# Enable and start the service
echo "Enabling and starting systemd service"
systemctl daemon-reload
systemctl enable ${SERVICE_NAME}
systemctl start ${SERVICE_NAME}

# Verify the service is running
if systemctl is-active --quiet ${SERVICE_NAME}; then
  echo -e "${GREEN}CoentroVPN helper daemon installed and running successfully${NC}"
else
  echo -e "${RED}Error: Failed to start helper daemon service${NC}"
  echo "Check the service status with: systemctl status ${SERVICE_NAME}"
  exit 1
fi

echo -e "${YELLOW}Note: The helper daemon is now running with elevated privileges${NC}"
echo "Socket path: ${SOCKET_DIR}/helper.sock"
echo -e "${GREEN}Installation complete!${NC}"
