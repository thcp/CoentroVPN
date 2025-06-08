#!/bin/bash
# Test script for TUN interface configuration on macOS

set -e  # Exit on error

echo "=== CoentroVPN TUN Interface Test (macOS) ==="
echo "Running tests as $(whoami) with UID $(id -u) and GID $(id -g)"

# Create and configure a TUN interface
echo "=== Creating and configuring TUN interface ==="

# Try to open a TUN device
TUN_DEVICE="utun0"
echo "Using TUN device: $TUN_DEVICE"

# Bring the interface up
echo "Bringing up the interface..."
sudo ifconfig $TUN_DEVICE up mtu 1500

# Configure the IP address using different approaches
echo "Configuring IP address..."

# Approach 1: Use ifconfig with inet and dest_ip
echo "Approach 1: Using ifconfig with inet and dest_ip..."
sudo ifconfig $TUN_DEVICE inet 10.0.0.1 10.0.0.2 netmask 255.255.255.0
ifconfig $TUN_DEVICE

# Approach 2: Use ifconfig with alias
echo "Approach 2: Using ifconfig with alias..."
sudo ifconfig $TUN_DEVICE inet 10.0.0.1/24 alias
ifconfig $TUN_DEVICE

# Approach 3: Use networksetup
echo "Approach 3: Using networksetup..."
sudo networksetup -setmanual $TUN_DEVICE 10.0.0.1 255.255.255.0 10.0.0.2
ifconfig $TUN_DEVICE

# Approach 4: Use ifconfig with different syntax
echo "Approach 4: Using ifconfig with different syntax..."
sudo ifconfig $TUN_DEVICE 10.0.0.1 10.0.0.2 netmask 255.255.255.0
ifconfig $TUN_DEVICE

# Approach 5: Use ifconfig with add
echo "Approach 5: Using ifconfig with add..."
sudo ifconfig $TUN_DEVICE add 10.0.0.1/24
ifconfig $TUN_DEVICE

# Approach 6: Use ifconfig with different order
echo "Approach 6: Using ifconfig with different order..."
sudo ifconfig $TUN_DEVICE netmask 255.255.255.0 inet 10.0.0.1 10.0.0.2
ifconfig $TUN_DEVICE

# Approach 7: Use ifconfig with peer
echo "Approach 7: Using ifconfig with peer..."
sudo ifconfig $TUN_DEVICE inet 10.0.0.1 255.255.255.0 10.0.0.2
ifconfig $TUN_DEVICE

# Approach 8: Use ifconfig with peer and netmask
echo "Approach 8: Using ifconfig with peer and netmask..."
sudo ifconfig $TUN_DEVICE inet 10.0.0.1 netmask 255.255.255.0 peer 10.0.0.2
ifconfig $TUN_DEVICE

# Approach 9: Use ifconfig with different order
echo "Approach 9: Using ifconfig with different order..."
sudo ifconfig $TUN_DEVICE inet 10.0.0.1 10.0.0.2
ifconfig $TUN_DEVICE

# Clean up
echo "=== Cleaning up ==="
sudo ifconfig $TUN_DEVICE down
echo "TUN interface brought down"

echo "=== Test completed ==="
