# Testing CoentroVPN on macOS

This document provides instructions for testing the CoentroVPN split daemon architecture on macOS.

## Prerequisites

- macOS 10.15 or later
- Rust toolchain installed
- Administrative privileges (for creating TUN interfaces and modifying routing tables)
- SIP (System Integrity Protection) disabled or partially disabled for using `dtruss` (optional, for advanced debugging)

## Building the Project

```bash
# Clone the repository
git clone https://github.com/your-username/CoentroVPN.git
cd CoentroVPN

# Build the project
cargo build
```

## Testing File Descriptor Passing

The file descriptor passing mechanism is a critical component of the split daemon architecture. It allows the privileged helper daemon to create a TUN interface and pass the file descriptor to the unprivileged client.

### Automated Testing

We provide a script to automate the testing of file descriptor passing on macOS:

```bash
# Make the script executable if needed
chmod +x scripts/test_fd_passing_macos.sh

# Run the test script
./scripts/test_fd_passing_macos.sh
```

The script will:
1. Build the necessary binaries
2. Start the helper daemon with root privileges
3. Run the client with `dtruss` to trace system calls (requires SIP to be disabled)
4. Verify that a utun device is created with the correct configuration
5. Test cleanup when the client disconnects
6. Check logs for proper operation

### Manual Testing

If you prefer to test manually or if the automated script doesn't work for your environment:

1. Start the helper daemon with root privileges:
   ```bash
   sudo ./target/debug/coentro_helper --log-level debug
   ```

2. In another terminal, run the client:
   ```bash
   ./target/debug/coentro_client setup-tunnel
   ```

3. Verify that a utun device is created:
   ```bash
   ifconfig | grep utun
   ```

4. Check the IP address and status of the utun device:
   ```bash
   ifconfig utunX  # Replace X with the number from step 3
   ```

5. Test routing by adding a route:
   ```bash
   ./target/debug/coentro_client setup-tunnel --routes 192.168.1.0/24
   ```

6. Verify the route was added:
   ```bash
   netstat -nr | grep 192.168.1
   ```

7. Tear down the tunnel:
   ```bash
   ./target/debug/coentro_client teardown-tunnel
   ```

8. Verify the utun device is down:
   ```bash
   ifconfig utunX  # Should show the device is DOWN
   ```

## Troubleshooting

### Common Issues

1. **Permission Denied**: Make sure you're running the helper daemon with root privileges.

2. **Socket Connection Failed**: Check if the socket directory exists and has the correct permissions:
   ```bash
   sudo mkdir -p /var/run/coentrovpn
   sudo chmod 777 /var/run/coentrovpn  # For testing only, use 755 in production
   ```

3. **TUN Device Creation Failed**: Ensure you have the proper permissions:
   ```bash
   ls -la /dev/utun*
   ```

4. **dtruss Not Working**: SIP might be enabled. You can partially disable it for developer tools:
   ```bash
   # Reboot into recovery mode (hold Cmd+R during startup)
   csrutil enable --without dtrace
   ```

### Logs

Check the logs for more detailed information:

- Helper daemon logs: By default, these go to stdout/stderr
- Client logs: By default, these go to stdout/stderr
- System logs: Use `log show --predicate 'process == "coentro_helper"'` to view system logs

## Advanced Debugging

For advanced debugging of file descriptor passing:

1. Use `dtruss` to trace system calls (requires SIP to be disabled):
   ```bash
   sudo dtruss -f -t recvmsg ./target/debug/coentro_client setup-tunnel
   ```

2. Look for `recvmsg` calls with `SCM_RIGHTS` control messages, which indicate file descriptor passing.

3. Check the file descriptors in use by the client:
   ```bash
   lsof -p $(pgrep coentro_client)
   ```

4. Monitor network interfaces in real-time:
   ```bash
   watch -n 1 'ifconfig | grep utun'
   ```
