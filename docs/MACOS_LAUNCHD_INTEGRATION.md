# macOS launchd Integration Guide

This document describes the integration of the CoentroVPN helper daemon with macOS launchd, including socket activation, service management, and security considerations.

## Overview

The CoentroVPN helper daemon runs with elevated privileges to manage network interfaces and routing tables. On macOS, we use launchd to:

1. Start the helper daemon automatically at system boot
2. Restart the daemon if it crashes
3. Provide socket activation for on-demand launching
4. Manage socket permissions and lifecycle

## Installation

The helper daemon is installed using the `scripts/install_helper_macos.sh` script, which:

1. Builds the helper daemon
2. Installs it to `/usr/local/bin`
3. Creates necessary directories for sockets and logs
4. Installs a launchd property list file
5. Loads and starts the service

```bash
sudo ./scripts/install_helper_macos.sh
```

## Uninstallation

To uninstall the helper daemon:

```bash
sudo ./scripts/install_helper_macos.sh --uninstall
```

## Socket Activation

Socket activation is a feature of launchd that allows the daemon to be started on-demand when a client connects to its socket. This saves system resources as the daemon only runs when needed.

### How Socket Activation Works

1. launchd creates the socket file at the specified path
2. When a client connects to the socket, launchd starts the daemon
3. launchd passes the socket file descriptor to the daemon
4. The daemon accepts connections on the pre-created socket

### Implementation Details

The helper daemon detects socket activation by:

1. Checking for launchd-specific environment variables
2. Retrieving the socket file descriptor from launchd
3. Using the socket for IPC communication

## Security Considerations

### Socket Permissions and Authentication

The socket uses restricted permissions (660 or rw-rw----) to limit access to authorized users and groups. This is configured in the launchd plist file:

```xml
<key>SockPathMode</key>
<integer>384</integer> <!-- Corresponds to 0660 permissions -->
```

If you need to fix the socket permissions on an existing installation, you can use the provided script:

```bash
sudo ./scripts/fix_socket_permissions.sh
```

This script will:
1. Check if the socket exists and its current permissions
2. Create the "coentrovpn" group if it doesn't exist
3. Set the socket permissions to 660 (rw-rw----)
4. Set the socket group ownership to "coentrovpn"

#### Authentication Mechanisms

The helper daemon implements several layers of authentication:

1. **File Permissions**: The socket file permissions (0660) restrict access to the owner and group.
2. **UID/GID Verification**: The helper daemon verifies the UID/GID of connecting clients to ensure they are authorized.
3. **Group-Based Access Control**: Users in the "coentrovpn" group are granted access to the socket.

#### Creating the "coentrovpn" Group

For optimal security, create a dedicated "coentrovpn" group and add authorized users to it:

```bash
# Create the group (requires root)
sudo dseditgroup -o create -r "CoentroVPN Users" coentrovpn

# Add a user to the group
sudo dseditgroup -o edit -a username -t user coentrovpn
```

#### Authentication Implementation Details

The authentication process works as follows:

1. When a client connects, the helper daemon retrieves the client's UID and GID using `getsockopt` with `LOCAL_PEERCRED`.
2. The daemon checks if the client's UID is in the list of allowed UIDs or if the client's GID is in the list of allowed GIDs.
3. If the client is authorized, the connection is accepted; otherwise, it is rejected with an authentication error.

#### Security Best Practices

1. **Principle of Least Privilege**: Only add users to the "coentrovpn" group if they need to use the VPN.
2. **Regular Auditing**: Periodically review the members of the "coentrovpn" group.
3. **Secure Default Configuration**: The default configuration only allows the root user and members of the "coentrovpn" group.
4. **Defense in Depth**: Multiple layers of security (file permissions, UID/GID verification) provide robust protection.

### Future Security Enhancements

Planned security enhancements include:

1. **Token-based Authentication**: A token-based authentication system may be implemented for more granular access control.
2. **Rate Limiting**: Implement rate limiting to prevent brute force attacks.
3. **Audit Logging**: Add comprehensive audit logging for security events.

## Troubleshooting

### Checking Service Status

```bash
sudo launchctl list | grep co.coentrovpn.helper
```

### Viewing Logs

```bash
cat /var/log/coentrovpn/helper.log
```

### Common Issues

1. **Service fails to start**: Check the logs for errors. Ensure the helper binary exists and has the correct permissions.
2. **Socket file not created**: Verify that the socket directory exists and has the correct permissions.
3. **Client cannot connect**: Check socket permissions and ensure the client has the necessary privileges. Common solutions:
   - Verify the socket has 660 permissions: `ls -la /var/run/coentrovpn/helper.sock`
   - Ensure the socket is owned by root:coentrovpn: `ls -la /var/run/coentrovpn/helper.sock`
   - Check if the user is in the coentrovpn group: `groups username`
   - Add the user to the coentrovpn group if needed: `sudo dseditgroup -o edit -a username -t user coentrovpn`
   - Run the fix_socket_permissions.sh script: `sudo ./scripts/fix_socket_permissions.sh`
4. **Socket has incorrect permissions**: If the socket has incorrect permissions (e.g., 666 instead of 660), run the fix_socket_permissions.sh script to correct them.

## Testing

### Launchd Integration Testing

A comprehensive test script is provided to verify the launchd integration:

```bash
sudo ./scripts/test_launchd_integration.sh
```

This script tests:
1. Installation and service startup
2. Socket file creation
3. Client connection to the helper daemon
4. Helper daemon status retrieval
5. Uninstallation and cleanup

### Authentication Testing

A dedicated test script is provided to verify the authentication mechanism:

```bash
sudo ./scripts/test_auth_macos.sh
```

This script tests:
1. Socket permissions verification
2. Creation of a test user not in the "coentrovpn" group
3. Verification that the test user cannot connect to the socket
4. Addition of the test user to the "coentrovpn" group
5. Verification that the test user can now connect to the socket
6. Cleanup of the test user

This test ensures that the group-based authentication mechanism is working correctly and that only authorized users can connect to the helper daemon.

## Implementation Notes

### Socket Activation in Code

The helper daemon's socket activation code is in `coentro_helper/src/main.rs`. It:

1. Checks for launchd environment variables
2. Retrieves the socket file descriptor
3. Uses the socket for IPC communication

### Launchd Property List

The launchd property list file (`co.coentrovpn.helper.plist`) defines:

1. The program to run and its arguments
2. Socket configuration
3. Log file paths
4. Service behavior (keep-alive, run at load)
5. User and group for the daemon process

## Future Improvements

1. **Enhance UID/GID verification** with additional security checks
2. **Implement system sleep/wake event handling** for better service reliability
3. **Add more robust error handling** for socket activation
4. **Implement token-based authentication** for more granular access control
5. **Add comprehensive audit logging** for security events
