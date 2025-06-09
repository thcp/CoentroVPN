#!/bin/bash
# CoentroVPN Authentication Test Script for macOS
# This script tests the authentication mechanism for the CoentroVPN helper daemon.

set -e

# Configuration
SOCKET_PATH="/var/run/coentrovpn/helper.sock"
TEST_USER="coentrovpn_test"
TEST_GROUP="coentrovpn"

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

# Function to clean up test user
cleanup() {
  echo -e "${YELLOW}Cleaning up test user and group...${NC}"
  
  # Delete the test user if it exists
  if dscl . -read /Users/$TEST_USER &>/dev/null; then
    echo "Deleting test user: $TEST_USER"
    dscl . -delete /Users/$TEST_USER
  fi
  
  echo -e "${GREEN}Cleanup complete${NC}"
}

# Register the cleanup function to run on script exit
trap cleanup EXIT

echo -e "${BLUE}=== CoentroVPN Authentication Test ===${NC}"

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

if [ "$PERMS" != "660" ]; then
  echo -e "${YELLOW}Warning: Socket permissions are not 660 (rw-rw----)${NC}"
  echo "Current permissions: $PERMS"
  echo "This may affect the authentication tests"
fi

# Check if the coentrovpn group exists
echo -e "${YELLOW}Checking if $TEST_GROUP group exists...${NC}"
if ! dseditgroup -o read $TEST_GROUP &>/dev/null; then
  echo -e "${RED}Error: $TEST_GROUP group does not exist${NC}"
  echo "Please create the group first"
  exit 1
fi

echo -e "${GREEN}$TEST_GROUP group exists${NC}"

# Create a test user
echo -e "${YELLOW}Creating test user: $TEST_USER${NC}"
if dscl . -read /Users/$TEST_USER &>/dev/null; then
  echo "Test user already exists, deleting it first"
  dscl . -delete /Users/$TEST_USER
fi

# Generate a random UID above 500
TEST_UID=$((500 + RANDOM % 1000))
while dscl . -list /Users UniqueID | awk '{print $2}' | grep -q "^$TEST_UID$"; do
  TEST_UID=$((500 + RANDOM % 1000))
done

# Create the user
dscl . -create /Users/$TEST_USER
dscl . -create /Users/$TEST_USER UserShell /bin/bash
dscl . -create /Users/$TEST_USER RealName "CoentroVPN Test User"
dscl . -create /Users/$TEST_USER UniqueID $TEST_UID
dscl . -create /Users/$TEST_USER PrimaryGroupID 20
dscl . -create /Users/$TEST_USER NFSHomeDirectory /Users/$TEST_USER
dscl . -passwd /Users/$TEST_USER "password"

echo -e "${GREEN}Test user created with UID $TEST_UID${NC}"

# Test 1: User not in coentrovpn group should fail to connect
echo -e "${BLUE}Test 1: User not in coentrovpn group should fail to connect${NC}"
echo -e "${YELLOW}Running test as $TEST_USER...${NC}"

# Run the test directly with sudo -u
echo "Attempting to connect to socket as user not in $TEST_GROUP group..."
if sudo -u $TEST_USER nc -U $SOCKET_PATH </dev/null >/dev/null 2>&1; then
  echo -e "${RED}FAIL: Connection succeeded, but should have failed${NC}"
  echo -e "${RED}Test 1 failed: User not in $TEST_GROUP group was able to connect${NC}"
  exit 1
else
  echo -e "${GREEN}PASS: Connection failed as expected${NC}"
  echo -e "${GREEN}Test 1 passed: User not in $TEST_GROUP group failed to connect${NC}"
fi

# Test 2: Add user to coentrovpn group and test connection
echo -e "${BLUE}Test 2: User in coentrovpn group should be able to connect${NC}"
echo -e "${YELLOW}Adding $TEST_USER to $TEST_GROUP group...${NC}"

# Add the test user to the coentrovpn group
dseditgroup -o edit -a $TEST_USER -t user $TEST_GROUP

echo -e "${GREEN}Added $TEST_USER to $TEST_GROUP group${NC}"

# Run the test directly with sudo -u
echo "Attempting to connect to socket as user in $TEST_GROUP group..."
if sudo -u $TEST_USER nc -U $SOCKET_PATH </dev/null >/dev/null 2>&1; then
  echo -e "${GREEN}PASS: Connection succeeded as expected${NC}"
  echo -e "${GREEN}Test 2 passed: User in $TEST_GROUP group was able to connect${NC}"
else
  echo -e "${RED}FAIL: Connection failed, but should have succeeded${NC}"
  echo -e "${RED}Test 2 failed: User in $TEST_GROUP group failed to connect${NC}"
  exit 1
fi

echo -e "${BLUE}=== All tests passed! ===${NC}"
echo -e "${GREEN}The authentication mechanism is working correctly${NC}"
