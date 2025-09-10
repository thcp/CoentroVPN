#!/bin/bash
# CoentroVPN macOS smoke test: helper install, IPC ping, utun setup/verify, QUIC echo, cleanup
set -euo pipefail

BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}== CoentroVPN macOS smoke test ==${NC}"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo -e "${RED}This script is intended for macOS (Darwin). Aborting.${NC}" >&2
  exit 1
fi

# Move to repo root based on script location
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
cd "$REPO_ROOT"

SOCKET_DIR="/var/run/coentrovpn"
SOCKET_PATH="$SOCKET_DIR/helper.sock"

CLIENT_CMD=(cargo run -p coentro_client --)

cleanup() {
  if [[ -n "${SETUP_PID:-}" ]] && ps -p "$SETUP_PID" >/dev/null 2>&1; then
    echo -e "${YELLOW}Sending SIGINT to client setup (PID $SETUP_PID) for teardown...${NC}"
    kill -INT "$SETUP_PID" || true
    wait "$SETUP_PID" || true
  fi
  echo -e "${GREEN}Cleanup completed.${NC}"
}
trap cleanup EXIT

echo -e "${BLUE}[1/6] Installing helper (direct mode)${NC}"
if [[ $EUID -ne 0 ]]; then
  echo -e "${YELLOW}Elevated privileges required to install helper. Prompting for sudo...${NC}"
  sudo ./scripts/install_helper_macos_direct.sh
else
  ./scripts/install_helper_macos_direct.sh
fi

echo -e "${BLUE}[2/6] Verifying helper socket and permissions${NC}"
if [[ ! -S "$SOCKET_PATH" ]]; then
  echo -e "${RED}Helper socket not found at $SOCKET_PATH${NC}" >&2
  exit 1
fi
ls -la "$SOCKET_PATH"

echo -e "${BLUE}[3/6] Pinging helper via client IPC${NC}"
"${CLIENT_CMD[@]}" --ping-helper
echo -e "${GREEN}Helper ping successful.${NC}"

echo -e "${BLUE}[4/6] Setting up tunnel (utun) in background${NC}"
set +e
"${CLIENT_CMD[@]}" setup-tunnel --ip 10.0.0.1/24 &
SETUP_PID=$!
set -e
echo "Client setup PID: $SETUP_PID"

sleep 2
echo -e "${BLUE}Checking utun devices...${NC}"
ifconfig | grep -E '^utun[0-9]:' || echo -e "${YELLOW}No utun found yet; setup may still be initializing.${NC}"

echo -e "${BLUE}[5/6] Running QUIC echo example (single-process) with dev TLS feature${NC}"
cargo run -p shared_utils --features insecure-tls --example quic_example

echo -e "${BLUE}[6/6] Tearing down tunnel${NC}"
if [[ -n "$SETUP_PID" ]] && ps -p "$SETUP_PID" >/dev/null 2>&1; then
  kill -INT "$SETUP_PID" || true
  wait "$SETUP_PID" || true
else
  echo -e "${YELLOW}Setup process no longer running; skipping SIGINT.${NC}"
fi

echo -e "${GREEN}Smoke test completed successfully.${NC}"
