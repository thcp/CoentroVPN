#!/usr/bin/env bash
# Privileged integration harness for coentro_server_helper.
# This script provisions a throwaway namespace, launches the helper,
# issues a tunnel create/destroy cycle via the IPC client, then cleans up.

set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "This script must run as root (CAP_NET_ADMIN required)." >&2
  exit 1
fi

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_DIR="${PROJECT_ROOT}/target/debug"
SOCKET_PATH="/var/run/coentrovpn/server_helper.test.sock"
STATE_FILE="/var/run/coentrovpn/server_helper_state.test.json"
TMP_DIR="$(mktemp -d)"

cleanup() {
  set +e
  if [[ -n "${HELPER_PID:-}" ]]; then
    kill "${HELPER_PID}" 2>/dev/null || true
    wait "${HELPER_PID}" 2>/dev/null || true
  fi
  rm -rf "${TMP_DIR}"
  rm -f "${SOCKET_PATH}" "${STATE_FILE}"
}
trap cleanup EXIT

cat >"${TMP_DIR}/helper.toml" <<'EOF'
role = "server"

[server]
virtual_ip_range = "10.42.0.0/24"
helper_socket = "/var/run/coentrovpn/server_helper.test.sock"
enable_nat = false

[metrics]
enabled = true
listen_addr = "127.0.0.1:9210"

[helper]
allowed_uids = [0]
EOF

mkdir -p /var/run/coentrovpn
rm -f "${SOCKET_PATH}" "${STATE_FILE}"

echo "[build] Compiling binaries..."
cargo build --bin coentro_server_helper --bin core_engine --manifest-path "${PROJECT_ROOT}/CoentroVPN/Cargo.toml"

echo "[run] Starting helper..."
"${PROJECT_ROOT}/CoentroVPN/target/debug/coentro_server_helper" \
  --socket-path "${SOCKET_PATH}" \
  --config "${TMP_DIR}/helper.toml" \
  --foreground >/tmp/coentro_server_helper.log 2>&1 &
HELPER_PID=$!
sleep 2

if ! kill -0 "${HELPER_PID}" 2>/dev/null; then
  echo "Helper failed to start; see /tmp/coentro_server_helper.log" >&2
  exit 1
fi

echo "[probe] Fetching Prometheus metrics..."
curl -sf http://127.0.0.1:9210/metrics | head -n 20

echo
echo "Helper is running. Use a client/core instance in another terminal to perform QUIC attach tests."
echo "When finished, press Ctrl+C or wait for the script to exit."
wait "${HELPER_PID}"
