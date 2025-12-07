#!/usr/bin/env bash
set -euo pipefail

# Test PSK auth end-to-end using env var overrides.
# - Starts core_engine (server) with PSK auth via env vars
# - Runs coentro_client to connect with the same PSK
# Requirements:
# - Rust toolchain + cargo
# - Helper daemon running and reachable at /var/run/coentrovpn/helper.sock (or override with --helper-socket)
# - One of: ss, lsof, or netstat for UDP readiness checks

usage() {
  cat <<EOF
Usage: $0 [--port <port>] [--bind <addr>] [--psk <hex|base64>] [--helper-socket <path>] [--cert <path>] [--key <path>] [--ca <path>]

Defaults:
  --port            4433
  --bind            127.0.0.1
  --helper-socket   /var/run/coentrovpn/helper.sock

Examples:
  $0 --port 4433
  $0 --psk "+c2b9Kx3n3uGk8B7wQ=="
  $0 --cert server.crt --key server.key --ca server.crt
EOF
}

PORT=4433
BIND=127.0.0.1
PSK=""
HELPER_SOCKET="/var/run/coentrovpn/helper.sock"
CERT=""
KEY=""
CA=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --port) PORT="$2"; shift 2;;
    --bind) BIND="$2"; shift 2;;
    --psk)  PSK="$2"; shift 2;;
    --helper-socket) HELPER_SOCKET="$2"; shift 2;;
    --cert) CERT="$2"; shift 2;;
    --key)  KEY="$2"; shift 2;;
    --ca)   CA="$2"; shift 2;;
    -h|--help) usage; exit 0;;
    *) echo "Unknown arg: $1"; usage; exit 1;;
  esac
done

if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo not found in PATH" >&2
  exit 1
fi

have() { command -v "$1" >/dev/null 2>&1; }

check_udp_ready() {
  local host="$1" port="$2"
  # Prefer ss if available (Linux)
  if have ss; then
    # Listening UDP sockets (-u -l), numeric (-n)
    ss -u -l -n | awk '{print $5}' | grep -E -- "(^|[^0-9])${host}:${port}($|[^0-9])" >/dev/null 2>&1 && return 0
  fi
  # Try lsof (macOS/Linux)
  if have lsof; then
    # lsof -iUDP@host:port returns rows when bound
    lsof -nP -iUDP@"${host}":"${port}" 2>/dev/null | grep -q -- "core_engine" && return 0
    # Fallback: any process bound at that UDP address
    lsof -nP -iUDP@"${host}":"${port}" 2>/dev/null | grep -q -- ":${port}" && return 0
  fi
  # Try netstat (BSD/macOS: -an -p udp, Linux: -anu)
  if have netstat; then
    if netstat -h 2>&1 | grep -q -- "-p proto"; then
      # BSD/macOS style
      netstat -an -p udp 2>/dev/null | grep -E -- "${host}\\.${port}.*\*\.\*" >/dev/null 2>&1 && return 0
      netstat -an -p udp 2>/dev/null | grep -E -- "${host}[.:]${port}" >/dev/null 2>&1 && return 0
    else
      # Linux style
      netstat -anu 2>/dev/null | grep -E -- "${host}:${port}" >/dev/null 2>&1 && return 0
    fi
  fi
  return 1
}

# Generate a random PSK (hex) if not provided
if [[ -z "$PSK" ]]; then
  if command -v openssl >/dev/null 2>&1; then
    PSK="$(openssl rand -hex 32)" # 32 bytes hex (64 hex chars)
  else
    # Fallback: use /dev/urandom + hexdump
    PSK="$(head -c 32 /dev/urandom | hexdump -ve '1/1 "%02x"')"
  fi
fi

echo "[*] Using PSK (hex/base64 supported by app): ${PSK}"
echo "[*] Server bind: ${BIND}:${PORT}"
echo "[*] Helper socket: ${HELPER_SOCKET}"

# Preflight: helper socket presence (warn only)
if [[ ! -S "$HELPER_SOCKET" ]]; then
  echo "[!] Helper socket not found at $HELPER_SOCKET"
  echo "    Start helper first (macOS): sudo ./scripts/install_helper_macos_direct.sh"
  echo "    Proceeding anyway; client may fail before QUIC handshake."
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
pushd "$REPO_ROOT" >/dev/null

# Export env overrides for the server
export COENTROVPN_ROLE=server
export COENTROVPN_NETWORK_BIND_ADDRESS="$BIND"
export COENTROVPN_NETWORK_PORT="$PORT"
export COENTROVPN_SECURITY_AUTH_MODE=psk
export COENTROVPN_SECURITY_AUTH_REQUIRED=true
export COENTROVPN_SECURITY_PSK="$PSK"

SERVER_LOG="$(mktemp -t coentro_server.XXXXXX.log)"
echo "[*] Starting core_engine (logs: $SERVER_LOG)"

set +e
TMP_TLS_DIR=""
# Use provided cert/key if supplied; otherwise generate a short‑lived CA and a server certificate (SAN=DNS:localhost)
if [[ -n "$CERT" || -n "$KEY" || -n "$CA" ]]; then
  if [[ -n "$CERT" && -n "$KEY" ]]; then
    if [[ ! -s "$CERT" || ! -s "$KEY" ]]; then
      echo "[!] Provided cert or key path is invalid or empty" >&2
      exit 1
    fi
    export COENTROVPN_SECURITY_CERT_PATH="$CERT"
    export COENTROVPN_SECURITY_KEY_PATH="$KEY"
    echo "[*] Using provided TLS cert/key"
  else
    echo "[!] If providing TLS material, both --cert and --key must be supplied." >&2
    exit 1
  fi
else
  if command -v openssl >/dev/null 2>&1; then
    TMP_TLS_DIR="$(mktemp -d -t coentro_tls.XXXXXX)"
    # 1) Generate CA key and self-signed CA cert
    openssl genpkey -algorithm RSA -out "${TMP_TLS_DIR}/ca.key" -pkeyopt rsa_keygen_bits:4096 >/dev/null 2>&1 || true
    openssl req -x509 -new -key "${TMP_TLS_DIR}/ca.key" -sha256 -days 2 -out "${TMP_TLS_DIR}/ca.crt" -subj "/CN=Coentro Local CA" >/dev/null 2>&1 || true

    # 2) Generate server key and CSR (CN=localhost)
    openssl genpkey -algorithm RSA -out "${TMP_TLS_DIR}/server.key" -pkeyopt rsa_keygen_bits:2048 >/dev/null 2>&1 || true
    openssl req -new -key "${TMP_TLS_DIR}/server.key" -out "${TMP_TLS_DIR}/server.csr" -subj "/CN=localhost" >/dev/null 2>&1 || true

    # 3) Create SAN ext file and sign server cert with CA (SAN=DNS:localhost)
    cat > "${TMP_TLS_DIR}/san.cnf" <<SAN
subjectAltName=DNS:localhost
basicConstraints=CA:FALSE
keyUsage=digitalSignature, keyEncipherment
extendedKeyUsage=serverAuth
SAN
    openssl x509 -req -in "${TMP_TLS_DIR}/server.csr" -CA "${TMP_TLS_DIR}/ca.crt" -CAkey "${TMP_TLS_DIR}/ca.key" -CAcreateserial -out "${TMP_TLS_DIR}/server.crt" -days 2 -sha256 -extfile "${TMP_TLS_DIR}/san.cnf" >/dev/null 2>&1 || true

    if [[ -s "${TMP_TLS_DIR}/server.crt" && -s "${TMP_TLS_DIR}/server.key" && -s "${TMP_TLS_DIR}/ca.crt" ]]; then
      export COENTROVPN_SECURITY_CERT_PATH="${TMP_TLS_DIR}/server.crt"
      export COENTROVPN_SECURITY_KEY_PATH="${TMP_TLS_DIR}/server.key"
      CA="${TMP_TLS_DIR}/ca.crt"
      echo "[*] Generated local CA and server cert at ${TMP_TLS_DIR}"
    else
      echo "[!] Failed to generate TLS CA/cert; please provide --cert/--key/--ca." >&2
      exit 1
    fi
  else
    echo "[!] openssl not found; please provide --cert/--key/--ca for TLS." >&2
    exit 1
  fi
fi

cargo run -p core_engine -- --config config.toml >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!
set -e

cleanup() {
  echo "[*] Cleaning up (server PID: $SERVER_PID)"
  if ps -p $SERVER_PID >/dev/null 2>&1; then
    kill $SERVER_PID 2>/dev/null || true
    wait $SERVER_PID 2>/dev/null || true
  fi
  if [[ -n "$TMP_TLS_DIR" && -d "$TMP_TLS_DIR" ]]; then
    rm -rf "$TMP_TLS_DIR"
  fi
}
trap cleanup EXIT INT TERM

# Wait for server port
echo -n "[*] Waiting for server UDP ${BIND}:${PORT} to be ready"
ready=0
for i in {1..60}; do
  if check_udp_ready "$BIND" "$PORT"; then ready=1; echo " - up"; break; fi
  echo -n "."; sleep 0.5
done
if [[ $ready -ne 1 ]]; then
  echo "\n[!] Server UDP socket not detected as ready. Tail log:" >&2
  tail -n 100 "$SERVER_LOG" >&2 || true
  exit 1
fi

echo "[*] Running client setup-tunnel (this may require helper)"
set +e
CLIENT_CA_ARG=()
if [[ -n "$CA" ]]; then
  CLIENT_CA_ARG=(--ca "$CA")
elif [[ -n "${COENTROVPN_SECURITY_CERT_PATH:-}" ]]; then
  # As a fallback for self-signed, use server cert as the CA
  CLIENT_CA_ARG=(--ca "$COENTROVPN_SECURITY_CERT_PATH")
fi
cargo run -p coentro_client -- \
  --log-level info \
  --helper-socket "$HELPER_SOCKET" \
  setup-tunnel \
  --server "${BIND}:${PORT}" \
  --psk "$PSK" \
  "${CLIENT_CA_ARG[@]}" \
  --ip 10.0.0.1/24 \
  --routes 0.0.0.0/0 \
  --dns 8.8.8.8 \
  --mtu 1500 \
  --no-wait
RC=$?
set -e

if [[ $RC -ne 0 ]]; then
  echo "[!] Client exited with status $RC. If helper wasn't running, this is expected."
  echo "    Server log tail (for auth-related errors):"
  tail -n 50 "$SERVER_LOG" || true
  exit $RC
fi

echo "[*] Client completed successfully. Stopping server and cleaning up."
cleanup
exit 0

popd >/dev/null
