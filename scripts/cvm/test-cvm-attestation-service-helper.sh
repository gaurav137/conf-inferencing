#!/usr/bin/env bash
set -euo pipefail

# Helper script that runs ON the CVM itself.
# Starts cvm-attestation-service, calls POST /attest, saves response, and stops the server.
#
# Usage: sudo ./cvm-attest-helper.sh <request-json-file> <response-json-file> [port]

if [[ $# -lt 2 ]]; then
    echo "Usage: $0 <request-json-file> <response-json-file> [port]" >&2
    exit 1
fi

REQUEST_FILE="$1"
RESPONSE_FILE="$2"
PORT="${3:-8900}"
SERVER_BIN="/tmp/cvm-attestation-service"
SERVER_LOG="/tmp/cvm-attestation-service.log"

# Kill any existing instance
pkill -x cvm-attestation-service 2>/dev/null || true
sleep 1

# Start server in the background (local backgrounding works fine)
"${SERVER_BIN}" -addr ":${PORT}" > "${SERVER_LOG}" 2>&1 &
SERVER_PID=$!

# Wait for server to be ready (up to 10 seconds)
echo "Waiting for server (pid ${SERVER_PID}) on port ${PORT}..."
for i in $(seq 1 20); do
    if curl -sf -o /dev/null http://localhost:${PORT}/attest -X POST -d '{}' 2>/dev/null; then
        break
    fi
    if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
        echo "ERROR: Server exited unexpectedly. Log:"
        cat "${SERVER_LOG}" 2>/dev/null || true
        exit 1
    fi
    sleep 0.5
done

# Verify it's still running
if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
    echo "ERROR: Server is not running. Log:"
    cat "${SERVER_LOG}" 2>/dev/null || true
    exit 1
fi
echo "Server is running (pid ${SERVER_PID})"

# Call the attest endpoint
echo "Calling POST /attest ..."
HTTP_CODE=$(curl -s -w '%{http_code}' -o "${RESPONSE_FILE}" \
    -X POST "http://localhost:${PORT}/attest" \
    -H 'Content-Type: application/json' \
    -d "@${REQUEST_FILE}")

echo "HTTP status: ${HTTP_CODE}"

# Stop server
kill "${SERVER_PID}" 2>/dev/null || true
wait "${SERVER_PID}" 2>/dev/null || true
echo "Server stopped"

if [[ "${HTTP_CODE}" != "200" ]]; then
    echo "ERROR: attestation request failed"
    cat "${RESPONSE_FILE}" 2>/dev/null || true
    echo ""
    echo "Server log:"
    cat "${SERVER_LOG}" 2>/dev/null || true
    exit 1
fi

echo "Response saved to ${RESPONSE_FILE}"
