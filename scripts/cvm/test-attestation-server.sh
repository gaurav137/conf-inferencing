#!/usr/bin/env bash
set -euo pipefail

# Test script for attestation-server on Azure CVM
# Generates an RSA key pair, uses SHA256(public key DER) as report_data,
# starts the attestation server on the CVM, calls POST /attest with the
# report_data, and validates the runtime claims user-data matches the
# public key hash.
#
# Usage: ./scripts/aks/test-attestation-server.sh <user@host> [ssh-key]

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <user@host> [ssh-key]" >&2
    exit 1
fi

VM_HOST="$1"
SSH_KEY="${2:-~/.ssh/id_rsa}"
SSH_OPTS="-i ${SSH_KEY} -o StrictHostKeyChecking=no -o ConnectTimeout=10"

BINARY="bin/attestation-server"
REMOTE_BIN="/tmp/attestation-server"
SERVER_PORT="8900"
LOCAL_OUT="tmp/attestation-server-output"

# Extract just the hostname/IP from user@host
VM_IP="${VM_HOST#*@}"

echo "=== Attestation Server Test ==="
echo "Target: ${VM_HOST}"
echo ""

# 1. Build
echo "--- Building attestation-server ---"
make attestation-server
echo ""

# 2. Generate RSA key pair and compute report_data = SHA256(pubkey DER) || zeros
echo "--- Generating RSA key pair ---"
mkdir -p "${LOCAL_OUT}"
RSA_PRIVATE="${LOCAL_OUT}/test_key.pem"
RSA_PUBLIC_DER="${LOCAL_OUT}/test_key_pub.der"

openssl genrsa -out "${RSA_PRIVATE}" 2048 2>/dev/null
openssl rsa -in "${RSA_PRIVATE}" -pubout -outform DER -out "${RSA_PUBLIC_DER}" 2>/dev/null
echo "  Private key: ${RSA_PRIVATE}"
echo "  Public key (DER): ${RSA_PUBLIC_DER} ($(wc -c < "${RSA_PUBLIC_DER}") bytes)"

# report_data = SHA256(pubkey DER) (32 bytes) + 32 zero bytes = 64 bytes total
PUBKEY_HASH=$(sha256sum "${RSA_PUBLIC_DER}" | cut -d' ' -f1)
echo "  SHA256(pubkey): ${PUBKEY_HASH}"

# Build 64-byte report_data and base64-encode it
REPORT_DATA_HEX="${PUBKEY_HASH}$(printf '%064d' 0)"
REPORT_DATA_B64=$(printf '%s' "${REPORT_DATA_HEX}" | xxd -r -p | base64 -w0)
echo "  report_data (base64): ${REPORT_DATA_B64}"
echo ""

# 3. Upload server binary to CVM
echo "--- Uploading binary ---"
scp ${SSH_OPTS} "${BINARY}" "${VM_HOST}:${REMOTE_BIN}"
echo ""

# 4. Start attestation server on CVM (kill any existing instance first)
echo "--- Starting attestation-server on CVM ---"
ssh ${SSH_OPTS} "${VM_HOST}" "sudo pkill -f attestation-server 2>/dev/null; sleep 1; sudo bash -c '${REMOTE_BIN} -addr :${SERVER_PORT} </dev/null >/tmp/attestation-server.log 2>&1 &'"
echo "  Waiting for server to start..."
sleep 3

# Verify server is running
if ssh ${SSH_OPTS} "${VM_HOST}" "curl -sf -o /dev/null http://localhost:${SERVER_PORT}/ 2>/dev/null"; then
    true # any response means it's up
elif ssh ${SSH_OPTS} "${VM_HOST}" "pgrep -f attestation-server >/dev/null 2>&1"; then
    echo "  Server process is running"
else
    echo "  ERROR: Server failed to start. Log:"
    ssh ${SSH_OPTS} "${VM_HOST}" "cat /tmp/attestation-server.log 2>/dev/null || true"
    exit 1
fi
echo "  Server is running on port ${SERVER_PORT}"
echo ""

# 5. Call POST /attest with reportData
echo "--- Calling POST /attest ---"
RESPONSE_FILE="${LOCAL_OUT}/attest_response.json"
HTTP_CODE=$(ssh ${SSH_OPTS} "${VM_HOST}" \
    "curl -s -w '%{http_code}' -o /tmp/attest_response.json \
        -X POST http://localhost:${SERVER_PORT}/attest \
        -H 'Content-Type: application/json' \
        -d '{\"reportData\":\"${REPORT_DATA_B64}\"}'")

echo "  HTTP status: ${HTTP_CODE}"

if [[ "${HTTP_CODE}" != "200" ]]; then
    echo "  ERROR: attestation request failed"
    ssh ${SSH_OPTS} "${VM_HOST}" "cat /tmp/attest_response.json 2>/dev/null" || true
    ssh ${SSH_OPTS} "${VM_HOST}" "sudo pkill -f attestation-server 2>/dev/null || true"
    exit 1
fi

# Download response
scp ${SSH_OPTS} "${VM_HOST}:/tmp/attest_response.json" "${RESPONSE_FILE}"
echo "  Response saved to ${RESPONSE_FILE}"
echo ""

# 6. Stop server
echo "--- Stopping attestation-server ---"
ssh ${SSH_OPTS} "${VM_HOST}" "sudo pkill -f attestation-server 2>/dev/null || true"
echo "  Server stopped"
echo ""

# 7. Extract and save individual artifacts
echo "--- Extracting artifacts ---"
if command -v jq &>/dev/null; then
    jq -r '.tpmQuote' "${RESPONSE_FILE}" | base64 -d > "${LOCAL_OUT}/tpm_quote.bin" 2>/dev/null && \
        echo "  tpm_quote.bin ($(wc -c < "${LOCAL_OUT}/tpm_quote.bin") bytes)"
    jq -r '.hclReport' "${RESPONSE_FILE}" | base64 -d > "${LOCAL_OUT}/hcl_report.bin" 2>/dev/null && \
        echo "  hcl_report.bin ($(wc -c < "${LOCAL_OUT}/hcl_report.bin") bytes)"
    jq -r '.snpReport' "${RESPONSE_FILE}" | base64 -d > "${LOCAL_OUT}/snp_report.bin" 2>/dev/null && \
        echo "  snp_report.bin ($(wc -c < "${LOCAL_OUT}/snp_report.bin") bytes)"
    AIK_CERT=$(jq -r '.aikCert // empty' "${RESPONSE_FILE}")
    if [[ -n "${AIK_CERT}" ]]; then
        echo "${AIK_CERT}" | base64 -d > "${LOCAL_OUT}/aik_cert.der" 2>/dev/null && \
            echo "  aik_cert.der ($(wc -c < "${LOCAL_OUT}/aik_cert.der") bytes)"
    fi
    jq '.runtimeClaims' "${RESPONSE_FILE}" > "${LOCAL_OUT}/runtime_claims.json" 2>/dev/null && \
        echo "  runtime_claims.json"
else
    echo "  WARNING: jq not found, skipping artifact extraction"
fi
echo ""

# 8. Summary
echo "--- Artifacts ---"
ls -lh "${LOCAL_OUT}/"
echo ""

# 9. Validate runtime claims user-data matches public key hash
echo "--- Validating runtime claims ---"
if [[ -f "${LOCAL_OUT}/runtime_claims.json" ]]; then
    USER_DATA=$(jq -r '."user-data" // .userData // empty' "${LOCAL_OUT}/runtime_claims.json" 2>/dev/null || true)

    if [[ -z "${USER_DATA}" || "${USER_DATA}" == "null" ]]; then
        echo "  WARNING: user-data field not found in runtime_claims.json"
        echo ""
        echo "  Runtime claims contents:"
        cat "${LOCAL_OUT}/runtime_claims.json"
    else
        echo "  user-data from runtime claims:"
        echo "    ${USER_DATA}"

        # Expected: SHA256(pubkey) zero-padded to 64 bytes, as hex
        EXPECTED_USER_DATA="${PUBKEY_HASH}$(printf '%064d' 0)"
        echo "  expected user-data:"
        echo "    ${EXPECTED_USER_DATA}"

        if [[ "${USER_DATA,,}" == "${EXPECTED_USER_DATA,,}" ]]; then
            echo ""
            echo "  ✓ PASS: user-data matches SHA256(public key)"
        else
            echo ""
            echo "  ✗ FAIL: user-data does not match expected value"
            exit 1
        fi
    fi
else
    echo "  WARNING: runtime_claims.json not found, skipping validation"
fi
echo ""
echo "Done."
