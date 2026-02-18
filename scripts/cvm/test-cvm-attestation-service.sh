#!/usr/bin/env bash
set -euo pipefail

# Test script for cvm-attestation-service on Azure CVM
# Generates an RSA key pair, uses SHA256(public key DER) as report_data,
# starts the attestation service on the CVM, calls POST /attest with the
# report_data, and validates the runtime claims user-data matches the
# public key hash.
#
# Usage: ./scripts/cvm/test-cvm-attestation-service.sh <user@host> [ssh-key]

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <user@host> [ssh-key]" >&2
    exit 1
fi

VM_HOST="$1"
SSH_KEY="${2:-~/.ssh/id_rsa}"
SSH_OPTS="-i ${SSH_KEY} -o StrictHostKeyChecking=no -o ConnectTimeout=10"

BINARY="bin/cvm-attestation-service"
HELPER_SCRIPT="scripts/cvm/test-cvm-attestation-service-helper.sh"
REMOTE_BIN="/tmp/cvm-attestation-service"
REMOTE_HELPER="/tmp/test-cvm-attestation-service-helper.sh"
SERVER_PORT="8900"
LOCAL_OUT="tmp/cvm-attestation-service-output"

# Extract just the hostname/IP from user@host
VM_IP="${VM_HOST#*@}"

echo "=== CVM Attestation Service Test ==="
echo "Target: ${VM_HOST}"
echo ""

# 1. Build
echo "--- Building cvm-attestation-service ---"
make cvm-attestation-service
echo ""

# 2. Generate RSA key pair and compute report_data = SHA256(pubkey DER) || zeros
echo "--- Generating RSA key pair ---"
mkdir -p "${LOCAL_OUT}"
RSA_PRIVATE="${LOCAL_OUT}/priv_key.pem"
RSA_PUBLIC_PEM="${LOCAL_OUT}/pub_key.pem"

openssl genrsa -out "${RSA_PRIVATE}" 2048 2>/dev/null
openssl rsa -in "${RSA_PRIVATE}" -pubout -outform PEM -out "${RSA_PUBLIC_PEM}" 2>/dev/null
echo "  Private key: ${RSA_PRIVATE}"
echo "  Public key (PEM): ${RSA_PUBLIC_PEM}"

# report_data = SHA256(pubkey DER) (32 bytes) + 32 zero bytes = 64 bytes total
PUBKEY_HASH=$(openssl rsa -in "${RSA_PRIVATE}" -pubout -outform DER 2>/dev/null | sha256sum | cut -d' ' -f1)
echo "  SHA256(pubkey DER): ${PUBKEY_HASH}"

# Build 64-byte report_data and base64-encode it
REPORT_DATA_HEX="${PUBKEY_HASH}$(printf '%064d' 0)"
REPORT_DATA_B64=$(printf '%s' "${REPORT_DATA_HEX}" | xxd -r -p | base64 -w0)
echo "  report_data (base64): ${REPORT_DATA_B64}"

# Generate a random 32-byte nonce for the TPM quote
NONCE_B64=$(openssl rand -base64 32)
echo "  nonce (base64): ${NONCE_B64}"
echo ""

# 3. Upload server binary and helper script to CVM
echo "--- Uploading binary and helper script ---"
scp ${SSH_OPTS} "${BINARY}" "${VM_HOST}:${REMOTE_BIN}"
scp ${SSH_OPTS} "${HELPER_SCRIPT}" "${VM_HOST}:${REMOTE_HELPER}"
ssh ${SSH_OPTS} "${VM_HOST}" "chmod +x ${REMOTE_BIN} ${REMOTE_HELPER}"
echo ""

# 4. Write request JSON on the CVM
echo "--- Preparing request ---"
ssh ${SSH_OPTS} "${VM_HOST}" "printf '%s' '{\"reportData\":\"${REPORT_DATA_B64}\",\"nonce\":\"${NONCE_B64}\"}' > /tmp/attest_request.json"
echo "  Request JSON written to CVM:/tmp/attest_request.json"
echo ""

# 5. Run helper script on CVM (starts server, calls API, stops server — all in one SSH call)
echo "--- Running attestation on CVM ---"
ssh ${SSH_OPTS} "${VM_HOST}" "sudo ${REMOTE_HELPER} /tmp/attest_request.json /tmp/attest_response.json ${SERVER_PORT}"
echo ""

# 6. Download response
echo "--- Downloading response ---"
RESPONSE_FILE="${LOCAL_OUT}/attest_response.json"
scp ${SSH_OPTS} "${VM_HOST}:/tmp/attest_response.json" "${RESPONSE_FILE}"
echo "  Response saved to ${RESPONSE_FILE}"
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
