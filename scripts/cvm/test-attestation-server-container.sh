#!/usr/bin/env bash
set -euo pipefail

# Test script for attestation-server running as a Docker container on Azure CVM.
# Builds the Docker image locally, exports it as a tarball, copies it to the CVM,
# loads it, runs the container with TPM device access, calls POST /attest,
# validates the runtime claims user-data, then runs the attestation-verifier
# locally and verifies the collected evidence passes all checks.
#
# Usage: ./scripts/cvm/test-attestation-server-container.sh <user@host> [ssh-key]

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <user@host> [ssh-key]" >&2
    exit 1
fi

VM_HOST="$1"
SSH_KEY="${2:-~/.ssh/id_rsa}"
SSH_OPTS="-i ${SSH_KEY} -o StrictHostKeyChecking=no -o ConnectTimeout=10"

TEST_TAG="test"

SERVER_IMAGE_NAME="attestation-server"
SERVER_IMAGE_TAR="tmp/attestation-server-image.tar.gz"
SERVER_CONTAINER_NAME="attestation-server-test"
SERVER_PORT="8900"
LOCAL_OUT="tmp/attestation-server-container-output"

VERIFIER_IMAGE_NAME="attestation-verifier"
VERIFIER_CONTAINER_NAME="attestation-verifier-test"
VERIFIER_PORT="8901"

# 0. Clean up generated content from previous runs
echo "--- Cleaning up previous run artifacts ---"
rm -rf "${LOCAL_OUT}"
rm -f "${SERVER_IMAGE_TAR}"
docker rm -f "${SERVER_CONTAINER_NAME}" 2>/dev/null || true
docker rm -f "${VERIFIER_CONTAINER_NAME}" 2>/dev/null || true
echo "  Done"
echo ""

echo "=== Attestation Server Container Test ==="
echo "Target: ${VM_HOST}"
echo ""

# 1. Build Docker images
echo "--- Building attestation-server Docker image ---"
docker build -t "${SERVER_IMAGE_NAME}:${TEST_TAG}" -f Dockerfile.attestation-server .
echo ""

echo "--- Building attestation-verifier Docker image ---"
docker build -t "${VERIFIER_IMAGE_NAME}:${TEST_TAG}" -f Dockerfile.attestation-verifier .
echo ""

# 2. Export image as tarball
echo "--- Exporting Docker image ---"
mkdir -p tmp
docker save "${SERVER_IMAGE_NAME}:${TEST_TAG}" | gzip > "${SERVER_IMAGE_TAR}"
echo "  Image saved to ${SERVER_IMAGE_TAR} ($(du -h "${SERVER_IMAGE_TAR}" | cut -f1))"
echo ""

# 3. Generate RSA key pair and compute report_data = SHA256(pubkey DER) || zeros
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

# Generate a random 32-byte nonce for the TPM quote
NONCE_B64=$(openssl rand -base64 32)
echo "  nonce (base64): ${NONCE_B64}"
echo ""

# 4. Upload image tarball to CVM
echo "--- Uploading Docker image to CVM ---"
scp ${SSH_OPTS} "${SERVER_IMAGE_TAR}" "${VM_HOST}:/tmp/attestation-server-image.tar.gz"
echo ""

# 5. Install Docker on CVM if needed, load image, and run container
echo "--- Setting up container on CVM ---"
ssh ${SSH_OPTS} "${VM_HOST}" bash -s <<'REMOTE_SETUP'
set -euo pipefail

# Install Docker if not present
if ! command -v docker &>/dev/null; then
    echo "  Installing Docker..."
    curl -fsSL https://get.docker.com | sudo sh
    sudo usermod -aG docker $USER
fi

# Stop and remove any existing test container
sudo docker rm -f attestation-server-test 2>/dev/null || true

# Load the image
echo "  Loading Docker image..."
sudo docker load < /tmp/attestation-server-image.tar.gz

echo "  Docker image loaded"
sudo docker images attestation-server
REMOTE_SETUP
echo ""

# 6. Write request JSON on the CVM
echo "--- Preparing request ---"
ssh ${SSH_OPTS} "${VM_HOST}" "printf '%s' '{\"reportData\":\"${REPORT_DATA_B64}\",\"nonce\":\"${NONCE_B64}\"}' > /tmp/attest_request.json"
echo "  Request JSON written to CVM:/tmp/attest_request.json"
echo ""

# 7. Run container with TPM access, call API, collect response
echo "--- Running attestation container on CVM ---"
ssh ${SSH_OPTS} "${VM_HOST}" bash -s <<REMOTE_RUN
set -euo pipefail

# Start the container with TPM device access
echo "  Starting container..."
sudo docker run -d \
    --name ${SERVER_CONTAINER_NAME} \
    --device /dev/tpmrm0:/dev/tpmrm0 \
    -p ${SERVER_PORT}:${SERVER_PORT} \
    ${SERVER_IMAGE_NAME}:${TEST_TAG}

# Wait for server to be ready (up to 10 seconds)
echo "  Waiting for server to start..."
for i in \$(seq 1 20); do
    if curl -sf -o /dev/null http://localhost:${SERVER_PORT}/attest -X POST -d '{}' 2>/dev/null; then
        break
    fi
    if ! sudo docker ps -q -f name=${SERVER_CONTAINER_NAME} | grep -q .; then
        echo "  ERROR: Container exited unexpectedly. Logs:"
        sudo docker logs ${SERVER_CONTAINER_NAME} 2>&1
        exit 1
    fi
    sleep 0.5
done

# Verify container is running
if ! sudo docker ps -q -f name=${SERVER_CONTAINER_NAME} | grep -q .; then
    echo "  ERROR: Container not running. Logs:"
    sudo docker logs ${SERVER_CONTAINER_NAME} 2>&1
    exit 1
fi
echo "  Container is running"

# Call POST /attest
echo "  Calling POST /attest ..."
sudo rm -f /tmp/attest_response.json
HTTP_CODE=\$(curl -s -w '%{http_code}' -o /tmp/attest_response.json \
    -X POST "http://localhost:${SERVER_PORT}/attest" \
    -H 'Content-Type: application/json' \
    -d @/tmp/attest_request.json)

echo "  HTTP status: \${HTTP_CODE}"

# Show container logs
echo "  Container logs:"
sudo docker logs ${SERVER_CONTAINER_NAME} 2>&1 | sed 's/^/    /'

# Stop container
sudo docker rm -f ${SERVER_CONTAINER_NAME} 2>/dev/null || true
echo "  Container stopped"

if [[ "\${HTTP_CODE}" != "200" ]]; then
    echo "  ERROR: attestation request failed"
    cat /tmp/attest_response.json 2>/dev/null || true
    exit 1
fi

echo "  Response saved to CVM:/tmp/attest_response.json"
REMOTE_RUN
echo ""

# 8. Download response
echo "--- Downloading response ---"
RESPONSE_FILE="${LOCAL_OUT}/attest_response.json"
scp ${SSH_OPTS} "${VM_HOST}:/tmp/attest_response.json" "${RESPONSE_FILE}"
echo "  Response saved to ${RESPONSE_FILE}"
echo ""

# 9. Extract and save individual artifacts
echo "--- Extracting artifacts ---"
if command -v jq &>/dev/null; then
    jq -r '.tpmQuote' "${RESPONSE_FILE}" | base64 -d > "${LOCAL_OUT}/tpm_quote.bin" 2>/dev/null && \
        echo "  tpm_quote.bin ($(wc -c < "${LOCAL_OUT}/tpm_quote.bin") bytes)"
    jq -r '.hclReport' "${RESPONSE_FILE}" | base64 -d > "${LOCAL_OUT}/hcl_report.bin" 2>/dev/null && \
        echo "  hcl_report.bin ($(wc -c < "${LOCAL_OUT}/hcl_report.bin") bytes)"
    jq -r '.snpReport' "${RESPONSE_FILE}" | base64 -d > "${LOCAL_OUT}/snp_report.bin" 2>/dev/null && \
        echo "  snp_report.bin ($(wc -c < "${LOCAL_OUT}/snp_report.bin") bytes)"
    jq -r '.aikCert' "${RESPONSE_FILE}" | base64 -d > "${LOCAL_OUT}/aik_cert.der" 2>/dev/null && \
        echo "  aik_cert.der ($(wc -c < "${LOCAL_OUT}/aik_cert.der") bytes)"
    jq '.pcrs' "${RESPONSE_FILE}" > "${LOCAL_OUT}/pcr_values.json" 2>/dev/null && \
        echo "  pcr_values.json"
    jq '.runtimeClaims' "${RESPONSE_FILE}" > "${LOCAL_OUT}/runtime_claims.json" 2>/dev/null && \
        echo "  runtime_claims.json"
else
    echo "  WARNING: jq not found, skipping artifact extraction"
fi
echo ""

# 10. Summary
echo "--- Artifacts ---"
ls -lh "${LOCAL_OUT}/"
echo ""

# 11. Validate runtime claims user-data matches public key hash
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

# ══════════════════════════════════════════════════════════════════════════════
# Attestation Verifier
# ══════════════════════════════════════════════════════════════════════════════

echo "=== Attestation Verifier Test ==="
echo ""

# 12. Run verifier container locally
echo "--- Starting attestation-verifier container ---"
docker rm -f "${VERIFIER_CONTAINER_NAME}" 2>/dev/null || true
docker run -d \
    --name "${VERIFIER_CONTAINER_NAME}" \
    -p "${VERIFIER_PORT}:${VERIFIER_PORT}" \
    "${VERIFIER_IMAGE_NAME}:${TEST_TAG}"

# Wait for verifier to be ready
echo "  Waiting for verifier to start..."
for i in $(seq 1 20); do
    if curl -sf -o /dev/null "http://localhost:${VERIFIER_PORT}/verify" -X POST -d '{}' 2>/dev/null; then
        break
    fi
    sleep 0.5
done
echo "  Verifier is running"
echo ""

# 14. Build verify request from the saved attest response
echo "--- Building verify request ---"
VERIFY_REQUEST_FILE="${LOCAL_OUT}/verify_request.json"
jq -n --slurpfile evidence "${LOCAL_OUT}/attest_response.json" \
    --arg nonce "${NONCE_B64}" \
    '{evidence: $evidence[0], nonce: $nonce}' \
    > "${VERIFY_REQUEST_FILE}"
echo "  Verify request saved to ${VERIFY_REQUEST_FILE}"
echo ""

# 15. Call POST /verify
echo "--- Calling POST /verify ---"
VERIFY_RESPONSE_FILE="${LOCAL_OUT}/verify_response.json"
HTTP_CODE=$(curl -s -w '%{http_code}' -o "${VERIFY_RESPONSE_FILE}" \
    -X POST "http://localhost:${VERIFIER_PORT}/verify" \
    -H 'Content-Type: application/json' \
    -d @"${VERIFY_REQUEST_FILE}")

echo "  HTTP status: ${HTTP_CODE}"

# Stop verifier container
docker rm -f "${VERIFIER_CONTAINER_NAME}" 2>/dev/null || true
echo "  Verifier container stopped"
echo ""

if [[ "${HTTP_CODE}" != "200" ]]; then
    echo "  ERROR: verify request failed"
    cat "${VERIFY_RESPONSE_FILE}" 2>/dev/null || true
    exit 1
fi

# 16. Display verification results
echo "--- Verification Results ---"
jq '.' "${VERIFY_RESPONSE_FILE}"
echo ""

# 17. Check overall verdict
VERIFIED=$(jq -r '.verified' "${VERIFY_RESPONSE_FILE}")
if [[ "${VERIFIED}" == "true" ]]; then
    echo "  ✓ PASS: All verification checks passed"
else
    echo "  ✗ FAIL: Verification failed"
    echo ""
    echo "  Failed checks:"
    jq -r '.checks | to_entries[] | select(.value.passed == false) | "    \(.key): \(.value.error)"' "${VERIFY_RESPONSE_FILE}"
    exit 1
fi

echo ""
echo "Done."
