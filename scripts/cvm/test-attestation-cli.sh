#!/usr/bin/env bash
set -euo pipefail

# Test script for attestation-cli on Azure CVM
# Generates an RSA key pair, uses SHA256(public key DER) as report_data,
# runs attestation on the CVM, and validates the runtime claims user-data
# matches the public key hash.
#
# Usage: ./scripts/aks/test-attestation-cli.sh <user@host> [ssh-key]

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <user@host> [ssh-key]" >&2
    exit 1
fi

VM_HOST="$1"
SSH_KEY="${2:-~/.ssh/id_rsa}"
SSH_OPTS="-i ${SSH_KEY} -o StrictHostKeyChecking=no -o ConnectTimeout=10"

BINARY="bin/attestation-cli"
REMOTE_BIN="/tmp/attestation-cli"
REMOTE_DIR="/tmp"
LOCAL_OUT="tmp/attestation-output"

ARTIFACTS=(tpm_quote.bin hcl_report.bin snp_report.bin aik_cert.der pcr_values.json runtime_claims.json)

echo "=== Attestation CLI Test ==="
echo "Target: ${VM_HOST}"
echo ""

# 1. Build
echo "--- Building attestation-cli ---"
make attestation-cli
echo ""

# 2. Generate RSA key pair and compute report_data = SHA256(pubkey DER) || zeros
echo "--- Generating RSA key pair ---"
mkdir -p "${LOCAL_OUT}"
RSA_PRIVATE="${LOCAL_OUT}/test_key.pem"
RSA_PUBLIC_PEM="${LOCAL_OUT}/test_key_pub.pem"
REPORT_DATA_FILE="${LOCAL_OUT}/report_data.bin"

openssl genrsa -out "${RSA_PRIVATE}" 2048 2>/dev/null
openssl rsa -in "${RSA_PRIVATE}" -pubout -outform PEM -out "${RSA_PUBLIC_PEM}" 2>/dev/null
echo "  Private key: ${RSA_PRIVATE}"
echo "  Public key (PEM): ${RSA_PUBLIC_PEM}"

# report_data = SHA256(pubkey DER) (32 bytes) + 32 zero bytes = 64 bytes total
PUBKEY_HASH=$(openssl rsa -in "${RSA_PRIVATE}" -pubout -outform DER 2>/dev/null | sha256sum | cut -d' ' -f1)
echo "  SHA256(pubkey): ${PUBKEY_HASH}"

# Write 64-byte report_data: 32 bytes of hash + 32 bytes of zeros
printf '%s' "${PUBKEY_HASH}" | xxd -r -p > "${REPORT_DATA_FILE}"
dd if=/dev/zero bs=1 count=32 >> "${REPORT_DATA_FILE}" 2>/dev/null
echo "  report_data: ${REPORT_DATA_FILE} ($(wc -c < "${REPORT_DATA_FILE}") bytes)"
echo ""

# 3. Copy binary and report_data to CVM
echo "--- Uploading binary and report_data ---"
scp ${SSH_OPTS} "${BINARY}" "${VM_HOST}:${REMOTE_BIN}"
scp ${SSH_OPTS} "${REPORT_DATA_FILE}" "${VM_HOST}:${REMOTE_DIR}/report_data.bin"
echo ""

# 4. Run on CVM with custom report_data
echo "--- Running attestation-cli with custom report_data ---"
ssh ${SSH_OPTS} "${VM_HOST}" "cd ${REMOTE_DIR} && sudo ${REMOTE_BIN} -report-data ${REMOTE_DIR}/report_data.bin"
echo ""

# 5. Copy artifacts back
echo "--- Downloading artifacts ---"
mkdir -p "${LOCAL_OUT}"
for f in "${ARTIFACTS[@]}"; do
    scp ${SSH_OPTS} "${VM_HOST}:${REMOTE_DIR}/${f}" "${LOCAL_OUT}/${f}" 2>/dev/null && \
        echo "  ${f} -> ${LOCAL_OUT}/${f}" || \
        echo "  ${f} (not found, skipping)"
done
echo ""

# 6. Summary
echo "--- Artifacts ---"
ls -lh "${LOCAL_OUT}/"
echo ""

# 7. Validate runtime claims user-data matches public key hash
echo "--- Validating runtime claims ---"
if [[ -f "${LOCAL_OUT}/runtime_claims.json" ]]; then
    # Extract user-data from runtime claims (it's a hex string of the 64 report_data bytes)
    USER_DATA=$(jq -r '."user-data" // .userData // empty' "${LOCAL_OUT}/runtime_claims.json" 2>/dev/null || true)

    if [[ -z "${USER_DATA}" ]]; then
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
