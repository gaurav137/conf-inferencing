#!/usr/bin/env bash
set -euo pipefail

# Deploy an Azure Confidential VM (CVM) for attestation testing.
#
# Usage: ./scripts/cvm/deploy-cvm.sh <vm-name> [resource-group] [location] [admin-user]
#
# Examples:
#   ./scripts/cvm/deploy-cvm.sh my-cvm
#   ./scripts/cvm/deploy-cvm.sh my-cvm my-rg eastus2
#   ./scripts/cvm/deploy-cvm.sh my-cvm my-rg eastus2 gsinha

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <vm-name> [resource-group] [location] [admin-user]" >&2
    exit 1
fi

VM_NAME="$1"
RESOURCE_GROUP="${2:-${VM_NAME}-rg}"
LOCATION="${3:-westeurope}"
ADMIN_USER="${4:-azureuser}"

echo "=== Deploy Azure Confidential VM ==="
echo "  VM Name:        ${VM_NAME}"
echo "  Resource Group: ${RESOURCE_GROUP}"
echo "  Location:       ${LOCATION}"
echo "  Admin User:     ${ADMIN_USER}"
echo ""

# 1. Create resource group if it doesn't exist
echo "--- Creating resource group ---"
az group create \
    --name "${RESOURCE_GROUP}" \
    --location "${LOCATION}" \
    --output table
echo ""

# 2. Create the CVM
echo "--- Creating Confidential VM ---"
az vm create \
    --resource-group "${RESOURCE_GROUP}" \
    --name "${VM_NAME}" \
    --admin-username "${ADMIN_USER}" \
    --size Standard_DC2as_v5 \
    --generate-ssh-keys \
    --enable-vtpm true \
    --image "Canonical:0001-com-ubuntu-confidential-vm-jammy:22_04-lts-cvm:latest" \
    --public-ip-sku Standard \
    --security-type ConfidentialVM \
    --os-disk-security-encryption-type VMGuestStateOnly \
    --enable-secure-boot true \
    --output table
echo ""

# 3. Get public IP
echo "--- VM Details ---"
PUBLIC_IP=$(az vm show \
    --resource-group "${RESOURCE_GROUP}" \
    --name "${VM_NAME}" \
    --show-details \
    --query publicIps \
    --output tsv)

echo "  Public IP: ${PUBLIC_IP}"
echo "  SSH:       ssh ${ADMIN_USER}@${PUBLIC_IP}"
echo ""
echo "  Test CLI:    ./scripts/cvm/test-cvm-attestation-cli.sh ${ADMIN_USER}@${PUBLIC_IP}"
echo "  Test Server: ./scripts/cvm/test-cvm-attestation-service.sh ${ADMIN_USER}@${PUBLIC_IP}"
echo ""
echo "Done."
