#!/bin/bash
#
# Deploy kubelet-proxy to AKS Flex Node
#
# This script deploys kubelet-proxy to an AKS Flex node that was previously
# set up using deploy-aks.sh. It:
# 1. Deploys the signing-server as a local Docker container with TLS
# 2. Builds the kubelet-proxy binary
# 3. Copies the binary and signing certificate to the VM via SSH
# 4. Runs install.sh on the VM to install kubelet-proxy
#
# Usage:
#   ./deploy-kubelet-proxy.sh [options]
#
# Options:
#   --help, -h     Show this help message
#
# Prerequisites:
#   - deploy-aks.sh must have been run successfully
#   - Docker must be installed and running
#   - Go must be installed for building the binary
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
GENERATED_DIR="$SCRIPT_DIR/generated"
SIGNING_SERVER_IMAGE="signing-server:local"
SIGNING_SERVER_CONTAINER="signing-server-aks"
SIGNING_SERVER_PORT=8443
PROXY_LISTEN_ADDR="127.0.0.1:6444"

# Get resource names from currently logged in user
get_resource_info() {
    log_info "Getting resource information from Azure..."
    
    # Get the currently logged in user's UPN
    CURRENT_USER_UPN=$(az ad signed-in-user show --query userPrincipalName -o tsv 2>/dev/null) || {
        log_error "Failed to get current user. Make sure you are logged in with 'az login'"
        exit 1
    }
    
    # Extract username from UPN
    USERNAME=$(echo "$CURRENT_USER_UPN" | cut -d'@' -f1 | tr '.' '-' | tr '[:upper:]' '[:lower:]')
    
    # Set resource names
    RESOURCE_GROUP="${USERNAME}-flex-test-rg"
    VM_NAME="${USERNAME}-flex-vm"
    SSH_PRIVATE_KEY_FILE="$GENERATED_DIR/${VM_NAME}-ssh.pem"
    
    log_info "Username: $USERNAME"
    log_info "Resource group: $RESOURCE_GROUP"
    log_info "VM name: $VM_NAME"
    
    # Verify SSH key exists
    if [[ ! -f "$SSH_PRIVATE_KEY_FILE" ]]; then
        log_error "SSH private key not found at: $SSH_PRIVATE_KEY_FILE"
        log_error "Make sure deploy-aks.sh was run successfully"
        exit 1
    fi
    
    # Get VM public IP
    VM_PUBLIC_IP=$(az vm show --resource-group "$RESOURCE_GROUP" --name "$VM_NAME" --show-details --query publicIps -o tsv 2>/dev/null) || {
        log_error "Failed to get VM public IP. Make sure the VM exists."
        exit 1
    }
    
    if [[ -z "$VM_PUBLIC_IP" ]]; then
        log_error "VM public IP is empty"
        exit 1
    fi
    
    log_info "VM public IP: $VM_PUBLIC_IP"
}

# Build kubelet-proxy binary
build_binary() {
    log_info "Building kubelet-proxy binary..."
    cd "$PROJECT_ROOT"
    
    # Build for Linux (Azure VMs run Linux)
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -v -ldflags "-s -w" \
        -o bin/kubelet-proxy-linux-amd64 \
        ./cmd/kubelet-proxy
    
    log_info "Binary built: bin/kubelet-proxy-linux-amd64"
}

# Build signing-server Docker image
build_signing_server_image() {
    log_info "Building signing-server container image..."
    cd "$PROJECT_ROOT"
    
    docker build -t "$SIGNING_SERVER_IMAGE" -f Dockerfile.signing-server .
    
    log_info "Signing server image built: $SIGNING_SERVER_IMAGE"
}

# Deploy signing-server as local Docker container with TLS
deploy_signing_server() {
    log_info "Starting signing-server as local Docker container with TLS..."
    
    # Stop and remove existing container if running
    docker stop "$SIGNING_SERVER_CONTAINER" 2>/dev/null || true
    docker rm "$SIGNING_SERVER_CONTAINER" 2>/dev/null || true
    
    # Run signing-server container with TLS enabled
    docker run -d \
        --name "$SIGNING_SERVER_CONTAINER" \
        -p "$SIGNING_SERVER_PORT:8080" \
        "$SIGNING_SERVER_IMAGE" \
        --listen-addr=:8080 \
        --auto-generate=true \
        --tls=true \
        --tls-hosts="localhost,127.0.0.1"
    
    # Wait for signing-server to be ready
    log_info "Waiting for signing-server to be ready (HTTPS)..."
    for i in {1..20}; do
        if curl -sf --insecure "https://localhost:$SIGNING_SERVER_PORT/health" >/dev/null 2>&1; then
            log_info "Signing server is running at https://localhost:$SIGNING_SERVER_PORT"
            return 0
        fi
        sleep 0.5
    done
    
    log_error "Signing server failed to start"
    docker logs "$SIGNING_SERVER_CONTAINER"
    exit 1
}

# Download signing certificate from signing-server
download_signing_cert() {
    log_info "Downloading signing certificate from signing-server..."
    
    mkdir -p "$GENERATED_DIR"
    
    local signing_cert_file="$GENERATED_DIR/signing-cert.pem"
    curl -sf --insecure "https://localhost:$SIGNING_SERVER_PORT/signingcert" -o "$signing_cert_file" || {
        log_error "Failed to download signing certificate from signing-server"
        exit 1
    }
    
    log_info "Signing certificate downloaded to: $signing_cert_file"
    SIGNING_CERT_FILE="$signing_cert_file"
}

# Deploy kubelet-proxy to the Azure VM
deploy_to_vm() {
    log_info "Deploying kubelet-proxy to Azure VM: $VM_NAME..."
    
    local ssh_opts="-i $SSH_PRIVATE_KEY_FILE -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
    local staging_dir="/opt/kubelet-proxy-staging"
    
    # Create staging directory on VM
    log_info "Creating staging directory on VM..."
    ssh $ssh_opts azureuser@$VM_PUBLIC_IP "sudo mkdir -p $staging_dir && sudo chown azureuser:azureuser $staging_dir" || {
        log_error "Failed to create staging directory on VM"
        exit 1
    }
    
    # Copy files to VM
    log_info "Copying files to VM..."
    
    # Copy kubelet-proxy binary
    scp $ssh_opts "$PROJECT_ROOT/bin/kubelet-proxy-linux-amd64" azureuser@$VM_PUBLIC_IP:$staging_dir/kubelet-proxy || {
        log_error "Failed to copy kubelet-proxy binary to VM"
        exit 1
    }
    
    # Copy install.sh script
    scp $ssh_opts "$PROJECT_ROOT/scripts/install.sh" azureuser@$VM_PUBLIC_IP:$staging_dir/install.sh || {
        log_error "Failed to copy install.sh to VM"
        exit 1
    }
    
    # Copy signing certificate
    scp $ssh_opts "$SIGNING_CERT_FILE" azureuser@$VM_PUBLIC_IP:$staging_dir/signing-cert.pem || {
        log_error "Failed to copy signing certificate to VM"
        exit 1
    }
    
    # Verify files were copied
    log_info "Verifying files on VM..."
    ssh $ssh_opts azureuser@$VM_PUBLIC_IP "ls -la $staging_dir/"
    
    # Run install.sh on VM with --signing-cert-file and --local-binary options
    log_info "Running install.sh on VM..."
    ssh $ssh_opts azureuser@$VM_PUBLIC_IP "sudo bash $staging_dir/install.sh \
        --local-binary $staging_dir/kubelet-proxy \
        --signing-cert-file $staging_dir/signing-cert.pem \
        --proxy-listen-addr $PROXY_LISTEN_ADDR" || {
        log_error "Failed to run install.sh on VM"
        exit 1
    }
    
    log_info "kubelet-proxy installed successfully on VM"
}

# Verify kubelet-proxy deployment
verify_deployment() {
    log_info "Verifying kubelet-proxy deployment on VM..."
    
    local ssh_opts="-i $SSH_PRIVATE_KEY_FILE -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
    
    echo ""
    echo "=== kubelet-proxy status ==="
    ssh $ssh_opts azureuser@$VM_PUBLIC_IP "sudo systemctl status kubelet-proxy --no-pager" || true
    
    echo ""
    echo "=== Recent kubelet-proxy logs ==="
    ssh $ssh_opts azureuser@$VM_PUBLIC_IP "sudo journalctl -u kubelet-proxy --no-pager -n 20" || true
    
    echo ""
    echo "=== kubelet status ==="
    ssh $ssh_opts azureuser@$VM_PUBLIC_IP "sudo systemctl status kubelet --no-pager | head -15" || true
    
    echo ""
    echo "=== Cluster nodes ==="
    kubectl get nodes -o wide
}

# Print summary
print_summary() {
    echo ""
    log_info "=========================================="
    log_info "  kubelet-proxy Deployment Summary"
    log_info "=========================================="
    echo ""
    echo "Signing Server:"
    echo "  Container:     $SIGNING_SERVER_CONTAINER"
    echo "  URL:           https://localhost:$SIGNING_SERVER_PORT"
    echo ""
    echo "VM Deployment:"
    echo "  VM Name:       $VM_NAME"
    echo "  VM IP:         $VM_PUBLIC_IP"
    echo "  Proxy Address: $PROXY_LISTEN_ADDR"
    echo ""
    echo "Useful Commands:"
    echo "  View proxy logs:     ssh -i $SSH_PRIVATE_KEY_FILE azureuser@$VM_PUBLIC_IP 'sudo journalctl -u kubelet-proxy -f'"
    echo "  View kubelet logs:   ssh -i $SSH_PRIVATE_KEY_FILE azureuser@$VM_PUBLIC_IP 'sudo journalctl -u kubelet -f'"
    echo "  Signing server logs: docker logs $SIGNING_SERVER_CONTAINER"
    echo "  Test pod policies:   ./test-pod-policies.sh"
    echo ""
    echo "Pod policy verification is now ENABLED."
    echo "Unsigned pods scheduled to this node will be rejected."
    echo ""
}

# Print usage
usage() {
    head -22 "$0" | grep -E "^#" | sed 's/^# \?//'
    exit 0
}

# Main function
main() {
    log_info "Starting kubelet-proxy deployment to AKS Flex node"
    echo ""
    
    # Check prerequisites
    command -v az >/dev/null 2>&1 || { log_error "Azure CLI (az) is required but not installed"; exit 1; }
    command -v docker >/dev/null 2>&1 || { log_error "Docker is required but not installed"; exit 1; }
    command -v go >/dev/null 2>&1 || { log_error "Go is required but not installed"; exit 1; }
    command -v kubectl >/dev/null 2>&1 || { log_error "kubectl is required but not installed"; exit 1; }
    
    # Check if logged in to Azure
    az account show &>/dev/null || { log_error "Not logged in to Azure. Run 'az login' first."; exit 1; }
    
    # Get resource information
    get_resource_info
    
    # Deploy
    build_binary
    build_signing_server_image
    deploy_signing_server
    download_signing_cert
    deploy_to_vm
    verify_deployment
    print_summary
    
    log_info "Deployment complete!"
}

# Parse arguments
case "${1:-}" in
    --help|-h)
        usage
        ;;
    *)
        main "$@"
        ;;
esac
