#!/bin/bash
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
LOCATION="${LOCATION:-centralindia}"
KUBERNETES_VERSION="${KUBERNETES_VERSION:-}"
VM_SIZE="${VM_SIZE:-Standard_D2s_v3}"
AKS_NODE_COUNT="${AKS_NODE_COUNT:-}"
AKS_NODE_VM_SIZE="${AKS_NODE_VM_SIZE:-Standard_D4ds_v5}"
VM_IMAGE="${VM_IMAGE:-Ubuntu2404}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GENERATED_DIR="$SCRIPT_DIR/generated"

# Get currently logged in user info
get_current_user() {
    log_info "Getting current user information..."
    
    # Get the currently logged in user's UPN or email
    CURRENT_USER_ID=$(az ad signed-in-user show --query id -o tsv 2>/dev/null) || {
        log_error "Failed to get current user. Make sure you are logged in with 'az login'"
        exit 1
    }
    
    CURRENT_USER_UPN=$(az ad signed-in-user show --query userPrincipalName -o tsv 2>/dev/null) || {
        log_error "Failed to get current user UPN"
        exit 1
    }
    
    # Extract username from UPN (before the @)
    USERNAME=$(echo "$CURRENT_USER_UPN" | cut -d'@' -f1 | tr '.' '-' | tr '[:upper:]' '[:lower:]')
    
    log_info "Current user: $CURRENT_USER_UPN"
    log_info "Username for resources: $USERNAME"
}

# Set resource names based on username
set_resource_names() {
    RESOURCE_GROUP="${USERNAME}-flex-test-rg"
    AKS_CLUSTER_NAME="${USERNAME}-flex-aks"
    VM_NAME="${USERNAME}-flex-vm"
    RESOURCE_OWNER_MI_NAME="${USERNAME}-flex-resource-owner-mi"
    KUBELET_MI_NAME="${USERNAME}-flex-kubelet-mi"
    SSH_KEY_NAME="${USERNAME}-flex-ssh"
    
    log_info "Resource group: $RESOURCE_GROUP"
    log_info "AKS cluster: $AKS_CLUSTER_NAME"
    log_info "VM name: $VM_NAME"
    log_info "Resource owner managed identity: $RESOURCE_OWNER_MI_NAME"
    log_info "Kubelet managed identity: $KUBELET_MI_NAME"
}

# Create resource group with SkipCleanup tag
create_resource_group() {
    log_info "Creating resource group: $RESOURCE_GROUP in $LOCATION..."
    
    if az group show --name "$RESOURCE_GROUP" &>/dev/null; then
        log_warn "Resource group $RESOURCE_GROUP already exists"
    else
        az group create \
            --name "$RESOURCE_GROUP" \
            --location "$LOCATION" \
            --tags SkipCleanup=true \
            --output none
        
        log_info "Resource group created with SkipCleanup=true tag"
    fi
}

# Create AKS cluster with Azure RBAC enabled
create_aks_cluster() {
    log_info "Creating AKS cluster: $AKS_CLUSTER_NAME..."
    
    if az aks show --resource-group "$RESOURCE_GROUP" --name "$AKS_CLUSTER_NAME" &>/dev/null; then
        log_warn "AKS cluster $AKS_CLUSTER_NAME already exists"
    else
        # Build AKS create command with Azure RBAC enabled and dev/test configuration
        local aks_create_cmd="az aks create \
            --resource-group $RESOURCE_GROUP \
            --name $AKS_CLUSTER_NAME \
            --location $LOCATION \
            --node-vm-size $AKS_NODE_VM_SIZE \
            --enable-aad \
            --enable-azure-rbac \
            --aad-admin-group-object-ids '' \
            --output none"
        
        # Add node count only if specified
        if [[ -n "$AKS_NODE_COUNT" ]]; then
            aks_create_cmd="$aks_create_cmd --node-count $AKS_NODE_COUNT"
        fi
        
        # Add kubernetes version only if specified
        if [[ -n "$KUBERNETES_VERSION" ]]; then
            aks_create_cmd="$aks_create_cmd --kubernetes-version $KUBERNETES_VERSION"
        fi
        
        eval $aks_create_cmd
        
        log_info "AKS cluster created"
    fi
    
    # Add current user as cluster admin
    log_info "Adding current user as AKS cluster admin..."
    
    # Get the AKS cluster resource ID
    AKS_ID=$(az aks show --resource-group "$RESOURCE_GROUP" --name "$AKS_CLUSTER_NAME" --query id -o tsv)
    
    # Assign Azure Kubernetes Service RBAC Cluster Admin role to current user
    az role assignment create \
        --assignee "$CURRENT_USER_ID" \
        --role "Azure Kubernetes Service RBAC Cluster Admin" \
        --scope "$AKS_ID" \
        --output none 2>/dev/null || log_warn "Role assignment may already exist"
    
    log_info "Current user added as cluster admin"
    
    # Tag the MC (managed cluster) resource group with SkipCleanup=true
    log_info "Setting SkipCleanup tag on MC resource group..."
    
    MC_RESOURCE_GROUP=$(az aks show --resource-group "$RESOURCE_GROUP" --name "$AKS_CLUSTER_NAME" --query nodeResourceGroup -o tsv)
    
    az group update \
        --name "$MC_RESOURCE_GROUP" \
        --tags SkipCleanup=true \
        --output none
    
    log_info "MC resource group ($MC_RESOURCE_GROUP) tagged with SkipCleanup=true"
}

# Create user assigned managed identities
create_managed_identities() {
    # Create resource-owner managed identity
    log_info "Creating resource-owner managed identity: $RESOURCE_OWNER_MI_NAME..."
    
    if az identity show --resource-group "$RESOURCE_GROUP" --name "$RESOURCE_OWNER_MI_NAME" &>/dev/null; then
        log_warn "Managed identity $RESOURCE_OWNER_MI_NAME already exists"
    else
        az identity create \
            --resource-group "$RESOURCE_GROUP" \
            --name "$RESOURCE_OWNER_MI_NAME" \
            --location "$LOCATION" \
            --output none
        
        log_info "Resource-owner managed identity created"
    fi
    
    # Get the resource-owner managed identity IDs
    RESOURCE_OWNER_MI_ID=$(az identity show --resource-group "$RESOURCE_GROUP" --name "$RESOURCE_OWNER_MI_NAME" --query id -o tsv)
    RESOURCE_OWNER_MI_PRINCIPAL_ID=$(az identity show --resource-group "$RESOURCE_GROUP" --name "$RESOURCE_OWNER_MI_NAME" --query principalId -o tsv)
    RESOURCE_OWNER_MI_CLIENT_ID=$(az identity show --resource-group "$RESOURCE_GROUP" --name "$RESOURCE_OWNER_MI_NAME" --query clientId -o tsv)
    log_info "Resource-owner MI ID: $RESOURCE_OWNER_MI_ID"
    
    # Assign Owner role to resource-owner MI on the resource group
    log_info "Assigning Owner role to resource-owner MI on resource group..."
    local rg_id
    rg_id=$(az group show --name "$RESOURCE_GROUP" --query id -o tsv)
    az role assignment create \
        --assignee-object-id "$RESOURCE_OWNER_MI_PRINCIPAL_ID" \
        --assignee-principal-type ServicePrincipal \
        --role "Owner" \
        --scope "$rg_id" \
        --output none 2>/dev/null || log_warn "Owner role assignment may already exist"
    log_info "Owner role assigned to resource-owner MI"
    
    # Create kubelet managed identity
    log_info "Creating kubelet managed identity: $KUBELET_MI_NAME..."
    
    if az identity show --resource-group "$RESOURCE_GROUP" --name "$KUBELET_MI_NAME" &>/dev/null; then
        log_warn "Managed identity $KUBELET_MI_NAME already exists"
    else
        az identity create \
            --resource-group "$RESOURCE_GROUP" \
            --name "$KUBELET_MI_NAME" \
            --location "$LOCATION" \
            --output none
        
        log_info "Kubelet managed identity created"
    fi
    
    # Get the kubelet managed identity IDs
    KUBELET_MI_ID=$(az identity show --resource-group "$RESOURCE_GROUP" --name "$KUBELET_MI_NAME" --query id -o tsv)
    KUBELET_MI_CLIENT_ID=$(az identity show --resource-group "$RESOURCE_GROUP" --name "$KUBELET_MI_NAME" --query clientId -o tsv)
    log_info "Kubelet MI ID: $KUBELET_MI_ID"
}

# Create Ubuntu 24.04 VM with SSH enabled and managed identity
create_vm() {
    log_info "Creating Ubuntu 24.04 VM: $VM_NAME..."
    
    # Ensure generated directory exists
    mkdir -p "$GENERATED_DIR"
    
    # SSH key file path
    SSH_PRIVATE_KEY_FILE="$GENERATED_DIR/${VM_NAME}-ssh.pem"
    
    if az vm show --resource-group "$RESOURCE_GROUP" --name "$VM_NAME" &>/dev/null; then
        log_warn "VM $VM_NAME already exists"
    else
        # Create VM with new SSH key and both managed identities
        log_info "Creating VM with new SSH key..."
        az vm create \
            --resource-group "$RESOURCE_GROUP" \
            --name "$VM_NAME" \
            --location "$LOCATION" \
            --image "$VM_IMAGE" \
            --size "$VM_SIZE" \
            --admin-username azureuser \
            --generate-ssh-keys \
            --assign-identity "$RESOURCE_OWNER_MI_ID" "$KUBELET_MI_ID" \
            --public-ip-sku Standard \
            --output none
        
        log_info "VM created"
        
        # Copy the generated SSH private key to the generated folder
        if [[ -f ~/.ssh/id_rsa ]]; then
            cp ~/.ssh/id_rsa "$SSH_PRIVATE_KEY_FILE"
            chmod 600 "$SSH_PRIVATE_KEY_FILE"
            log_info "SSH private key saved to: $SSH_PRIVATE_KEY_FILE"
        else
            log_warn "Could not find generated SSH key at ~/.ssh/id_rsa"
        fi
    fi
    
    # Wait for VM to get a public IP
    log_info "Waiting for VM to get a public IP..."
    for i in {1..30}; do
        VM_PUBLIC_IP=$(az vm show --resource-group "$RESOURCE_GROUP" --name "$VM_NAME" --show-details --query publicIps -o tsv 2>/dev/null || echo "")
        if [[ -n "$VM_PUBLIC_IP" ]]; then
            break
        fi
        sleep 2
    done
    
    if [[ -z "$VM_PUBLIC_IP" ]]; then
        log_error "Failed to get VM public IP after waiting"
        exit 1
    fi
    
    log_info "VM public IP: $VM_PUBLIC_IP"
    log_info "SSH private key: $SSH_PRIVATE_KEY_FILE"
    echo ""
    log_info "To SSH into the VM, run:"
    echo "  ssh -i $SSH_PRIVATE_KEY_FILE azureuser@$VM_PUBLIC_IP"
    echo ""
}

# Get AKS credentials
get_aks_credentials() {
    log_info "Getting AKS credentials..."
    
    az aks get-credentials \
        --resource-group "$RESOURCE_GROUP" \
        --name "$AKS_CLUSTER_NAME" \
        --overwrite-existing
    
    log_info "AKS credentials configured for kubectl"
}

# Generate config file for aks-flex-node
generate_config_file() {
    log_info "Generating aks-flex-node-config.json..."
    
    # Get subscription ID
    local subscription_id
    subscription_id=$(az account show --query id -o tsv)
    
    # Get tenant ID
    local tenant_id
    tenant_id=$(az account show --query tenantId -o tsv)
    
    # Get kubelet managed identity client ID
    local mi_client_id
    mi_client_id="$KUBELET_MI_CLIENT_ID"
    
    # Get AKS cluster resource ID
    local aks_resource_id
    aks_resource_id=$(az aks show --resource-group "$RESOURCE_GROUP" --name "$AKS_CLUSTER_NAME" --query id -o tsv)
    # Ensure resourceGroups has correct casing (capital G) as it's case sensitive
    aks_resource_id=$(echo "$aks_resource_id" | sed 's|/resourcegroups/|/resourceGroups/|g')
    
    # Get Kubernetes version from the cluster (in case we didn't specify one)
    local k8s_version
    k8s_version=$(az aks show --resource-group "$RESOURCE_GROUP" --name "$AKS_CLUSTER_NAME" --query currentKubernetesVersion -o tsv)
    
    # Ensure generated directory exists
    mkdir -p "$GENERATED_DIR"
    
    # Generate the config file
    local config_file="$GENERATED_DIR/aks-flex-node-config.json"
    cat > "$config_file" <<EOF
{
  "azure": {
    "subscriptionId": "$subscription_id",
    "tenantId": "$tenant_id",
    "cloud": "AzurePublicCloud",
    "azureVm": {
      "managedIdentity": {
        "clientId": "$mi_client_id"
      }
    },
    "targetCluster": {
      "resourceId": "$aks_resource_id",
      "location": "$LOCATION"
    }
  },
  "kubernetes": {
    "version": "$k8s_version"
  },
  "agent": {
    "logLevel": "debug",
    "logDir": "/var/log/aks-flex-node"
  }
}
EOF
    
    log_info "Config file generated: $config_file"
}

# Run AKS Flex Node install script on VM
install_aks_flex_node() {
    log_info "Setting up Azure CLI and running AKS Flex Node install script on VM..."
    
    local ssh_opts="-i $SSH_PRIVATE_KEY_FILE -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
    
    # Create a temporary setup script
    local setup_script=$(cat <<'SCRIPT_EOF'
#!/bin/bash
set -e

# Function to install Azure CLI with retry for dpkg lock
install_az_cli() {
    local max_retries=5
    local retry_delay=10
    
    for ((i=1; i<=max_retries; i++)); do
        echo "Installing Azure CLI (attempt $i/$max_retries)..."
        if curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash; then
            echo "Azure CLI installed successfully"
            return 0
        fi
        
        # Check if it failed due to dpkg lock
        if [[ $i -lt $max_retries ]]; then
            echo "Installation failed, possibly due to dpkg lock. Waiting ${retry_delay}s before retry..."
            sleep $retry_delay
        fi
    done
    
    echo "Failed to install Azure CLI after $max_retries attempts"
    return 1
}

# Install Azure CLI if not present
if ! command -v az &> /dev/null; then
    install_az_cli
else
    echo "Azure CLI already installed"
fi

# Login with resource-owner managed identity
echo "Logging in with managed identity..."
az login --identity --client-id "$RESOURCE_OWNER_MI_CLIENT_ID"

# Cleanup previous setup if any
echo "Running uninstall script to cleanup previous setup..."
curl -fsSL https://gsinhaflexsa.z13.web.core.windows.net/scripts/uninstall.sh | sudo bash -s -- --force

echo "Setup completed successfully"
SCRIPT_EOF
)
    
    # Replace the placeholder with actual client ID and execute
    setup_script=$(echo "$setup_script" | sed "s/\$RESOURCE_OWNER_MI_CLIENT_ID/$RESOURCE_OWNER_MI_CLIENT_ID/g")
    
    ssh $ssh_opts azureuser@$VM_PUBLIC_IP "$setup_script" || {
        log_error "Failed to run setup script on VM"
        exit 1
    }
    
    # Copy config file to VM after uninstall but before install
    log_info "Copying config file to Azure VM..."
    local config_file="$GENERATED_DIR/aks-flex-node-config.json"
    
    # Create the target directory on the VM
    log_info "Creating /etc/aks-flex-node directory on VM..."
    ssh $ssh_opts azureuser@$VM_PUBLIC_IP "sudo mkdir -p /etc/aks-flex-node" || {
        log_error "Failed to create directory on VM"
        exit 1
    }
    
    # Copy the config file to a temp location first, then move with sudo
    log_info "Copying config file to VM..."
    scp $ssh_opts "$config_file" azureuser@$VM_PUBLIC_IP:/tmp/config.json || {
        log_error "Failed to copy config file to VM"
        exit 1
    }
    
    ssh $ssh_opts azureuser@$VM_PUBLIC_IP "sudo mv /tmp/config.json /etc/aks-flex-node/config.json" || {
        log_error "Failed to move config file to /etc/aks-flex-node"
        exit 1
    }
    
    log_info "Config file copied to /etc/aks-flex-node/config.json on VM"
    
    # Now run the install and enable script
    log_info "Running install and enable script on VM..."
    local install_script=$(cat <<'INSTALL_SCRIPT_EOF'
#!/bin/bash
set -e

# Run the AKS Flex Node install script
echo "Running AKS Flex Node install script..."
curl -fsSL https://gsinhaflexsa.z13.web.core.windows.net/scripts/install.sh | sudo bash -s -- --download-binary-base-url https://gsinhaflexsa.z13.web.core.windows.net

# Enable and start the aks-flex-node-agent service
echo "Enabling and starting aks-flex-node-agent service..."
sudo systemctl enable --now aks-flex-node-agent

# Wait for status.json to appear and kubelet to be ready
echo "Waiting for aks-flex-node to become ready... (use journalctl -u aks-flex-node-agent -f to view logs)"
status_file="/run/aks-flex-node/status.json"
max_wait=300  # 5 minutes
wait_interval=10
elapsed=0

while [[ $elapsed -lt $max_wait ]]; do
    # Check if aks-flex-node-agent service has failed
    if ! systemctl is-active --quiet aks-flex-node-agent; then
        service_status=$(systemctl is-active aks-flex-node-agent 2>/dev/null || echo "unknown")
        if [[ "$service_status" == "failed" || "$service_status" == "inactive" ]]; then
            echo "ERROR: aks-flex-node-agent service has stopped (status: $service_status)"
            echo "Dumping aks-flex-node-agent logs:"
            journalctl -u aks-flex-node-agent --since "5 minutes ago" --no-pager
            exit 1
        fi
    else
        # Service is running, show last 3 lines of logs
        echo "Last 3 lines of aks-flex-node-agent logs:"
        journalctl -u aks-flex-node-agent --no-pager -n 3
    fi
    
    if [[ -f "$status_file" ]]; then
        kubelet_running=$(sudo jq -r '.kubeletRunning' "$status_file" 2>/dev/null || echo "false")
        kubelet_ready=$(sudo jq -r '.kubeletReady' "$status_file" 2>/dev/null || echo "")
        
        echo "Status: kubeletRunning=$kubelet_running, kubeletReady=$kubelet_ready"
        
        if [[ "$kubelet_running" == "true" && "$kubelet_ready" == "Ready" ]]; then
            echo "AKS Flex Node is ready!"
            break
        fi
    else
        echo "Waiting for $status_file to appear..."
    fi
    
    sleep $wait_interval
    elapsed=$((elapsed + wait_interval))
done

if [[ $elapsed -ge $max_wait ]]; then
    echo "ERROR: AKS Flex Node did not become ready within ${max_wait} seconds"
    echo "Dumping aks-flex-node-agent logs:"
    journalctl -u aks-flex-node-agent --since "5 minutes ago" --no-pager
    exit 1
fi

echo "Install and setup completed successfully"
INSTALL_SCRIPT_EOF
)
    
    ssh $ssh_opts azureuser@$VM_PUBLIC_IP "$install_script" || {
        log_error "Failed to run install script on VM"
        exit 1
    }
    
    log_info "AKS Flex Node installation completed on VM"
}

# Verify the VM node joined the AKS cluster
verify_node_joined() {
    log_info "Verifying Azure VM is showing up as a node on the AKS cluster..."
    
    echo ""
    kubectl get nodes
    echo ""
    
    # Check if the node with the VM name exists in the cluster
    if kubectl get node "$VM_NAME" &>/dev/null; then
        log_info "Node verification successful - VM '$VM_NAME' is showing up as a node in the cluster"
    else
        log_error "VM '$VM_NAME' is not showing up as a node in the AKS cluster"
        exit 1
    fi
}

# Print summary
print_summary() {
    echo ""
    log_info "=========================================="
    log_info "  Deployment Summary"
    log_info "=========================================="
    echo ""
    echo "Resource Group:     $RESOURCE_GROUP"
    echo "Location:           $LOCATION"
    echo ""
    echo "AKS Cluster:        $AKS_CLUSTER_NAME"
    echo "Kubernetes Version: ${KUBERNETES_VERSION:-<default>}"
    echo "Node Count:         $AKS_NODE_COUNT"
    echo "Node VM Size:       $AKS_NODE_VM_SIZE"
    echo ""
    echo "VM Name:            $VM_NAME"
    echo "VM Public IP:       $VM_PUBLIC_IP"
    echo "VM Admin User:      azureuser"
    echo "VM Image:           $VM_IMAGE"
    echo ""
    echo "Resource Owner MI:  $RESOURCE_OWNER_MI_NAME"
    echo "Kubelet MI:         $KUBELET_MI_NAME"
    echo ""
    echo "Generated Files:"
    echo "  SSH Private Key:  $SSH_PRIVATE_KEY_FILE"
    echo "  Config File:      $GENERATED_DIR/aks-flex-node-config.json"
    echo ""
    echo "=========================================="
    echo ""
    echo "To SSH into the VM:"
    echo "  ssh -i $SSH_PRIVATE_KEY_FILE azureuser@$VM_PUBLIC_IP"
    echo ""
    echo "To use kubectl with the AKS cluster:"
    echo "  kubectl get nodes"
    echo ""
    echo "To delete all resources:"
    echo "  az group delete --name $RESOURCE_GROUP --yes --no-wait"
    echo ""
}

# Main function
main() {
    log_info "Starting Azure deployment for kubelet-proxy testing"
    echo ""
    
    # Check prerequisites
    command -v az >/dev/null 2>&1 || { log_error "Azure CLI (az) is required but not installed"; exit 1; }
    
    # Check if logged in
    az account show &>/dev/null || { log_error "Not logged in to Azure. Run 'az login' first."; exit 1; }
    
    # Get current user and set resource names
    get_current_user
    set_resource_names
    
    echo ""
    
    # Create resources
    create_resource_group
    create_managed_identities
    create_aks_cluster
    create_vm
    get_aks_credentials
    generate_config_file
    install_aks_flex_node
    verify_node_joined
    
    # Print summary
    print_summary
    
    log_info "Deployment complete!"
}

# Parse arguments
case "${1:-}" in
    --help|-h)
        echo "Usage: $0 [options]"
        echo ""
        echo "Options:"
        echo "  --help, -h     Show this help message"
        echo ""
        echo "Environment Variables:"
        echo "  LOCATION              Azure region (default: centralindia)"
        echo "  KUBERNETES_VERSION    AKS Kubernetes version (default: AKS default)"
        echo "  VM_SIZE               VM size (default: Standard_D2s_v3)"
        echo "  AKS_NODE_COUNT        AKS node count (default: AKS default)"
        echo "  AKS_NODE_VM_SIZE      AKS node VM size (default: Standard_D4ds_v5)"
        echo ""
        exit 0
        ;;
    *)
        main "$@"
        ;;
esac
