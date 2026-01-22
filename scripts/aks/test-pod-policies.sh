#!/bin/bash
# Test pod policies script
# This script tests pod scheduling with tolerations and node selectors
# Assumes deploy-aks.sh was run previously to set up the AKS environment

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GENERATED_DIR="$SCRIPT_DIR/generated"

# Test sample pod scheduling on the node
test_sample_pod() {
    local vm_name="$1"
    
    log_info "Creating sample pod with toleration and node selector to test scheduling..."
    
    # Create a test pod YAML
    local test_pod_yaml=$(cat <<'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: test-pod-policy-pod
  namespace: default
spec:
  tolerations:
  - key: "pod-policy"
    operator: "Equal"
    value: "required"
    effect: "NoSchedule"
  nodeSelector:
    pod-policy: "required"
  containers:
  - name: test-container
    image: mcr.microsoft.com/cbl-mariner/base/nginx:1.22
    ports:
    - containerPort: 80
  restartPolicy: Never
EOF
)
    
    # Delete existing test pod if it exists
    kubectl delete pod test-pod-policy-pod --ignore-not-found=true 2>/dev/null
    
    # Create the test pod
    echo "$test_pod_yaml" | kubectl apply -f -
    
    # Wait for the pod to be scheduled and running
    log_info "Waiting for test pod to be scheduled and running..."
    local max_wait=120
    local wait_interval=5
    local elapsed=0
    
    while [[ $elapsed -lt $max_wait ]]; do
        local pod_status=$(kubectl get pod test-pod-policy-pod -o jsonpath='{.status.phase}' 2>/dev/null || echo "Pending")
        local pod_node=$(kubectl get pod test-pod-policy-pod -o jsonpath='{.spec.nodeName}' 2>/dev/null || echo "")
        
        log_info "Pod status: $pod_status, Node: $pod_node"
        
        if [[ "$pod_status" == "Running" ]]; then
            if [[ "$pod_node" == "$vm_name" ]]; then
                log_info "Test pod is running on the expected node '$vm_name'"
                break
            else
                log_error "Test pod is running on unexpected node '$pod_node' instead of '$vm_name'"
                exit 1
            fi
        fi
        
        sleep $wait_interval
        elapsed=$((elapsed + wait_interval))
    done
    
    if [[ $elapsed -ge $max_wait ]]; then
        log_error "Test pod did not become running within ${max_wait} seconds"
        kubectl describe pod test-pod-policy-pod
        exit 1
    fi
    
    # Don't clean up test pod so it can be inspected after the test
    log_info "Test successful! Pod 'test-pod-policy-pod' is left running for inspection."
    log_info "To clean up manually, run: kubectl delete pod test-pod-policy-pod"
    log_info "Sample pod test completed successfully"
}

# Main function
main() {
    log_info "Starting pod policy test..."
    echo ""
    
    # Check prerequisites
    command -v kubectl >/dev/null 2>&1 || { log_error "kubectl is required but not installed"; exit 1; }
    
    # Check if we have a valid kubeconfig
    kubectl cluster-info &>/dev/null || { log_error "Cannot connect to Kubernetes cluster. Make sure kubeconfig is set up correctly."; exit 1; }
    
    # Get the node with pod-policy label
    log_info "Finding node with pod-policy=required label..."
    local vm_name=$(kubectl get nodes -l pod-policy=required -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
    
    if [[ -z "$vm_name" ]]; then
        log_error "No node found with pod-policy=required label"
        log_error "Make sure deploy-aks.sh was run successfully and the node has the correct label"
        exit 1
    fi
    
    log_info "Found node with pod-policy label: $vm_name"
    
    # Run the test
    test_sample_pod "$vm_name"
    
    log_info "All tests passed!"
}

# Parse arguments
case "${1:-}" in
    --help|-h)
        echo "Usage: $0 [options]"
        echo ""
        echo "Tests pod scheduling with tolerations and node selectors."
        echo "Assumes deploy-aks.sh was run previously to set up the AKS environment."
        echo ""
        echo "Options:"
        echo "  --help, -h     Show this help message"
        echo ""
        exit 0
        ;;
    *)
        main "$@"
        ;;
esac
