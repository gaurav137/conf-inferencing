#!/bin/bash
# Test pod policies script
# This script tests pod scheduling with signed pod policies
# Assumes deploy-aks.sh and deploy-kubelet-proxy.sh were run previously

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
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
POD_POLICIES_DIR="$SCRIPT_DIR/../pod-policies"
SIGNING_SERVER_PORT=8443
SIGNING_SERVER_URL="https://localhost:$SIGNING_SERVER_PORT"

# Sign the nginx pod policy using the signing server
sign_pod_policy() {
    log_info "Signing nginx-pod-policy.json using signing server..."
    
    # Check if signing server is running
    if ! curl -sf --insecure "$SIGNING_SERVER_URL/health" >/dev/null 2>&1; then
        log_error "Signing server is not running at $SIGNING_SERVER_URL"
        log_error "Make sure deploy-kubelet-proxy.sh was run successfully"
        exit 1
    fi
    
    # Use the existing nginx-pod-policy.json
    local policy_file="$POD_POLICIES_DIR/nginx-pod-policy.json"
    
    if [[ ! -f "$policy_file" ]]; then
        log_error "Pod policy file not found: $policy_file"
        exit 1
    fi
    
    log_info "Using pod policy: $policy_file"
    
    # Sign the policy
    local response
    response=$(curl -sf --insecure -X POST \
        -H "Content-Type: application/json" \
        -d @"$policy_file" \
        "$SIGNING_SERVER_URL/sign") || {
        log_error "Failed to sign pod policy"
        exit 1
    }
    
    # Extract signature from response
    POLICY_SIGNATURE=$(echo "$response" | jq -r '.signature')
    POLICY_BASE64=$(echo "$response" | jq -r '.policy')
    
    if [[ -z "$POLICY_SIGNATURE" || "$POLICY_SIGNATURE" == "null" ]]; then
        log_error "Failed to get signature from signing server response"
        echo "Response: $response"
        exit 1
    fi
    
    log_info "Policy signed successfully"
    log_info "Signature: ${POLICY_SIGNATURE:0:50}..."
}

# Test sample pod scheduling on the node with signed policy
test_sample_pod() {
    local vm_name="$1"
    
    log_info "Creating signed pod that conforms to nginx-pod-policy.json..."
    
    mkdir -p "$GENERATED_DIR"
    
    # Create pod YAML that conforms to nginx-pod-policy.json
    # The policy expects: container name "test", image "nginx:latest"
    local test_pod_yaml=$(cat <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: test-pod-policy-pod
  namespace: default
  annotations:
    kubelet-proxy.io/policy: "$POLICY_BASE64"
    kubelet-proxy.io/signature: "$POLICY_SIGNATURE"
spec:
  tolerations:
  - key: "pod-policy"
    operator: "Equal"
    value: "required"
    effect: "NoSchedule"
  nodeSelector:
    pod-policy: "required"
  containers:
  - name: test
    image: nginx:latest
    ports:
    - containerPort: 80
  restartPolicy: Never
EOF
)
    
    # Save the pod YAML for inspection
    echo "$test_pod_yaml" > "$GENERATED_DIR/test-pod-signed.yaml"
    log_info "Signed pod YAML saved to: $GENERATED_DIR/test-pod-signed.yaml"
    
    # Delete existing test pod if it exists
    kubectl delete pod test-pod-policy-pod --ignore-not-found=true 2>/dev/null
    sleep 2
    
    # Create the test pod
    log_info "Applying signed pod to cluster..."
    echo "$test_pod_yaml" | kubectl apply -f -
    
    # Wait for the pod to be scheduled and running
    log_info "Waiting for test pod to be scheduled and running..."
    local max_wait=120
    local wait_interval=5
    local elapsed=0
    
    while [[ $elapsed -lt $max_wait ]]; do
        local pod_status=$(kubectl get pod test-pod-policy-pod -o jsonpath='{.status.phase}' 2>/dev/null || echo "Pending")
        local pod_node=$(kubectl get pod test-pod-policy-pod -o jsonpath='{.spec.nodeName}' 2>/dev/null || echo "")
        local pod_reason=$(kubectl get pod test-pod-policy-pod -o jsonpath='{.status.reason}' 2>/dev/null || echo "")
        
        log_info "Pod status: $pod_status, Node: $pod_node, Reason: $pod_reason"
        
        if [[ "$pod_status" == "Running" ]]; then
            if [[ "$pod_node" == "$vm_name" ]]; then
                log_info "Test pod is running on the expected node '$vm_name'"
                break
            else
                log_error "Test pod is running on unexpected node '$pod_node' instead of '$vm_name'"
                exit 1
            fi
        elif [[ "$pod_status" == "Failed" ]]; then
            log_error "Pod failed to start"
            kubectl describe pod test-pod-policy-pod
            exit 1
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
}

# Main function
main() {
    log_info "Starting pod policy test..."
    echo ""
    
    # Check prerequisites
    command -v kubectl >/dev/null 2>&1 || { log_error "kubectl is required but not installed"; exit 1; }
    command -v curl >/dev/null 2>&1 || { log_error "curl is required but not installed"; exit 1; }
    command -v jq >/dev/null 2>&1 || { log_error "jq is required but not installed"; exit 1; }
    
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
    
    # Sign the nginx pod policy
    sign_pod_policy
    
    # Run the test with signed pod
    test_sample_pod "$vm_name"
    
    log_info "All tests passed!"
}

# Parse arguments
case "${1:-}" in
    --help|-h)
        echo "Usage: $0 [options]"
        echo ""
        echo "Tests pod scheduling with signed pod policies."
        echo "Assumes deploy-aks.sh and deploy-kubelet-proxy.sh were run previously."
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
