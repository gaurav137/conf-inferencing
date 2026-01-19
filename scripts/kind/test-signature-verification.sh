#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_test() { echo -e "${BLUE}[TEST]${NC} $1"; }

# Configuration
CLUSTER_NAME="${CLUSTER_NAME:-kubelet-proxy-test}"
WORKER_NODE_NAME="${CLUSTER_NAME}-worker"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
SIGNING_DIR="$PROJECT_ROOT/tmp/signing"
SIGN_POD_SCRIPT="$PROJECT_ROOT/scripts/sign-pod.sh"

check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check cluster exists
    if ! kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
        log_error "Cluster '$CLUSTER_NAME' not found. Run 'make deploy-kind' first."
        exit 1
    fi
    
    # Check signing script exists
    if [[ ! -x "$SIGN_POD_SCRIPT" ]]; then
        log_error "Signing script not found or not executable: $SIGN_POD_SCRIPT"
        exit 1
    fi
    
    # Check kubectl context
    kubectl config use-context "kind-${CLUSTER_NAME}" >/dev/null 2>&1
    
    log_info "Prerequisites OK"
}

generate_signing_keys() {
    log_info "Generating signing keys..."
    
    mkdir -p "$SIGNING_DIR"
    cd "$SIGNING_DIR"
    
    # Generate ECDSA key pair
    openssl ecparam -name prime256v1 -genkey -noout -out signing-key.pem
    openssl req -new -x509 -key signing-key.pem -out signing-cert.pem -days 365 \
        -subj "/CN=kubelet-proxy-signer/O=test"
    
    # Export public key
    openssl ec -in signing-key.pem -pubout -out signing-public.pem 2>/dev/null
    
    log_info "Signing keys generated in $SIGNING_DIR"
    ls -la "$SIGNING_DIR"
}

deploy_with_signature_verification() {
    log_info "Redeploying kubelet-proxy with signature verification enabled..."
    
    # Copy the signing certificate to the worker node
    docker exec "$WORKER_NODE_NAME" mkdir -p /etc/kubelet-proxy/signing
    docker cp "$SIGNING_DIR/signing-cert.pem" "$WORKER_NODE_NAME:/etc/kubelet-proxy/signing/"
    
    # Update systemd service to include signature verification
    docker exec "$WORKER_NODE_NAME" bash -c 'cat > /etc/systemd/system/kubelet-proxy.service <<EOF
[Unit]
Description=Kubelet Proxy - Pod Admission Control
Documentation=https://github.com/gaurav137/conf-inferencing
Before=kubelet.service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/kubelet-proxy \
    --kubeconfig /etc/kubernetes/kubelet.conf \
    --listen-addr 127.0.0.1:6444 \
    --tls-cert /etc/kubelet-proxy/kubelet-proxy.crt \
    --tls-key /etc/kubelet-proxy/kubelet-proxy.key \
    --admission-policy /etc/kubelet-proxy/admission-policy.json \
    --signature-verification-cert /etc/kubelet-proxy/signing/signing-cert.pem \
    --log-requests=true \
    --log-pod-payloads=false

Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF'
    
    # Restart the service
    docker exec "$WORKER_NODE_NAME" systemctl daemon-reload
    docker exec "$WORKER_NODE_NAME" systemctl restart kubelet-proxy
    
    # Wait for restart
    sleep 3
    
    if docker exec "$WORKER_NODE_NAME" systemctl is-active --quiet kubelet-proxy; then
        log_info "kubelet-proxy restarted with signature verification"
    else
        log_error "kubelet-proxy failed to restart"
        docker exec "$WORKER_NODE_NAME" journalctl -u kubelet-proxy --no-pager -n 20
        exit 1
    fi
}

create_test_pod_yaml() {
    local name="$1"
    local namespace="$2"
    
    cat <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: $name
  namespace: $namespace
spec:
  containers:
  - name: test
    image: nginx:latest
    ports:
    - containerPort: 80
EOF
}

sign_pod_spec() {
    local pod_yaml="$1"
    local output_file="$2"
    
    # Extract spec from the pod yaml and sign it
    local spec_json
    spec_json=$(echo "$pod_yaml" | yq -o json '.spec' | jq -cS .)
    
    # Create signature using openssl
    local signature
    signature=$(echo -n "$spec_json" | openssl dgst -sha256 -sign "$SIGNING_DIR/signing-key.pem" | base64 -w0)
    
    # Add annotation to pod
    echo "$pod_yaml" | yq ".metadata.annotations.\"kubelet-proxy.io/signature\" = \"$signature\""
}

cleanup_test_resources() {
    log_info "Cleaning up existing test resources..."
    kubectl delete pod test-signed --ignore-not-found=true 2>/dev/null || true
    kubectl delete pod test-unsigned --ignore-not-found=true 2>/dev/null || true
    kubectl delete pod test-bad-sig --ignore-not-found=true 2>/dev/null || true
    kubectl delete namespace sig-test --ignore-not-found=true 2>/dev/null || true
    sleep 2
}

test_signed_pod() {
    log_test "TEST 1: Creating a SIGNED pod (should be ALLOWED)..."
    echo ""
    
    mkdir -p "$SIGNING_DIR/pods"
    
    # Create pod YAML
    local pod_yaml
    pod_yaml=$(create_test_pod_yaml "test-signed" "default")
    echo "$pod_yaml" > "$SIGNING_DIR/pods/test-signed-unsigned.yaml"
    
    # Sign the pod spec
    # Extract spec, canonicalize, sign
    local spec_json
    spec_json=$(echo "$pod_yaml" | yq -o json '.spec' | jq -cS .)
    
    local signature
    signature=$(echo -n "$spec_json" | openssl dgst -sha256 -sign "$SIGNING_DIR/signing-key.pem" | base64 -w0)
    
    # Create signed pod yaml
    cat > "$SIGNING_DIR/pods/test-signed.yaml" <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: test-signed
  namespace: default
  annotations:
    kubelet-proxy.io/signature: "$signature"
spec:
  containers:
  - name: test
    image: nginx:latest
    ports:
    - containerPort: 80
EOF
    
    log_info "Created signed pod with signature annotation"
    echo "Signature: ${signature:0:50}..."
    
    # Apply the signed pod
    kubectl apply -f "$SIGNING_DIR/pods/test-signed.yaml"
    
    log_info "Waiting for pod to be scheduled..."
    sleep 10
    
    echo ""
    echo "Pod status:"
    kubectl get pod test-signed -o wide
    echo ""
    
    # Check pod status
    POD_STATUS=$(kubectl get pod test-signed -o jsonpath='{.status.phase}')
    if [[ "$POD_STATUS" == "Running" || "$POD_STATUS" == "Pending" || "$POD_STATUS" == "ContainerCreating" ]]; then
        log_info "✓ TEST 1 PASSED: Signed pod was allowed (status: $POD_STATUS)"
    else
        log_error "✗ TEST 1 FAILED: Signed pod status is $POD_STATUS"
        kubectl describe pod test-signed
    fi
    echo ""
}

test_unsigned_pod() {
    log_test "TEST 2: Creating an UNSIGNED pod (should be REJECTED)..."
    echo ""
    
    # Create unsigned pod yaml
    cat > "$SIGNING_DIR/pods/test-unsigned.yaml" <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: test-unsigned
  namespace: default
spec:
  containers:
  - name: test
    image: nginx:latest
    ports:
    - containerPort: 80
EOF
    
    # Apply the unsigned pod
    kubectl apply -f "$SIGNING_DIR/pods/test-unsigned.yaml"
    
    log_info "Waiting for admission decision..."
    sleep 5
    
    echo ""
    echo "Pod status:"
    kubectl get pod test-unsigned -o wide 2>/dev/null || echo "Pod not found"
    echo ""
    
    # Check if pod is in Failed state
    POD_STATUS=$(kubectl get pod test-unsigned -o jsonpath='{.status.phase}' 2>/dev/null || echo "NotFound")
    POD_REASON=$(kubectl get pod test-unsigned -o jsonpath='{.status.reason}' 2>/dev/null || echo "")
    
    if [[ "$POD_STATUS" == "Failed" && "$POD_REASON" == "NodeAdmissionRejected" ]]; then
        log_info "✓ TEST 2 PASSED: Unsigned pod was REJECTED (status: $POD_STATUS, reason: $POD_REASON)"
        echo ""
        kubectl describe pod test-unsigned | grep -A3 "Message:"
    elif [[ "$POD_STATUS" == "Failed" ]]; then
        log_warn "? TEST 2 PARTIAL: Pod is Failed but reason is '$POD_REASON'"
        kubectl describe pod test-unsigned | grep -A5 "Status:"
    else
        log_error "✗ TEST 2 FAILED: Unsigned pod was NOT rejected (status: $POD_STATUS)"
        kubectl describe pod test-unsigned
    fi
    echo ""
}

test_bad_signature_pod() {
    log_test "TEST 3: Creating a pod with INVALID signature (should be REJECTED)..."
    echo ""
    
    # Create pod with bad signature
    cat > "$SIGNING_DIR/pods/test-bad-sig.yaml" <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: test-bad-sig
  namespace: default
  annotations:
    kubelet-proxy.io/signature: "aW52YWxpZHNpZ25hdHVyZQ=="
spec:
  containers:
  - name: test
    image: nginx:latest
    ports:
    - containerPort: 80
EOF
    
    # Apply the pod with bad signature
    kubectl apply -f "$SIGNING_DIR/pods/test-bad-sig.yaml"
    
    log_info "Waiting for admission decision..."
    sleep 5
    
    echo ""
    echo "Pod status:"
    kubectl get pod test-bad-sig -o wide 2>/dev/null || echo "Pod not found"
    echo ""
    
    # Check if pod is in Failed state
    POD_STATUS=$(kubectl get pod test-bad-sig -o jsonpath='{.status.phase}' 2>/dev/null || echo "NotFound")
    POD_REASON=$(kubectl get pod test-bad-sig -o jsonpath='{.status.reason}' 2>/dev/null || echo "")
    
    if [[ "$POD_STATUS" == "Failed" && "$POD_REASON" == "NodeAdmissionRejected" ]]; then
        log_info "✓ TEST 3 PASSED: Pod with bad signature was REJECTED (status: $POD_STATUS, reason: $POD_REASON)"
        echo ""
        kubectl describe pod test-bad-sig | grep -A3 "Message:"
    elif [[ "$POD_STATUS" == "Failed" ]]; then
        log_warn "? TEST 3 PARTIAL: Pod is Failed but reason is '$POD_REASON'"
    else
        log_error "✗ TEST 3 FAILED: Pod with bad signature was NOT rejected (status: $POD_STATUS)"
        kubectl describe pod test-bad-sig
    fi
    echo ""
}

show_proxy_logs() {
    log_test "Recent kubelet-proxy logs (signature verification)..."
    echo ""
    docker exec "$WORKER_NODE_NAME" journalctl -u kubelet-proxy --no-pager -n 40 | grep -E "(signature|Signature|SIGNATURE|admitted|rejected|Rejected)" | tail -20 || true
    echo ""
}

run_tests() {
    echo ""
    echo "========================================"
    echo "  Signature Verification Tests"
    echo "========================================"
    echo ""
    
    check_prerequisites
    generate_signing_keys
    deploy_with_signature_verification
    cleanup_test_resources
    test_signed_pod
    test_unsigned_pod
    test_bad_signature_pod
    show_proxy_logs
    
    echo ""
    echo "========================================"
    echo "  Test Summary"
    echo "========================================"
    echo ""
    echo "Signing keys are in: $SIGNING_DIR"
    echo ""
    echo "To sign a pod:"
    echo "  $SIGN_POD_SCRIPT sign-spec <pod.yaml>"
    echo ""
    echo "To watch proxy logs in real-time:"
    echo "  docker exec $WORKER_NODE_NAME journalctl -u kubelet-proxy -f"
    echo ""
    echo "To clean up test resources:"
    echo "  kubectl delete pod test-signed test-unsigned test-bad-sig"
    echo ""
    echo "To restore proxy without signature verification:"
    echo "  make deploy-kind"
    echo ""
}

# Parse arguments
case "${1:-}" in
    --generate-keys)
        generate_signing_keys
        ;;
    --deploy)
        check_prerequisites
        generate_signing_keys
        deploy_with_signature_verification
        ;;
    --cleanup)
        cleanup_test_resources
        log_info "Test resources cleaned up"
        ;;
    *)
        run_tests
        ;;
esac
