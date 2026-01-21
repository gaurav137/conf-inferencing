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
SIGN_POD_SCRIPT="$PROJECT_ROOT/scripts/sign-pod.sh"
TEST_PODS_DIR="$PROJECT_ROOT/tmp/test-pods"
SIGNING_SERVER_CONTAINER="signing-server"
SIGNING_SERVER_PORT="${SIGNING_SERVER_PORT:-8080}"

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
    
    # Check signing-server container is running
    if ! docker ps --format '{{.Names}}' | grep -q "^${SIGNING_SERVER_CONTAINER}$"; then
        log_error "Signing server container not running. Run 'make deploy-kind' first."
        exit 1
    fi
    
    # Check kubectl context
    kubectl config use-context "kind-${CLUSTER_NAME}" >/dev/null 2>&1
    
    log_info "Prerequisites OK"
}

check_signing_server() {
    log_test "Checking signing-server status..."
    echo ""
    
    docker ps --filter "name=$SIGNING_SERVER_CONTAINER" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
    echo ""
    
    # Verify signing-server is responding
    if curl -sf "http://localhost:$SIGNING_SERVER_PORT/health" >/dev/null 2>&1; then
        log_info "Signing server is HEALTHY"
    else
        log_error "Signing server is NOT responding"
        docker logs "$SIGNING_SERVER_CONTAINER" --tail 20
        exit 1
    fi
    echo ""
}

check_proxy_status() {
    log_test "Checking kubelet-proxy status on worker node..."
    echo ""
    
    if docker exec "$WORKER_NODE_NAME" systemctl is-active --quiet kubelet-proxy; then
        log_info "kubelet-proxy is RUNNING"
        # Check if signature verification is enabled
        if docker exec "$WORKER_NODE_NAME" cat /etc/systemd/system/kubelet-proxy.service | grep -q "signature-verification-cert"; then
            log_info "Signature verification is ENABLED"
        else
            log_error "Signature verification is NOT enabled in kubelet-proxy config"
            exit 1
        fi
    else
        log_error "kubelet-proxy is NOT running"
        docker exec "$WORKER_NODE_NAME" journalctl -u kubelet-proxy --no-pager -n 20
        exit 1
    fi
    echo ""
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
  nodeSelector:
    node-type: signed-workloads
  tolerations:
  - key: "signed-workloads"
    operator: "Equal"
    value: "required"
    effect: "NoSchedule"
  containers:
  - name: test
    image: nginx:latest
    ports:
    - containerPort: 80
EOF
}

cleanup_test_resources() {
    log_info "Cleaning up existing test resources..."
    kubectl delete pod test-signed --ignore-not-found=true 2>/dev/null || true
    kubectl delete pod test-unsigned --ignore-not-found=true 2>/dev/null || true
    kubectl delete pod test-bad-sig --ignore-not-found=true 2>/dev/null || true
    sleep 2
}

test_signed_pod() {
    log_test "TEST 1: Creating a SIGNED pod (should be ALLOWED)..."
    echo ""
    
    mkdir -p "$TEST_PODS_DIR"
    
    # Create unsigned pod YAML
    create_test_pod_yaml "test-signed" "default" > "$TEST_PODS_DIR/test-signed-unsigned.yaml"
    
    # Sign the pod using sign-pod.sh (which uses signing-server)
    log_info "Signing pod spec using signing-server..."
    "$SIGN_POD_SCRIPT" sign-spec "$TEST_PODS_DIR/test-signed-unsigned.yaml" > "$TEST_PODS_DIR/test-signed.yaml" 2>/dev/null
    
    log_info "Created signed pod with signature annotation"
    
    # Apply the signed pod
    kubectl apply -f "$TEST_PODS_DIR/test-signed.yaml"
    
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
    
    mkdir -p "$TEST_PODS_DIR"
    
    # Create unsigned pod yaml
    create_test_pod_yaml "test-unsigned" "default" > "$TEST_PODS_DIR/test-unsigned.yaml"
    
    # Apply the unsigned pod
    kubectl apply -f "$TEST_PODS_DIR/test-unsigned.yaml"
    
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
    
    mkdir -p "$TEST_PODS_DIR"
    
    # Create pod with bad signature
    cat > "$TEST_PODS_DIR/test-bad-sig.yaml" <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: test-bad-sig
  namespace: default
  annotations:
    kubelet-proxy.io/signature: "aW52YWxpZHNpZ25hdHVyZQ=="
spec:
  nodeSelector:
    node-type: signed-workloads
  tolerations:
  - key: "signed-workloads"
    operator: "Equal"
    value: "required"
    effect: "NoSchedule"
  containers:
  - name: test
    image: nginx:latest
    ports:
    - containerPort: 80
EOF
    
    # Apply the pod with bad signature
    kubectl apply -f "$TEST_PODS_DIR/test-bad-sig.yaml"
    
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
    check_signing_server
    check_proxy_status
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
    echo "To sign a pod:"
    echo "  $SIGN_POD_SCRIPT sign-spec <pod.yaml>"
    echo ""
    echo "To watch proxy logs in real-time:"
    echo "  docker exec $WORKER_NODE_NAME journalctl -u kubelet-proxy -f"
    echo ""
    echo "To clean up test resources:"
    echo "  kubectl delete pod test-signed test-unsigned test-bad-sig"
    echo ""
}

# Parse arguments
case "${1:-}" in
    --status)
        check_prerequisites
        check_signing_server
        check_proxy_status
        ;;
    --cleanup)
        cleanup_test_resources
        log_info "Test resources cleaned up"
        ;;
    *)
        run_tests
        ;;
esac
