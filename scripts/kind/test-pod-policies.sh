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
TEST_POLICIES_DIR="$SCRIPT_DIR/pod-policies"
SIGNING_SERVER_CONTAINER="signing-server"
SIGNING_SERVER_PORT="${SIGNING_SERVER_PORT:-8080}"
SIGNING_SERVER_URL="${SIGNING_SERVER_URL:-http://localhost:$SIGNING_SERVER_PORT}"

# Test result tracking
TEST1_RESULT=""
TEST2_RESULT=""
TEST3_RESULT=""
TEST4_RESULT=""
TEST5_RESULT=""
TEST6_RESULT=""
TEST7_RESULT=""
TEST8_RESULT=""

check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check cluster exists
    if ! kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
        log_error "Cluster '$CLUSTER_NAME' not found. Run 'make deploy-kind' first."
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
    
    # Verify signing-server is responding (try HTTPS first, then HTTP)
    if curl -sf --insecure "https://localhost:$SIGNING_SERVER_PORT/health" >/dev/null 2>&1; then
        log_info "Signing server is HEALTHY (HTTPS)"
        SIGNING_SERVER_URL="https://localhost:$SIGNING_SERVER_PORT"
    elif curl -sf "http://localhost:$SIGNING_SERVER_PORT/health" >/dev/null 2>&1; then
        log_info "Signing server is HEALTHY (HTTP)"
        SIGNING_SERVER_URL="http://localhost:$SIGNING_SERVER_PORT"
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
        # Check if pod policy verification is enabled
        if docker exec "$WORKER_NODE_NAME" cat /etc/systemd/system/kubelet-proxy.service | grep -q "policy-verification-cert"; then
            log_info "Pod policy verification is ENABLED"
        else
            log_error "Pod policy verification is NOT enabled in kubelet-proxy config"
            exit 1
        fi
    else
        log_error "kubelet-proxy is NOT running"
        docker exec "$WORKER_NODE_NAME" journalctl -u kubelet-proxy --no-pager -n 20
        exit 1
    fi
    echo ""
}

# Load and compact a policy JSON file (sorted keys, no whitespace)
load_policy_json() {
    local policy_file="$1"
    python3 -c "
import json
import sys

with open('$policy_file', 'r') as f:
    policy = json.load(f)

def sort_dict(obj):
    if isinstance(obj, dict):
        return {k: sort_dict(v) for k, v in sorted(obj.items())}
    elif isinstance(obj, list):
        return [sort_dict(item) for item in obj]
    return obj

sorted_policy = sort_dict(policy)
print(json.dumps(sorted_policy, separators=(',', ':')))
"
}

# Sign a policy JSON and return the signature
sign_policy() {
    local policy_base64="$1"
    
    local response
    # Use --insecure for HTTPS with self-signed cert
    response=$(curl -sf --insecure -X POST "$SIGNING_SERVER_URL/sign" \
        -H "Content-Type: application/json" \
        -d "{\"payload\": $(printf '%s' "$policy_base64" | jq -Rs .)}")
    
    if [[ $? -ne 0 ]]; then
        echo ""
        return 1
    fi
    
    echo "$response" | jq -r '.signature'
}

cleanup_test_resources() {
    log_info "Cleaning up existing test resources..."
    kubectl delete pod test-signed --ignore-not-found=true 2>/dev/null || true
    kubectl delete pod test-unsigned --ignore-not-found=true 2>/dev/null || true
    kubectl delete pod test-bad-sig --ignore-not-found=true 2>/dev/null || true
    kubectl delete pod test-image-mismatch --ignore-not-found=true 2>/dev/null || true
    kubectl delete pod test-full-policy --ignore-not-found=true 2>/dev/null || true
    kubectl delete pod test-command-mismatch --ignore-not-found=true 2>/dev/null || true
    kubectl delete pod test-env-mismatch --ignore-not-found=true 2>/dev/null || true
    kubectl delete pod test-volume-mismatch --ignore-not-found=true 2>/dev/null || true
    kubectl delete configmap test-config --ignore-not-found=true 2>/dev/null || true
    kubectl delete pvc test-data --ignore-not-found=true 2>/dev/null || true
    sleep 2
}

test_signed_pod() {
    log_test "TEST 1: Creating a SIGNED pod (should be ALLOWED)..."
    echo ""
    
    # Load the nginx policy from the checked-in file
    local policy_file="$TEST_POLICIES_DIR/nginx-pod-policy.json"
    if [[ ! -f "$policy_file" ]]; then
        log_error "Policy file not found: $policy_file"
        TEST1_RESULT="FAILED"
        return
    fi
    
    log_info "Loading policy from $policy_file"
    local policy_json
    policy_json=$(load_policy_json "$policy_file")
    
    # Base64 encode the policy
    local policy_base64
    policy_base64=$(printf '%s' "$policy_json" | base64 -w 0)
    
    log_info "Policy: $policy_json"
    
    # Sign the policy
    log_info "Signing policy using signing-server..."
    local signature
    signature=$(sign_policy "$policy_base64")
    
    if [[ -z "$signature" || "$signature" == "null" ]]; then
        log_error "Failed to sign policy"
        TEST1_RESULT="FAILED"
        return
    fi
    
    # Create the signed pod YAML
    cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: test-signed
  namespace: default
  annotations:
    kubelet-proxy.io/policy: "$policy_base64"
    kubelet-proxy.io/signature: "$signature"
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
        TEST1_RESULT="PASSED"
    else
        log_error "✗ TEST 1 FAILED: Signed pod status is $POD_STATUS"
        kubectl describe pod test-signed
        TEST1_RESULT="FAILED"
    fi
    echo ""
}

test_unsigned_pod() {
    log_test "TEST 2: Creating an UNSIGNED pod (should be REJECTED)..."
    echo ""
    
    # Create unsigned pod yaml directly
    cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: test-unsigned
  namespace: default
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
    
    log_info "Waiting for admission decision..."
    sleep 5
    
    echo ""
    echo "Pod status:"
    kubectl get pod test-unsigned -o wide 2>/dev/null || echo "Pod not found"
    echo ""
    
    # Check if pod is in Failed state
    POD_STATUS=$(kubectl get pod test-unsigned -o jsonpath='{.status.phase}' 2>/dev/null || echo "NotFound")
    POD_REASON=$(kubectl get pod test-unsigned -o jsonpath='{.status.reason}' 2>/dev/null || echo "")
    POD_MESSAGE=$(kubectl get pod test-unsigned -o jsonpath='{.status.message}' 2>/dev/null || echo "")
    
    EXPECTED_MSG="pod policy required but not found"
    if [[ "$POD_STATUS" == "Failed" && "$POD_REASON" == "NodeAdmissionRejected" ]]; then
        if echo "$POD_MESSAGE" | grep -q "$EXPECTED_MSG"; then
            log_info "✓ TEST 2 PASSED: Unsigned pod was REJECTED with expected message"
            echo ""
            kubectl describe pod test-unsigned | grep -A3 "Message:"
            TEST2_RESULT="PASSED"
        else
            log_error "✗ TEST 2 FAILED: Pod rejected but message mismatch"
            log_error "  Expected: '$EXPECTED_MSG'"
            log_error "  Got: '$POD_MESSAGE'"
            TEST2_RESULT="FAILED"
        fi
    elif [[ "$POD_STATUS" == "Failed" ]]; then
        log_warn "? TEST 2 PARTIAL: Pod is Failed but reason is '$POD_REASON'"
        kubectl describe pod test-unsigned | grep -A5 "Status:"
        TEST2_RESULT="PARTIAL"
    else
        log_error "✗ TEST 2 FAILED: Unsigned pod was NOT rejected (status: $POD_STATUS)"
        kubectl describe pod test-unsigned
        TEST2_RESULT="FAILED"
    fi
    echo ""
}

test_bad_signature_pod() {
    log_test "TEST 3: Creating a pod with INVALID signature (should be REJECTED)..."
    echo ""
    
    # Load the nginx policy from the checked-in file
    local policy_file="$TEST_POLICIES_DIR/nginx-pod-policy.json"
    local policy_json
    policy_json=$(load_policy_json "$policy_file")
    local policy_base64
    policy_base64=$(printf '%s' "$policy_json" | base64 -w 0)
    
    # Create pod with valid policy but garbage signature
    cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: test-bad-sig
  namespace: default
  annotations:
    kubelet-proxy.io/policy: "$policy_base64"
    kubelet-proxy.io/signature: "aW52YWxpZHNpZ25hdHVyZWRhdGE="
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
    
    log_info "Waiting for admission decision..."
    sleep 5
    
    echo ""
    echo "Pod status:"
    kubectl get pod test-bad-sig -o wide 2>/dev/null || echo "Pod not found"
    echo ""
    
    # Check if pod is in Failed state
    POD_STATUS=$(kubectl get pod test-bad-sig -o jsonpath='{.status.phase}' 2>/dev/null || echo "NotFound")
    POD_REASON=$(kubectl get pod test-bad-sig -o jsonpath='{.status.reason}' 2>/dev/null || echo "")
    POD_MESSAGE=$(kubectl get pod test-bad-sig -o jsonpath='{.status.message}' 2>/dev/null || echo "")
    
    EXPECTED_MSG="policy signature verification failed"
    if [[ "$POD_STATUS" == "Failed" && "$POD_REASON" == "NodeAdmissionRejected" ]]; then
        if echo "$POD_MESSAGE" | grep -q "$EXPECTED_MSG"; then
            log_info "✓ TEST 3 PASSED: Pod with bad signature was REJECTED with expected message"
            echo ""
            kubectl describe pod test-bad-sig | grep -A3 "Message:"
            TEST3_RESULT="PASSED"
        else
            log_error "✗ TEST 3 FAILED: Pod rejected but message mismatch"
            log_error "  Expected: '$EXPECTED_MSG'"
            log_error "  Got: '$POD_MESSAGE'"
            TEST3_RESULT="FAILED"
        fi
    elif [[ "$POD_STATUS" == "Failed" ]]; then
        log_warn "? TEST 3 PARTIAL: Pod is Failed but reason is '$POD_REASON'"
        TEST3_RESULT="PARTIAL"
    else
        log_error "✗ TEST 3 FAILED: Pod with bad signature was NOT rejected (status: $POD_STATUS)"
        kubectl describe pod test-bad-sig
        TEST3_RESULT="FAILED"
    fi
    echo ""
}

test_image_mismatch_pod() {
    log_test "TEST 4: Creating a pod with MISMATCHED IMAGE (policy says nginx, pod uses busybox)..."
    echo ""
    
    # Load the nginx policy from the checked-in file (this policy allows nginx:latest)
    local policy_file="$TEST_POLICIES_DIR/nginx-pod-policy.json"
    if [[ ! -f "$policy_file" ]]; then
        log_error "Policy file not found: $policy_file"
        TEST4_RESULT="FAILED"
        return
    fi
    
    local policy_json
    policy_json=$(load_policy_json "$policy_file")
    local policy_base64
    policy_base64=$(printf '%s' "$policy_json" | base64 -w 0)
    
    # Sign the nginx policy
    log_info "Signing nginx policy..."
    local signature
    signature=$(sign_policy "$policy_base64")
    
    if [[ -z "$signature" || "$signature" == "null" ]]; then
        log_error "Failed to sign policy"
        TEST4_RESULT="FAILED"
        return
    fi
    
    log_info "Creating pod with busybox:latest but using nginx policy signature..."
    
    # Create a pod with busybox image but using the nginx policy signature
    cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: test-image-mismatch
  namespace: default
  annotations:
    kubelet-proxy.io/policy: "$policy_base64"
    kubelet-proxy.io/signature: "$signature"
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
    image: busybox:latest
    command: ["sleep", "3600"]
EOF
    
    log_info "Waiting for admission decision..."
    sleep 5
    
    echo ""
    echo "Pod status:"
    kubectl get pod test-image-mismatch -o wide 2>/dev/null || echo "Pod not found"
    echo ""
    
    # Check if pod is in Failed state
    POD_STATUS=$(kubectl get pod test-image-mismatch -o jsonpath='{.status.phase}' 2>/dev/null || echo "NotFound")
    POD_REASON=$(kubectl get pod test-image-mismatch -o jsonpath='{.status.reason}' 2>/dev/null || echo "")
    POD_MESSAGE=$(kubectl get pod test-image-mismatch -o jsonpath='{.status.message}' 2>/dev/null || echo "")
    
    EXPECTED_MSG="image.*does not match policy"
    if [[ "$POD_STATUS" == "Failed" && "$POD_REASON" == "NodeAdmissionRejected" ]]; then
        if echo "$POD_MESSAGE" | grep -qE "$EXPECTED_MSG"; then
            log_info "✓ TEST 4 PASSED: Pod with mismatched image was REJECTED with expected message"
            echo ""
            kubectl describe pod test-image-mismatch | grep -A3 "Message:"
            TEST4_RESULT="PASSED"
        else
            log_error "✗ TEST 4 FAILED: Pod rejected but message mismatch"
            log_error "  Expected pattern: '$EXPECTED_MSG'"
            log_error "  Got: '$POD_MESSAGE'"
            TEST4_RESULT="FAILED"
        fi
    elif [[ "$POD_STATUS" == "Failed" ]]; then
        log_warn "? TEST 4 PARTIAL: Pod is Failed but reason is '$POD_REASON'"
        kubectl describe pod test-image-mismatch | grep -A5 "Status:"
        TEST4_RESULT="PARTIAL"
    else
        log_error "✗ TEST 4 FAILED: Pod with mismatched image was NOT rejected (status: $POD_STATUS)"
        kubectl describe pod test-image-mismatch
        TEST4_RESULT="FAILED"
    fi
    echo ""
}

# Helper to create test volumes (ConfigMap and PVC)
create_test_volumes() {
    log_info "Creating test volumes (ConfigMap and emptyDir)..."
    
    # Create a ConfigMap for the config volume
    kubectl apply -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: test-config
  namespace: default
data:
  config.yaml: |
    setting: value
EOF
}

test_full_policy_pod() {
    log_test "TEST 5: Creating a pod with FULL POLICY (command, args, env, volumeMounts) - should be ALLOWED..."
    echo ""
    
    # Ensure test volumes exist
    create_test_volumes
    
    # Load the full policy from the checked-in file
    local policy_file="$TEST_POLICIES_DIR/full-policy-pod-policy.json"
    if [[ ! -f "$policy_file" ]]; then
        log_error "Policy file not found: $policy_file"
        TEST5_RESULT="FAILED"
        return
    fi
    
    log_info "Loading policy from $policy_file"
    local policy_json
    policy_json=$(load_policy_json "$policy_file")
    
    # Base64 encode the policy
    local policy_base64
    policy_base64=$(printf '%s' "$policy_json" | base64 -w 0)
    
    log_info "Policy: $policy_json"
    
    # Sign the policy
    log_info "Signing policy using signing-server..."
    local signature
    signature=$(sign_policy "$policy_base64")
    
    if [[ -z "$signature" || "$signature" == "null" ]]; then
        log_error "Failed to sign policy"
        TEST5_RESULT="FAILED"
        return
    fi
    
    # Create the signed pod YAML with all fields matching policy
    cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: test-full-policy
  namespace: default
  annotations:
    kubelet-proxy.io/policy: "$policy_base64"
    kubelet-proxy.io/signature: "$signature"
spec:
  nodeSelector:
    node-type: signed-workloads
  tolerations:
  - key: "signed-workloads"
    operator: "Equal"
    value: "required"
    effect: "NoSchedule"
  volumes:
  - name: config
    configMap:
      name: test-config
  - name: data
    emptyDir: {}
  containers:
  - name: app
    image: busybox:latest
    command: ["/bin/myapp"]
    args: ["--config=/etc/app/config.yaml", "--verbose"]
    env:
    - name: APP_ENV
      value: "production"
    - name: LOG_LEVEL
      value: "debug"
    volumeMounts:
    - name: config
      mountPath: /etc/app
      readOnly: true
    - name: data
      mountPath: /data
      readOnly: false
EOF
    
    log_info "Waiting for pod to be scheduled..."
    sleep 10
    
    echo ""
    echo "Pod status:"
    kubectl get pod test-full-policy -o wide
    echo ""
    
    # Check pod status
    POD_STATUS=$(kubectl get pod test-full-policy -o jsonpath='{.status.phase}')
    POD_REASON=$(kubectl get pod test-full-policy -o jsonpath='{.status.reason}' 2>/dev/null || echo "")
    if [[ "$POD_STATUS" == "Running" || "$POD_STATUS" == "Pending" || "$POD_STATUS" == "ContainerCreating" ]]; then
        # For busybox with fake command, it will fail but should be admitted first
        if [[ "$POD_REASON" != "NodeAdmissionRejected" ]]; then
            log_info "✓ TEST 5 PASSED: Full policy pod was allowed (status: $POD_STATUS)"
            TEST5_RESULT="PASSED"
        else
            log_error "✗ TEST 5 FAILED: Full policy pod was rejected"
            kubectl describe pod test-full-policy
            TEST5_RESULT="FAILED"
        fi
    elif [[ "$POD_STATUS" == "Failed" && "$POD_REASON" != "NodeAdmissionRejected" ]]; then
        # Pod failed for other reasons (e.g., command not found) - that's OK, it was admitted
        log_info "✓ TEST 5 PASSED: Full policy pod was admitted (failed later due to: $POD_REASON)"
        TEST5_RESULT="PASSED"
    else
        log_error "✗ TEST 5 FAILED: Full policy pod status is $POD_STATUS (reason: $POD_REASON)"
        kubectl describe pod test-full-policy
        TEST5_RESULT="FAILED"
    fi
    echo ""
}

test_command_mismatch_pod() {
    log_test "TEST 6: Creating a pod with MISMATCHED COMMAND (should be REJECTED)..."
    echo ""
    
    # Load the full policy (expects command: ["/bin/myapp"])
    local policy_file="$TEST_POLICIES_DIR/full-policy-pod-policy.json"
    local policy_json
    policy_json=$(load_policy_json "$policy_file")
    local policy_base64
    policy_base64=$(printf '%s' "$policy_json" | base64 -w 0)
    
    # Sign the policy
    local signature
    signature=$(sign_policy "$policy_base64")
    
    if [[ -z "$signature" || "$signature" == "null" ]]; then
        log_error "Failed to sign policy"
        TEST6_RESULT="FAILED"
        return
    fi
    
    log_info "Creating pod with different command (policy expects /bin/myapp, using /bin/sh)..."
    
    # Create pod with DIFFERENT command than policy
    cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: test-command-mismatch
  namespace: default
  annotations:
    kubelet-proxy.io/policy: "$policy_base64"
    kubelet-proxy.io/signature: "$signature"
spec:
  nodeSelector:
    node-type: signed-workloads
  tolerations:
  - key: "signed-workloads"
    operator: "Equal"
    value: "required"
    effect: "NoSchedule"
  volumes:
  - name: config
    configMap:
      name: test-config
  - name: data
    emptyDir: {}
  containers:
  - name: app
    image: busybox:latest
    command: ["/bin/sh"]  # MISMATCH: policy expects /bin/myapp
    args: ["--config=/etc/app/config.yaml", "--verbose"]
    env:
    - name: APP_ENV
      value: "production"
    - name: LOG_LEVEL
      value: "debug"
    volumeMounts:
    - name: config
      mountPath: /etc/app
      readOnly: true
    - name: data
      mountPath: /data
      readOnly: false
EOF
    
    log_info "Waiting for admission decision..."
    sleep 5
    
    echo ""
    echo "Pod status:"
    kubectl get pod test-command-mismatch -o wide 2>/dev/null || echo "Pod not found"
    echo ""
    
    POD_STATUS=$(kubectl get pod test-command-mismatch -o jsonpath='{.status.phase}' 2>/dev/null || echo "NotFound")
    POD_REASON=$(kubectl get pod test-command-mismatch -o jsonpath='{.status.reason}' 2>/dev/null || echo "")
    POD_MESSAGE=$(kubectl get pod test-command-mismatch -o jsonpath='{.status.message}' 2>/dev/null || echo "")
    
    EXPECTED_MSG="command.*does not match policy"
    if [[ "$POD_STATUS" == "Failed" && "$POD_REASON" == "NodeAdmissionRejected" ]]; then
        if echo "$POD_MESSAGE" | grep -qE "$EXPECTED_MSG"; then
            log_info "✓ TEST 6 PASSED: Pod with command mismatch was REJECTED with expected message"
            echo ""
            kubectl describe pod test-command-mismatch | grep -A3 "Message:"
            TEST6_RESULT="PASSED"
        else
            log_error "✗ TEST 6 FAILED: Pod rejected but message mismatch"
            log_error "  Expected pattern: '$EXPECTED_MSG'"
            log_error "  Got: '$POD_MESSAGE'"
            TEST6_RESULT="FAILED"
        fi
    elif [[ "$POD_STATUS" == "Failed" ]]; then
        log_warn "? TEST 6 PARTIAL: Pod is Failed but reason is '$POD_REASON'"
        TEST6_RESULT="PARTIAL"
    else
        log_error "✗ TEST 6 FAILED: Pod with command mismatch was NOT rejected (status: $POD_STATUS)"
        kubectl describe pod test-command-mismatch
        TEST6_RESULT="FAILED"
    fi
    echo ""
}

test_env_mismatch_pod() {
    log_test "TEST 7: Creating a pod with MISMATCHED ENV (should be REJECTED)..."
    echo ""
    
    # Load the full policy
    local policy_file="$TEST_POLICIES_DIR/full-policy-pod-policy.json"
    local policy_json
    policy_json=$(load_policy_json "$policy_file")
    local policy_base64
    policy_base64=$(printf '%s' "$policy_json" | base64 -w 0)
    
    # Sign the policy
    local signature
    signature=$(sign_policy "$policy_base64")
    
    if [[ -z "$signature" || "$signature" == "null" ]]; then
        log_error "Failed to sign policy"
        TEST7_RESULT="FAILED"
        return
    fi
    
    log_info "Creating pod with different env (policy expects APP_ENV=production, using APP_ENV=development)..."
    
    # Create pod with DIFFERENT env than policy
    cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: test-env-mismatch
  namespace: default
  annotations:
    kubelet-proxy.io/policy: "$policy_base64"
    kubelet-proxy.io/signature: "$signature"
spec:
  nodeSelector:
    node-type: signed-workloads
  tolerations:
  - key: "signed-workloads"
    operator: "Equal"
    value: "required"
    effect: "NoSchedule"
  volumes:
  - name: config
    configMap:
      name: test-config
  - name: data
    emptyDir: {}
  containers:
  - name: app
    image: busybox:latest
    command: ["/bin/myapp"]
    args: ["--config=/etc/app/config.yaml", "--verbose"]
    env:
    - name: APP_ENV
      value: "development"  # MISMATCH: policy expects "production"
    - name: LOG_LEVEL
      value: "debug"
    volumeMounts:
    - name: config
      mountPath: /etc/app
      readOnly: true
    - name: data
      mountPath: /data
      readOnly: false
EOF
    
    log_info "Waiting for admission decision..."
    sleep 5
    
    echo ""
    echo "Pod status:"
    kubectl get pod test-env-mismatch -o wide 2>/dev/null || echo "Pod not found"
    echo ""
    
    POD_STATUS=$(kubectl get pod test-env-mismatch -o jsonpath='{.status.phase}' 2>/dev/null || echo "NotFound")
    POD_REASON=$(kubectl get pod test-env-mismatch -o jsonpath='{.status.reason}' 2>/dev/null || echo "")
    POD_MESSAGE=$(kubectl get pod test-env-mismatch -o jsonpath='{.status.message}' 2>/dev/null || echo "")
    
    EXPECTED_MSG="env var.*does not match policy"
    if [[ "$POD_STATUS" == "Failed" && "$POD_REASON" == "NodeAdmissionRejected" ]]; then
        if echo "$POD_MESSAGE" | grep -qE "$EXPECTED_MSG"; then
            log_info "✓ TEST 7 PASSED: Pod with env mismatch was REJECTED with expected message"
            echo ""
            kubectl describe pod test-env-mismatch | grep -A3 "Message:"
            TEST7_RESULT="PASSED"
        else
            log_error "✗ TEST 7 FAILED: Pod rejected but message mismatch"
            log_error "  Expected pattern: '$EXPECTED_MSG'"
            log_error "  Got: '$POD_MESSAGE'"
            TEST7_RESULT="FAILED"
        fi
    elif [[ "$POD_STATUS" == "Failed" ]]; then
        log_warn "? TEST 7 PARTIAL: Pod is Failed but reason is '$POD_REASON'"
        TEST7_RESULT="PARTIAL"
    else
        log_error "✗ TEST 7 FAILED: Pod with env mismatch was NOT rejected (status: $POD_STATUS)"
        kubectl describe pod test-env-mismatch
        TEST7_RESULT="FAILED"
    fi
    echo ""
}

test_volume_mismatch_pod() {
    log_test "TEST 8: Creating a pod with MISMATCHED VOLUME MOUNT (should be REJECTED)..."
    echo ""
    
    # Load the full policy (expects mountPath: /etc/app and /data)
    local policy_file="$TEST_POLICIES_DIR/full-policy-pod-policy.json"
    local policy_json
    policy_json=$(load_policy_json "$policy_file")
    local policy_base64
    policy_base64=$(printf '%s' "$policy_json" | base64 -w 0)
    
    # Sign the policy
    local signature
    signature=$(sign_policy "$policy_base64")
    
    if [[ -z "$signature" || "$signature" == "null" ]]; then
        log_error "Failed to sign policy"
        TEST8_RESULT="FAILED"
        return
    fi
    
    log_info "Creating pod with different volume mount path (policy expects /etc/app, using /etc/config)..."
    
    # Create pod with DIFFERENT volume mount path than policy
    cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: test-volume-mismatch
  namespace: default
  annotations:
    kubelet-proxy.io/policy: "$policy_base64"
    kubelet-proxy.io/signature: "$signature"
spec:
  nodeSelector:
    node-type: signed-workloads
  tolerations:
  - key: "signed-workloads"
    operator: "Equal"
    value: "required"
    effect: "NoSchedule"
  volumes:
  - name: config
    configMap:
      name: test-config
  - name: data
    emptyDir: {}
  containers:
  - name: app
    image: busybox:latest
    command: ["/bin/myapp"]
    args: ["--config=/etc/app/config.yaml", "--verbose"]
    env:
    - name: APP_ENV
      value: "production"
    - name: LOG_LEVEL
      value: "debug"
    volumeMounts:
    - name: config
      mountPath: /etc/config  # MISMATCH: policy expects /etc/app
      readOnly: true
    - name: data
      mountPath: /data
      readOnly: false
EOF
    
    log_info "Waiting for admission decision..."
    sleep 5
    
    echo ""
    echo "Pod status:"
    kubectl get pod test-volume-mismatch -o wide 2>/dev/null || echo "Pod not found"
    echo ""
    
    POD_STATUS=$(kubectl get pod test-volume-mismatch -o jsonpath='{.status.phase}' 2>/dev/null || echo "NotFound")
    POD_REASON=$(kubectl get pod test-volume-mismatch -o jsonpath='{.status.reason}' 2>/dev/null || echo "")
    POD_MESSAGE=$(kubectl get pod test-volume-mismatch -o jsonpath='{.status.message}' 2>/dev/null || echo "")
    
    EXPECTED_MSG="volume mount.*does not match policy"
    if [[ "$POD_STATUS" == "Failed" && "$POD_REASON" == "NodeAdmissionRejected" ]]; then
        if echo "$POD_MESSAGE" | grep -qE "$EXPECTED_MSG"; then
            log_info "✓ TEST 8 PASSED: Pod with volume mount mismatch was REJECTED with expected message"
            echo ""
            kubectl describe pod test-volume-mismatch | grep -A3 "Message:"
            TEST8_RESULT="PASSED"
        else
            log_error "✗ TEST 8 FAILED: Pod rejected but message mismatch"
            log_error "  Expected pattern: '$EXPECTED_MSG'"
            log_error "  Got: '$POD_MESSAGE'"
            TEST8_RESULT="FAILED"
        fi
    elif [[ "$POD_STATUS" == "Failed" ]]; then
        log_warn "? TEST 8 PARTIAL: Pod is Failed but reason is '$POD_REASON'"
        TEST8_RESULT="PARTIAL"
    else
        log_error "✗ TEST 8 FAILED: Pod with volume mount mismatch was NOT rejected (status: $POD_STATUS)"
        kubectl describe pod test-volume-mismatch
        TEST8_RESULT="FAILED"
    fi
    echo ""
}

show_proxy_logs() {
    log_test "Recent kubelet-proxy logs (policy verification)..."
    echo ""
    docker exec "$WORKER_NODE_NAME" journalctl -u kubelet-proxy --no-pager -n 60 | grep -E "(policy|Policy|POLICY|admitted|rejected|Rejected|command|env|volume)" | tail -30 || true
    echo ""
}

run_tests() {
    echo ""
    echo "========================================"
    echo "  Pod Policy Verification Tests"
    echo "========================================"
    echo ""
    
    check_prerequisites
    check_signing_server
    check_proxy_status
    cleanup_test_resources
    test_signed_pod
    test_unsigned_pod
    test_bad_signature_pod
    test_image_mismatch_pod
    test_full_policy_pod
    test_command_mismatch_pod
    test_env_mismatch_pod
    test_volume_mismatch_pod
    show_proxy_logs
    
    echo ""
    echo "========================================"
    echo "  Test Results Summary"
    echo "========================================"
    echo ""
    
    # Count results
    local passed=0
    local failed=0
    local partial=0
    
    # Print individual test results
    if [[ "$TEST1_RESULT" == "PASSED" ]]; then
        echo -e "  ${GREEN}✓${NC} TEST 1: Signed pod allowed       - PASSED"
        passed=$((passed + 1))
    else
        echo -e "  ${RED}✗${NC} TEST 1: Signed pod allowed       - FAILED"
        failed=$((failed + 1))
    fi
    
    if [[ "$TEST2_RESULT" == "PASSED" ]]; then
        echo -e "  ${GREEN}✓${NC} TEST 2: Unsigned pod rejected    - PASSED"
        passed=$((passed + 1))
    elif [[ "$TEST2_RESULT" == "PARTIAL" ]]; then
        echo -e "  ${YELLOW}?${NC} TEST 2: Unsigned pod rejected    - PARTIAL"
        partial=$((partial + 1))
    else
        echo -e "  ${RED}✗${NC} TEST 2: Unsigned pod rejected    - FAILED"
        failed=$((failed + 1))
    fi
    
    if [[ "$TEST3_RESULT" == "PASSED" ]]; then
        echo -e "  ${GREEN}✓${NC} TEST 3: Bad signature rejected   - PASSED"
        passed=$((passed + 1))
    elif [[ "$TEST3_RESULT" == "PARTIAL" ]]; then
        echo -e "  ${YELLOW}?${NC} TEST 3: Bad signature rejected   - PARTIAL"
        partial=$((partial + 1))
    else
        echo -e "  ${RED}✗${NC} TEST 3: Bad signature rejected   - FAILED"
        failed=$((failed + 1))
    fi
    
    if [[ "$TEST4_RESULT" == "PASSED" ]]; then
        echo -e "  ${GREEN}✓${NC} TEST 4: Image mismatch rejected  - PASSED"
        passed=$((passed + 1))
    elif [[ "$TEST4_RESULT" == "PARTIAL" ]]; then
        echo -e "  ${YELLOW}?${NC} TEST 4: Image mismatch rejected  - PARTIAL"
        partial=$((partial + 1))
    else
        echo -e "  ${RED}✗${NC} TEST 4: Image mismatch rejected  - FAILED"
        failed=$((failed + 1))
    fi
    
    if [[ "$TEST5_RESULT" == "PASSED" ]]; then
        echo -e "  ${GREEN}✓${NC} TEST 5: Full policy pod allowed  - PASSED"
        passed=$((passed + 1))
    elif [[ "$TEST5_RESULT" == "PARTIAL" ]]; then
        echo -e "  ${YELLOW}?${NC} TEST 5: Full policy pod allowed  - PARTIAL"
        partial=$((partial + 1))
    else
        echo -e "  ${RED}✗${NC} TEST 5: Full policy pod allowed  - FAILED"
        failed=$((failed + 1))
    fi
    
    if [[ "$TEST6_RESULT" == "PASSED" ]]; then
        echo -e "  ${GREEN}✓${NC} TEST 6: Command mismatch rejected - PASSED"
        passed=$((passed + 1))
    elif [[ "$TEST6_RESULT" == "PARTIAL" ]]; then
        echo -e "  ${YELLOW}?${NC} TEST 6: Command mismatch rejected - PARTIAL"
        partial=$((partial + 1))
    else
        echo -e "  ${RED}✗${NC} TEST 6: Command mismatch rejected - FAILED"
        failed=$((failed + 1))
    fi
    
    if [[ "$TEST7_RESULT" == "PASSED" ]]; then
        echo -e "  ${GREEN}✓${NC} TEST 7: Env mismatch rejected    - PASSED"
        passed=$((passed + 1))
    elif [[ "$TEST7_RESULT" == "PARTIAL" ]]; then
        echo -e "  ${YELLOW}?${NC} TEST 7: Env mismatch rejected    - PARTIAL"
        partial=$((partial + 1))
    else
        echo -e "  ${RED}✗${NC} TEST 7: Env mismatch rejected    - FAILED"
        failed=$((failed + 1))
    fi
    
    if [[ "$TEST8_RESULT" == "PASSED" ]]; then
        echo -e "  ${GREEN}✓${NC} TEST 8: Volume mismatch rejected - PASSED"
        passed=$((passed + 1))
    elif [[ "$TEST8_RESULT" == "PARTIAL" ]]; then
        echo -e "  ${YELLOW}?${NC} TEST 8: Volume mismatch rejected - PARTIAL"
        partial=$((partial + 1))
    else
        echo -e "  ${RED}✗${NC} TEST 8: Volume mismatch rejected - FAILED"
        failed=$((failed + 1))
    fi
    
    echo ""
    echo "----------------------------------------"
    if [[ $failed -eq 0 && $partial -eq 0 ]]; then
        echo -e "  ${GREEN}All $passed tests PASSED!${NC}"
    elif [[ $failed -eq 0 ]]; then
        echo -e "  ${YELLOW}$passed passed, $partial partial${NC}"
    else
        echo -e "  ${RED}$passed passed, $failed failed, $partial partial${NC}"
    fi
    echo "----------------------------------------"
    echo ""
    echo "To watch proxy logs in real-time:"
    echo "  docker exec $WORKER_NODE_NAME journalctl -u kubelet-proxy -f"
    echo ""
    echo "To clean up test resources:"
    echo "  kubectl delete pod test-signed test-unsigned test-bad-sig test-image-mismatch test-full-policy test-command-mismatch test-env-mismatch test-volume-mismatch"
    echo ""
    
    # Exit with error if any tests failed
    if [[ $failed -gt 0 ]]; then
        exit 1
    fi
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
