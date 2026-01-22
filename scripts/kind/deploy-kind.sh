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
CLUSTER_NAME="${CLUSTER_NAME:-kubelet-proxy-test}"
KIND_IMAGE="${KIND_IMAGE:-kindest/node:v1.33.0}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
WORKER_NODE_NAME="${CLUSTER_NAME}-worker"
SIGNING_SERVER_IMAGE="signing-server:local"
SIGNING_SERVER_CONTAINER="signing-server"
SIGNING_SERVER_PORT=8080

# Proxy configuration
PROXY_LISTEN_ADDR="127.0.0.1:6444"

cleanup() {
    log_info "Cleaning up existing cluster if present..."
    kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null || true
    
    # Stop and remove signing-server container if running
    docker stop "$SIGNING_SERVER_CONTAINER" 2>/dev/null || true
    docker rm "$SIGNING_SERVER_CONTAINER" 2>/dev/null || true
}

build_binary() {
    log_info "Building kubelet-proxy binary..."
    cd "$PROJECT_ROOT"
    
    # Build for Linux (kind nodes run Linux)
    # CGO_ENABLED=0 creates a statically linked binary that doesn't depend on glibc
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -v -ldflags "-s -w" \
        -o bin/kubelet-proxy-linux-amd64 \
        ./cmd/kubelet-proxy
    
    log_info "Binary built: bin/kubelet-proxy-linux-amd64 (static)"
}

build_signing_server_image() {
    log_info "Building signing-server container image..."
    cd "$PROJECT_ROOT"
    
    docker build -t "$SIGNING_SERVER_IMAGE" -f Dockerfile.signing-server .
    
    log_info "Signing server image built: $SIGNING_SERVER_IMAGE"
}

create_cluster() {
    log_info "Creating kind cluster: $CLUSTER_NAME (1 control-plane + 1 worker)"
    
    # Create cluster with custom config - 2 nodes
    cat <<EOF | kind create cluster --name "$CLUSTER_NAME" --image "$KIND_IMAGE" --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
- role: worker
  # Extra mounts for logs on worker node
  extraMounts:
  - hostPath: /tmp/kubelet-proxy-logs
    containerPath: /var/log/kubelet-proxy
EOF
    
    # Wait for cluster to be ready
    log_info "Waiting for cluster to be ready..."
    kubectl wait --for=condition=Ready nodes --all --timeout=120s
    
    log_info "Cluster nodes:"
    kubectl get nodes -o wide
}

label_and_taint_worker_node() {
    log_info "Adding label and taint to worker node for signed pods only..."
    
    # Add label to worker node
    kubectl label node "$WORKER_NODE_NAME" node-type=signed-workloads --overwrite
    
    # Add taint to worker node - only pods with matching toleration can be scheduled
    kubectl taint node "$WORKER_NODE_NAME" signed-workloads=required:NoSchedule --overwrite
    
    log_info "Worker node labeled and tainted:"
    kubectl get node "$WORKER_NODE_NAME" -o jsonpath='{.spec.taints}' | jq . 2>/dev/null || kubectl get node "$WORKER_NODE_NAME" -o jsonpath='{.spec.taints}'
    echo ""
}

deploy_signing_server() {
    log_info "Starting signing-server as local Docker container with TLS..."
    
    # Stop existing container if running
    docker stop "$SIGNING_SERVER_CONTAINER" 2>/dev/null || true
    docker rm "$SIGNING_SERVER_CONTAINER" 2>/dev/null || true
    
    # Get host IP that will be accessible from kind nodes (IPv4 only)
    local host_ip
    host_ip=$(docker network inspect kind -f '{{range .IPAM.Config}}{{if .Gateway}}{{.Gateway}} {{end}}{{end}}' 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1)
    if [ -z "$host_ip" ]; then
        host_ip="172.17.0.1"
    fi
    log_info "Using host IP for TLS SANs: $host_ip"
    
    # Run signing-server container with TLS enabled
    # Include both localhost and the Docker gateway IP as SANs for the TLS cert
    docker run -d \
        --name "$SIGNING_SERVER_CONTAINER" \
        -p "$SIGNING_SERVER_PORT:8080" \
        "$SIGNING_SERVER_IMAGE" \
        --listen-addr=:8080 \
        --auto-generate=true \
        --tls=true \
        --tls-hosts="localhost,127.0.0.1,${host_ip}"
    
    # Wait for signing-server to be ready (now using HTTPS)
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

deploy_to_node() {
    log_info "Deploying kubelet-proxy to worker node using install.sh: $WORKER_NODE_NAME"
    
    local staging_dir="/opt/kubelet-proxy-staging"
    
    # Get host IP that is accessible from kind node (IPv4 only)
    local host_ip
    host_ip=$(docker network inspect kind -f '{{range .IPAM.Config}}{{if .Gateway}}{{.Gateway}} {{end}}{{end}}' 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1)
    if [ -z "$host_ip" ]; then
        host_ip="172.17.0.1"
    fi
    local signing_cert_url="https://${host_ip}:${SIGNING_SERVER_PORT}/signingcert"
    
    # Create staging directory on node
    docker exec "$WORKER_NODE_NAME" mkdir -p "$staging_dir"
    
    # Download TLS certificate from signing-server for CA verification
    log_info "Downloading TLS certificate from signing-server..."
    local tls_cert_file="$PROJECT_ROOT/tmp/signing-server-tls.crt"
    curl -sf --insecure "https://localhost:$SIGNING_SERVER_PORT/tlscert" -o "$tls_cert_file" || {
        log_error "Failed to download TLS certificate from signing-server"
        exit 1
    }
    log_info "TLS certificate downloaded to $tls_cert_file"
    
    # Copy files to worker node
    log_info "Copying files to worker node..."
    
    # Copy local binary, install script, and TLS cert
    docker cp "$PROJECT_ROOT/bin/kubelet-proxy-linux-amd64" "$WORKER_NODE_NAME:$staging_dir/kubelet-proxy"
    docker cp "$PROJECT_ROOT/scripts/install.sh" "$WORKER_NODE_NAME:$staging_dir/install.sh"
    docker cp "$tls_cert_file" "$WORKER_NODE_NAME:$staging_dir/signing-server-tls.crt"
    
    # Verify files were copied
    log_info "Verifying files on node..."
    docker exec "$WORKER_NODE_NAME" ls -la "$staging_dir/"
    
    # Run install.sh with local binary, signing cert URL, and TLS CA cert
    log_info "Running install.sh on worker node..."
    log_info "Signing cert URL: $signing_cert_url"
    docker exec "$WORKER_NODE_NAME" bash "$staging_dir/install.sh" \
        --local-binary "$staging_dir/kubelet-proxy" \
        --signing-cert-url "$signing_cert_url" \
        --signing-cert-url-ca-cert "$staging_dir/signing-server-tls.crt" \
        --proxy-listen-addr "$PROXY_LISTEN_ADDR"
}

verify_deployment() {
    log_info "Verifying deployment on worker node: $WORKER_NODE_NAME"
    
    echo ""
    echo "=== Kubelet-proxy status on worker ==="
    docker exec "$WORKER_NODE_NAME" systemctl status kubelet-proxy --no-pager || true
    
    echo ""
    echo "=== Recent kubelet-proxy logs ==="
    docker exec "$WORKER_NODE_NAME" journalctl -u kubelet-proxy --no-pager -n 20 || true
    
    echo ""
    echo "=== Cluster nodes ==="
    kubectl get nodes -o wide
    
    echo ""
    echo "=== All pods ==="
    kubectl get pods -A
}

print_usage() {
    echo ""
    log_info "Deployment complete! Here's how to test:"
    echo ""
    echo "NOTE: kubelet-proxy is installed on the WORKER node only."
    echo "      The worker node has a taint 'signed-workloads=required:NoSchedule'."
    echo "      Pods must have matching toleration AND node selector to be scheduled there."
    echo "      Pod policy verification is ENABLED - unsigned pods will be rejected."
    echo ""
    echo "1. Check kubelet-proxy logs on worker:"
    echo "   docker exec $WORKER_NODE_NAME journalctl -u kubelet-proxy -f"
    echo ""
    echo "2. Run pod policies verification tests:"
    echo "   make test-pod-policies"
    echo ""
    echo "3. Deploy an unsigned pod (will be rejected):"
    echo "   kubectl run test-unsigned --image=nginx --restart=Never"
    echo "   kubectl get pod test-unsigned  # Should show Failed status"
    echo ""
    echo "4. Check signing-server:"
    echo "   docker logs $SIGNING_SERVER_CONTAINER"
    echo "   curl --insecure https://localhost:$SIGNING_SERVER_PORT/health"
    echo ""
    echo "5. Clean up:"
    echo "   kind delete cluster --name $CLUSTER_NAME"
    echo ""
}

main() {
    log_info "Starting kubelet-proxy deployment to kind cluster"
    
    # Check prerequisites
    command -v kind >/dev/null 2>&1 || { log_error "kind is required but not installed"; exit 1; }
    command -v docker >/dev/null 2>&1 || { log_error "docker is required but not installed"; exit 1; }
    command -v kubectl >/dev/null 2>&1 || { log_error "kubectl is required but not installed"; exit 1; }
    command -v openssl >/dev/null 2>&1 || { log_error "openssl is required but not installed"; exit 1; }
    
    # Create tmp directory
    mkdir -p "$PROJECT_ROOT/tmp"
    mkdir -p /tmp/kubelet-proxy-logs
    
    # Run deployment steps
    cleanup
    build_binary
    build_signing_server_image
    create_cluster
    label_and_taint_worker_node
    deploy_signing_server
    deploy_to_node
    verify_deployment
    print_usage
    
    log_info "Done!"
}

# Run main
main "$@"
