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
PROXY_CERT_DIR="/etc/kubelet-proxy"

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

generate_proxy_certs() {
    log_info "Generating TLS certificates for kubelet-proxy..."
    
    local cert_dir="$PROJECT_ROOT/tmp/certs"
    mkdir -p "$cert_dir"
    
    # Generate self-signed certificate for kubelet-proxy server
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "$cert_dir/kubelet-proxy.key" \
        -out "$cert_dir/kubelet-proxy.crt" \
        -subj "/CN=kubelet-proxy/O=kubelet-proxy" \
        -addext "subjectAltName=IP:127.0.0.1,DNS:localhost,DNS:kubelet-proxy" \
        2>/dev/null
    
    log_info "Certificates generated in $cert_dir"
}

deploy_signing_server() {
    log_info "Starting signing-server as local Docker container..."
    
    # Stop existing container if running
    docker stop "$SIGNING_SERVER_CONTAINER" 2>/dev/null || true
    docker rm "$SIGNING_SERVER_CONTAINER" 2>/dev/null || true
    
    # Run signing-server container
    docker run -d \
        --name "$SIGNING_SERVER_CONTAINER" \
        -p "$SIGNING_SERVER_PORT:8080" \
        "$SIGNING_SERVER_IMAGE" \
        --listen-addr=:8080 \
        --auto-generate=true
    
    # Wait for signing-server to be ready
    log_info "Waiting for signing-server to be ready..."
    for i in {1..20}; do
        if curl -sf "http://localhost:$SIGNING_SERVER_PORT/health" >/dev/null 2>&1; then
            log_info "Signing server is running at http://localhost:$SIGNING_SERVER_PORT"
            return 0
        fi
        sleep 0.5
    done
    
    log_error "Signing server failed to start"
    docker logs "$SIGNING_SERVER_CONTAINER"
    exit 1
}

get_signing_cert() {
    log_info "Fetching signing certificate from signing-server..."
    
    local cert_dir="$PROJECT_ROOT/tmp/certs"
    
    # Fetch the certificate from local signing-server
    curl -sf "http://localhost:$SIGNING_SERVER_PORT/signingcert" > "$cert_dir/signing-cert.pem"
    
    if [[ ! -s "$cert_dir/signing-cert.pem" ]]; then
        log_error "Failed to fetch signing certificate"
        exit 1
    fi
    
    log_info "Signing certificate saved to $cert_dir/signing-cert.pem"
}

create_systemd_service() {
    log_info "Creating systemd service file..."
    
    local service_dir="$PROJECT_ROOT/tmp"
    mkdir -p "$service_dir"
    
    cat > "$service_dir/kubelet-proxy.service" <<'EOF'
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
    --policy-verification-cert /etc/kubelet-proxy/signing-cert.pem \
    --log-requests=true \
    --log-pod-payloads=false

Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    
    log_info "Systemd service file created"
}

create_kubelet_proxy_kubeconfig() {
    log_info "Creating kubeconfig for kubelet to connect via proxy..."
    
    local config_dir="$PROJECT_ROOT/tmp"
    mkdir -p "$config_dir"
    
    # This script will be run inside the container to create the kubeconfig
    cat > "$config_dir/create-proxy-kubeconfig.sh" <<'SCRIPT'
#!/bin/bash
set -e

# Read the original kubelet kubeconfig
ORIG_KUBECONFIG="/etc/kubernetes/kubelet.conf"
PROXY_KUBECONFIG="/etc/kubernetes/kubelet-via-proxy.conf"

# Get the original user credentials
CLIENT_CERT=$(kubectl config view --kubeconfig="$ORIG_KUBECONFIG" -o jsonpath='{.users[0].user.client-certificate}' --raw)
CLIENT_KEY=$(kubectl config view --kubeconfig="$ORIG_KUBECONFIG" -o jsonpath='{.users[0].user.client-key}' --raw)

# Create new kubeconfig pointing to proxy
cat > "$PROXY_KUBECONFIG" <<EOF
apiVersion: v1
kind: Config
clusters:
- cluster:
    certificate-authority: /etc/kubelet-proxy/kubelet-proxy.crt
    server: https://127.0.0.1:6444
  name: proxy
contexts:
- context:
    cluster: proxy
    user: kubelet
  name: proxy
current-context: proxy
users:
- name: kubelet
  user:
    client-certificate: ${CLIENT_CERT}
    client-key: ${CLIENT_KEY}
EOF

echo "Created $PROXY_KUBECONFIG"
SCRIPT
    
    chmod +x "$config_dir/create-proxy-kubeconfig.sh"
}

create_setup_script() {
    log_info "Creating node setup script..."
    
    local script_dir="$PROJECT_ROOT/tmp"
    mkdir -p "$script_dir"
    
    cat > "$script_dir/setup-node.sh" <<'SCRIPT'
#!/bin/bash
set -e

# Staging directory where files are copied
# Note: /tmp is a tmpfs mount in kind nodes, so we use /opt instead
STAGING_DIR="/opt/kubelet-proxy-staging"

echo "=== Setting up kubelet-proxy on node ==="

# Create directories
mkdir -p /etc/kubelet-proxy
mkdir -p /var/log/kubelet-proxy

# Move files to proper locations
mv "$STAGING_DIR/kubelet-proxy" /usr/local/bin/kubelet-proxy
chmod +x /usr/local/bin/kubelet-proxy

mv "$STAGING_DIR/kubelet-proxy.crt" /etc/kubelet-proxy/
mv "$STAGING_DIR/kubelet-proxy.key" /etc/kubelet-proxy/
mv "$STAGING_DIR/signing-cert.pem" /etc/kubelet-proxy/

mv "$STAGING_DIR/kubelet-proxy.service" /etc/systemd/system/

# Create proxy kubeconfig for kubelet
"$STAGING_DIR/create-proxy-kubeconfig.sh"

# Reload systemd and start proxy
systemctl daemon-reload
systemctl enable kubelet-proxy
systemctl start kubelet-proxy

# Wait for proxy to be ready
echo "Waiting for kubelet-proxy to start..."
sleep 3

if systemctl is-active --quiet kubelet-proxy; then
    echo "kubelet-proxy is running"
else
    echo "ERROR: kubelet-proxy failed to start"
    journalctl -u kubelet-proxy --no-pager -n 50
    exit 1
fi

# Backup original kubelet config
cp /var/lib/kubelet/config.yaml /var/lib/kubelet/config.yaml.backup

# Update kubelet to use proxy kubeconfig
# We need to modify the kubelet drop-in to use our proxy kubeconfig
mkdir -p /etc/systemd/system/kubelet.service.d

cat > /etc/systemd/system/kubelet.service.d/20-kubelet-proxy.conf <<EOF
[Service]
Environment="KUBELET_KUBECONFIG_ARGS=--kubeconfig=/etc/kubernetes/kubelet-via-proxy.conf --bootstrap-kubeconfig="
EOF

# Reload and restart kubelet
systemctl daemon-reload
systemctl restart kubelet

echo "Waiting for kubelet to restart..."
sleep 5

if systemctl is-active --quiet kubelet; then
    echo "kubelet is running with proxy"
else
    echo "WARNING: kubelet may have issues, checking status..."
    systemctl status kubelet --no-pager || true
fi

echo "=== Setup complete ==="
echo ""
echo "To check kubelet-proxy logs:"
echo "  docker exec $HOSTNAME journalctl -u kubelet-proxy -f"
echo ""
echo "To check kubelet logs:"
echo "  docker exec $HOSTNAME journalctl -u kubelet -f"
SCRIPT
    
    chmod +x "$script_dir/setup-node.sh"
}

deploy_to_node() {
    log_info "Deploying kubelet-proxy to worker node: $WORKER_NODE_NAME"
    
    local tmp_dir="$PROJECT_ROOT/tmp"
    local cert_dir="$tmp_dir/certs"
    # Note: /tmp is a tmpfs in kind nodes, so we use /opt for staging
    local staging_dir="/opt/kubelet-proxy-staging"
    
    # Create staging directory on node
    docker exec "$WORKER_NODE_NAME" mkdir -p "$staging_dir"
    
    # Copy files to worker node
    log_info "Copying files to worker node..."
    
    docker cp "$PROJECT_ROOT/bin/kubelet-proxy-linux-amd64" "$WORKER_NODE_NAME:$staging_dir/kubelet-proxy"
    docker cp "$cert_dir/kubelet-proxy.crt" "$WORKER_NODE_NAME:$staging_dir/"
    docker cp "$cert_dir/kubelet-proxy.key" "$WORKER_NODE_NAME:$staging_dir/"
    docker cp "$cert_dir/signing-cert.pem" "$WORKER_NODE_NAME:$staging_dir/"
    docker cp "$tmp_dir/kubelet-proxy.service" "$WORKER_NODE_NAME:$staging_dir/"
    docker cp "$tmp_dir/create-proxy-kubeconfig.sh" "$WORKER_NODE_NAME:$staging_dir/"
    docker cp "$tmp_dir/setup-node.sh" "$WORKER_NODE_NAME:$staging_dir/"
    
    # Verify files were copied
    log_info "Verifying files on node..."
    docker exec "$WORKER_NODE_NAME" ls -la "$staging_dir/"
    
    # Run setup script on worker node
    log_info "Running setup script on worker node..."
    docker exec "$WORKER_NODE_NAME" chmod +x "$staging_dir/setup-node.sh"
    docker exec "$WORKER_NODE_NAME" "$staging_dir/setup-node.sh"
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
    echo "   curl http://localhost:$SIGNING_SERVER_PORT/health"
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
    generate_proxy_certs
    create_systemd_service
    create_kubelet_proxy_kubeconfig
    create_setup_script
    create_cluster
    label_and_taint_worker_node
    deploy_signing_server
    get_signing_cert
    deploy_to_node
    verify_deployment
    print_usage
    
    log_info "Done!"
}

# Run main
main "$@"
