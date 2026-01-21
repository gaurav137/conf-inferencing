#!/bin/bash
set -e

# Script to sign pod policies using the signing-server for kubelet-proxy signature verification
# Instead of signing the full pod spec (which changes when Kubernetes adds defaults),
# we generate a policy from the pod spec and sign that policy.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
SIGNING_SERVER_URL="${SIGNING_SERVER_URL:-http://localhost:8080}"
SIGNING_SERVER_PORT="${SIGNING_SERVER_PORT:-8080}"

# Legacy key directory (for backward compatibility with verify-spec)
KEY_DIR="${KEY_DIR:-$PROJECT_ROOT/tmp/signing-keys}"

usage() {
    echo "Usage: $0 <command> [options]"
    echo ""
    echo "Commands:"
    echo "  sign-spec <pod.yaml>       Generate policy from pod, sign it, and output pod with annotations"
    echo "  get-cert                   Fetch the signing certificate from signing-server"
    echo "  show-policy <pod.yaml>     Show the policy that would be generated (without signing)"
    echo ""
    echo "Environment variables:"
    echo "  SIGNING_SERVER_URL         URL to signing-server (default: http://localhost:8080)"
    echo "  KEY_DIR                    Directory for certs (default: $KEY_DIR)"
    echo ""
    echo "Examples:"
    echo "  $0 sign-spec my-pod.yaml > signed-pod.yaml"
    echo "  kubectl apply -f signed-pod.yaml"
    echo "  $0 get-cert > signing-cert.pem"
    echo "  $0 show-policy my-pod.yaml"
}

get_signing_server_url() {
    echo "$SIGNING_SERVER_URL"
}

check_signing_server() {
    local url
    url=$(get_signing_server_url)
    
    if ! curl -sf "$url/health" >/dev/null 2>&1; then
        echo "Error: signing-server is not running at $url" >&2
        echo "Start the signing-server with: docker run -d -p 8080:8080 --name signing-server signing-server:local" >&2
        return 1
    fi
    return 0
}

get_cert() {
    check_signing_server || exit 1
    
    local url
    url=$(get_signing_server_url)
    
    curl -sf "$url/signingcert"
    local rc=$?
    
    if [[ $rc -ne 0 ]]; then
        echo "Error: Failed to fetch signing certificate" >&2
        exit 1
    fi
}

# Generate a policy JSON from a pod spec
# The policy captures what the pod is allowed to do, organized by container name
generate_policy() {
    local pod_file="$1"
    
    python3 -c "
import yaml
import json
import sys

with open('$pod_file', 'r') as f:
    pod = yaml.safe_load(f)

spec = pod.get('spec', {})

# Build the policy from the pod spec
policy = {}

# Helper function to extract container policy
def extract_container_policy(container):
    container_policy = {}
    
    # Image is required
    if 'image' in container:
        container_policy['image'] = container['image']
    
    # Extract security context settings
    sec_ctx = container.get('securityContext', {})
    
    # Privileged flag
    if sec_ctx.get('privileged'):
        container_policy['privileged'] = True
    
    # Capabilities
    caps = sec_ctx.get('capabilities', {})
    add_caps = caps.get('add', [])
    if add_caps:
        container_policy['capabilities'] = sorted(add_caps)
    
    return container_policy

# Extract containers by name
containers = {}
for container in spec.get('containers', []):
    name = container.get('name', '')
    if name:
        containers[name] = extract_container_policy(container)
if containers:
    policy['containers'] = containers

# Extract init containers by name
init_containers = {}
for container in spec.get('initContainers', []):
    name = container.get('name', '')
    if name:
        init_containers[name] = extract_container_policy(container)
if init_containers:
    policy['initContainers'] = init_containers

# Extract host namespace settings
if spec.get('hostNetwork'):
    policy['allowHostNetwork'] = True
if spec.get('hostPID'):
    policy['allowHostPID'] = True
if spec.get('hostIPC'):
    policy['allowHostIPC'] = True

# Extract node selectors
node_selector = spec.get('nodeSelector', {})
if node_selector:
    policy['nodeSelector'] = node_selector

# Output the policy as compact JSON with sorted keys
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

show_policy() {
    local pod_file="$1"
    
    if [[ -z "$pod_file" ]]; then
        echo "Error: pod file required" >&2
        usage
        exit 1
    fi
    
    if [[ ! -f "$pod_file" ]]; then
        echo "Error: file not found: $pod_file" >&2
        exit 1
    fi
    
    echo "Policy that would be generated from $pod_file:" >&2
    generate_policy "$pod_file" | python3 -m json.tool
}

sign_spec() {
    local pod_file="$1"
    
    if [[ -z "$pod_file" ]]; then
        echo "Error: pod file required" >&2
        usage
        exit 1
    fi
    
    if [[ ! -f "$pod_file" ]]; then
        echo "Error: file not found: $pod_file" >&2
        exit 1
    fi
    
    check_signing_server || exit 1
    
    local url
    url=$(get_signing_server_url)
    
    # Check if we have python3 for YAML/JSON processing
    if ! command -v python3 &>/dev/null; then
        echo "Error: python3 required for YAML processing" >&2
        exit 1
    fi
    
    # Generate policy from the pod spec
    local policy_json
    policy_json=$(generate_policy "$pod_file")
    
    if [[ -z "$policy_json" ]]; then
        echo "Error: Failed to generate policy from pod spec" >&2
        exit 1
    fi
    
    echo "Generated policy: $policy_json" >&2
    
    # Base64 encode the policy for the annotation
    local policy_base64
    policy_base64=$(printf '%s' "$policy_json" | base64 -w 0)
    
    echo "Policy base64: $policy_base64" >&2
    
    # Call signing-server to sign the base64-encoded policy
    # This ensures we sign exactly what's stored in the annotation
    local response
    response=$(curl -sf -X POST "$url/sign" \
        -H "Content-Type: application/json" \
        -d "{\"payload\": $(printf '%s' "$policy_base64" | jq -Rs .)}")
    
    if [[ $? -ne 0 ]]; then
        echo "Error: Failed to sign policy" >&2
        exit 1
    fi
    
    local signature
    signature=$(echo "$response" | jq -r '.signature')
    
    if [[ -z "$signature" || "$signature" == "null" ]]; then
        echo "Error: No signature returned from signing-server" >&2
        exit 1
    fi
    
    echo "Signature: $signature" >&2
    
    # Output the pod with the policy and signature annotations added
    python3 -c "
import yaml
import sys

with open('$pod_file', 'r') as f:
    pod = yaml.safe_load(f)

if 'metadata' not in pod:
    pod['metadata'] = {}
if 'annotations' not in pod['metadata']:
    pod['metadata']['annotations'] = {}

# Add the base64-encoded policy
pod['metadata']['annotations']['kubelet-proxy.io/policy'] = '$policy_base64'
# Add the signature
pod['metadata']['annotations']['kubelet-proxy.io/signature'] = '$signature'

yaml.dump(pod, sys.stdout, default_flow_style=False)
"
    
    echo "" >&2
    echo "Policy and signature added to pod spec" >&2
}

# Parse arguments
case "${1:-}" in
    sign-spec)
        sign_spec "$2"
        ;;
    get-cert)
        get_cert
        ;;
    show-policy)
        show_policy "$2"
        ;;
    -h|--help)
        usage
        ;;
    *)
        echo "Error: Unknown command '${1:-}'" >&2
        usage
        exit 1
        ;;
esac
