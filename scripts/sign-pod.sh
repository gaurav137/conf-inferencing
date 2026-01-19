#!/bin/bash
set -e

# Script to generate signing keys and sign pod specs for kubelet-proxy signature verification

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KEY_DIR="${KEY_DIR:-$SCRIPT_DIR/../tmp/signing-keys}"

usage() {
    echo "Usage: $0 <command> [options]"
    echo ""
    echo "Commands:"
    echo "  generate-keys              Generate a new ECDSA key pair"
    echo "  sign-spec <pod.yaml>       Sign a pod's spec and output with signature annotation"
    echo "  verify-spec <pod.yaml>     Verify a pod's signature"
    echo ""
    echo "Environment variables:"
    echo "  KEY_DIR                    Directory for keys (default: $KEY_DIR)"
    echo ""
    echo "Examples:"
    echo "  $0 generate-keys"
    echo "  $0 sign-spec my-pod.yaml > signed-pod.yaml"
    echo "  kubectl apply -f signed-pod.yaml"
}

generate_keys() {
    mkdir -p "$KEY_DIR"
    
    echo "Generating ECDSA P-256 key pair..."
    
    # Generate private key
    openssl ecparam -name prime256v1 -genkey -noout -out "$KEY_DIR/signing.key"
    
    # Generate public key certificate (self-signed)
    openssl req -new -x509 -key "$KEY_DIR/signing.key" \
        -out "$KEY_DIR/signing.crt" \
        -days 365 \
        -subj "/CN=kubelet-proxy-signer/O=kubelet-proxy"
    
    # Also export just the public key
    openssl ec -in "$KEY_DIR/signing.key" -pubout -out "$KEY_DIR/signing.pub"
    
    echo ""
    echo "Keys generated in $KEY_DIR:"
    echo "  Private key: $KEY_DIR/signing.key"
    echo "  Public cert: $KEY_DIR/signing.crt (use with --signature-verification-cert)"
    echo "  Public key:  $KEY_DIR/signing.pub"
    echo ""
    echo "To use with kubelet-proxy:"
    echo "  kubelet-proxy --signature-verification-cert $KEY_DIR/signing.crt ..."
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
    
    if [[ ! -f "$KEY_DIR/signing.key" ]]; then
        echo "Error: signing key not found. Run '$0 generate-keys' first." >&2
        exit 1
    fi
    
    # Check if we have yq or python for YAML/JSON processing
    if command -v yq &>/dev/null; then
        YAML_TOOL="yq"
    elif command -v python3 &>/dev/null; then
        YAML_TOOL="python"
    else
        echo "Error: yq or python3 required for YAML processing" >&2
        exit 1
    fi
    
    # Extract the spec as canonical JSON
    local spec_json
    if [[ "$YAML_TOOL" == "yq" ]]; then
        spec_json=$(yq -o=json '.spec' "$pod_file" | jq -cS '.')
    else
        spec_json=$(python3 -c "
import yaml
import json
import sys

with open('$pod_file', 'r') as f:
    pod = yaml.safe_load(f)

def sort_dict(obj):
    if isinstance(obj, dict):
        return {k: sort_dict(v) for k, v in sorted(obj.items())}
    elif isinstance(obj, list):
        return [sort_dict(item) for item in obj]
    return obj

spec = sort_dict(pod.get('spec', {}))
print(json.dumps(spec, separators=(',', ':')))
")
    fi
    
    # Compute SHA256 hash and sign it
    local signature
    signature=$(echo -n "$spec_json" | openssl dgst -sha256 -sign "$KEY_DIR/signing.key" | base64 -w0)
    
    # Output the pod with the signature annotation added
    if [[ "$YAML_TOOL" == "yq" ]]; then
        yq eval ".metadata.annotations.\"kubelet-proxy.io/signature\" = \"$signature\"" "$pod_file"
    else
        python3 -c "
import yaml
import sys

with open('$pod_file', 'r') as f:
    pod = yaml.safe_load(f)

if 'metadata' not in pod:
    pod['metadata'] = {}
if 'annotations' not in pod['metadata']:
    pod['metadata']['annotations'] = {}

pod['metadata']['annotations']['kubelet-proxy.io/signature'] = '$signature'

yaml.dump(pod, sys.stdout, default_flow_style=False)
"
    fi
    
    echo "" >&2
    echo "Signature added to pod spec" >&2
    echo "Spec hash (for debugging): $(echo -n "$spec_json" | sha256sum | cut -d' ' -f1)" >&2
}

verify_spec() {
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
    
    local cert_file="${KEY_DIR}/signing.crt"
    if [[ ! -f "$cert_file" ]]; then
        cert_file="${KEY_DIR}/signing.pub"
    fi
    
    if [[ ! -f "$cert_file" ]]; then
        echo "Error: public key not found. Run '$0 generate-keys' first." >&2
        exit 1
    fi
    
    # Check for yq or python
    if command -v yq &>/dev/null; then
        YAML_TOOL="yq"
    elif command -v python3 &>/dev/null; then
        YAML_TOOL="python"
    else
        echo "Error: yq or python3 required for YAML processing" >&2
        exit 1
    fi
    
    # Extract signature and spec
    local signature spec_json
    if [[ "$YAML_TOOL" == "yq" ]]; then
        signature=$(yq '.metadata.annotations."kubelet-proxy.io/signature"' "$pod_file")
        spec_json=$(yq -o=json '.spec' "$pod_file" | jq -cS '.')
    else
        signature=$(python3 -c "
import yaml
with open('$pod_file', 'r') as f:
    pod = yaml.safe_load(f)
print(pod.get('metadata', {}).get('annotations', {}).get('kubelet-proxy.io/signature', ''))
")
        spec_json=$(python3 -c "
import yaml
import json

with open('$pod_file', 'r') as f:
    pod = yaml.safe_load(f)

def sort_dict(obj):
    if isinstance(obj, dict):
        return {k: sort_dict(v) for k, v in sorted(obj.items())}
    elif isinstance(obj, list):
        return [sort_dict(item) for item in obj]
    return obj

spec = sort_dict(pod.get('spec', {}))
print(json.dumps(spec, separators=(',', ':')))
")
    fi
    
    if [[ -z "$signature" || "$signature" == "null" ]]; then
        echo "Error: no signature found in pod" >&2
        exit 1
    fi
    
    # Verify
    echo "Verifying signature..."
    echo "Spec hash: $(echo -n "$spec_json" | sha256sum | cut -d' ' -f1)"
    
    if echo -n "$spec_json" | openssl dgst -sha256 -verify "$cert_file" -signature <(echo "$signature" | base64 -d) 2>/dev/null; then
        echo "✓ Signature is VALID"
    else
        echo "✗ Signature is INVALID"
        exit 1
    fi
}

# Main
case "${1:-}" in
    generate-keys)
        generate_keys
        ;;
    sign-spec)
        sign_spec "$2"
        ;;
    verify-spec)
        verify_spec "$2"
        ;;
    *)
        usage
        exit 1
        ;;
esac
