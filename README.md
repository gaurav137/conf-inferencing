# conf-inferencing

A collection of Go binaries for confidential inferencing on AKS Flex nodes.

## Binaries

- **kubelet-proxy** - Kubernetes kubelet proxy that intercepts API server communication for pod admission control
- **signing-server** - HTTP REST API server for signing pod specs with ECDSA keys

## Prerequisites

- Go 1.21 or later
- Make
- Docker (for building signing-server container)

## Building

Build all binaries:
```bash
make build
```

Build a specific binary:
```bash
make kubelet-proxy
make signing-server
```

## Other Commands

```bash
make clean   # Remove build artifacts
make test    # Run tests
make fmt     # Format code
make vet     # Run go vet
make lint    # Run linter (requires golangci-lint)
make help    # Show available targets
```

## kubelet-proxy

The kubelet-proxy is a binary that runs on a Kubernetes node, intercepting HTTP traffic between the kubelet and the API server. It watches for pod assignments and allows you to inspect, accept, or reject pods before they are created on the node.

### Architecture

```
┌─────────────┐      ┌──────────────┐      ┌─────────────┐
│  API Server │ ←──→ │ kubelet-proxy │ ←──→ │   Kubelet   │
└─────────────┘      └──────────────┘      └─────────────┘
                            │
                            ▼
                     Pod Policy Verification
                     (accept/reject pod)
```

The kubelet connects to kubelet-proxy (thinking it's the API server). The proxy:
1. Forwards all requests to the real API server
2. Intercepts pod watch/list **responses** from the API server
3. Verifies cryptographic signatures on each pod
4. For rejected pods:
   - Patches the pod status to `Failed` via the API server (Kubernetes-native rejection)
   - Filters the pod from the response so kubelet doesn't attempt to run it
5. The pod shows as `Failed` with a clear error message in `kubectl get pods`

### Pod Rejection Flow

When a pod is rejected, the proxy uses the **Kubernetes-native rejection pattern** (same as how kubelet reports failures):

```yaml
# Pod status after rejection
status:
  phase: Failed
  reason: NodeAdmissionRejected
  message: "Pod rejected by kubelet-proxy: <policy reason>"
  conditions:
    - type: Ready
      status: "False"
      reason: NodeAdmissionRejected
```

This approach:
- ✅ Pod moves to `Failed` state - clear visibility
- ✅ Scheduler does not retry the pod
- ✅ User sees a clear error message via `kubectl describe pod`
- ✅ Cluster stays healthy
- ✅ Standard Kubernetes behavior

### Features

- **Kubernetes-Native Rejection**: Rejects pods by patching status to Failed (same as kubelet)
- **Response Interception**: Intercepts pod list/watch responses from the API server  
- **Pod Policy Verification**: Cryptographic verification of pod policy signatures
- **Kubeconfig Support**: Uses standard kubeconfig file for API server connection
- **Watch Stream Support**: Properly handles Kubernetes watch streams
- **Logging**: Detailed logging of all requests and admission decisions
- **TLS Support**: Full TLS support for secure communication
- **Graceful Shutdown**: Handles signals for clean shutdown

### Usage

```bash
./bin/kubelet-proxy \
  --kubeconfig /path/to/kubeconfig \
  --listen-addr :6443 \
  --tls-cert /path/to/server.crt \
  --tls-key /path/to/server.key \
  --policy-verification-cert /path/to/signing-cert.pem \
  --log-requests
```

### Deployment

On the node, configure the kubelet to connect to kubelet-proxy instead of the API server directly:

1. Start kubelet-proxy with the node's kubeconfig file
2. Update kubelet configuration to point to kubelet-proxy's address
3. kubelet-proxy forwards traffic to the real API server

### Command Line Options

| Option | Default | Description |
|--------|---------|-------------|
| `--kubeconfig` | (required) | Path to kubeconfig file for API server connection |
| `--context` | | Context to use from kubeconfig (uses current-context if empty) |
| `--listen-addr` | `:6443` | Address to listen on for kubelet connections |
| `--tls-cert` | | Path to TLS certificate for serving |
| `--tls-key` | | Path to TLS key for serving |
| `--policy-verification-cert` | | Path to certificate for pod policy verification |
| `--log-requests` | `true` | Log all proxied requests |
| `--log-pod-payloads` | `false` | Log full pod JSON payloads |

### Pod Policy Verification

kubelet-proxy can verify cryptographic signatures on pod policies to ensure only authorized workloads run on a node. When enabled, pods must have a valid policy and signature annotation or they will be rejected.

#### How It Works

1. The pod spec (`.spec` field) is serialized to canonical JSON (sorted keys, no whitespace)
2. The JSON is hashed with SHA256
3. The hash is signed with the private key (ECDSA or RSA)
4. The base64-encoded signature is stored in the `kubelet-proxy.io/signature` annotation
5. On the node, kubelet-proxy verifies the signature using the public key from the provided certificate

#### Enabling Pod Policy Verification

Provide a certificate containing the public key:

```bash
./bin/kubelet-proxy \
  --kubeconfig /path/to/kubeconfig \
  --policy-verification-cert /path/to/signing-cert.pem
```

#### Signing Pods

Pods are signed by generating a policy JSON from the pod spec, base64-encoding it, and signing it via the signing-server:

```bash
# Sign a payload using the signing-server
curl -X POST http://localhost:8080/sign \
  -H "Content-Type: application/json" \
  -d '{"payload": "<base64-encoded-policy>"}'

# Fetch the signing certificate from signing-server
curl http://localhost:8080/signingcert > signing-cert.pem
```

When using the kind deployment, the signing-server runs as a local Docker container on port 8080.

#### Policy Schema

Instead of signing the full pod spec (which changes when Kubernetes adds defaults), kubelet-proxy uses a **policy-based approach**. Security-relevant fields are extracted from the pod spec into a deterministic policy JSON, which is then signed and verified.

The policy uses a **per-container structure** where each container is identified by name, allowing precise verification that each container in the pod matches its signed policy.

##### Top-Level Policy Fields

| Field | Type | Description |
|-------|------|-------------|
| `containers` | `object` | Map of container name to container policy |
| `initContainers` | `object` | Map of init container name to container policy |
| `allowHostNetwork` | `boolean` | Present and `true` if pod spec has `hostNetwork: true` |
| `allowHostPID` | `boolean` | Present and `true` if pod spec has `hostPID: true` |
| `allowHostIPC` | `boolean` | Present and `true` if pod spec has `hostIPC: true` |
| `nodeSelector` | `object` | Key-value pairs from pod spec `nodeSelector` |

##### Container Policy Fields

Each entry in `containers` or `initContainers` is keyed by container name and contains:

| Field | Type | Description |
|-------|------|-------------|
| `image` | `string` | The container image (supports wildcards in verification) |
| `command` | `string[]` | Container entrypoint array (overrides ENTRYPOINT) |
| `args` | `string[]` | Arguments to the entrypoint (overrides CMD) |
| `env` | `object[]` | Environment variables with `name` and `value` fields |
| `volumeMounts` | `object[]` | Volume mounts with `name`, `mountPath`, and optional `readOnly` fields |
| `privileged` | `boolean` | Present and `true` if `securityContext.privileged: true` |
| `capabilities` | `string[]` | Sorted list of Linux capabilities from `securityContext.capabilities.add` |

##### Policy Generation Rules

- **Per-container tracking**: Each container is tracked by name, ensuring the pod spec containers match exactly
- **Omitted fields**: Fields are only included in the policy if they have non-empty or non-false values
- **Environment variables**: Only env vars with direct `value` are included; `valueFrom` references are excluded
- **Deterministic serialization**: The policy is serialized as compact JSON with sorted keys (no whitespace) to ensure consistent signatures
- **Base64 encoding**: The policy JSON is base64-encoded before signing and stored in the annotation

##### Example Policy

For a pod with:
```yaml
spec:
  initContainers:
    - name: init
      image: busybox:latest
  containers:
    - name: app
      image: nginx:latest
      command: ["/bin/sh"]
      args: ["-c", "nginx -g 'daemon off;'"]
      env:
        - name: LOG_LEVEL
          value: "info"
      volumeMounts:
        - name: config
          mountPath: /etc/nginx/conf.d
          readOnly: true
      securityContext:
        privileged: true
        capabilities:
          add: ["NET_ADMIN", "SYS_TIME"]
    - name: sidecar
      image: envoyproxy/envoy:v1.28
  hostNetwork: true
  nodeSelector:
    kubernetes.io/os: linux
```

The generated policy would be:
```json
{
  "allowHostNetwork": true,
  "containers": {
    "app": {
      "args": ["-c", "nginx -g 'daemon off;'"],
      "capabilities": ["NET_ADMIN", "SYS_TIME"],
      "command": ["/bin/sh"],
      "env": [{"name": "LOG_LEVEL", "value": "info"}],
      "image": "nginx:latest",
      "privileged": true,
      "volumeMounts": [{"mountPath": "/etc/nginx/conf.d", "name": "config", "readOnly": true}]
    },
    "sidecar": {
      "image": "envoyproxy/envoy:v1.28"
    }
  },
  "initContainers": {
    "init": {
      "image": "busybox:latest"
    }
  },
  "nodeSelector": {
    "kubernetes.io/os": "linux"
  }
}
```

##### Verification Behavior

During admission, kubelet-proxy verifies:
1. **Container name matching**: Every container in the pod must have a corresponding entry in the policy (by name)
2. **Image matching**: Each container's image must match its policy entry (wildcards supported)
3. **Command and args matching**: `command` and `args` must match exactly per container
4. **Environment variables matching**: Environment variables (with direct values) must match exactly
5. **Volume mounts matching**: Volume mounts must match by name, mountPath, and readOnly flag
6. **Security context matching**: `privileged` and `capabilities` must match exactly per container
7. **Host namespace matching**: `hostNetwork`, `hostPID`, `hostIPC` must match the policy
8. **Node selector matching**: Node selectors must match exactly

##### Viewing a Policy

#### Signature Annotation

The policy and signature are stored in pod annotations:

```yaml
metadata:
  annotations:
    kubelet-proxy.io/policy: "eyJhbGxvd2VkSW1hZ2VzIjpbIm5naW54OmxhdGVzdCJdfQ=="  # base64-encoded policy JSON
    kubelet-proxy.io/signature: "MEUCIQDx...base64-encoded-signature..."           # signature of the policy
```

The kubelet-proxy verifies pods by:
1. Extracting the `kubelet-proxy.io/policy` annotation (base64-encoded policy)
2. Extracting the `kubelet-proxy.io/signature` annotation
3. Verifying the signature against the policy using the configured signing certificate
4. Optionally validating that the pod spec matches the claimed policy

#### Supported Key Types

- **ECDSA** (recommended): P-256, P-384, P-521 curves
- **RSA**: PKCS#1 v1.5 signatures

## signing-server

The signing-server is an HTTP REST API server that manages ECDSA signing keys and signs pod specs. It generates a key pair once on startup and holds the private key in memory for the lifetime of the server.

### Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check endpoint |
| `/generatekeys` | POST | Generate ECDSA key pair (auto-generated on startup) |
| `/sign` | POST | Sign a payload and return base64-encoded signature |
| `/signingcert` | GET | Return the signing certificate in PEM format |

### Usage

```bash
./bin/signing-server --listen-addr :8080
```

### Docker

Build and run as a container:

```bash
docker build -t signing-server:local -f Dockerfile.signing-server .
docker run -d -p 8080:8080 --name signing-server signing-server:local
```

The `make deploy-kind` command automatically builds and runs the signing-server container.

### API Examples

Sign a payload:
```bash
curl -X POST http://localhost:8080/sign \
  -H "Content-Type: application/json" \
  -d '{"payload": "data-to-sign"}'
```

Get signing certificate:
```bash
curl http://localhost:8080/signingcert > signing-cert.pem
```

## Project Structure

```
.
├── cmd/
│   ├── kubelet-proxy/           # kubelet-proxy binary entry point
│   └── signing-server/          # signing-server binary entry point
├── internal/
│   └── kubeletproxy/
│       ├── admission/          # Admission control logic
│       │   ├── admission.go    # Core admission types
│       │   ├── chain.go        # Chain multiple controllers
│       │   ├── logging.go      # Logging controller
│       │   └── verify.go       # Pod policy verification controller
│       ├── config.go           # Configuration
│       ├── kubeconfig.go       # Kubeconfig parser
│       └── proxy.go            # HTTP proxy implementation
├── scripts/
│   └── kind/                   # Kind cluster deployment scripts
│       ├── deploy-kind.sh      # Deploy to kind cluster
│       ├── teardown-kind.sh    # Remove kind cluster
│       └── test-pod-policies.sh  # Test pod policy verification
├── Dockerfile.signing-server   # Dockerfile for signing-server
├── examples/                   # Example configurations
├── pkg/                        # Public library code
├── bin/                        # Compiled binaries (generated)
├── Makefile
├── go.mod
└── README.md
```

## Testing with Kind

Deploy kubelet-proxy to a kind cluster with signing-server running locally:

```bash
# Deploy to kind cluster (2 nodes: control-plane + worker)
# This also starts signing-server as a local Docker container
make deploy-kind

# Run pod policy verification tests
make test-kind

# Tear down cluster and stop signing-server
make teardown-kind
```

The kind deployment:
- Creates a 2-node cluster (control-plane + worker)
- Runs signing-server as a local Docker container on port 8080
- Fetches the signing certificate from signing-server
- Installs kubelet-proxy on the worker node with pod policy verification enabled
- Configures kubelet to route through the proxy
