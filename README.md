# conf-inferencing

A collection of Go binaries for confidential inferencing on AKS Flex nodes.

## Binaries

- **kubelet-proxy** - Kubernetes kubelet proxy that intercepts API server communication for pod admission control

## Prerequisites

- Go 1.24 or later
- Make

## Building

Build all binaries:
```bash
make build
```

Build a specific binary:
```bash
make kubelet-proxy
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
                     Policy Evaluation
                     (accept/reject pod)
```

The kubelet connects to kubelet-proxy (thinking it's the API server). The proxy:
1. Forwards all requests to the real API server
2. Intercepts pod watch/list **responses** from the API server
3. Evaluates each pod against admission policies
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
- **Policy-Based Decisions**: Configure admission rules via JSON policy files
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
  --admission-policy /path/to/policy.json \
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
| `--admission-policy` | | Path to admission policy JSON file |
| `--log-requests` | `true` | Log all proxied requests |
| `--log-pod-payloads` | `false` | Log full pod JSON payloads |

### Admission Policies

Create a JSON policy file to define admission rules. See [examples/admission-policy.json](examples/admission-policy.json) for a sample policy.

#### Policy Structure

```json
{
  "name": "my-policy",
  "defaultAction": "allow",
  "rules": [
    {
      "name": "deny-privileged",
      "action": "deny",
      "match": {
        "security": {
          "denyPrivileged": true
        }
      },
      "message": "Privileged containers are not allowed"
    }
  ]
}
```

#### Match Criteria

- **namespaces**: List of namespace patterns (supports wildcards)
- **namespaceRegex**: Regex pattern for namespace matching
- **labels**: Required pod labels
- **annotations**: Required pod annotations
- **images**: Image matching rules (allowed/denied registries, require digest)
- **security**: Security context rules (privileged, host namespaces, capabilities)

## Project Structure

```
.
├── cmd/
│   └── kubelet-proxy/           # kubelet-proxy binary entry point
├── internal/
│   └── kubeletproxy/
│       ├── admission/          # Admission control logic
│       │   ├── admission.go    # Core admission types
│       │   ├── chain.go        # Chain multiple controllers
│       │   ├── logging.go      # Logging controller
│       │   └── policy.go       # Policy-based controller
│       ├── config.go           # Configuration
│       └── proxy.go            # HTTP proxy implementation
├── examples/
│   ├── admission-policy.json   # Sample admission policy
│   └── strict-admission-policy.json
├── pkg/                        # Public library code
├── bin/                        # Compiled binaries (generated)
├── Makefile
├── go.mod
└── README.md
```
