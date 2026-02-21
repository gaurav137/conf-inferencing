# Confidential Nodes

A collection of Go binaries for enabling confidential nodes on [AKS Flex Node](https://github.com/gaurav137/AKSFlexNode).

## Installation on VM Nodes

Use the `install.sh` script with a signing certificate file:

```bash
VERSION=v0.0.7
curl -fsSL https://github.com/gaurav137/conf-node/releases/download/$VERSION/install.sh | sudo bash -s -- \
  --signing-cert-file /path/to/signing-cert.pem
```

### Uninstalling

To remove kubelet-proxy and restore the original kubelet configuration:

```bash
sudo ./scripts/uninstall.sh
```

## Binaries

- **kubelet-proxy** - Kubernetes kubelet proxy that intercepts API server communication for pod admission control

## Scripts

- **signing-tool.sh** - CLI script for generating signing keys and signing pod policies using openssl

## Prerequisites

- Go 1.21 or later
- Make
- openssl

## Building

Build all binaries:
```bash
make build
```

Build a specific binary:
```bash
make kubelet-proxy
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

Pods are signed by generating a policy JSON from the pod spec, base64-encoding it, and signing it via the `signing-tool.sh` script:

```bash
# Generate signing keys (one-time setup)
./scripts/signing-tool.sh generate

# Sign a base64-encoded policy
./scripts/signing-tool.sh sign "<base64-encoded-policy>"

# Get the signing certificate path
./scripts/signing-tool.sh cert
```

The signing tool uses RSA-PSS (SHA-256) via `openssl` — no HTTP server required.

#### Policy Schema

Instead of signing the full pod spec (which changes when Kubernetes adds defaults), kubelet-proxy uses a **policy-based approach**. Security-relevant fields are extracted from the pod spec into a deterministic policy JSON, which is then signed and verified.

The policy is an **array of container policies**, where each container is identified by name, allowing precise verification that each container in the pod matches its signed policy.

##### Policy Structure

The policy is a JSON array of container policy objects:

```json
[
  {
    "name": "<container-name>",
    "properties": {
      "image": "<image>",
      "command": ["cmd", "arg1"],
      "environmentVariables": [{"name": "VAR", "value": "val"}],
      "volumeMounts": [{"name": "vol", "mountPath": "/mnt", "readOnly": true}],
      "privileged": false,
      "capabilities": ["NET_ADMIN"]
    }
  }
]
```

##### Container Policy Fields

Each container policy object has:

| Field | Type | Description |
|-------|------|-------------|
| `name` | `string` | The container name (must match the pod spec container name) |
| `properties` | `object` | Container properties to verify |

##### Container Properties Fields

| Field | Type | Description |
|-------|------|-------------|
| `image` | `string` | The container image (must match exactly) |
| `command` | `string[]` | Container entrypoint array (overrides ENTRYPOINT) |
| `environmentVariables` | `object[]` | Environment variables with `name`, `value`, and optional `regex` fields |
| `volumeMounts` | `object[]` | Volume mounts with `name`, `mountPath`, `mountType`, and `readOnly` fields |
| `privileged` | `boolean` | Whether the container can run as privileged |
| `capabilities` | `string[]` | Linux capabilities to add |

##### Environment Variable Fields

| Field | Type | Description |
|-------|------|-------------|
| `name` | `string` | Environment variable name |
| `value` | `string` | Environment variable value |
| `regex` | `boolean` | If true, value is treated as a regex pattern |

##### Volume Mount Fields

| Field | Type | Description |
|-------|------|-------------|
| `name` | `string` | Volume name |
| `mountPath` | `string` | Path where the volume is mounted |
| `mountType` | `string` | Optional volume type |
| `readOnly` | `boolean` | Whether the mount is read-only |

##### Example Policy

For a pod with:
```yaml
spec:
  containers:
    - name: app
      image: busybox:latest
      command: ["/bin/myapp"]
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
```

The policy would be:
```json
[
  {
    "name": "app",
    "properties": {
      "image": "busybox:latest",
      "command": ["/bin/myapp"],
      "environmentVariables": [
        {"name": "APP_ENV", "value": "production"},
        {"name": "LOG_LEVEL", "value": "debug"}
      ],
      "volumeMounts": [
        {"name": "config", "mountPath": "/etc/app", "readOnly": true},
        {"name": "data", "mountPath": "/data", "readOnly": false}
      ]
    }
  }
]
```

##### Simple Policy Example

For a basic nginx pod:
```yaml
spec:
  containers:
    - name: test
      image: nginx:latest
```

The policy would be:
```json
[
  {
    "name": "test",
    "properties": {
      "image": "nginx:latest",
      "command": [],
      "environmentVariables": [],
      "volumeMounts": []
    }
  }
]
```

##### Verification Behavior

During admission, kubelet-proxy verifies:
1. **Container name matching**: Every container in the pod must have a corresponding entry in the policy (by name)
2. **Image matching**: Each container's image must match its policy entry
3. **Command matching**: `command` must match exactly per container
4. **Environment variables matching**: Environment variables must match (supports regex matching)
5. **Volume mounts matching**: Volume mounts must match by name, mountPath, and readOnly flag
6. **Security context matching**: `privileged` and `capabilities` must match exactly per container

##### Special "allowall" Policy

A special policy value `["allowall"]` can be used to bypass all pod validation. When signed and provided as the policy annotation, kubelet-proxy will allow the pod without checking any container properties. This is useful for trusted workloads or debugging scenarios.

```yaml
metadata:
  annotations:
    # Base64-encoded ["allowall"] = WyJhbGxvd2FsbCJd
    kubelet-proxy.io/policy: "WyJhbGxvd2FsbCJd"
    kubelet-proxy.io/signature: "<signature-of-the-allowall-policy>"
```

**Warning**: The `allowall` policy still requires a valid signature, ensuring only authorized signers can bypass validation.

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

- **RSA-PSS** (recommended): RSA with PSS padding and SHA-256
- **ECDSA**: P-256, P-384, P-521 curves (legacy support)

## signing-tool.sh

The `signing-tool.sh` script replaces the previous local-signing-server HTTP service. It uses `openssl` CLI to generate RSA-2048 signing keys and sign payloads using RSA-PSS with SHA-256 — no HTTP server required.

### Commands

| Command | Description |
|---------|-------------|
| `generate` | Generate RSA-2048 key pair and self-signed certificate |
| `sign <base64-payload>` | Sign a base64-encoded payload, output base64 signature |
| `cert` | Print the path to the signing certificate PEM file |

### Usage

```bash
# Generate keys (one-time, idempotent)
./scripts/signing-tool.sh generate

# Sign a payload
./scripts/signing-tool.sh sign "$(echo -n '{"image":"nginx"}' | base64 -w0)"

# Get certificate path
./scripts/signing-tool.sh cert
```

The `make deploy-kind` command automatically calls `signing-tool.sh generate` to create keys.

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
│       │   └── verify.go       # Pod policy verification controller
│       ├── config.go           # Configuration
│       ├── kubeconfig.go       # Kubeconfig parser
│       └── proxy.go            # HTTP proxy implementation
├── scripts/
│   ├── signing-tool.sh         # CLI signing utility (openssl-based)
│   └── kind/                   # Kind cluster deployment scripts
│       ├── deploy-kind.sh      # Deploy to kind cluster
│       ├── teardown-kind.sh    # Remove kind cluster
│       └── test-pod-policies.sh  # Test pod policy verification
├── examples/                   # Example configurations
├── pkg/                        # Public library code
├── bin/                        # Compiled binaries (generated)
├── Makefile
├── go.mod
└── README.md
```

## Testing with Kind

Deploy kubelet-proxy to a kind cluster:

```bash
# Deploy to kind cluster (2 nodes: control-plane + worker)
# This generates signing keys locally via signing-tool.sh
make deploy-kind

# Run pod policy verification tests
make test-kind

# Tear down cluster
make teardown-kind
```

The kind deployment:
- Creates a 2-node cluster (control-plane + worker)
- Generates signing keys locally using `signing-tool.sh`
- Installs kubelet-proxy on the worker node with pod policy verification enabled
- Configures kubelet to route through the proxy

## Testing with AKS

Deploy kubelet-proxy to an AKS cluster with an AKS Flex Node VM:

```bash
# Deploy AKS cluster and flex node with kubelet-proxy
make deploy-aks

# Run pod policy verification tests
make test-aks
```

The AKS deployment:
- Creates an Azure RBAC-enabled AKS cluster
- Deploys an Ubuntu 24.04 VM with managed identities for kubelet and resource access
- Joins the VM to the AKS cluster as a flex node using [AKS Flex Node](https://github.com/gaurav137/AKSFlexNode)
- Generates signing keys locally using `signing-tool.sh`
- Installs kubelet-proxy with pod policy verification enabled
- Adds a taint `pod-policy=required:NoSchedule` to the node for policy-required workloads
- Signs and deploys test pods using `signing-tool.sh`
