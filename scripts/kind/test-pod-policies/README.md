# Test Policies for Pod Policy Verification

This directory contains policy JSON files used for testing kubelet-proxy pod policy verification.

## Policy Files

| File | Description | Used In Test |
|------|-------------|--------------|
| `nginx-pod-policy.json` | Policy allowing nginx:latest container on signed-workloads nodes | Signed pod test (TEST 1), Bad signature test (TEST 3), Image mismatch test (TEST 4) |
| `busybox-pod-policy.json` | Policy allowing busybox:latest container | Reference only |

## Policy Schema

Each policy JSON follows the per-container structure:

```json
{
  "containers": {
    "<container-name>": {
      "image": "<image>",
      "privileged": true,           // optional
      "capabilities": ["CAP_NAME"]  // optional
    }
  },
  "initContainers": { ... },        // optional
  "allowHostNetwork": true,         // optional
  "allowHostPID": true,             // optional
  "allowHostIPC": true,             // optional
  "nodeSelector": { "key": "value"} // optional
}
```

## How Policies Are Used in Tests

The test script (`scripts/kind/test-pod-policies.sh`) loads these policy files and:

1. Compacts the JSON (removes whitespace, sorts keys)
2. Base64-encodes the compacted JSON
3. Signs the base64 string using the signing-server
4. Creates pod YAML with the policy and signature as annotations

## Test Scenarios

| Test | Policy Used | Pod Image | Expected |
|------|-------------|-----------|----------|
| TEST 1: Signed pod | `nginx-pod-policy.json` | nginx:latest | ALLOWED |
| TEST 2: Unsigned pod | (none) | nginx:latest | REJECTED |
| TEST 3: Bad signature | `nginx-pod-policy.json` | nginx:latest | REJECTED |
| TEST 4: Image mismatch | `nginx-pod-policy.json` | busybox:latest | REJECTED |

## Running Tests

```bash
# From project root
make test-kind

# Or directly
./scripts/kind/test-pod-policies.sh
```
