# Project variables
PROJECT_NAME := conf-node
GO := go
GOFLAGS := -v
BUILD_DIR := bin
DIST_DIR := dist
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")

# Binary names
KUBELET_PROXY := kubelet-proxy
SIGNING_SERVER := local-signing-server
ATTESTATION_CLIENT := attestation-cli
ATTESTATION_SERVER := attestation-server
ATTESTATION_VERIFIER := attestation-verifier

# Build flags
LDFLAGS := -ldflags "-s -w -X main.version=$(VERSION)"

.PHONY: all build clean kubelet-proxy local-signing-server attestation-cli attestation-server attestation-verifier help release

## all: Build all binaries
all: build

## build: Build all binaries
build: kubelet-proxy local-signing-server attestation-cli attestation-server attestation-verifier

## kubelet-proxy: Build the kubelet-proxy binary
kubelet-proxy:
	@echo "Building kubelet-proxy..."
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(GOFLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(KUBELET_PROXY) ./cmd/kubelet-proxy

## local-signing-server: Build the local-signing-server binary
local-signing-server:
	@echo "Building local-signing-server..."
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(GOFLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(SIGNING_SERVER) ./cmd/local-signing-server

## attestation-cli: Build the attestation-cli binary
attestation-cli:
	@echo "Building attestation-cli..."
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(GOFLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(ATTESTATION_CLIENT) ./cmd/attestation-cli

## attestation-server: Build the attestation-server binary
attestation-server:
	@echo "Building attestation-server..."
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(GOFLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(ATTESTATION_SERVER) ./cmd/attestation-server

## attestation-verifier: Build the attestation-verifier binary
attestation-verifier:
	@echo "Building attestation-verifier..."
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(GOFLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(ATTESTATION_VERIFIER) ./cmd/attestation-verifier

## clean: Remove build artifacts
clean:
	@echo "Cleaning..."
	@rm -rf $(BUILD_DIR) $(DIST_DIR)

## test: Run tests
test:
	$(GO) test -v ./...

## fmt: Format Go code
fmt:
	$(GO) fmt ./...

## vet: Run go vet
vet:
	$(GO) vet ./...

## lint: Run linter (requires golangci-lint)
lint:
	golangci-lint run ./...

## release: Build release artifacts for all platforms
release: clean
	@echo "Building release artifacts for version $(VERSION)..."
	@mkdir -p $(DIST_DIR)
	
	@# Build kubelet-proxy linux/amd64
	@echo "Building kubelet-proxy linux/amd64..."
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build $(LDFLAGS) -o $(DIST_DIR)/kubelet-proxy ./cmd/kubelet-proxy
	tar -czf $(DIST_DIR)/kubelet-proxy-linux-amd64.tar.gz -C $(DIST_DIR) kubelet-proxy
	sha256sum $(DIST_DIR)/kubelet-proxy-linux-amd64.tar.gz | cut -d' ' -f1 > $(DIST_DIR)/kubelet-proxy-linux-amd64.tar.gz.sha256
	@rm $(DIST_DIR)/kubelet-proxy
	
	@# Build kubelet-proxy linux/arm64
	@echo "Building kubelet-proxy linux/arm64..."
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build $(LDFLAGS) -o $(DIST_DIR)/kubelet-proxy ./cmd/kubelet-proxy
	tar -czf $(DIST_DIR)/kubelet-proxy-linux-arm64.tar.gz -C $(DIST_DIR) kubelet-proxy
	sha256sum $(DIST_DIR)/kubelet-proxy-linux-arm64.tar.gz | cut -d' ' -f1 > $(DIST_DIR)/kubelet-proxy-linux-arm64.tar.gz.sha256
	@rm $(DIST_DIR)/kubelet-proxy
	
	@# Build local-signing-server linux/amd64
	@echo "Building local-signing-server linux/amd64..."
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build $(LDFLAGS) -o $(DIST_DIR)/local-signing-server ./cmd/local-signing-server
	tar -czf $(DIST_DIR)/local-signing-server-linux-amd64.tar.gz -C $(DIST_DIR) local-signing-server
	sha256sum $(DIST_DIR)/local-signing-server-linux-amd64.tar.gz | cut -d' ' -f1 > $(DIST_DIR)/local-signing-server-linux-amd64.tar.gz.sha256
	@rm $(DIST_DIR)/local-signing-server
	
	@# Build local-signing-server linux/arm64
	@echo "Building local-signing-server linux/arm64..."
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build $(LDFLAGS) -o $(DIST_DIR)/local-signing-server ./cmd/local-signing-server
	tar -czf $(DIST_DIR)/local-signing-server-linux-arm64.tar.gz -C $(DIST_DIR) local-signing-server
	sha256sum $(DIST_DIR)/local-signing-server-linux-arm64.tar.gz | cut -d' ' -f1 > $(DIST_DIR)/local-signing-server-linux-arm64.tar.gz.sha256
	@rm $(DIST_DIR)/local-signing-server
	
	@# Build attestation-cli linux/amd64
	@echo "Building attestation-cli linux/amd64..."
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build $(LDFLAGS) -o $(DIST_DIR)/attestation-cli ./cmd/attestation-cli
	tar -czf $(DIST_DIR)/attestation-cli-linux-amd64.tar.gz -C $(DIST_DIR) attestation-cli
	sha256sum $(DIST_DIR)/attestation-cli-linux-amd64.tar.gz | cut -d' ' -f1 > $(DIST_DIR)/attestation-cli-linux-amd64.tar.gz.sha256
	@rm $(DIST_DIR)/attestation-cli
	
	@# Build attestation-cli linux/arm64
	@echo "Building attestation-cli linux/arm64..."
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build $(LDFLAGS) -o $(DIST_DIR)/attestation-cli ./cmd/attestation-cli
	tar -czf $(DIST_DIR)/attestation-cli-linux-arm64.tar.gz -C $(DIST_DIR) attestation-cli
	sha256sum $(DIST_DIR)/attestation-cli-linux-arm64.tar.gz | cut -d' ' -f1 > $(DIST_DIR)/attestation-cli-linux-arm64.tar.gz.sha256
	@rm $(DIST_DIR)/attestation-cli
	
	@# Build attestation-server linux/amd64
	@echo "Building attestation-server linux/amd64..."
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build $(LDFLAGS) -o $(DIST_DIR)/attestation-server ./cmd/attestation-server
	tar -czf $(DIST_DIR)/attestation-server-linux-amd64.tar.gz -C $(DIST_DIR) attestation-server
	sha256sum $(DIST_DIR)/attestation-server-linux-amd64.tar.gz | cut -d' ' -f1 > $(DIST_DIR)/attestation-server-linux-amd64.tar.gz.sha256
	@rm $(DIST_DIR)/attestation-server
	
	@# Build attestation-server linux/arm64
	@echo "Building attestation-server linux/arm64..."
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build $(LDFLAGS) -o $(DIST_DIR)/attestation-server ./cmd/attestation-server
	tar -czf $(DIST_DIR)/attestation-server-linux-arm64.tar.gz -C $(DIST_DIR) attestation-server
	sha256sum $(DIST_DIR)/attestation-server-linux-arm64.tar.gz | cut -d' ' -f1 > $(DIST_DIR)/attestation-server-linux-arm64.tar.gz.sha256
	@rm $(DIST_DIR)/attestation-server
	
	@# Build attestation-verifier linux/amd64
	@echo "Building attestation-verifier linux/amd64..."
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build $(LDFLAGS) -o $(DIST_DIR)/attestation-verifier ./cmd/attestation-verifier
	tar -czf $(DIST_DIR)/attestation-verifier-linux-amd64.tar.gz -C $(DIST_DIR) attestation-verifier
	sha256sum $(DIST_DIR)/attestation-verifier-linux-amd64.tar.gz | cut -d' ' -f1 > $(DIST_DIR)/attestation-verifier-linux-amd64.tar.gz.sha256
	@rm $(DIST_DIR)/attestation-verifier
	
	@# Build attestation-verifier linux/arm64
	@echo "Building attestation-verifier linux/arm64..."
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build $(LDFLAGS) -o $(DIST_DIR)/attestation-verifier ./cmd/attestation-verifier
	tar -czf $(DIST_DIR)/attestation-verifier-linux-arm64.tar.gz -C $(DIST_DIR) attestation-verifier
	sha256sum $(DIST_DIR)/attestation-verifier-linux-arm64.tar.gz | cut -d' ' -f1 > $(DIST_DIR)/attestation-verifier-linux-arm64.tar.gz.sha256
	@rm $(DIST_DIR)/attestation-verifier
	
	@echo "Release artifacts created in $(DIST_DIR)/"
	@ls -la $(DIST_DIR)/

## deploy-kind: Deploy kubelet-proxy to a kind cluster for testing
deploy-kind:
	@./scripts/kind/deploy-kind.sh

## teardown-kind: Remove the kind test cluster
teardown-kind:
	@./scripts/kind/teardown-kind.sh

## test-kind: Run pod policy verification tests against the kind cluster
test-kind: test-pod-policies

## test-pod-policies: Run pod policy verification tests against the kind cluster
test-pod-policies:
	@./scripts/kind/test-pod-policies.sh

## deploy-aks: Deploy AKS cluster with flex node and kubelet-proxy
deploy-aks:
	@./scripts/aks/deploy-cluster.sh
	@./scripts/aks/deploy-flex-node-vm.sh
	@./scripts/aks/deploy-kubelet-proxy.sh

## test-aks: Run pod policy verification tests against the AKS cluster
test-aks:
	@./scripts/aks/test-pod-policies.sh

## help: Show this help message
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@sed -n 's/^##//p' $(MAKEFILE_LIST) | column -t -s ':' | sed -e 's/^/ /'
