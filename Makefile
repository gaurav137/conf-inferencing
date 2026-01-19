# Project variables
PROJECT_NAME := conf-inferencing
GO := go
GOFLAGS := -v
BUILD_DIR := bin

# Binary names
KUBELET_PROXY := kubelet-proxy

# Build flags
LDFLAGS := -ldflags "-s -w"

.PHONY: all build clean kubelet-proxy help

## all: Build all binaries
all: build

## build: Build all binaries
build: kubelet-proxy

## kubelet-proxy: Build the kubelet-proxy binary
kubelet-proxy:
	@echo "Building kubelet-proxy..."
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(GOFLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(KUBELET_PROXY) ./cmd/kubelet-proxy

## clean: Remove build artifacts
clean:
	@echo "Cleaning..."
	@rm -rf $(BUILD_DIR)

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

## deploy-kind: Deploy kubelet-proxy to a kind cluster for testing
deploy-kind:
	@./scripts/kind/deploy-kind.sh

## teardown-kind: Remove the kind test cluster
teardown-kind:
	@./scripts/kind/teardown-kind.sh

## test-kind: Run tests against the kind cluster deployment
test-kind:
	@./scripts/kind/test-deployment.sh

## test-signature: Run signature verification tests against the kind cluster
test-signature:
	@./scripts/kind/test-signature-verification.sh

## help: Show this help message
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@sed -n 's/^##//p' $(MAKEFILE_LIST) | column -t -s ':' | sed -e 's/^/ /'
