# sandboxd — build, codegen, and verification targets.

SHELL      := /bin/bash
MODULE     := github.com/axelmierczuk/sandboxd-mcp
TOOLS_DIR  := $(CURDIR)/.tools
BIN_DIR    := $(CURDIR)/bin
export PATH := $(TOOLS_DIR):$(PATH)

BUF_VERSION            := v1.72.0
PROTOC_GEN_GO_VERSION  := v1.36.12
PROTOC_GEN_GRPC_VERSION:= v1.6.2
GOLANGCI_VERSION       := v2.6.2
GO_TOOLCHAIN           := go1.25.13

VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE    := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w \
	-X $(MODULE)/internal/version.Version=$(VERSION) \
	-X $(MODULE)/internal/version.Commit=$(COMMIT) \
	-X $(MODULE)/internal/version.Date=$(DATE)

# Every platform the agent must run on. The agent is the component that lands
# on machines we do not control, so its build matrix is the wide one.
AGENT_PLATFORMS := \
	linux/amd64 linux/arm64 \
	darwin/amd64 darwin/arm64 \
	windows/amd64 windows/arm64

.DEFAULT_GOAL := help

## help: list available targets
.PHONY: help
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## //' | awk -F':' '{printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

## tools: install pinned build tooling into .tools/
.PHONY: tools
tools:
	@mkdir -p $(TOOLS_DIR)
	# CI pins GOTOOLCHAIN=local to the exact version named in go.mod, so a
	# tool whose own go.mod requires a newer point release (as buf's
	# regularly does) fails to install unless we hand it a toolchain that
	# satisfies it — same reasoning as the golangci-lint pin below.
	GOBIN=$(TOOLS_DIR) GOTOOLCHAIN=$(GO_TOOLCHAIN) go install github.com/bufbuild/buf/cmd/buf@$(BUF_VERSION)
	GOBIN=$(TOOLS_DIR) GOTOOLCHAIN=$(GO_TOOLCHAIN) go install google.golang.org/protobuf/cmd/protoc-gen-go@$(PROTOC_GEN_GO_VERSION)
	GOBIN=$(TOOLS_DIR) GOTOOLCHAIN=$(GO_TOOLCHAIN) go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@$(PROTOC_GEN_GRPC_VERSION)
	# golangci-lint refuses to run against a module targeting a newer Go than
	# the one it was built with, so pin the toolchain rather than inheriting
	# whatever default the host happens to have.
	GOBIN=$(TOOLS_DIR) GOTOOLCHAIN=$(GO_TOOLCHAIN) go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_VERSION)

## proto: regenerate Go code from proto/
.PHONY: proto
proto:
	$(TOOLS_DIR)/buf generate

## proto-lint: lint and format-check proto definitions
.PHONY: proto-lint
proto-lint:
	$(TOOLS_DIR)/buf lint
	$(TOOLS_DIR)/buf format --diff --exit-code

## proto-breaking: fail if proto changes break the wire contract on main
.PHONY: proto-breaking
proto-breaking:
	$(TOOLS_DIR)/buf breaking --against '.git#branch=main'

## proto-check: verify committed codegen matches the .proto sources
.PHONY: proto-check
proto-check: proto
	@git diff --exit-code -- gen/ \
		|| { echo "gen/ is stale; run 'make proto' and commit the result"; exit 1; }

## build: build all three binaries for the host platform
.PHONY: build
build:
	@mkdir -p $(BIN_DIR)
	go build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN_DIR)/ ./cmd/...

## build-agent-all: cross-compile the agent for every supported platform
.PHONY: build-agent-all
build-agent-all:
	@mkdir -p $(BIN_DIR)
	@for p in $(AGENT_PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; ext=""; \
		[ "$$os" = "windows" ] && ext=".exe"; \
		echo "  building sandboxd-agent $$os/$$arch"; \
		GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags '$(LDFLAGS)' \
			-o $(BIN_DIR)/sandboxd-agent-$$os-$$arch$$ext ./cmd/sandboxd-agent || exit 1; \
	done

## test: run unit tests with race detection
.PHONY: test
test:
	go test -race -count=1 ./...

## lint: run golangci-lint
.PHONY: lint
lint:
	$(TOOLS_DIR)/golangci-lint run

## fmt: format Go sources and proto definitions
.PHONY: fmt
fmt:
	gofmt -w $$(git ls-files '*.go' | grep -v '^gen/')
	$(TOOLS_DIR)/buf format -w

## vet: run go vet
.PHONY: vet
vet:
	go vet ./...

## check: everything CI runs
.PHONY: check
check: proto-lint proto-check vet lint test

## clean: remove build output
.PHONY: clean
clean:
	rm -rf $(BIN_DIR) dist/
