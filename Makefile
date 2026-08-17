# fleet — build, codegen, and verification targets.

SHELL      := /bin/bash
MODULE     := github.com/axelmierczuk/fleet-mcp
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

# Every GOOS that `vet` and `lint` must be run under. Build tags mean a
# single-platform pass over this tree checks roughly two thirds of it.
CHECK_GOOSES := linux darwin windows

# Build tags that `vet` and `lint` must include on top of the default set.
#
# The end-to-end suite is behind `integration` so that `go test ./...` stays
# fast, and a tag that hides a package from the test runner hides it from the
# checkers too: without this, test/e2e is neither vetted nor linted, and the
# first anyone hears of a call that does not compile under GOOS=windows is a red
# CI run. Same reasoning as the per-GOOS loops below, one level up.
CHECK_TAGS := integration

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
	# CI checks out a PR's merge commit as a detached HEAD via fetch-depth:0,
	# which populates refs/remotes/origin/main but never a local branch
	# literally named "main" — buf's git input needs a ref that actually
	# resolves, so target the remote-tracking branch rather than assuming a
	# local one exists (it also doesn't, and shouldn't have to, on a fresh
	# CI checkout).
	$(TOOLS_DIR)/buf breaking --against '.git#branch=origin/main'

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
		echo "  building fleet-agent $$os/$$arch"; \
		GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags '$(LDFLAGS)' \
			-o $(BIN_DIR)/fleet-agent-$$os-$$arch$$ext ./cmd/fleet-agent || exit 1; \
	done

## test: run unit tests with race detection
.PHONY: test
test:
	go test -race -count=1 ./...

## test-integration: run the end-to-end suite against the real binaries
#
# Not part of `check`, and not part of `test`: it builds three binaries, starts
# a control plane and two agent daemons per scenario, and moves 24 MiB over a
# real mTLS gRPC stream. Twenty seconds is cheap for what it covers and far too
# expensive to pay on every `go test ./...`.
#
# No Docker, no root, no network beyond loopback. The one scenario that wants a
# container is opt-in; see test-integration-docker and test/e2e/README.md.
#
# Race-enabled like `test`, and for the same reason. The product runs in its own
# processes here so the detector cannot see inside it, but the harness is
# concurrent code too — one scenario keeps two dozen calls in flight against a
# single session — and a suite written to catch races the unit tests cannot
# should not be the one package in this repository that races unwatched. It
# costs about three seconds.
.PHONY: test-integration
test-integration:
	go test -tags integration -race -count=1 -timeout 20m ./test/...

## test-integration-docker: also run the containerised tree-kill scenario
#
# Separate because it pulls a Go image and builds the product inside it, which
# is minutes rather than seconds. What it buys is a PID namespace small enough
# to enumerate exhaustively, so "the timeout left no survivors" can be asserted
# against every process in it rather than against one process group.
.PHONY: test-integration-docker
test-integration-docker:
	FLEET_E2E_DOCKER=1 go test -tags integration -count=1 -timeout 30m -run InContainer ./test/...

## lint: run golangci-lint for every GOOS the agent ships for
#
# Once per GOOS, not once. A host-only run structurally cannot see a file
# guarded by a build tag for another platform: `golangci-lint run` on macOS
# never loads svcpid_linux.go, so a gosec finding in it is invisible locally
# and lands in CI instead. This repo has shipped two green-locally,
# red-in-CI pushes exactly that way — that gosec finding, and a test that did
# not compile on Windows. CI's own lint job runs on one runner and sees one
# GOOS too; only its test matrix vets all three, and only after the push. The
# extra passes cost seconds and close the gap before it.
.PHONY: lint
lint:
	@for os in $(CHECK_GOOSES); do \
		echo "  golangci-lint GOOS=$$os"; \
		GOOS=$$os CGO_ENABLED=0 $(TOOLS_DIR)/golangci-lint run || exit 1; \
	done

## fmt: format Go sources and proto definitions
.PHONY: fmt
fmt:
	gofmt -w $$(git ls-files '*.go' | grep -v '^gen/')
	$(TOOLS_DIR)/buf format -w

## vet: run go vet for every GOOS the agent ships for
#
# Same reasoning as lint, and it catches the other half of the problem: a test
# that references syscall.Kill compiles everywhere except Windows, and a
# runtime `if runtime.GOOS == "windows" { t.Skip() }` does not help, because
# the package has to typecheck before any test can skip itself.
.PHONY: vet
vet:
	@for os in $(CHECK_GOOSES); do \
		echo "  go vet GOOS=$$os"; \
		GOOS=$$os CGO_ENABLED=0 go vet -tags '$(CHECK_TAGS)' ./... || exit 1; \
	done

## check: the local gate — what CI runs, across every GOOS
#
# CI's own lint job runs on one runner, so it sees one GOOS too; the test
# matrix is what catches the rest, after a push. Running all three here means
# finding it before.
.PHONY: check
check: proto-lint proto-check vet lint test

## clean: remove build output
.PHONY: clean
clean:
	rm -rf $(BIN_DIR) dist/
