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

# Everything above that decides what ends up in .tools/, named once so CI can
# key a cache on it (see tools-key). A pin that is missing from this list is a
# pin whose bump would not change the cache key, which means CI would keep
# serving the old binary from cache forever — worse than no cache at all. That
# is what tools-key-check exists to prevent; it fails if the Makefile defines a
# *_VERSION this list does not name.
TOOL_PINS := \
	BUF_VERSION \
	PROTOC_GEN_GO_VERSION \
	PROTOC_GEN_GRPC_VERSION \
	GOLANGCI_VERSION \
	GO_TOOLCHAIN

# binary:expected-module-version, checked by tools-verify against what each
# binary reports about itself.
TOOL_BINS := \
	buf:$(BUF_VERSION) \
	protoc-gen-go:$(PROTOC_GEN_GO_VERSION) \
	protoc-gen-go-grpc:$(PROTOC_GEN_GRPC_VERSION) \
	golangci-lint:$(GOLANGCI_VERSION)

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

# Packages no `...` pattern can reach.
#
# test/e2e/testdata/helpers is a real Go main package, but the go tool skips
# every directory under testdata, so `./...` has never loaded it — under any
# GOOS, with or without the tag above. The one file in it that exists purely for
# Windows, pgid_other.go, was therefore compiled by nothing: the integration job
# runs on Linux and macOS only, and that job is the only thing that builds these
# helpers. Naming the package explicitly is what makes the per-GOOS loops below
# mean what they say.
#
# The exact path, not a wildcard: `./test/e2e/testdata/...` is skipped for the
# same reason `./...` is, and golangci-lint expands its patterns with the same
# go tool, so it reports "no go files to analyze" rather than the two findings
# that are actually in there. Both checkers therefore have to name it, and
# because naming anything at all replaces the implicit default, `./...` has to
# be spelled out alongside it.
CHECK_EXTRA_PKGS := ./test/e2e/testdata/helpers

# Which is an explicit list of the things a wildcard cannot find, and so is
# exactly the kind of list that rots: put a second package under testdata and
# every checker goes quiet about it again, which is #60 with a different path.
# check-extra-pkgs below holds the list to the tree rather than trusting it.

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

## tools-key: print the exact identity of everything `make tools` installs
#
# The target above is four `go install`s that compile for about two minutes to
# produce byte-identical binaries every single run, because every input to them
# is pinned. CI hashes this output into its .tools/ cache key so a run whose
# pins have not moved can skip the compile entirely.
#
# It prints values, not names: the hash has to change when a version changes
# and only then. Anything derived from the whole Makefile would bust the cache
# on an unrelated edit; anything narrower than the pins would not bust it on a
# bump, which is the failure that matters.
.PHONY: tools-key
tools-key: tools-key-check
	@$(foreach v,$(TOOL_PINS),printf '%s=%s\n' '$(v)' '$($(v))';)

## tools-key-check: fail if a pinned version is missing from TOOL_PINS
#
# A cache key that cannot change is the one way this cache can be worse than no
# cache: it would serve the pre-bump binary until someone noticed by hand. So
# make the omission loud rather than trusting whoever adds the fifth tool to
# remember. Convention is what is scanned for — a pin is a `*_VERSION` (plus
# the toolchain) assigned at column zero, with or without an `export` — so a
# pin named outside it still needs adding to TOOL_PINS by hand.
#
# This covers the key only. tools-bins-check below covers the other half: that
# the fifth tool is also something tools-verify actually looks at.
.PHONY: tools-key-check
tools-key-check:
	@pins=$$(awk '/^(export[ \t]+)?(GO_TOOLCHAIN|[A-Z][A-Z0-9_]*_VERSION)[ \t]*[:?+]*=/ { sub(/^export[ \t]+/, ""); sub(/[ \t]*[:?+]*=.*/, ""); print }' $(firstword $(MAKEFILE_LIST))); \
	if [ -z "$$pins" ]; then \
		echo "tools-key-check: no pinned versions found in $(firstword $(MAKEFILE_LIST));" >&2; \
		echo "  the cache key would be a constant and CI would never reinstall" >&2; \
		exit 1; \
	fi; \
	for v in $$pins; do \
		case " $(TOOL_PINS) " in \
			*" $$v "*) ;; \
			*) echo "tools-key-check: $$v is pinned here but missing from TOOL_PINS;" >&2; \
			   echo "  CI keys its .tools/ cache on TOOL_PINS, so bumping $$v would hit a stale cache" >&2; \
			   exit 1;; \
		esac; \
	done

## tools-bins-check: fail if `make tools` installs a binary TOOL_BINS omits
#
# tools-key-check keeps the cache *key* honest when a fifth tool arrives. This
# keeps the cache *check* honest, which is the half that was missing: TOOL_BINS
# is a hand-written list, tools-verify iterates it and nothing else, so a fifth
# tool that nobody adds to it is a fifth binary tools-verify never looks at. A
# restore that dropped exactly that binary would still be reported as "matches
# every pin" — which is the partial restore this whole mechanism exists to
# catch, reintroduced by the same omission tools-key-check already guards the
# key against.
#
# What counts as installed is the recipe line that puts it in .tools/, so scan
# for those rather than keeping a second hand-written list in step with the
# first. Recipe lines only — anchored to leading whitespace so that prose about
# the scan, including this paragraph, can never be read as input to it. The
# binary name is the last path element, minus a /vN major-version suffix, which
# is how the go tool names it.
.PHONY: tools-bins-check
tools-bins-check:
	@fail=0; \
	for pkg in $$(sed -n 's/^[[:blank:]].*GOBIN=$$(TOOLS_DIR).*go install \([^@ ]*\)@.*/\1/p' $(firstword $(MAKEFILE_LIST))); do \
		name=$${pkg##*/}; \
		case "$$name" in v[0-9]|v[0-9][0-9]) rest=$${pkg%/*}; name=$${rest##*/};; esac; \
		case " $(TOOL_BINS) " in \
			*" $$name:"*) ;; \
			*) echo "tools-bins-check: 'make tools' installs $$name but TOOL_BINS does not name it;" >&2; \
			   echo "  tools-verify only checks TOOL_BINS, so a cache restore missing $$name would pass" >&2; \
			   fail=1;; \
		esac; \
	done; \
	if [ $$fail -ne 0 ]; then exit 1; fi

## tools-verify: assert .tools/ holds exactly the pinned versions
#
# `go install` is not the only thing that writes .tools/ any more — CI restores
# it from a cache — and a cache that hands back the wrong binary is worse than
# a slow one: these binaries decide what `buf lint` accepts and what the wire
# check compares against. Cheap enough (four execs, no compiling) to run on
# every restore, so ask each binary what it is instead of trusting the key that
# fetched it. `go version -m` reads the module version, the building toolchain
# and the target GOOS/GOARCH out of the binary itself, which is the same claim
# for all four and is not a `--version` flag anyone can reformat.
#
# GOOS/GOARCH is checked because the cache key was the only thing standing
# between a runner and a binary for another platform, and a key is a claim
# about what was stored, not about what came back. Everything else here is a
# check of the contents against the pins; this is the one axis where "it is a
# Go binary of exactly the right version" is still the wrong file.
.PHONY: tools-verify
tools-verify: tools-bins-check
	@fail=0; hostos=$$(go env GOHOSTOS); hostarch=$$(go env GOHOSTARCH); \
	for pair in $(TOOL_BINS); do \
		bin=$${pair%%:*}; want=$${pair#*:}; path=$(TOOLS_DIR)/$$bin; \
		if [ ! -x "$$path" ]; then \
			echo "  $$bin: not in $(TOOLS_DIR)" >&2; fail=1; continue; \
		fi; \
		info=$$(go version -m "$$path") || { echo "  $$bin: not a Go binary" >&2; fail=1; continue; }; \
		got=$$(echo "$$info" | awk '$$1 == "mod" { print $$3; exit }'); \
		built=$$(echo "$$info" | awk 'NR == 1 { print $$2; exit }'); \
		goos=$$(echo "$$info" | awk '$$1 == "build" && $$2 ~ /^GOOS=/ { sub(/^GOOS=/, "", $$2); print $$2; exit }'); \
		goarch=$$(echo "$$info" | awk '$$1 == "build" && $$2 ~ /^GOARCH=/ { sub(/^GOARCH=/, "", $$2); print $$2; exit }'); \
		[ "$$got" = "$$want" ] || { echo "  $$bin: is $$got, want $$want" >&2; fail=1; }; \
		[ "$$built" = "$(GO_TOOLCHAIN)" ] || { echo "  $$bin: built by $$built, want $(GO_TOOLCHAIN)" >&2; fail=1; }; \
		[ "$$goos/$$goarch" = "$$hostos/$$hostarch" ] || { echo "  $$bin: built for $$goos/$$goarch, want $$hostos/$$hostarch" >&2; fail=1; }; \
	done; \
	if [ $$fail -ne 0 ]; then \
		echo "  .tools/ does not match the pins in $(firstword $(MAKEFILE_LIST)); run 'make tools'" >&2; \
		exit 1; \
	fi; \
	echo "  .tools/ matches every pin"

## tools-selftest: prove the tooling gates reject what they exist to reject
#
# The three checks above are the whole reason caching .tools/ is not worse than
# recompiling it, and a check that has quietly stopped firing is indistinguish-
# able from a check with nothing to report: both are green. So hand each one the
# input it exists for and require it to fail.
#
# Not in `check`. It needs a populated .tools/ and cross-builds a throwaway
# binary, and it is verifying CI's cache rather than this working tree — so CI's
# Proto job runs it, next to the cache it protects. Same reasoning as
# test-norace: the gate belongs where the thing it guards lives.
.PHONY: tools-selftest
tools-selftest:
	@bash $(CURDIR)/scripts/tools-selftest.sh $(CURDIR)/$(firstword $(MAKEFILE_LIST)) $(TOOLS_DIR)

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
#
# Every platform is attempted even after one fails, and the failures are named
# together at the end. This is CI's whole cross-compile job now rather than six
# jobs paying six checkouts and six setup-gos for twenty seconds of work each,
# and those six carried fail-fast: false: one platform breaking should still
# tell you about the other five in the same run, not one per push.
#
# An empty list is an error rather than a no-op. A loop over nothing succeeds,
# and this target is now the only thing standing behind a CI job called "build
# the agent for every supported platform" — so the one way it could report
# green having built nothing is the one way the six-way matrix could not (an
# empty matrix vector is a hard workflow error). This is not hypothetical
# tidiness: AGENT_PLATFORMS is a `\`-continued list, and dropping the
# continuation off the first line silently empties it.
.PHONY: build-agent-all
build-agent-all:
	@mkdir -p $(BIN_DIR)
	@if [ -z "$(strip $(AGENT_PLATFORMS))" ]; then \
		echo "  build-agent-all: AGENT_PLATFORMS is empty; nothing would be built" >&2; \
		exit 1; \
	fi
	@failed=""; \
	for p in $(AGENT_PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; ext=""; \
		[ "$$os" = "windows" ] && ext=".exe"; \
		echo "  building fleet-agent $$os/$$arch"; \
		GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags '$(LDFLAGS)' \
			-o $(BIN_DIR)/fleet-agent-$$os-$$arch$$ext ./cmd/fleet-agent \
			|| failed="$$failed $$os/$$arch"; \
	done; \
	if [ -n "$$failed" ]; then \
		echo "  fleet-agent failed to build for:$$failed" >&2; \
		exit 1; \
	fi

## test: run unit tests with race detection
.PHONY: test
test:
	go test -race -count=1 ./...

## test-norace: run unit tests without the race detector
#
# Every other test run in this repository, and every job in CI, passes -race.
# That is exactly how #56 sat green on main: a test that failed 5/5 without the
# detector and passed 100% with it, because the detector's slowdown was what
# made its assertion true. Twelve green jobs saw nothing, while `go test ./...`
# — the command a contributor actually runs first — failed for everyone.
#
# So this is that command, kept here rather than typed into a workflow file, so
# that what CI runs on Linux and what you can run on a laptop are the same
# thing. A failure here with the -race jobs green is not a flake to re-run: it
# means an assertion depends on how slow the machine was.
.PHONY: test-norace
test-norace:
	go test -count=1 ./...

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
#
# The package list is spelled out for the reason CHECK_EXTRA_PKGS gives: the
# implicit `./...` a bare `golangci-lint run` uses cannot reach the e2e
# helpers, so this target reported clean on a package it had never opened.
.PHONY: lint
lint:
	@for os in $(CHECK_GOOSES); do \
		echo "  golangci-lint GOOS=$$os"; \
		GOOS=$$os CGO_ENABLED=0 $(TOOLS_DIR)/golangci-lint run ./... $(CHECK_EXTRA_PKGS) || exit 1; \
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
		GOOS=$$os CGO_ENABLED=0 go vet -tags '$(CHECK_TAGS)' ./... $(CHECK_EXTRA_PKGS) || exit 1; \
	done

## check-extra-pkgs: fail if a package outside every `...` pattern is outside the gate
#
# The hole #60 was about is not that a package was skipped; it is that the gate
# reported clean on a package it had never opened, so nobody knew. A hand-kept
# list of the packages `./...` cannot reach has the same failure mode the moment
# someone adds one, so the list is checked against the tree rather than trusted.
#
# CI is checked too, and it is the half that matters: its vet and lint steps
# name these paths inline rather than reading this variable, and CI is the gate
# that blocks a merge. `make check` does not run there, so this is the last
# place the two can be held together before a push.
#
# It cannot see the other shape of the same hole — a file whose build tag no
# GOOS in CHECK_GOOSES satisfies, which is compiled by nothing and needs a
# constraint solver rather than a path list. See svcpid_other.go.
.PHONY: check-extra-pkgs
check-extra-pkgs:
	@missing=""; \
	for dir in $$(git ls-files '*.go' | grep -E '(^|/)(testdata|vendor|[._][^/]*)/' | sed 's|/[^/]*$$||' | sort -u); do \
		case " $(CHECK_EXTRA_PKGS) " in \
			*" ./$$dir "*) ;; \
			*) missing="$$missing ./$$dir" ;; \
		esac; \
	done; \
	if [ -n "$$missing" ]; then \
		echo "no ... pattern reaches these packages, and CHECK_EXTRA_PKGS does not name them:$$missing"; \
		echo "add them to CHECK_EXTRA_PKGS here, and to the vet and lint steps in .github/workflows/ci.yml"; \
		exit 1; \
	fi; \
	for pkg in $(CHECK_EXTRA_PKGS); do \
		grep -q -- "$$pkg" .github/workflows/ci.yml || { \
			echo "CHECK_EXTRA_PKGS names $$pkg but no step in .github/workflows/ci.yml does,"; \
			echo "so it is outside the gate that actually blocks a merge"; \
			exit 1; \
		}; \
	done

## check: the local gate — what CI runs, across every GOOS
#
# CI's own lint job runs on one runner, so it sees one GOOS too; the test
# matrix is what catches the rest, after a push. Running all three here means
# finding it before.
#
# The one thing CI runs that this does not is test-norace. It is free there —
# the x1 runner, in parallel with a test matrix that takes three minutes — and
# it would be a third of this gate's wall clock here, paid by everyone on
# every run. Run it by hand if you have touched anything whose assertion could
# depend on how fast the machine is.
.PHONY: check
check: proto-lint proto-check check-extra-pkgs vet lint test

## clean: remove build output
.PHONY: clean
clean:
	rm -rf $(BIN_DIR) dist/
