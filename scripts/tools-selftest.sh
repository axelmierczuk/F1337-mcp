#!/usr/bin/env bash
#
# Prove the tooling gates fail on the inputs they exist for.
#
# The .tools/ cache is only as good as the checks standing in front of it, and
# a check that has quietly stopped firing looks exactly like a check that has
# nothing to report. Both of those are green. So rather than trust that
# tools-key-check, tools-bins-check, tools-verify and check-ci-pins still reject
# what they were written to reject, hand each one the input it exists for and
# require it to fail.
#
# Every case here is one that has actually been observed to pass against some
# version of these targets, and reverting any one guard turns at least one of
# them red — the guards that cover two shapes of the same hole turn both.
#
# Each case drives the target CI actually runs — `make tools-key` and `make
# tools-verify` — and never the guard underneath by name. A guard only protects
# anything if the shipping path reaches it, and calling it directly proves the
# wrong half: with these cases invoking tools-key-check and tools-bins-check
# themselves, deleting `tools-verify: tools-bins-check` (or `tools-key:
# tools-key-check`) left every case here green while putting the hole they were
# written to close straight back. tools-verify went back to reporting ".tools/
# matches every pin" about a binary it had never looked at, and nothing said so.
#
# Fixtures are a copy of the Makefile in a temp directory, with .tools/
# symlinked binary by binary, so a case can drop or swap one without touching
# the real tree.

set -euo pipefail

makefile=${1:?usage: tools-selftest.sh <makefile> <tools-dir>}
tools_dir=${2:?usage: tools-selftest.sh <makefile> <tools-dir>}

if [ ! -d "$tools_dir" ]; then
	echo "tools-selftest: $tools_dir does not exist; run 'make tools' first" >&2
	exit 1
fi

workflow=$(dirname "$makefile")/.github/workflows/ci.yml
if [ ! -f "$workflow" ]; then
	echo "tools-selftest: no workflow at $workflow" >&2
	echo "  two of these gates compare the Makefile against it, and a fixture" >&2
	echo "  missing it would report those two as passing without comparing" >&2
	exit 1
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

failures=0

# reset copies the real Makefile back over the fixture, then applies an awk
# program to it. Called with no program it just restores the pristine copy.
#
# The workflow is copied alongside it because two of these gates compare the
# Makefile against CI's own configuration, so a fixture holding only half of
# that pair would test the halves apart and never their agreement.
reset() {
	cp "$makefile" "$tmp/Makefile"
	if [ $# -gt 0 ]; then
		awk "$1" "$tmp/Makefile" >"$tmp/Makefile.new"
		mv "$tmp/Makefile.new" "$tmp/Makefile"
	fi
	mkdir -p "$tmp/.github/workflows"
	cp "$workflow" "$tmp/.github/workflows/ci.yml"
	rm -rf "$tmp/.tools"
	mkdir -p "$tmp/.tools"
	for b in "$tools_dir"/*; do
		[ -e "$b" ] || continue
		ln -s "$b" "$tmp/.tools/$(basename "$b")"
	done
}

# expect_fail <description> <expected message fragment> -- <make args...>
expect_fail() {
	local desc=$1 marker=$2 out=""
	shift 3 # description, marker, the literal --
	if out=$(make -C "$tmp" "$@" 2>&1); then
		echo "  FAIL  $desc" >&2
		echo "        the gate passed; it must reject this" >&2
		failures=$((failures + 1))
	elif ! printf '%s' "$out" | grep -qF -- "$marker"; then
		echo "  FAIL  $desc" >&2
		echo "        failed, but not with \"$marker\":" >&2
		printf '%s\n' "$out" | sed 's/^/          /' >&2
		failures=$((failures + 1))
	else
		echo "  ok    $desc"
	fi
}

expect_pass() {
	local desc=$1 out=""
	shift 2 # description, the literal --
	if out=$(make -C "$tmp" "$@" 2>&1); then
		echo "  ok    $desc"
	else
		echo "  FAIL  $desc" >&2
		printf '%s\n' "$out" | sed 's/^/          /' >&2
		failures=$((failures + 1))
	fi
}

# The pristine fixture must pass, or every negative below proves nothing.
reset
expect_pass "an unmodified tree passes every tooling gate" -- tools-key-check tools-bins-check tools-verify

# --- tools-key-check: the cache key must move when a pin does ----------------
#
# Driven through `make tools-key`, which is what CI runs to build the key.

reset '{ print } /^GO_TOOLCHAIN/ { print "YQ_VERSION             := v4.44.3" }'
expect_fail "a fifth pin absent from TOOL_PINS" "missing from TOOL_PINS" -- tools-key

reset '{ print } /^GO_TOOLCHAIN/ { print "export YQ_VERSION := v4.44.3" }'
expect_fail "an export-prefixed pin absent from TOOL_PINS" "missing from TOOL_PINS" -- tools-key

# Every pin, found the same way tools-key-check finds them, rather than the five
# that happen to be here today: naming them made this case quietly stop testing
# anything the moment a legitimate sixth pin was added, because one surviving
# pin is enough for "no pins at all" to be false.
reset '/^(export[ \t]+)?(GO_TOOLCHAIN|[A-Z][A-Z0-9_]*_VERSION)[ \t]*[:?+]*=/ { print "#" $0; next } { print }'
expect_fail "no pins at all, so the key would be a constant" "no pinned versions found" -- tools-key

# --- tools-bins-check: tools-verify must cover every installed binary --------
#
# Driven through `make tools-verify`, which is the step CI runs on every job and
# the only thing standing between a bad restore and a green build.

reset '{ print } /go install github.com\/golangci/ { print "\tGOBIN=$(TOOLS_DIR) GOTOOLCHAIN=$(GO_TOOLCHAIN) go install github.com/mikefarah/yq/v4@$(GO_TOOLCHAIN)" }'
expect_fail "a fifth installed binary absent from TOOL_BINS" "TOOL_BINS does not name it" -- tools-verify

# The same tool, installed by a recipe line wrapped the way this Makefile wraps
# its other long lines. A scan that reads one physical line at a time sees
# GOBIN= on one and `go install` on the next, and reports nothing.
reset '{ print } /go install github.com\/golangci/ { print "\tGOBIN=$(TOOLS_DIR) GOTOOLCHAIN=$(GO_TOOLCHAIN) \\"; print "\t\tgo install github.com/mikefarah/yq/v4@$(GO_TOOLCHAIN)" }'
expect_fail "a fifth installed binary on a continued recipe line" "TOOL_BINS does not name it" -- tools-verify

# --- tools-verify: what a bad restore looks like -----------------------------

reset
rm "$tmp/.tools/protoc-gen-go-grpc"
expect_fail "a partial restore, 3 binaries of 4" "not in" -- tools-verify

reset
rm "$tmp/.tools/buf"
printf '#!/bin/sh\necho nope\n' >"$tmp/.tools/buf"
chmod +x "$tmp/.tools/buf"
expect_fail "something in .tools/ that is not a Go binary" "not a Go binary" -- tools-verify

# The one that matters most: pins moved, cache did not. A restore keyed on the
# old pins hands back the old binary, and only this check notices.
reset '/^PROTOC_GEN_GO_VERSION/ { print "PROTOC_GEN_GO_VERSION  := v0.0.0"; next } { print }'
expect_fail "a binary left behind by a pin bump" "want v0.0.0" -- tools-verify

# Right module, right toolchain, wrong machine. The cache key is scoped by
# runner OS and arch, but a key describes what was stored, not what came back.
reset
host_os=$(go env GOHOSTOS)
case $(go env GOHOSTARCH) in
amd64) other_arch=arm64 ;;
*) other_arch=amd64 ;;
esac
(
	cd "$tmp"
	mkdir -p src && cd src
	printf 'module selftest\n\ngo 1.25\n' >go.mod
	printf 'package main\n\nfunc main() {}\n' >main.go
	GOOS="$host_os" GOARCH="$other_arch" CGO_ENABLED=0 go build -o "$tmp/cross" .
)
rm "$tmp/.tools/protoc-gen-go"
cp "$tmp/cross" "$tmp/.tools/protoc-gen-go"
expect_fail "a binary built for $host_os/$other_arch" "built for $host_os/$other_arch" -- tools-verify

# --- check-ci-pins: CI must run the linter the pins name ---------------------
#
# The Lint job downloads its own golangci-lint rather than using .tools/, so the
# one bump that matters is the one where the Makefile moves and this file does
# not: everything local switches linter and the job that blocks the merge does
# not.

reset '/^GOLANGCI_VERSION/ { print "GOLANGCI_VERSION       := v0.0.0"; next } { print }'
expect_fail "a golangci-lint pin CI did not follow" "but GOLANGCI_VERSION is v0.0.0" -- check-ci-pins

# And it must not go quiet if the steps it compares against are restructured
# away — a gate with nothing left to check is not a gate that passed.
reset
grep -v 'golangci/golangci-lint-action' "$tmp/.github/workflows/ci.yml" >"$tmp/ci.new"
mv "$tmp/ci.new" "$tmp/.github/workflows/ci.yml"
expect_fail "no golangci-lint step left to compare against" "no golangci-lint-action version found" -- check-ci-pins

# --- build-agent-all: a loop over nothing is not a successful build ----------

reset
expect_fail "an empty AGENT_PLATFORMS" "AGENT_PLATFORMS is empty" -- build-agent-all AGENT_PLATFORMS=

if [ "$failures" -ne 0 ]; then
	echo "tools-selftest: $failures gate(s) did not behave as required" >&2
	exit 1
fi
echo "  every tooling gate rejected what it exists to reject"
