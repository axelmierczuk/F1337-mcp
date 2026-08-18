#!/usr/bin/env bash
#
# Prove the tooling gates fail on the inputs they exist for.
#
# The .tools/ cache is only as good as the three checks standing in front of
# it, and a check that has quietly stopped firing looks exactly like a check
# that has nothing to report. Both of those are green. So rather than trust
# that tools-key-check, tools-bins-check and tools-verify still reject what
# they were written to reject, hand each one the input it exists for and
# require it to fail.
#
# Every case here is one that has actually been observed to pass against some
# version of these targets. Reverting any single guard turns exactly one of
# these red.
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

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

failures=0

# reset copies the real Makefile back over the fixture, then applies an awk
# program to it. Called with no program it just restores the pristine copy.
reset() {
	cp "$makefile" "$tmp/Makefile"
	if [ $# -gt 0 ]; then
		awk "$1" "$tmp/Makefile" >"$tmp/Makefile.new"
		mv "$tmp/Makefile.new" "$tmp/Makefile"
	fi
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

reset '{ print } /^GO_TOOLCHAIN/ { print "YQ_VERSION             := v4.44.3" }'
expect_fail "a fifth pin absent from TOOL_PINS" "missing from TOOL_PINS" -- tools-key-check

reset '{ print } /^GO_TOOLCHAIN/ { print "export YQ_VERSION := v4.44.3" }'
expect_fail "an export-prefixed pin absent from TOOL_PINS" "missing from TOOL_PINS" -- tools-key-check

reset '/^(BUF_VERSION|PROTOC_GEN_GO_VERSION|PROTOC_GEN_GRPC_VERSION|GOLANGCI_VERSION|GO_TOOLCHAIN)/ { print "#" $0; next } { print }'
expect_fail "no pins at all, so the key would be a constant" "no pinned versions found" -- tools-key-check

# --- tools-bins-check: tools-verify must cover every installed binary --------

reset '{ print } /go install github.com\/golangci/ { print "\tGOBIN=$(TOOLS_DIR) GOTOOLCHAIN=$(GO_TOOLCHAIN) go install github.com/mikefarah/yq/v4@$(GO_TOOLCHAIN)" }'
expect_fail "a fifth installed binary absent from TOOL_BINS" "TOOL_BINS does not name it" -- tools-bins-check

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

# --- build-agent-all: a loop over nothing is not a successful build ----------

reset
expect_fail "an empty AGENT_PLATFORMS" "AGENT_PLATFORMS is empty" -- build-agent-all AGENT_PLATFORMS=

if [ "$failures" -ne 0 ]; then
	echo "tools-selftest: $failures gate(s) did not behave as required" >&2
	exit 1
fi
echo "  every tooling gate rejected what it exists to reject"
