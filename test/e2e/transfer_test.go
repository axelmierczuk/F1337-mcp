//go:build integration

package e2e

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// largeFileBytes is the size of the file the transfer scenario moves.
//
// Big enough to be several thousand chunks and to sit well past the 4 MiB
// default gRPC message size the client deliberately overrides — a transfer
// that fit in one message would exercise none of the streaming. Small enough
// that the scenario costs a second, because a suite nobody runs finds nothing.
const largeFileBytes = 24 << 20

// TestLargeFileTransferRoundTrips pushes a file to a sandbox and pulls it back,
// and compares digests at both ends.
//
// The digest is the assertion. A transfer that dropped a chunk, doubled one, or
// wrote the chunks out of order would produce a file of exactly the right size
// with the wrong contents, and every count in the result would still agree.
func TestLargeFileTransferRoundTrips(t *testing.T) {
	f := newFleet(t)
	a := f.enroll("build-box", enrollOptions{})
	s := f.connect(t)
	s.ok("fleet_select", map[string]any{"name": a.name})

	source := filepath.Join(s.cwd, "payload.bin")
	want := writeRandomFile(t, source, largeFileBytes)

	remote := filepath.Join(a.home, "received", "payload.bin")
	push := structured[transferResult](t, s.okAs("fleet_transfer", map[string]any{
		"direction":   "push",
		"source":      source,
		"destination": remote,
	}, callOptions{timeout: 5 * time.Minute}))

	if push.Files != 1 {
		t.Fatalf("push moved %d files, want 1: %+v", push.Files, push)
	}
	if push.Bytes != largeFileBytes {
		t.Fatalf("push reports %d bytes, sent %d", push.Bytes, largeFileBytes)
	}
	if push.Sandbox != a.name {
		t.Fatalf("push echoed sandbox %q, want %q", push.Sandbox, a.name)
	}
	if got := digestOf(t, remote); got != want {
		t.Fatalf("the file that landed on the sandbox has digest %s, want %s", got, want)
	}

	// Back the other way, into a directory this workstation owns. A pull is
	// confined to the MCP server's working directory unless it is told
	// otherwise, and s.cwd is that directory.
	pulled := filepath.Join(s.cwd, "pulled", "payload.bin")
	pull := structured[transferResult](t, s.okAs("fleet_transfer", map[string]any{
		"direction":   "pull",
		"source":      remote,
		"destination": pulled,
	}, callOptions{timeout: 5 * time.Minute}))

	if pull.Files != 1 || pull.Bytes != largeFileBytes {
		t.Fatalf("pull moved %d files / %d bytes, want 1 / %d: %+v", pull.Files, pull.Bytes, largeFileBytes, pull)
	}
	if got := digestOf(t, pulled); got != want {
		t.Fatalf("the round-tripped file has digest %s, want %s", got, want)
	}

	// A second push of the same file moves nothing: the unchanged check is
	// what makes a repeated transfer of a tree usable, and a check that
	// silently re-sent everything would look identical in every field but
	// `unchanged`.
	again := structured[transferResult](t, s.okAs("fleet_transfer", map[string]any{
		"direction":   "push",
		"source":      source,
		"destination": remote,
	}, callOptions{timeout: 5 * time.Minute}))
	if again.Unchanged != 1 || again.Files != 0 {
		t.Fatalf("re-pushing an unchanged file moved %d files (%d unchanged): %+v", again.Files, again.Unchanged, again)
	}
	if got := digestOf(t, remote); got != want {
		t.Fatalf("a skipped transfer changed the destination: digest %s, want %s", got, want)
	}
}

// TestTransferTreeRoundTrips moves a directory rather than a file, which is
// where the walk, the exclusions and the relative paths come in.
func TestTransferTreeRoundTrips(t *testing.T) {
	f := newFleet(t)
	a := f.enroll("build-box", enrollOptions{})
	s := f.connect(t)
	s.ok("fleet_select", map[string]any{"name": a.name})

	tree := filepath.Join(s.cwd, "project")
	files := map[string]string{
		"main.go":              "package main\n",
		"internal/util/u.go":   "package util\n",
		"docs/readme.md":       "# docs\n",
		".git/objects/deadbee": "should not travel",
		"node_modules/x/i.js":  "should not travel",
	}
	digests := map[string]string{}
	for rel, content := range files {
		path := filepath.Join(tree, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatalf("create %s: %v", filepath.Dir(path), err)
		}
		writeFile(t, path, []byte(content))
		digests[rel] = digestOfBytes([]byte(content))
	}

	remote := filepath.Join(a.home, "project")
	push := structured[transferResult](t, s.okAs("fleet_transfer", map[string]any{
		"direction":   "push",
		"source":      tree,
		"destination": remote,
		"recursive":   true,
	}, callOptions{timeout: 5 * time.Minute}))

	if push.Files != 3 {
		t.Fatalf("push moved %d files, want the three that are not excluded by default: %+v", push.Files, push)
	}
	for _, rel := range []string{"main.go", "internal/util/u.go", "docs/readme.md"} {
		path := filepath.Join(remote, filepath.FromSlash(rel))
		if got := digestOf(t, path); got != digests[rel] {
			t.Fatalf("%s arrived with digest %s, want %s", rel, got, digests[rel])
		}
	}
	for _, rel := range []string{".git/objects/deadbee", "node_modules/x/i.js"} {
		if _, err := os.Stat(filepath.Join(remote, filepath.FromSlash(rel))); err == nil {
			t.Fatalf("%s was transferred despite the default exclusions", rel)
		}
	}
	if push.Excluded == 0 {
		t.Fatalf("the result does not report the excluded entries: %+v", push)
	}
}

// writeRandomFile writes n pseudo-random bytes and returns their digest.
//
// Pseudo-random rather than a repeated pattern: a chunk written twice, or two
// chunks swapped, produces the same bytes as the correct file under a
// repeating pattern and a different digest under this one.
func writeRandomFile(t *testing.T, path string, n int) string {
	t.Helper()

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("create %s: %v", filepath.Dir(path), err)
	}
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	defer func() { _ = file.Close() }()

	digest := sha256.New()
	source := rand.New(rand.NewSource(1)) //nolint:gosec // test data, not a key
	if _, err := io.CopyN(io.MultiWriter(file, digest), source, int64(n)); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close %s: %v", path, err)
	}
	return hex.EncodeToString(digest.Sum(nil))
}

func digestOf(t *testing.T, path string) string {
	t.Helper()

	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer func() { _ = file.Close() }()

	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return hex.EncodeToString(digest.Sum(nil))
}

func digestOfBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
