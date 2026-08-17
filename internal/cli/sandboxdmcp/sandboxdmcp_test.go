package sandboxdmcp_test

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axelmierczuk/fleet-mcp/internal/cli/sandboxdmcp"
)

func TestRoot_HelpNamesServeAndItsFlags(t *testing.T) {
	var out bytes.Buffer
	require.Zero(t, sandboxdmcp.Main([]string{"--help"}, &out))
	assert.Contains(t, out.String(), "serve")

	out.Reset()
	require.Zero(t, sandboxdmcp.Main([]string{"serve", "--help"}, &out))
	help := out.String()
	for _, flag := range []string{"--config-dir", "--registry", "--ca-cert", "--cert", "--key", "--log-level"} {
		assert.Containsf(t, help, flag, "serve should document %s", flag)
	}
	assert.Contains(t, help, "SANDBOXD_CONFIG_DIR")
	assert.Contains(t, help, "stderr", "the help must say where logs go")
}

// TestServe_RejectsAnUnknownLogLevel before anything opens a registry or a
// transport, so a typo does not produce a server that silently logs nothing.
func TestServe_RejectsAnUnknownLogLevel(t *testing.T) {
	var out bytes.Buffer
	code := sandboxdmcp.Main([]string{"serve", "--log-level", "verbose", "--config-dir", t.TempDir()}, &out)
	assert.Equal(t, 1, code)
	assert.NotContains(t, out.String(), "jsonrpc", "a startup failure must not emit protocol output")
}

// TestUnknownCommand_FailsWithoutTouchingStdout guards the invariant that
// stdout belongs to JSON-RPC: cobra's own errors go to stderr.
func TestUnknownCommand_FailsWithoutTouchingStdout(t *testing.T) {
	var out bytes.Buffer
	assert.Equal(t, 1, sandboxdmcp.Main([]string{"nonsense"}, &out))
	assert.NotContains(t, strings.ToLower(out.String()), "unknown command")
}

// TestServe_ResolvesTheConfigDirectory covers both ways of pointing the
// server at its state, end to end through the real serve path: the flag, and
// SANDBOXD_CONFIG_DIR when the flag is absent. Getting this wrong means a
// server that quietly keeps its registry somewhere the operator is not
// looking.
func TestServe_ResolvesTheConfigDirectory(t *testing.T) {
	for _, tc := range []struct {
		name    string
		useFlag bool
	}{
		{name: "flag", useFlag: true},
		{name: "environment", useFlag: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// A directory that does not exist yet, so its creation is the
			// evidence that this is the one the server chose.
			dir := filepath.Join(t.TempDir(), "sandboxd")

			args := []string{"serve"}
			if tc.useFlag {
				args = append(args, "--config-dir", dir)
				t.Setenv("SANDBOXD_CONFIG_DIR", filepath.Join(t.TempDir(), "ignored"))
			} else {
				t.Setenv("SANDBOXD_CONFIG_DIR", dir)
			}

			var out bytes.Buffer
			assert.Zero(t, runServeWithClosedStdin(t, args, &out))
			assert.DirExists(t, dir)
			assert.Empty(t, out.String(), "serve must write nothing to the command's output stream")
		})
	}
}

// runServeWithClosedStdin runs serve against an already-closed stdin, which
// is what a client that has gone away looks like, and returns the exit code.
func runServeWithClosedStdin(t *testing.T, args []string, out *bytes.Buffer) int {
	t.Helper()

	stdinR, stdinW, err := os.Pipe()
	require.NoError(t, err)
	require.NoError(t, stdinW.Close())

	stdoutR, stdoutW, err := os.Pipe()
	require.NoError(t, err)
	go func() { _, _ = io.Copy(io.Discard, stdoutR) }()

	origIn, origOut := os.Stdin, os.Stdout
	os.Stdin, os.Stdout = stdinR, stdoutW
	defer func() {
		os.Stdin, os.Stdout = origIn, origOut
		_ = stdinR.Close()
		_ = stdoutW.Close()
		_ = stdoutR.Close()
	}()

	done := make(chan int, 1)
	go func() { done <- sandboxdmcp.Main(args, out) }()

	select {
	case code := <-done:
		return code
	case <-time.After(20 * time.Second):
		t.Fatal("serve did not exit after stdin closed")
		return 1
	}
}
