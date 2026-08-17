//go:build unix

package fleetagent_test

import (
	"context"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Graceful shutdown driven by a real SIGTERM, which is what systemd and launchd
// actually send.
//
// This lives in a unix-tagged file rather than behind a runtime
// runtime.GOOS == "windows" skip because syscall.Kill does not exist on
// Windows: a skip inside the test still leaves the reference in the file, and
// `go vet ./...` on a Windows runner fails to typecheck the package before any
// test gets the chance to skip itself. Windows has no SIGTERM to cover — the
// SCM stops the process through kardianos, exercised by the same drain path in
// serve_test.go's context-cancellation case.
//
// Sending a signal to the test process is safe only while serve's handler is
// installed, so the test waits for the daemon to be serving first and for it to
// exit afterwards.
func TestServe_ShutsDownOnSIGTERM(t *testing.T) {
	ea := newEnrolledAgent(t, t.TempDir())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	codes, out := runServe(ctx, t, "serve", "--config", ea.configPath)

	waitServing(t, ea)

	require.NoError(t, syscall.Kill(syscall.Getpid(), syscall.SIGTERM))

	select {
	case code := <-codes:
		assert.Equal(t, 0, code, out.String())
	case <-time.After(20 * time.Second):
		t.Fatal("serve did not exit on SIGTERM")
	}
}
