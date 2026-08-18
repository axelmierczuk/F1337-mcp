package shell

import (
	"log/slog"
	"os"
	"testing"

	"github.com/aymanbagabas/go-pty"
	"github.com/stretchr/testify/require"

	"github.com/axelmierczuk/fleet-mcp/internal/platform"
)

// sessionCommand starts the shape [Service.run] starts: a command on a
// pseudo-terminal, leading a group of its own, with the agent's own copy of the
// child's end already given up.
//
// Everything run does to a command before it waits on it, and nothing else.
// There is no stream, no audit record and no service here, because what these
// tests are about is the wait — and a session driven through the RPC cannot say
// when the sweep went out relative to the collection, only what was left
// afterwards.
//
// The returned buffer is what the session's terminal printed. Something has to
// read it whether or not a test looks: a helper writing to a terminal nobody
// drains blocks in its own write, and a test about what the wait did would then
// be waiting for a program that never got to exit.
func sessionCommand(t *testing.T, mode string, args ...string) (*platform.ProcessGroup, *pty.Cmd, *syncBuffer) {
	t.Helper()
	requirePTY(t)

	raw, err := platform.OpenPTY()
	require.NoError(t, err)
	t.Cleanup(func() { _ = raw.Close() })

	group, err := platform.NewProcessGroup(platform.GroupConfig{KillOnClose: true})
	require.NoError(t, err)
	t.Cleanup(func() { _ = group.Close() })

	self, err := os.Executable()
	require.NoError(t, err)
	cmd := raw.Command(self, args...)
	cmd.Env = append(os.Environ(), helperEnvFor(mode))
	group.ConfigureInteractivePTYCommand(cmd)
	require.NoError(t, cmd.Start())
	require.NoError(t, group.Adopt(cmd.Process))
	require.True(t, group.Isolated(),
		"the command does not lead its own group, so there is nothing here for a sweep to be right or wrong about")
	// After Start, never before. See platform.ReleasePTYChildEnd.
	require.NoError(t, platform.ReleasePTYChildEnd(raw))

	printed := &syncBuffer{}
	go func() {
		buf := make([]byte, readBuffer)
		for {
			n, err := raw.Read(buf)
			if n > 0 {
				_, _ = printed.Write(buf[:n])
			}
			if err != nil {
				return
			}
		}
	}()

	t.Cleanup(func() {
		_ = group.Kill()
		_ = cmd.Wait()
	})
	return group, cmd, printed
}

// testLogger writes the daemon's log into a buffer a test can read.
//
// syncBuffer rather than a strings.Builder: the wait runs on its own goroutine
// and writes to the same logger the test reads.
func testLogger(into *syncBuffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(into, &slog.HandlerOptions{Level: slog.LevelDebug}))
}
