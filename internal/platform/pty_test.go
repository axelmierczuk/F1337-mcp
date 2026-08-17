package platform_test

import (
	"bytes"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/axelmierczuk/fleet-mcp/internal/platform"
)

func echoArgv() []string {
	if runtime.GOOS == "windows" {
		return []string{"cmd.exe", "/c", "echo sandboxd-pty"}
	}
	return []string{"/bin/sh", "-c", "echo sandboxd-pty"}
}

func TestOpenPTY(t *testing.T) {
	t.Parallel()

	if !platform.PTYSupported() {
		t.Skip("no pseudo-terminal available on this host")
	}

	tty, err := platform.OpenPTY()
	require.NoError(t, err)
	defer tty.Close()

	require.NotEmpty(t, tty.Name())
	require.NoError(t, tty.Resize(120, 40))
}

// TestPTY_RunsACommand checks the allocation is usable end to end, since a PTY
// that opens but cannot carry a process is no use to ExecService.
func TestPTY_RunsACommand(t *testing.T) {
	if !platform.PTYSupported() {
		t.Skip("no pseudo-terminal available on this host")
	}

	tty, err := platform.OpenPTY()
	require.NoError(t, err)
	defer tty.Close()

	argv := echoArgv()
	cmd := tty.Command(argv[0], argv[1:]...)
	require.NoError(t, cmd.Start())
	t.Cleanup(func() { _ = cmd.Wait() })

	// A PTY merges the two output streams and adds terminal control bytes, so
	// the assertion is containment rather than equality — which is also why a
	// PTY is opt-in rather than the default.
	found := make(chan bool, 1)
	go func() {
		var buf bytes.Buffer
		chunk := make([]byte, 512)
		for {
			n, err := tty.Read(chunk)
			if n > 0 {
				buf.Write(chunk[:n])
				if bytes.Contains(buf.Bytes(), []byte("sandboxd-pty")) {
					found <- true
					return
				}
			}
			if err != nil {
				found <- bytes.Contains(buf.Bytes(), []byte("sandboxd-pty"))
				return
			}
		}
	}()

	select {
	case ok := <-found:
		require.True(t, ok, "the command's output never reached the pty")
	case <-time.After(30 * time.Second):
		t.Fatal("timed out waiting for output from the pty")
	}
}

// TestPTY_WithProcessGroup covers the combination ExecService needs: a
// terminal-attached command that is still killable as a tree.
func TestPTY_WithProcessGroup(t *testing.T) {
	if !platform.PTYSupported() {
		t.Skip("no pseudo-terminal available on this host")
	}

	tty, err := platform.OpenPTY()
	require.NoError(t, err)
	defer tty.Close()

	group, err := platform.NewProcessGroup(platform.GroupConfig{})
	require.NoError(t, err)
	defer group.Close()

	argv := echoArgv()
	cmd := tty.Command(argv[0], argv[1:]...)
	group.ConfigurePTYCommand(cmd)
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = group.Kill()
		_ = cmd.Wait()
	})

	require.NoError(t, group.Adopt(cmd.Process))
	require.True(t, group.Isolated(),
		"a pty-attached child must still lead its own group, or a timeout cannot kill its children")
	require.Equal(t, cmd.Process.Pid, group.PID())
}
