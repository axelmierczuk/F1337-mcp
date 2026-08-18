//go:build unix

package shell

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	gopty "github.com/aymanbagabas/go-pty"
	"github.com/stretchr/testify/require"

	"github.com/axelmierczuk/fleet-mcp/internal/platform"
)

// TestSession_TheAgentGivesUpItsCopyOfTheSessionTerminal asserts the call, not
// the function.
//
// internal/platform has a test for what ReleasePTYChildEnd does, and it was
// added because deleting the body of that function left every test in the tree
// green. Deleting the *call* to it in [Service.run] still does: the function is
// covered and the line that reaches it is not, which is the same defect one
// level up and the shape this repository has shipped more often than any other.
//
// A Unix pty is a pair and go-pty holds both ends. Until the agent gives up its
// copy of the child's end the kernel still has a writer for the master, so a
// read there cannot end when the session's last process does — which is what a
// session's output pump is sitting in. Without this the pump only ends when the
// handler tears the terminal down, and every session on every Unix behaves the
// way a ConPTY has to.
//
// The synchronisation is free rather than timed: the release happens between
// starting the command and sending the ShellOpened, so a client that has its
// ShellOpened is a client whose session has already been through it.
//
// Unix only, because there is nothing to assert anywhere else: a ConPTY hands
// the child a pseudo-console rather than a second descriptor, and
// platform.ReleasePTYChildEnd is a documented no-op there.
func TestSession_TheAgentGivesUpItsCopyOfTheSessionTerminal(t *testing.T) {
	requirePTY(t)

	var captured capturedPTY
	svc := newService(t, options{openPTY: captured.open})
	client := serve(t, svc)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	_, err := openSession(ctx, t, client, openOptions("sleep"))
	require.NoError(t, err)

	unixPTY, ok := captured.get().(gopty.UnixPty)
	require.True(t, ok, "a pty on this platform is a Unix pair")

	_, err = unixPTY.Slave().Write([]byte("x"))
	require.ErrorIs(t, err, os.ErrClosed,
		"the agent is still holding the child's end of the session's terminal, so the kernel still has a writer for "+
			"the master: the session's output pump cannot end when its last process does, and the write above just "+
			"injected a byte into a running session's output")
}

// capturedPTY hands out real terminals and keeps the last one, so a test can
// ask what the agent did with its own end of it.
type capturedPTY struct {
	mu  sync.Mutex
	pty platform.PTY
}

func (c *capturedPTY) open() (platform.PTY, error) {
	p, err := platform.OpenPTY()
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pty = p
	return p, nil
}

func (c *capturedPTY) get() platform.PTY {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.pty
}

// stallingPTY has to be a UnixPty and not only a Pty.
//
// platform.ReleasePTYChildEnd asks a terminal for the child's end so the agent
// can give up its own copy, and it asks by type assertion. A wrapper that could
// not answer would leave the session holding that descriptor — a difference
// between the staged session and a real one, in exactly the machinery the test
// wrapping it is about. On Windows there is no second end to give up and no
// such interface, which is why these live here.
func (p *stallingPTY) Master() *os.File                   { return p.unix().Master() }
func (p *stallingPTY) Slave() *os.File                    { return p.unix().Slave() }
func (p *stallingPTY) Control(f func(fd uintptr)) error   { return p.unix().Control(f) }
func (p *stallingPTY) SetWinsize(ws *gopty.Winsize) error { return p.unix().SetWinsize(ws) }

// unix is the wrapped terminal, which platform.OpenPTY guarantees is one of
// these on every platform this file builds for.
func (p *stallingPTY) unix() gopty.UnixPty { return p.PTY.(gopty.UnixPty) }
