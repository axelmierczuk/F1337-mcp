package fleetctl

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/spf13/cobra"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/fleet-mcp/internal/client"
)

// `fleetctl shell` — an interactive terminal on a fleet machine.
//
// The point of this command is to remove the last reason to keep SSH
// configured alongside the fleet: an operator who can reach an agent through
// the fleet CA can get a real shell on it, over the same mTLS transport
// everything else uses, with the session recorded on the host.
//
// It is deliberately not an MCP tool, and there is no fleet_shell. A model does
// not need an interactive terminal — fleet_exec and fleet_process_start cover
// what it does — and streaming raw terminal bytes into a context window is a
// bad trade in every direction.

// sessionFailed is the exit code for a session that did not end with the remote
// command exiting.
//
// 255, following ssh: a status in that position means "the session itself
// failed" rather than "the command exited 255", which is a distinction a script
// wrapping this command has to be able to make. A dropped connection, a session
// reaped for idleness, and a shell killed by a signal all land here, each with
// a line on stderr saying which.
const sessionFailed = 255

// exitStatus carries a child's exit code out to this process's own.
//
// It is an error because that is the only thing a cobra RunE can return, and it
// is handled in [MainContext] rather than printed: `exit 3` in a remote shell
// means the CLI exits 3, not that it prints an error about it.
//
// what names whose status it is, because there are two: a remote shell, and on
// Windows the helper `fleetctl tui` hands the console to. Empty means the
// shell, which is every use of it outside handoff_windows.go.
type exitStatus struct {
	what string
	code int
}

func (e *exitStatus) Error() string {
	what := e.what
	if what == "" {
		what = "the remote shell"
	}
	return fmt.Sprintf("%s exited with status %d", what, e.code)
}

// newShellCommand takes no writer, unlike every other command in this package.
//
// A session's output goes to the operator's actual terminal, through the
// descriptor the client put into raw mode — not through the command tree's
// writer, which is a buffer in a test and would be the wrong file even when it
// is not. Anything this command has to say for itself goes to stderr, after the
// terminal has been restored. See shellSession.notes.
func newShellCommand(io.Writer) *cobra.Command {
	var (
		control      controlFlags
		registryPath string
		workingDir   string
		env          []string
	)
	cmd := &cobra.Command{
		Use:   "shell [sandbox] [-- command ...]",
		Short: "Open an interactive shell on a sandbox",
		Long: "shell opens an interactive terminal on a sandbox over the same mTLS gRPC\n" +
			"transport every other command uses, and returns the remote shell's exit code\n" +
			"as its own.\n\n" +
			"With no sandbox named it uses the one `fleetctl select` chose. With no command\n" +
			"after `--` it runs the host's login shell.\n\n" +
			"This is the most direct remote-code-execution surface in the product. It grants\n" +
			"nothing that `fleet_exec` does not already grant — anyone who can run a command\n" +
			"on a host has that host — but it is the most convenient path to it, and every\n" +
			"session is recorded in the agent's audit log: who opened it, on which sandbox,\n" +
			"when, and how it ended. Never what was typed or printed. See docs/security.md.",
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Everything before `--` names the sandbox; everything after is the
			// command to run. cobra records where the dash was, which is the
			// only way to tell `shell build-box` from `shell -- build-box`.
			sandboxArgs, command := splitAtDash(cmd, args)
			if len(sandboxArgs) > 1 {
				return fmt.Errorf("expected at most one sandbox name, got %d: %s; a command to run goes after `--`",
					len(sandboxArgs), strings.Join(sandboxArgs, " "))
			}
			explicit := ""
			if len(sandboxArgs) == 1 {
				explicit = sandboxArgs[0]
			}

			term, err := openTerminal()
			if err != nil {
				return err
			}

			target, err := resolveTarget(registryPath, explicit)
			if err != nil {
				return err
			}

			// A session reaches its sandbox through pool.Shell and never asks
			// what the health cache thinks, so a background probe loop would
			// be traffic nobody reads — for a command that stays open for as
			// long as the operator holds the terminal, for hours of it. See
			// oneShotHealthInterval; `fleetctl tui` is the one command on the
			// other side of that.
			pool, err := control.pool(oneShotHealthInterval)
			if err != nil {
				return err
			}
			defer func() { _ = pool.Close() }()

			shells, err := pool.Shell(target.Name(), target.Address())
			if err != nil {
				return err
			}

			// No per-call deadline. --timeout bounds a health probe, and a
			// session lasts as long as the operator wants it to; the agent's
			// own shell.idle_timeout is what stops an abandoned one lasting
			// forever, and it is the right place for that decision because it
			// is the machine holding the terminal.
			ctx, cancel := context.WithCancel(cmd.Context())
			defer cancel()

			stream, err := shells.Shell(ctx)
			if err != nil {
				return fmt.Errorf("opening a shell on %s: %w", target.Name(), client.MapError(err))
			}

			// No size here: run fills it in from the terminal it is about to
			// take over, which is both later and the only place a test can
			// reach. See shellSession.run.
			session := &shellSession{term: term, stream: stream, notes: cmd.ErrOrStderr()}
			code, err := session.run(ctx, cancel, &sandboxdv1.ShellOpen{
				Argv:       command,
				WorkingDir: workingDir,
				Env:        sessionEnv(env),
			})
			if err != nil {
				return fmt.Errorf("shell on %s: %w", target.Name(), client.MapError(err))
			}
			if code != 0 {
				// Silenced rather than printed: the remote shell's status is
				// this command's status, and cobra rendering "Error: the remote
				// shell exited with status 1" for an ordinary failed command
				// would be noise in front of output the operator has already
				// seen. Set here rather than on the command, so a genuine error
				// from any other path above still prints.
				cmd.SilenceErrors = true
				return &exitStatus{code: code}
			}
			return nil
		},
	}
	control.register(cmd)
	// The shared --timeout is a per-sandbox probe deadline everywhere else, and
	// here it bounds only reaching the agent. Left with its usual description it
	// would read as the length of the session, which is the one thing it is
	// not: a session lasts as long as the operator holds it open, and the
	// agent's own shell.idle_timeout is what bounds an abandoned one.
	cmd.Flags().Lookup("timeout").Usage = "how long to wait for the sandbox to answer; it does not bound the session"
	cmd.Flags().StringVar(&registryPath, "registry", "", "path to the fleet registry (default: <config dir>/registry.yaml)")
	cmd.Flags().StringVar(&workingDir, "dir", "", "directory to start in (default: the agent account's home directory)")
	cmd.Flags().StringArrayVar(&env, "env", nil, "environment variable to set, as KEY=VALUE; repeatable")
	return cmd
}

// splitAtDash divides the positional arguments at `--`.
func splitAtDash(cmd *cobra.Command, args []string) (before, after []string) {
	at := cmd.ArgsLenAtDash()
	if at < 0 {
		return args, nil
	}
	return args[:at], args[at:]
}

// terminalTypeVars are the environment variables a session carries from the
// operator's own terminal.
//
// TERM decides which escape sequences a full-screen program emits, so a session
// without it renders as well as `TERM=dumb` allows — which is to say `vi` draws
// nothing. The locale variables decide whether the remote program believes it
// can print UTF-8, and a mismatch turns every box-drawing character into a
// question mark. Nothing else is forwarded: the operator's own environment is
// full of credentials, and this is a command that runs on somebody else's
// machine.
var terminalTypeVars = []string{"TERM", "LANG", "LC_ALL", "LC_CTYPE"}

// sessionEnv is what the session starts with: the terminal-describing
// variables from this terminal, then whatever --env asked for on top.
func sessionEnv(overrides []string) []string {
	env := make([]string, 0, len(terminalTypeVars)+len(overrides))
	for _, name := range terminalTypeVars {
		if value := os.Getenv(name); value != "" {
			env = append(env, name+"="+value)
		}
	}
	return append(env, overrides...)
}

// shellStream is the half of the gRPC bidirectional stream this command uses.
// It is an interface so the session can be driven by a test without a server.
type shellStream interface {
	Send(*sandboxdv1.ShellRequest) error
	Recv() (*sandboxdv1.ShellResponse, error)
	CloseSend() error
}

// shellSession drives one session: the operator's terminal at one end, the
// stream at the other.
type shellSession struct {
	term   terminal
	stream shellStream
	// notes is where anything that is not session output goes — the reason a
	// session ended, a warning about a resize that could not be sent. Never
	// stdout: stdout is the remote terminal's, and a line of ours in the middle
	// of it would be indistinguishable from something the host printed.
	notes io.Writer

	// restore puts the terminal back, exactly once, from whichever of the four
	// exit paths reaches it first. See run.
	restore *restoreGuard

	// sendMu serialises everything this session puts on the stream, and
	// sendClosed remembers the half-close so nothing follows it.
	//
	// gRPC is explicit that one goroutine may send while another receives, and
	// that two may not send: "it is not safe to call SendMsg on the same
	// stream in different goroutines. It is also not safe to call CloseSend
	// concurrently with SendMsg." This session has two senders — the input
	// pump on every keystroke and the resize watcher on every SIGWINCH — plus
	// the half-close the input pump issues when stdin ends. A resize while the
	// operator is typing is not an edge case; it is what dragging a window
	// corner during a build does, and the CloseSend half of it is a plain data
	// race on the stream's own end-of-send flag.
	//
	// A plain mutex, unlike the agent's deadline-carrying equivalent: nothing
	// here is on a path that has to make progress. A send parked because the
	// far end stopped reading is unparked when the stream tears down, and the
	// only thing waiting behind it is a resize nobody is holding their breath
	// for. The agent's sender needs a deadline because the handler's own exit
	// message queues behind the output pump.
	sendMu     sync.Mutex
	sendClosed bool
}

// send puts one message on the stream. See shellSession.sendMu.
func (s *shellSession) send(req *sandboxdv1.ShellRequest) error {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	if s.sendClosed {
		// The write half is already shut. gRPC answers this with an internal
		// error about SendMsg after CloseSend, which describes the client
		// rather than the session; there is simply nothing left to send on.
		return errSendClosed
	}
	return s.stream.Send(req)
}

// closeSend tells the far end that no more input is coming.
func (s *shellSession) closeSend() error {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	if s.sendClosed {
		return nil
	}
	s.sendClosed = true
	return s.stream.CloseSend()
}

// errSendClosed is what a resize gets when it arrives after stdin has ended.
var errSendClosed = errors.New("the session's write half is closed")

// run carries the session and returns the exit code the CLI should use.
//
// # The four ways this ends, and the terminal at each of them
//
// The local terminal is in raw mode for the whole session, and a CLI that
// leaves it there has left the operator with a shell that does not echo and
// does not respond to Ctrl-C — worse than one that never ran. Every path out
// therefore goes through the same guard, which restores once:
//
//  1. Normal exit. The deferred restore, on the way out of this function.
//  2. A signal — SIGINT, SIGTERM, SIGHUP. The handler restores immediately,
//     before anything else unwinds, then cancels the session. Note that this is
//     *not* the operator pressing Ctrl-C: in raw mode that is byte 0x03 on the
//     wire and never a signal here. It is `kill`, a terminal hanging up, or a
//     service manager stopping the process.
//  3. A dropped connection. Recv fails, this function returns, and the deferred
//     restore runs.
//  4. A panic. The deferred restore runs while the stack unwinds — and for a
//     panic on one of the pump goroutines, where nothing unwinds through here,
//     each pump restores before it re-panics. See guardPanic.
func (s *shellSession) run(ctx context.Context, cancel context.CancelFunc, open *sandboxdv1.ShellOpen) (int, error) {
	undo, err := s.term.makeRaw()
	if err != nil {
		return 0, err
	}
	s.restore = &restoreGuard{undo: undo, notes: s.notes}
	defer s.restore.restore()

	stopSignals := s.watchSignals(cancel)
	defer stopSignals()

	// The window the session opens at, read here rather than by the caller.
	//
	// The agent applies it before the command starts, so it is what the shell's
	// first prompt is drawn at and what a program that reads its size once and
	// never listens for a change is stuck with. Reading it here is the last
	// moment before the open goes out — a window resized while a TLS handshake
	// was in flight is still caught — and it is the only place the terminal's
	// own size and the message carrying it meet somewhere a test can drive. At
	// the call site it was one line whose deletion nothing noticed: the resize
	// watcher's first report supplies a size a moment later, so every scenario
	// still saw the right one, one redraw late.
	open.Size = s.term.size()

	if err := s.send(&sandboxdv1.ShellRequest{
		Event: &sandboxdv1.ShellRequest_Open{Open: open},
	}); err != nil {
		if !errors.Is(err, io.EOF) {
			return 0, err
		}
		// io.EOF from Send is not what went wrong. gRPC returns it whenever
		// the *agent* has already ended the stream, and is explicit that the
		// status it ended with is available only from Recv — so returning this
		// error throws that status away.
		//
		// Two of ShellService's refusals are answered before its first Recv,
		// shell.enabled and exec.enabled, which means they race this Send: the
		// operator who lost that race was told "shell on box: EOF" for an
		// agent that had said which setting turns the service off. Which one
		// they got depended on whichever crossed the wire first, so the same
		// command answered differently on a loaded machine.
		if _, recvErr := s.stream.Recv(); recvErr != nil && !errors.Is(recvErr, io.EOF) {
			return 0, recvErr
		}
		return 0, err
	}

	go s.pumpInput()
	go s.pumpResizes(ctx)

	return s.render(ctx)
}

// render reads the session and writes it to the terminal, until it ends.
func (s *shellSession) render(ctx context.Context) (int, error) {
	for {
		resp, err := s.stream.Recv()
		if err != nil {
			if ctx.Err() != nil {
				// This process is stopping — a signal, or the caller cancelling
				// — and the stream failing is a consequence of that rather than
				// something to report as a connection failure.
				s.restore.restore()
				s.note("session ended")
				return sessionFailed, nil //nolint:nilerr // the stream failing is this shutdown's own doing, not something to report to the operator as a connection failure
			}
			if errors.Is(err, io.EOF) {
				// The stream closed without an exit message. The session
				// happened and its status did not survive; saying so is
				// better than reporting a status nobody sent.
				s.restore.restore()
				s.note("the session ended without reporting its exit status")
				return sessionFailed, nil //nolint:nilerr // a clean stream close is not an RPC failure; the missing status is reported as the exit code and the note above
			}
			return 0, err
		}

		switch event := resp.GetEvent().(type) {
		case *sandboxdv1.ShellResponse_Data:
			if _, err := s.term.Write(event.Data); err != nil {
				return 0, fmt.Errorf("writing session output to the terminal: %w", err)
			}
		case *sandboxdv1.ShellResponse_Exit:
			// The terminal goes back to cooked mode before anything is printed
			// about the session, so the note lands on a terminal that behaves
			// like one.
			s.restore.restore()
			return s.exitCode(event.Exit), nil
		case *sandboxdv1.ShellResponse_Opened:
			// Nothing to render. The operator asked for a shell and is about to
			// see its prompt; announcing the pty name and pid on top of it
			// would be the CLI talking over the session.
		}
	}
}

// exitCode turns a session's ending into the code this process exits with.
func (s *shellSession) exitCode(exit *sandboxdv1.ShellExit) int {
	switch {
	case exit.GetIdleTimeout():
		s.note("the session was closed by the agent after being idle for its configured limit")
		return sessionFailed
	case exit.GetSignaled():
		s.note("the remote shell was terminated by " + exit.GetSignal())
		return sessionFailed
	default:
		return int(exit.GetExitCode())
	}
}

// pumpInput carries the operator's keystrokes to the session.
//
// Every byte, uninterpreted. Ctrl-C is 0x03 here and nothing else: the terminal
// is in raw mode, so it never becomes a signal on this side, and it is the
// remote terminal's line discipline that turns it into a SIGINT for whatever is
// running there. That is the whole arrangement that makes interrupting a remote
// `sleep 100` interrupt the sleep rather than kill the client.
func (s *shellSession) pumpInput() {
	defer s.guardPanic()

	buf := make([]byte, 4096)
	for {
		n, err := s.term.Read(buf)
		if n > 0 {
			if sendErr := s.send(&sandboxdv1.ShellRequest{
				Event: &sandboxdv1.ShellRequest_Data{Data: buf[:n]},
			}); sendErr != nil {
				return
			}
		}
		if err != nil {
			// Local input is over — stdin closed, or the terminal went away.
			// The session is not: a command still running still has output to
			// deliver, so the write half is closed and the read half is left
			// alone.
			_ = s.closeSend()
			return
		}
	}
}

// pumpResizes forwards every change of the local window to the session.
//
// Without this the remote terminal keeps whatever size it was opened with, and
// every full-screen program on the far end draws to the wrong width: `top`
// wraps every row, `vi` puts its status line in the middle of the screen. The
// watch is per-platform — SIGWINCH on Unix, a poll on Windows — and lives in
// internal/platform for that reason.
func (s *shellSession) pumpResizes(ctx context.Context) {
	defer s.guardPanic()

	s.term.watch(ctx, func(columns, rows int) {
		if err := s.send(&sandboxdv1.ShellRequest{
			Event: &sandboxdv1.ShellRequest_Resize{Resize: &sandboxdv1.ShellSize{
				Columns: uint32(columns), //nolint:gosec // bounded by the terminal's own dimensions, which are 16-bit
				Rows:    uint32(rows),    //nolint:gosec // as above
			}},
		}); err != nil {
			// The session is ending; the render loop is the one that reports
			// it. A resize that could not be sent is not worth a line of its
			// own on the operator's screen.
			return
		}
	})
}

// watchSignals restores the terminal and ends the session when this process is
// asked to stop.
//
// It returns a function that stops the watch, which the caller defers: without
// it the handler outlives the command in a long-running process, and this CLI
// has one — `fleetctl serve` runs in the same binary.
//
// The signals here are the ones that can arrive *despite* raw mode. Ctrl-C is
// not among them, by design: raw mode is what stops it being a signal, so a
// handler is not what carries an interrupt to the far end. What these are is
// the case where something else stops this process while it holds the
// operator's terminal — `kill`, a closed terminal window, a service manager —
// and the terminal has to be usable afterwards.
func (s *shellSession) watchSignals(cancel context.CancelFunc) func() {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)

	done := make(chan struct{})
	go func() {
		select {
		case <-signals:
			// Restore first, cancel second. Cancelling unwinds the session
			// through several layers of network teardown, and the terminal must
			// be usable before any of that — including if one of those layers
			// blocks.
			s.restore.restore()
			cancel()
		case <-done:
		}
	}()

	return func() {
		signal.Stop(signals)
		close(done)
	}
}

// guardPanic restores the terminal before a panic on a pump goroutine takes the
// process down.
//
// A deferred restore in run covers a panic on the main goroutine, because the
// stack unwinds through it. Nothing unwinds through run when a goroutine
// panics: the runtime prints the trace and kills the process, and a terminal
// left in raw mode is what the operator is holding when it does. So each pump
// restores and re-panics, which keeps the crash — and its stack trace, which is
// the thing worth having — while handing back a terminal that works.
func (s *shellSession) guardPanic() {
	if r := recover(); r != nil {
		s.restore.restore()
		panic(r)
	}
}

// note writes a line about the session, after the terminal has been restored.
func (s *shellSession) note(message string) {
	if s.notes == nil {
		return
	}
	_, _ = fmt.Fprintln(s.notes, "fleetctl: "+message)
}

// restoreGuard puts the terminal back exactly once.
//
// Once, because the paths overlap by design: a session that ends normally
// restores in render and again in run's defer, and a signal arriving during
// teardown restores from the handler while the main goroutine is doing the
// same. Making that safe is what lets every path restore unconditionally
// instead of each one reasoning about whether another already has.
type restoreGuard struct {
	once  sync.Once
	undo  func() error
	notes io.Writer
}

func (g *restoreGuard) restore() {
	if g == nil || g.undo == nil {
		return
	}
	g.once.Do(func() {
		if err := g.undo(); err != nil && g.notes != nil {
			// Printed rather than returned: by the time this is known the
			// command is on its way out, and the operator's terminal is in a
			// state they need to hear about — `reset` is the fix.
			_, _ = fmt.Fprintf(g.notes, "fleetctl: could not restore the terminal (%v); run `reset` to fix it\n", err)
		}
	})
}
