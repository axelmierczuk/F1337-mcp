//go:build unix

package platform

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/aymanbagabas/go-pty"
)

// ProcessGroup is a Unix session and process group led by the supervised
// child. Signals are delivered to the negated group id, which is what reaches
// grandchildren: signalling the leader alone leaves `npm run dev`'s bundler
// running and holding the port.
type ProcessGroup struct {
	mu   sync.Mutex
	pid  int
	pgid int
	// proc is the leader as os/exec handed it over, kept because a pid is not
	// a name and this is. See [groupPin] and signalLeaderLocked. It is nil for
	// a group opened by pid, which is the one case where there is nothing to
	// keep.
	proc     *os.Process
	isolated bool
	// pin is what this group may still name; see [groupPin]. It is the whole
	// of the ordering that keeps a signal from reaching a process group the
	// agent never started.
	pin    groupPin
	closed bool
	// configured records that Configure was applied to the command this group
	// is about to adopt, and so that a session was actually asked for. Adopt
	// needs to know: "the child is not leading its own group" is a wait when
	// one was requested and a settled answer when one was not.
	configured bool
}

// groupPin is what a ProcessGroup still holds, and so what it may still name
// when it is asked to signal.
//
// The rule the type turns on: a pid is a durable name only while something
// holds it, and a process group id is a pid. What holds this group's id is the
// leader — alive or an unreaped zombie, it is a member of its own group, and
// the kernel keeps the id reserved while any member is there. Nobody else can
// take that away, because nobody else can reap another process's child. So the
// id is unambiguously this group's from Adopt until this package collects the
// leader, and is nobody's afterwards.
//
// Which is why the collection goes through the group rather than around it: it
// is the one event that changes the answer, and a caller that performs it
// somewhere else leaves this type signalling a number it no longer owns. See
// [ProcessGroup.Collect] and [AwaitExit].
type groupPin uint8

const (
	// pinGroup: the leader leads its own group and has not been collected, so
	// kill(-pgid) names this group and can name nothing else.
	pinGroup groupPin = iota

	// pinLeader: the group id is not this group's to name — the child never
	// entered a session of its own, or its exit could not be established
	// before the collection — but the leader is still the leader, and
	// [os.Process] names it without going through its number. Descendants are
	// out of reach from here; that is the loss the state records.
	pinLeader

	// pinNone: the leader has been collected. Its pid, and the group id that
	// was its pid, belong to the kernel now, and this group names nothing.
	pinNone
)

func newProcessGroup(_ GroupConfig) (*ProcessGroup, error) {
	// Nothing to allocate: the group is created by the child itself, in the
	// window between fork and exec, by the setsid() that Configure requests.
	return &ProcessGroup{}, nil
}

func openProcessGroup(pid int, _ string) (*ProcessGroup, error) {
	if pid <= 0 {
		return nil, fmt.Errorf("platform: invalid pid %d", pid)
	}
	pgid, err := syscall.Getpgid(pid)
	if err != nil {
		if errors.Is(err, syscall.ESRCH) {
			return nil, fmt.Errorf("platform: pid %d: %w", pid, ErrProcessNotFound)
		}
		return nil, fmt.Errorf("platform: reading process group of pid %d: %w", pid, err)
	}
	// pinGroup for a leader that leads its own group, and it is the weakest
	// claim this file makes. Nothing here holds the id: the agent did not spawn
	// this process and cannot reap it, so the id is released by whoever does —
	// init, after a reparented process exits — and no state in this type can
	// see that happen. The caller owns that check; see [SameProcess] and the
	// supervisor's re-adoption path, which re-reads start identity before every
	// signal.
	g := &ProcessGroup{pid: pid, pgid: pgid, isolated: pgid == pid, pin: pinLeader}
	if g.isolated {
		g.pin = pinGroup
	}
	return g, nil
}

// Configure requests a new session for the child, which also makes it the
// leader of a new process group with pgid == pid.
//
// Setsid alone, not Setsid plus Setpgid: the child calls setsid() first, and a
// setpgid() from a process that is already a session leader fails with EPERM,
// which aborts the exec. Setsid also detaches the child from the agent's
// controlling terminal, which is what a supervised background process wants —
// a PTY-attached command gets its own controlling terminal from the PTY layer.
func (g *ProcessGroup) Configure(attr *syscall.SysProcAttr) {
	attr.Setsid = true

	g.mu.Lock()
	defer g.mu.Unlock()
	g.configured = true
}

// ConfigureCommand applies Configure to cmd, allocating SysProcAttr if the
// caller has not already.
func (g *ProcessGroup) ConfigureCommand(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	g.Configure(cmd.SysProcAttr)
}

// ConfigurePTYCommand is ConfigureCommand for a go-pty command. go-pty sets
// Setsid and Setctty itself, so this only makes the intent explicit and keeps
// the call sequence identical between the two spawn paths.
func (g *ProcessGroup) ConfigurePTYCommand(cmd *pty.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	g.Configure(cmd.SysProcAttr)
}

// ConfigureInteractivePTYCommand is ConfigurePTYCommand for a session whose
// interrupts arrive through the terminal rather than from the agent.
//
// On Unix it is ConfigurePTYCommand: the child leads its own session with the
// pty as its controlling terminal, the line discipline turns a 0x03 byte into a
// SIGINT for whichever process group is in the foreground of that terminal, and
// the session's own group is what a kill reaches. All of that is what
// ConfigurePTYCommand already asks for.
//
// The two differ on Windows, where the console process group flag that makes an
// agent-sent CTRL_BREAK aimable is also what stops a Ctrl-C typed into the
// terminal being delivered at all. See the Windows file.
func (g *ProcessGroup) ConfigureInteractivePTYCommand(cmd *pty.Cmd) {
	g.ConfigurePTYCommand(cmd)
}

// adoptSettle bounds how long Adopt will wait for a session it asked for to
// become visible. It is a failsafe against a caller that configured a group and
// then started a command without it, never a margin the answer rests on: every
// other way out of adoptedGroup is the kernel answering. Reaching it costs one
// warning on a command that is already running, so it is set generously.
const adoptSettle = 2 * time.Second

// adoptedGroup reads pid's real process group from the kernel and keeps reading
// until the answer is settled. It returns the group the child is really in,
// whether that group is the child's own, and an error only for the settle case.
//
// Not a single sample, which is #82. Configure asks for the session through
// SysProcAttr.Setsid, and the child makes that call itself, between the fork and
// the exec — after the parent's fork has already returned. Go does not do the
// double-setpgid that would close that window, so a parent reading the pgid once
// immediately after Start can still catch the child in the group it was forked
// into. That reading is not wrong for an instant: Adopt records it for the life
// of the process, Signal then degrades to a bare pid and the post-exec sweep is
// skipped entirely, so a command's descendants outlive the call that started
// them. Which is the failure this package exists to prevent.
//
// So every ordinary way out of the loop is a fact the kernel reported:
//
//   - pgid == pid: the session exists, and nothing can take it away again —
//     not even the child exiting, since a group id belongs to its members
//     until the last of them is reaped.
//   - the pid is gone: nothing further can be learned from the kernel, and
//     nothing needs to be — see the branch itself.
//   - Configure was never applied: no session was ever asked for, so the child
//     is in the caller's own group and always will be.
//
// settle is the fourth, and the only one that is a duration. Reaching it means
// a session was requested and the child never entered one, which is reported
// rather than recorded in silence; see Adopt.
func adoptedGroup(pid int, configured bool, settle time.Duration,
	getpgid func(int) (int, error),
) (int, bool, error) {
	deadline := time.Now().Add(settle)
	for attempt := 0; ; attempt++ {
		pgid, err := getpgid(pid)
		if err != nil {
			// The child is gone, or gone as far as getpgid(2) is concerned: on
			// Darwin it answers ESRCH for a process that has exited and not yet
			// been reaped, while Linux answers with the group. A race with a
			// fast-exiting child is not an adoption failure either way, so the
			// question is only what to record about it.
			//
			// Which is answerable without the kernel. Configure asks for the
			// session through SysProcAttr.Setsid; setsid(2) in a freshly forked
			// child cannot fail, because a pid the kernel has just minted is not
			// already a process group leader, and had it failed anyway the child
			// would have reported the errno back through the fork pipe and Start
			// would have returned it rather than a running process. So a
			// configured command that started did lead its own session, and its
			// own pid is both the group to aim at and the truth about isolation.
			//
			// Recording false here instead is what made a short-lived leader on
			// macOS lose its post-exec sweep — the one thing that reaches the
			// `sh -c 'sleep 100 &'` grandchild it left behind.
			return pid, configured, nil //nolint:nilerr // a child that has already gone is not an adoption failure; see above
		}
		if pgid == pid {
			return pgid, true, nil
		}
		if !configured {
			return pgid, false, nil
		}
		if !time.Now().Before(deadline) {
			return pgid, false, fmt.Errorf(
				"platform: pid %d is still in process group %d after %s rather than leading its own: "+
					"a signal will reach it alone and its descendants will survive it",
				pid, pgid, settle)
		}
		// The child is between its fork and its setsid — a handful of
		// instructions on an idle host and a scheduling delay on a loaded one.
		// Yield first, because in the ordinary case that is the whole wait, and
		// only then start sleeping: a caller that configured a group its child
		// never enters would otherwise hold a core busy until the deadline.
		if attempt < 100 {
			runtime.Gosched()
			continue
		}
		time.Sleep(time.Millisecond)
	}
}

// Adopt records the started child. It reads the child's real process group id
// from the kernel rather than assuming Configure was applied, because assuming
// it is how a supervisor ends up sending SIGKILL to its own group.
//
// It returns an error when a session was configured and the child is not in one.
// The group is still recorded — the command is running and its pid is the one
// thing left to act on — but the caller is told, because the alternative is what
// #82 found: a group that quietly reaches one process instead of a tree, with
// nothing in the log to say so. That matches the Windows implementation, where a
// refused job assignment has always been an error with the pid still recorded.
func (g *ProcessGroup) Adopt(p *os.Process) error {
	if p == nil {
		return ErrNoProcess
	}

	g.mu.Lock()
	closed, configured := g.closed, g.configured
	g.mu.Unlock()
	if closed {
		return ErrGroupClosed
	}

	// Outside the lock. This waits on the child, and holding the mutex across it
	// would block Signal and Isolated for as long as it takes.
	pgid, isolated, err := adoptedGroup(p.Pid, configured, adoptSettle, syscall.Getpgid)

	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return ErrGroupClosed
	}
	g.pid = p.Pid
	g.pgid = pgid
	g.isolated = isolated
	// The process itself, not just its number. os/exec keeps enough state on it
	// to refuse a signal for a process it has already collected — a pidfd where
	// the kernel has them, a lock and a flag everywhere else — which is what
	// makes it a name rather than a number. It is what Signal aims at whenever
	// the group id is not this group's to name.
	g.proc = p
	g.pin = pinLeader
	if isolated {
		g.pin = pinGroup
	}
	return err
}

// Isolated reports whether the child really leads its own group. When it is
// false, Signal reaches only the leader, and descendants must be assumed to
// survive.
func (g *ProcessGroup) Isolated() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.isolated
}

// PID returns the pid of the adopted child, or zero.
func (g *ProcessGroup) PID() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.pid
}

// GroupID returns the Unix process group id, or zero before Adopt. It has no
// Windows counterpart and exists for diagnostics and tests.
func (g *ProcessGroup) GroupID() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.pgid
}

// Signal delivers sig to every process in the group.
//
// Once the group is empty the kernel reports ESRCH, which is translated to
// ErrProcessNotFound. Anything else is passed back as it came, including EPERM:
// a group this process may not signal is a live group, and reporting it as
// "already gone" is the one answer that would stop a caller trying again.
//
// A group is empty only once its last member has been reaped, and what the
// kernel answers in between is not the same on every platform. Measured on a
// group holding nothing but an unreaped zombie leader: Linux reports the group
// from getpgid(2) and delivers the signal, while Darwin answers ESRCH from
// getpgid(2) and EPERM from kill(2) — there is a group, and nothing in it that
// can take a signal. Most callers here need not care: they signal a group that
// still holds a live process, or accept ErrProcessNotFound as "already
// stopped". The one that does is [ProcessGroup.Sweep], which signals a group
// whose leader has just exited on purpose.
//
// What is worth depending on is the other side of that rule: a group id belongs
// to its members until the last of them is reaped, so a group that has outlived
// its leader is still reachable, and a pgid that has been fully released is free
// for the kernel to hand to somebody else. That is not a hazard this caller has
// to reason about any more — it is what [groupPin] records and what this call
// refuses on — but it is the reason the refusal exists. See [ErrGroupReleased].
func (g *ProcessGroup) Signal(sig Signal) error {
	osSig, err := sig.OSSignal()
	if err != nil {
		return err
	}
	unixSig, ok := osSig.(syscall.Signal)
	if !ok {
		return ErrSignalUnsupported
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	return g.signalLocked(unixSig, sig)
}

// signalLocked delivers sig with the lock held, and the lock is held across the
// kill(2) rather than only across the field read it used to guard.
//
// That is the half of the ordering the kernel cannot supply. [Collect] takes
// the same lock to record that the leader has been collected, so a signal that
// has passed the check below cannot still be on its way to the kernel when the
// id is released: the two are mutually exclusive rather than merely written in
// the right order. kill(2) does not block, so nothing is held for longer than a
// syscall.
//
// It is os/exec's own ordering, reached for the same reason. (*os.Process).
// pidSignal holds sigMu across its kill(2), and pidWait marks the process done
// before wait4 and then takes that lock exclusively to wait out any signaller
// already inside it — with a comment saying it is so a signal is not sent to a
// process that has been reaped.
func (g *ProcessGroup) signalLocked(unixSig syscall.Signal, sig Signal) error {
	if g.closed {
		return ErrGroupClosed
	}
	if g.pid == 0 {
		return ErrNoProcess
	}

	switch g.pin {
	case pinGroup:
		// Negative pid means "the process group with this id". This is the
		// whole reason the group exists.
		if err := syscall.Kill(-g.pgid, unixSig); err != nil {
			if errors.Is(err, syscall.ESRCH) {
				return fmt.Errorf("platform: signalling group %d: %w", g.pgid, ErrProcessNotFound)
			}
			return fmt.Errorf("platform: signalling group %d with %s: %w", g.pgid, sig, err)
		}
		return nil
	case pinLeader:
		return g.signalLeaderLocked(unixSig, sig)
	case pinNone:
		return fmt.Errorf("platform: group %d: %w", g.pgid, ErrGroupReleased)
	default:
		return fmt.Errorf("platform: group %d is in an unknown state", g.pgid)
	}
}

// signalLeaderLocked delivers sig to the leader alone, for a group that cannot
// name its group id: the child never entered a session of its own, or its exit
// could not be established before the collection. Called with the lock held.
//
// Through the [os.Process] Adopt was given, and that is the point rather than a
// convenience. A bare kill(2) on g.pid is the same defect one scale smaller —
// after the reap that number names whatever the kernel gave it to — while
// os/exec's own handle refuses a signal for a process it has already collected:
// on Linux by signalling through a pidfd, which names the process and not the
// number, and everywhere else by holding a lock across the kill and marking the
// process done under it.
//
// A group opened by pid has no such handle, and the fallback is the bare
// kill(2) with everything that implies. Nothing this package holds keeps a
// pid alive that this process is not the parent of, so the check belongs to the
// caller: see [SameProcess], and the supervisor's re-adoption path, which
// re-reads start identity before every signal it sends.
func (g *ProcessGroup) signalLeaderLocked(unixSig syscall.Signal, sig Signal) error {
	if g.proc == nil {
		if err := syscall.Kill(g.pid, unixSig); err != nil {
			if errors.Is(err, syscall.ESRCH) {
				return fmt.Errorf("platform: signalling pid %d: %w", g.pid, ErrProcessNotFound)
			}
			return fmt.Errorf("platform: signalling pid %d with %s: %w", g.pid, sig, err)
		}
		return nil
	}

	if err := g.proc.Signal(unixSig); err != nil {
		if errors.Is(err, os.ErrProcessDone) || errors.Is(err, syscall.ESRCH) {
			return fmt.Errorf("platform: signalling pid %d: %w", g.pid, ErrProcessNotFound)
		}
		return fmt.Errorf("platform: signalling pid %d with %s: %w", g.pid, sig, err)
	}
	return nil
}

// SignalLeader delivers sig to the group's leader alone, for the caller that
// explicitly asked not to reach the tree.
//
// It is [ProcessGroup.Signal] with the group left out, and it exists so that
// "just this process" is still a name rather than a number: the leader is
// signalled through the [os.Process] Adopt was given, which os/exec refuses to
// signal once it has collected it, and the collection is this group's own — so
// a stop racing an exit is refused instead of landing on whatever the kernel
// gave the pid to next. A caller that reaches for os.FindProcess and the pid
// instead has re-opened exactly that window, however carefully it checked
// first.
func (g *ProcessGroup) SignalLeader(sig Signal) error {
	osSig, err := sig.OSSignal()
	if err != nil {
		return err
	}
	unixSig, ok := osSig.(syscall.Signal)
	if !ok {
		return ErrSignalUnsupported
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return ErrGroupClosed
	}
	if g.pid == 0 {
		return ErrNoProcess
	}
	if g.pin == pinNone {
		return fmt.Errorf("platform: pid %d: %w", g.pid, ErrGroupReleased)
	}
	return g.signalLeaderLocked(unixSig, sig)
}

// Kill sends SIGKILL to the group. It is the escalation step of a graceful
// stop and cannot be caught or ignored.
func (g *ProcessGroup) Kill() error { return g.Signal(SignalKill) }

// Sweep kills whatever the group's leader left behind, for a caller that has
// just watched that leader exit and has not yet collected it. It is what
// [ProcessGroup.SweepAndCollect] sends, from inside the interval where sending
// it is safe; see [AwaitExit] for the ordering.
//
// It is Kill with one answer changed. A group whose only remaining member is
// its leader's uncollected zombie has nothing that can receive a signal, and
// the two platforms say so differently — measured, on this host and in a Linux
// container:
//
//	                     leader a zombie      leader collected, group empty
//	Linux   kill(-pgid)  delivered, 0         ESRCH
//	Darwin  kill(-pgid)  EPERM                ESRCH
//
// Kill passes EPERM back, deliberately: for a supervisor, a group it may not
// signal is a live group, and reporting it as "already gone" is the one answer
// that would stop the caller trying again. For a sweep it is the ordinary
// ending rather than a failure — the command left nothing behind, which is
// most commands, and a shell session that ends at a prompt with no jobs is
// exactly that. Passing it back cost every successful exec on macOS a WARN
// saying a descendant may have outlived the call, which is how a diagnostic
// stops being read.
//
// The reading is sound because of what this group is. Every member is a
// descendant of a child this agent started as itself — nothing here spawns
// with a Credential — so a member that exists and cannot be signalled is not a
// state this group can be in: an unprivileged agent's descendants share its
// uid, and a root agent may signal anything. EPERM from a group signal
// therefore means no member could receive it, which is the same fact ESRCH
// reports one moment later, and it is reported the same way.
func (g *ProcessGroup) Sweep() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.sweepLocked()
}

// sweepLocked is Sweep with the lock already held, so the sweep and the
// collection that follows it are one critical section.
func (g *ProcessGroup) sweepLocked() error {
	err := g.signalLocked(syscall.SIGKILL, SignalKill)
	if errors.Is(err, syscall.EPERM) {
		return fmt.Errorf("platform: sweeping group %d: %w", g.pgid, ErrProcessNotFound)
	}
	return err
}

// Collect reaps the group's leader, and is the only thing that may: collecting
// it is what releases the group id, so it belongs to the type that owns the id
// rather than to each caller that happens to hold a Cmd.
//
// wait is the caller's own collection — cmd.Wait, whichever Cmd that is — and
// its error is returned unchanged as waitErr. groupErr is separate and is not a
// failure of the collection: it reports that this group can no longer reach a
// tree, which is a guarantee worth a line in the daemon's log and never a
// reason to fail a call.
//
// # What is ordered against what
//
// [AwaitExit] first, which reports the leader's exit without collecting it, so
// the leader is a zombie and still a member of its own group. Then, under the
// lock every signal takes, the group is marked released — and only then is the
// leader collected. A signal that arrives before that mark is aimed at an id an
// uncollected member is still holding; one that arrives after is refused with
// [ErrGroupReleased]. There is no third case: the leader is this process's
// child, so nothing but this call can reap it, and until it does the id cannot
// go anywhere.
//
// That is os/exec's ordering, arrived at for the same reason: pidWait blocks on
// waitid(WNOWAIT), marks the process done *before* wait4, and then takes the
// signal lock to wait out anything already inside it.
//
// # When the exit cannot be established
//
// The group gives up the group id at that point rather than after the
// collection, and says so in groupErr. The collection is the one moment nothing
// can be ordered against: the lock cannot be held across it — a Wait for a
// process that is still running would block the very kill that would end it —
// and there is no way to learn from outside when the kernel releases the id
// inside it. So the group degrades to its leader, which [os.Process] names
// through a pidfd where there is one and through a lock of its own everywhere
// else, and no kill(-pgid) is ever sent again. What is given up is the
// descendants; what is kept is the ability to end the process the caller
// actually has to end.
//
// A group whose child never led one degrades the same way, from the start, for
// the same reason: there is no group id to be right about.
func (g *ProcessGroup) Collect(wait func() error) (groupErr, waitErr error) {
	return g.collect(false, wait)
}

// SweepAndCollect is [ProcessGroup.Collect] with the sweep sent inside the
// interval where it is safe to send: after the leader has exited and before it
// has been collected, holding the lock across both so nothing can slip between
// them.
//
// groupErr covers both ways the tree guarantee can break here — an exit that
// could not be established, so no sweep went out, and a sweep that failed — and
// both mean the same thing to the caller: a descendant may still be running on
// this host. The wording of the log line is the caller's, because "the call"
// and "the session" are different things to the operator reading it.
func (g *ProcessGroup) SweepAndCollect(wait func() error) (groupErr, waitErr error) {
	return g.collect(true, wait)
}

func (g *ProcessGroup) collect(sweep bool, wait func() error) (groupErr, waitErr error) {
	g.mu.Lock()
	pin, pid := g.pin, g.pid
	g.mu.Unlock()

	if pin != pinGroup {
		// Nothing to establish and nothing to sweep: a leader that never got
		// its own group had no group for its descendants to be in, and one
		// this call has already released cannot be collected twice. Either way
		// the leader is all there is, and it is named by its handle.
		return nil, g.collectLeader(wait)
	}

	// Outside the lock, and it has to be: this blocks until the leader exits,
	// and the kill that makes it exit comes through the lock.
	if err := AwaitExit(pid); err != nil {
		groundErr := fmt.Errorf(
			"platform: could not establish that pid %d has exited, so its group id was given up without being swept: %w", pid, err)
		g.mu.Lock()
		// Before the collection rather than after it, which is the whole point:
		// past here no signal from this group can name a group id, so the
		// collection below has nothing to race with. See the doc comment.
		if g.pin == pinGroup {
			g.pin = pinLeader
		}
		g.mu.Unlock()
		return groundErr, g.collectLeader(wait)
	}

	// The leader has exited and nothing has collected it, so its own zombie is
	// holding the group id: the sweep below cannot be aimed anywhere else, and
	// the collection cannot happen until this section ends.
	g.mu.Lock()
	if sweep {
		if err := g.sweepLocked(); err != nil &&
			!errors.Is(err, ErrProcessNotFound) && !errors.Is(err, ErrGroupClosed) {
			groupErr = fmt.Errorf("platform: sweeping group %d: %w", g.pgid, err)
		}
	}
	g.pin = pinNone
	g.mu.Unlock()

	return groupErr, wait()
}

// collectLeader performs a collection this call could not order anything
// against, and closes the group as soon as it has.
//
// The window it leaves is between wait4 returning inside wait and the mark
// below: a signal in exactly that gap is aimed at the leader through its
// handle, which os/exec refuses once it has collected it, rather than at a
// number. That is the floor, and it is Go's own — see (*os.Process).pidWait,
// which marks the process done before wait4 only when waitid could tell it the
// wait would not block.
func (g *ProcessGroup) collectLeader(wait func() error) error {
	err := wait()
	g.mu.Lock()
	g.pin = pinNone
	g.mu.Unlock()
	return err
}

// Close releases the handle. On Unix it holds no OS resource, so this only
// marks the group unusable; the child is not signalled. Terminating the tree
// is always an explicit Kill.
func (g *ProcessGroup) Close() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.closed = true
	return nil
}
