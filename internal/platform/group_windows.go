package platform

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"github.com/aymanbagabas/go-pty"
	"golang.org/x/sys/windows"
)

// jobObjectAllAccess is JOB_OBJECT_ALL_ACCESS. x/sys/windows does not define
// it.
const jobObjectAllAccess = 0x1F001F

var (
	modkernel32       = windows.NewLazySystemDLL("kernel32.dll")
	procOpenJobObject = modkernel32.NewProc("OpenJobObjectW")
	procIsProcessInJb = modkernel32.NewProc("IsProcessInJob")
)

// ProcessGroup is a Windows job object holding the supervised child and
// everything it spawns. Terminating the job kills the tree; terminating
// node.exe alone leaves its children running, which is the failure this type
// exists to prevent.
//
// # The assignment race
//
// A child is assigned to its job after CreateProcess returns, not atomically
// with it. Windows can do better — PROC_THREAD_ATTRIBUTE_JOB_LIST in an
// extended startup info block assigns at creation — but syscall.SysProcAttr
// exposes no attribute list, and the alternative (CREATE_SUSPENDED, assign,
// then find and resume the initial thread) requires thread enumeration that
// os/exec also does not expose.
//
// So there is a window, microseconds wide, in which a child that spawns
// grandchildren immediately can leave them outside the job. Nothing in this
// package closes it. It is documented rather than papered over, and Kill
// terminates the leader as well as the job so a partial assignment still kills
// what the agent definitely owns.
//
// # Why the leader is a handle and not a pid
//
// A pid names a process only for as long as the process object behind it
// exists, and Windows frees that object when the last handle to it closes —
// os/exec closes its own in Wait. Pids then come back out of a free list rather
// than in increasing order, so the number a group recorded at Adopt can be
// answering for something else by the time the group is asked to kill
// something. Terminating it would be a TerminateProcess against an uninvolved
// process, with the exit code these job objects use: 1.
//
// So the group opens a handle to the leader at the one moment the pid is
// unambiguous — Adopt, while os/exec still holds a handle of its own — and
// works from that handle afterwards. Holding it also makes the hazard
// unreachable rather than narrow: Windows will not reissue a pid while any
// handle to its process object is open, so g.pid stays correct for as long as
// the group exists, which is what lets Signal keep passing it to
// GenerateConsoleCtrlEvent.
type ProcessGroup struct {
	mu  sync.Mutex
	job windows.Handle
	pid uint32
	// leader is the handle opened when the group took the process on, and the
	// only thing that may be terminated. Zero when the group never managed to
	// open one, in which case leaderErr says why and is reported instead of
	// acting on the pid.
	leader    windows.Handle
	leaderErr error
	isolated  bool
	closed    bool
}

// Access rights for the leader handle.
//
// PROCESS_SET_QUOTA is what AssignProcessToJobObject needs and is asked for
// only on the path that assigns. The re-adoption path opens the same rights the
// old resolve-at-kill-time code did, so a process it could reach before is one
// it can still reach.
const (
	adoptAccess  = windows.PROCESS_SET_QUOTA | windows.PROCESS_TERMINATE | windows.PROCESS_QUERY_LIMITED_INFORMATION
	leaderAccess = windows.PROCESS_TERMINATE | windows.PROCESS_QUERY_LIMITED_INFORMATION
)

// openLeader resolves a pid to the handle the group will hold from then on.
//
// This is the only OpenProcess on a pid in this file's kill path, and it runs
// once, while the caller still has a reason to believe the pid is what it
// thinks it is. Its errors are shaped the way the kill path reports them, so a
// failure recorded here reads the same at kill time as it used to when the
// resolution happened there.
func openLeader(pid uint32, access uint32) (windows.Handle, error) {
	h, err := windows.OpenProcess(access, false, pid)
	if err != nil {
		// Only the errors that actually mean "no such process" may be reported
		// as one. An OpenProcess that fails because this agent may not touch
		// the process — the re-adoption path asks about pids it no longer owns
		// — says the process is there and alive, and reporting that as
		// ErrProcessNotFound tells the supervisor to stop trying and mark a
		// running process dead. See processGone.
		if processGone(err) {
			return 0, fmt.Errorf("platform: pid %d: %w", pid, ErrProcessNotFound)
		}
		return 0, fmt.Errorf("platform: opening pid %d: %w", pid, err)
	}
	return h, nil
}

// pinLeader opens the leader handle and then proves that the handle names the
// process the caller meant, rather than whatever held the pid by the time
// OpenProcess ran.
//
// Adopt needs no such proof: os/exec is still holding a handle of its own
// there, so the pid cannot have been reissued between the caller learning it
// and this package pinning it. The re-adoption path has no equivalent. Nothing
// holds the pid between StatProcess reading it and OpenProcess resolving it,
// and a number Windows has taken back off the free list inside that window
// resolves to an uninvolved process — which the group would then be holding a
// PROCESS_TERMINATE handle to, and would terminate on the next Kill. That is
// the defect this file exists to remove, one call earlier than where it used to
// live; the window is microseconds rather than the life of the group, but the
// free list is exactly what makes microseconds enough.
//
// The proof is start identity: the creation FILETIME read back through the
// pinned handle, against the one read from the pid a moment earlier. It is the
// comparison SameProcess makes and rests on the same property #15 does — a
// reused pid cannot also reproduce the instant the process it replaced was
// created. A mismatch is reported as ErrProcessNotFound, because the process
// the caller asked about is gone; every caller of this path already reads that
// as "already exited" and stops.
func pinLeader(pid uint32, startID string) (windows.Handle, error) {
	h, err := openLeader(pid, leaderAccess)
	if err != nil {
		return 0, err
	}

	creation, err := creationTime(h)
	if err != nil {
		_ = windows.CloseHandle(h)
		return 0, fmt.Errorf("platform: reading the start identity of pid %d: %w", pid, err)
	}
	if startIDFrom(creation) != startID {
		// The pid was reissued between the two calls. Let the handle go
		// without ever having acted on it, and without ever having told a
		// caller this group could signal something.
		_ = windows.CloseHandle(h)
		return 0, fmt.Errorf("platform: pid %d was reused before it could be pinned: %w", pid, ErrProcessNotFound)
	}
	return h, nil
}

func newProcessGroup(cfg GroupConfig) (*ProcessGroup, error) {
	var namePtr *uint16
	if cfg.Name != "" {
		var err error
		namePtr, err = windows.UTF16PtrFromString(cfg.Name)
		if err != nil {
			return nil, fmt.Errorf("platform: invalid job object name %q: %w", cfg.Name, err)
		}
	}

	job, err := windows.CreateJobObject(nil, namePtr)
	if err != nil {
		return nil, fmt.Errorf("platform: creating job object: %w", err)
	}

	if cfg.KillOnClose {
		var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
		info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
		// SetInformationJobObject takes the struct as a bare uintptr, so the
		// compiler stops tracking it as a pointer at the conversion and nothing
		// keeps info alive for the duration of the call. KeepAlive is what
		// supplies the guarantee that the argument-list rule for unsafe.Pointer
		// gives only to calls made directly to an assembly implementation.
		_, err := windows.SetInformationJobObject(
			job,
			windows.JobObjectExtendedLimitInformation,
			uintptr(unsafe.Pointer(&info)), //nolint:gosec // G103: SetInformationJobObject's parameter is a uintptr; there is no pointer-typed form
			uint32(unsafe.Sizeof(info)),
		)
		runtime.KeepAlive(&info)
		if err != nil {
			_ = windows.CloseHandle(job)
			return nil, fmt.Errorf("platform: setting kill-on-close on job object: %w", err)
		}
	}

	return &ProcessGroup{job: job}, nil
}

func openProcessGroup(pid int, name string) (*ProcessGroup, error) {
	if pid <= 0 {
		return nil, fmt.Errorf("platform: invalid pid %d", pid)
	}
	info, err := StatProcess(pid)
	if err != nil {
		return nil, err
	}

	// Validated before anything is opened, so no failure past this point has a
	// handle to give back.
	var namePtr *uint16
	if name != "" {
		namePtr, err = windows.UTF16PtrFromString(name)
		if err != nil {
			return nil, fmt.Errorf("platform: invalid job object name %q: %w", name, err)
		}
	}

	g := &ProcessGroup{pid: uint32(pid)} //nolint:gosec // pid is positive, checked above

	// Pin it now, for the reason Adopt does: a handle is what keeps this pid
	// naming this process afterwards. Unlike Adopt, nothing was holding the pid
	// while StatProcess and OpenProcess ran, so the handle has to be checked
	// against the identity StatProcess saw before it can be trusted — see
	// pinLeader. A failure is remembered rather than returned, because what
	// this call owes its caller is a decision about the job — the leader's own
	// error is the one Signal has always reported, at the moment it is asked.
	if h, err := pinLeader(g.pid, info.StartID); err != nil {
		g.leaderErr = err
	} else {
		g.leader = h
	}

	if namePtr == nil {
		return g, nil
	}

	// LazyProc.Call is an ordinary Go function, so converting namePtr inside
	// its argument list does not pin the string the way the same conversion
	// would in a direct syscall.Syscall call. Nothing reads namePtr after this
	// line, so without KeepAlive the collector is free to reclaim the UTF-16
	// buffer while OpenJobObjectW is reading it.
	handle, _, _ := procOpenJobObject.Call(uintptr(jobObjectAllAccess), 0, uintptr(unsafe.Pointer(namePtr))) //nolint:gosec // G103: LazyProc.Call takes ...uintptr; a Win32 string argument has no other form
	runtime.KeepAlive(namePtr)
	if handle == 0 {
		// The job could not be opened. Usually that means it is gone — every
		// handle to it closed, which on a job created without kill-on-close
		// leaves the processes running but unmanaged — but it also covers a
		// job in another session and one whose DACL does not grant this agent
		// full access. The three are not distinguished because the answer is
		// the same for all of them: degrade to single-process control rather
		// than refuse to adopt, and let Isolated report the loss of the tree
		// guarantee.
		return g, nil
	}

	g.job = windows.Handle(handle)
	g.isolated = processInJob(g.job, g.leader)
	if !g.isolated {
		// Reopening a job by name that this process is not in means the name
		// was reused by something else. Do not keep the handle. A group that
		// could not open its leader at all lands here too, and for the same
		// reason: it cannot tell whether this job is the right one, and using a
		// job object it cannot vouch for is the mistake this branch exists to
		// avoid.
		_ = windows.CloseHandle(g.job)
		g.job = 0
	}
	return g, nil
}

// processInJob asks about the process the group pinned, not about whoever holds
// its pid now — which is the whole reason the handle is kept.
func processInJob(job, process windows.Handle) bool {
	if process == 0 {
		return false
	}

	// result is written by the kernel, so it must still be where it was when
	// its address was taken. See the KeepAlive note in openProcessGroup.
	var result int32
	r, _, _ := procIsProcessInJb.Call(uintptr(process), uintptr(job), uintptr(unsafe.Pointer(&result))) //nolint:gosec // G103: LazyProc.Call takes ...uintptr; the PBOOL out-parameter has no other form
	runtime.KeepAlive(&result)
	return r != 0 && result != 0
}

// Configure puts the child in its own console process group, so a
// CTRL_BREAK_EVENT can be aimed at it without also hitting the agent. The job
// object, not this flag, is what makes the tree killable.
func (g *ProcessGroup) Configure(attr *syscall.SysProcAttr) {
	attr.CreationFlags |= windows.CREATE_NEW_PROCESS_GROUP
}

// ConfigureCommand applies Configure to cmd, allocating SysProcAttr if the
// caller has not already.
func (g *ProcessGroup) ConfigureCommand(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	g.Configure(cmd.SysProcAttr)
}

// ConfigurePTYCommand is ConfigureCommand for a go-pty command.
func (g *ProcessGroup) ConfigurePTYCommand(cmd *pty.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	g.Configure(cmd.SysProcAttr)
}

// ConfigureInteractivePTYCommand is ConfigurePTYCommand for a session whose
// interrupts arrive through the terminal rather than from the agent.
//
// It deliberately does *not* set CREATE_NEW_PROCESS_GROUP, which is the only
// thing Configure does on this platform. The flag's documented effect is that
// "CTRL+C signals will be disabled for all processes within the new process
// group" — it exists so an agent can aim a CTRL_BREAK_EVENT at a supervised
// child without also hitting itself, and it pays for that by turning off the
// one delivery path an interactive session needs. A shell attached to a ConPTY
// receives Ctrl-C because the byte reaches the pseudo-console and the console
// host raises a control event for the processes attached to it; starting that
// shell with Ctrl-C disabled means the operator presses Ctrl-C and nothing
// happens on the far end, which is an acceptance criterion of the feature
// rather than a detail.
//
// Nothing is lost by omitting it. The flag is not what makes the tree killable
// on Windows — the job object is, and Adopt still assigns the child to it — and
// this service never sends a console control event of its own, because an
// interrupt here is a byte on the wire rather than a signal the agent
// synthesises.
func (g *ProcessGroup) ConfigureInteractivePTYCommand(cmd *pty.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
}

// Adopt takes the started child on: it opens the handle the group will hold for
// the rest of its life, and assigns the child to the job object. See the type
// comment for the assignment race this cannot close, and for why the handle is
// opened here rather than at the moment it is used.
//
// It must be called before anything waits on p, and that is a requirement
// rather than a convention. Adopt resolves p.Pid exactly once, and what makes
// that resolution safe is os/exec still holding a handle of its own — which
// Wait closes. Called after a Wait, Adopt can pin, assign to the job, and later
// terminate a process that merely inherited the number. There is no way for it
// to detect that from the inside: an os.Process carries no identity beyond the
// pid, so the caller owns this one.
//
// When it returns an error the group still knows the child's pid but has not
// assigned it, so Signal and Kill fall back to the leader alone and report the
// leader's own result. Isolated stays false; a supervisor that ignores this
// error is a supervisor that will not reach the child's descendants.
func (g *ProcessGroup) Adopt(p *os.Process) error {
	if p == nil {
		return ErrNoProcess
	}
	if p.Pid <= 0 {
		return fmt.Errorf("platform: invalid pid %d", p.Pid)
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return ErrGroupClosed
	}

	g.pid = uint32(p.Pid) //nolint:gosec // pid is positive, checked above
	// Isolation describes the pid being taken on now, not whatever the group
	// held before. Carrying a previous Adopt's true past this point would let
	// terminate treat the job as the guarantee for a process that never reached
	// it, and drop the leader's error as though the job had covered it — a live
	// process reported as killed, which is the one answer this file must never
	// give.
	g.isolated = false
	if g.leader != 0 {
		// A second Adopt replaces the first. Nothing in this repository does
		// that, but leaving the old handle open would reserve a pid nothing is
		// going to release.
		_ = windows.CloseHandle(g.leader)
		g.leader, g.leaderErr = 0, nil
	}

	// The one moment the pid is unambiguous: p is the process os/exec just
	// started and has not waited on, so its own handle is still holding the
	// process object — and the pid — against reuse. Every later call works from
	// the handle taken here.
	h, err := openLeader(g.pid, adoptAccess)
	if err != nil {
		g.leaderErr = err
		return fmt.Errorf("platform: adopting pid %d: %w", p.Pid, err)
	}
	g.leader = h

	if g.job == 0 {
		return nil
	}
	if err := windows.AssignProcessToJobObject(g.job, h); err != nil {
		// The handle is kept: assignment failing is exactly the degraded case
		// where the leader is all there is to act on, and acting on it by
		// handle is the point.
		return fmt.Errorf("platform: assigning pid %d to job object: %w", p.Pid, err)
	}
	g.isolated = true
	return nil
}

// Isolated reports whether the child is in a job object. When it is false,
// Signal reaches only the child itself and descendants must be assumed to
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
	return int(g.pid)
}

// GroupID returns zero on Windows: a job object has no numeric id. It exists
// so callers do not need a build tag of their own.
func (g *ProcessGroup) GroupID() int { return 0 }

// Signal applies the closest Windows equivalent of sig.
//
// SignalTerm and SignalKill both terminate the job. Windows has no
// deliverable, catchable termination request for a process without a console,
// so the distinction a Unix caller draws between "ask" and "compel" does not
// survive the crossing: a graceful stop should send SignalInt first and only
// then escalate.
//
// SignalInt raises CTRL_BREAK_EVENT in the child's console process group,
// which a console application can handle. CTRL_C_EVENT is not used because it
// can only be sent to process group zero, which includes the agent.
//
// SignalHup, SignalUSR1 and SignalUSR2 return ErrSignalUnsupported.
//
// ErrProcessNotFound does not mean the same thing here as it does on Unix.
// Unix reports it when the whole group is empty, because that is what kill(2)
// says. When this group has a job object holding the process, terminating the
// job succeeds whether or not anything was still inside it, so a group whose
// processes have all exited reports success rather than ErrProcessNotFound;
// distinguishing the two needs a QueryInformationJobObject process-id-list
// walk this package does not do. When there is no job — the degraded
// single-process path, and the case where Adopt never assigned the child —
// the leader's own answer is reported, and ErrProcessNotFound there does mean
// gone. Use [SameProcess] or [ProcessExists] to ask about liveness; do not
// infer it from this error.
//
// The lock is held across the whole call rather than only across the field
// read. g.job and g.leader are kernel handles, and copying either out before
// releasing the lock leaves a window in which Close can release it: the value
// then names nothing, or — because Windows reissues handle values as soon as
// they are free — names whatever object the process opened next. Terminating an
// unrelated job object or an unrelated process because a Kill and a deferred
// Close overlapped is a worse outcome than either failing or blocking, and
// `defer g.Close()` beside a Kill from a timeout goroutine is the ordinary way
// to use this type. The Unix implementation needs no equivalent because it
// holds no OS resource.
func (g *ProcessGroup) Signal(sig Signal) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.closed {
		return ErrGroupClosed
	}
	if g.pid == 0 {
		return ErrNoProcess
	}

	switch sig {
	case SignalInt:
		// A console process group is named by a pid and there is no handle form
		// of this call, so this one is only as good as g.pid. It is good enough
		// because the group holds a handle to the leader: Windows will not
		// reissue that pid while the handle is open, so the number still names
		// the process this group adopted. A group that never opened one has
		// nothing to reserve its pid, so refuse rather than aim at a number.
		if g.leader == 0 {
			return g.leaderReason()
		}
		if err := windows.GenerateConsoleCtrlEvent(windows.CTRL_BREAK_EVENT, g.pid); err != nil {
			return fmt.Errorf("platform: sending CTRL_BREAK_EVENT to pid %d: %w", g.pid, err)
		}
		return nil
	case SignalTerm, SignalKill:
		return terminate(g.job, g.leaderRef(), g.isolated)
	case SignalUnspecified, SignalHup, SignalUSR1, SignalUSR2:
		return fmt.Errorf("%w: %s", ErrSignalUnsupported, sig)
	default:
		return fmt.Errorf("%w: %s", ErrSignalUnsupported, sig)
	}
}

// SignalLeader delivers sig to the group's leader alone, for the caller that
// explicitly asked not to reach the tree.
//
// It is [ProcessGroup.Signal] with the job left out, so a terminate goes to the
// leader's own handle and nothing else in the job goes with it. SignalInt is
// the exception it cannot make: CTRL_BREAK_EVENT is delivered to a console
// process group, which is what the flag Configure sets creates, and Windows
// offers no per-process form of it. That is the same answer this platform gives
// everywhere else — the leader is what can be reached individually, and only by
// terminating it.
//
// Its Unix counterpart exists to keep a signal aimed at a process rather than a
// number. Nothing here needs that: the group has held a handle to the leader
// since Adopt, and Windows will not reissue a pid while a handle to its process
// object is open.
func (g *ProcessGroup) SignalLeader(sig Signal) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.closed {
		return ErrGroupClosed
	}
	if g.pid == 0 {
		return ErrNoProcess
	}

	switch sig {
	case SignalInt:
		if g.leader == 0 {
			return g.leaderReason()
		}
		if err := windows.GenerateConsoleCtrlEvent(windows.CTRL_BREAK_EVENT, g.pid); err != nil {
			return fmt.Errorf("platform: sending CTRL_BREAK_EVENT to pid %d: %w", g.pid, err)
		}
		return nil
	case SignalTerm, SignalKill:
		return terminateLeader(g.leaderRef())
	case SignalUnspecified, SignalHup, SignalUSR1, SignalUSR2:
		return fmt.Errorf("%w: %s", ErrSignalUnsupported, sig)
	default:
		return fmt.Errorf("%w: %s", ErrSignalUnsupported, sig)
	}
}

// stillActive is STILL_ACTIVE, the exit code GetExitCodeProcess reports for a
// process that has not exited.
const stillActive = 259

// leaderRef is how the group names the process it took on: the handle it opened
// while the pid was still unambiguous, plus the pid itself for messages.
//
// The pid is never resolved back to a process. That is the difference between
// this type and the uint32 it replaced.
type leaderRef struct {
	handle windows.Handle
	pid    uint32
	// err is why handle is zero — the group never opened one, or the open
	// failed. It is reported instead of falling back to the pid.
	err error
}

// leaderRef snapshots the leader under the lock the caller already holds.
func (g *ProcessGroup) leaderRef() leaderRef {
	return leaderRef{handle: g.leader, pid: g.pid, err: g.leaderErr}
}

// leaderReason is the error for an operation that needed a leader handle the
// group does not have.
func (g *ProcessGroup) leaderReason() error {
	if g.leaderErr != nil {
		return g.leaderErr
	}
	return ErrNoProcess
}

// terminate kills the job, then the leader.
//
// Both, because a child that spawned grandchildren before the job assignment
// landed is still in the agent's care. TerminateProcess against a process that
// has already exited fails with ERROR_ACCESS_DENIED, so reporting that error
// unconditionally would turn every successful group kill into a failure.
//
// Which of the two answers is the caller's depends on whether the job actually
// holds the process, which is what assigned records:
//
//   - Assigned. The job is the guarantee: when it goes down the tree is gone,
//     and whether the leader could also be terminated individually afterwards
//     says nothing about the caller's request. The leader's error is dropped.
//   - Not assigned. TerminateJobObject then succeeds against a job that holds
//     nothing, which proves nothing about the process the caller asked about.
//     Adopt leaves a group in exactly this state when OpenProcess or
//     AssignProcessToJobObject fails — and AssignProcessToJobObject does fail
//     in the field, on a host where the agent itself is already inside a job
//     that forbids nesting. Dropping the leader's error there reports a live,
//     unreachable process as killed: a failure reported as success, and the
//     supervisor stops trying. The Unix implementation has never had this
//     problem, because a group it could not create is a group it signals by
//     pid, and kill(2)'s answer is passed straight back.
func terminate(job windows.Handle, leader leaderRef, assigned bool) error {
	if job == 0 {
		return terminateLeader(leader)
	}

	if err := windows.TerminateJobObject(job, 1); err != nil {
		// The job did not go down. The leader is then the only thing left to
		// try, and its error is the one worth reporting.
		jobErr := fmt.Errorf("platform: terminating job object: %w", err)
		if leaderErr := terminateLeader(leader); leaderErr != nil {
			return errors.Join(jobErr, leaderErr)
		}
		return jobErr
	}

	leaderErr := terminateLeader(leader)
	if !assigned {
		return leaderErr
	}
	// Best effort, and deliberately dropped: the leader is normally already
	// dead, killed by the job going down a moment ago.
	return nil
}

// terminateLeader kills the process the group took on, through the handle it
// has held since it took it on.
//
// There is no OpenProcess here, and its absence is the fix. Resolving the pid
// at this moment asks the kernel who holds that number now — a different
// question, with a different answer, once Wait has released the leader and
// Windows has handed the number to something else off the free list. The wrong
// answer is a TerminateProcess against an uninvolved process, which on Windows
// leaves it dead with exit code 1 and no output of its own to say what
// happened. A handle names one process for its whole lifetime and cannot be
// wrong about which.
//
// A leader that has already exited reports ErrProcessNotFound rather than
// success. Every caller reads that as "already gone", which it is. The reading
// it replaces — that this call killed it — is the one a supervisor must not be
// given for a process it may still need to stop, and it was only ever the
// answer here because a pid that some other handle kept alive looked different
// from one that nothing did.
func terminateLeader(l leaderRef) error {
	if l.handle == 0 {
		// No handle means the group never pinned this pid, so the pid is not
		// evidence of anything. Say why instead of terminating whatever holds
		// it now.
		if l.err != nil {
			return l.err
		}
		return ErrNoProcess
	}

	if processExited(l.handle) {
		return fmt.Errorf("platform: pid %d: %w", l.pid, ErrProcessNotFound)
	}
	if err := windows.TerminateProcess(l.handle, 1); err != nil {
		// It can exit on its own between the check and the call. TerminateProcess
		// against a process that has already exited fails with
		// ERROR_ACCESS_DENIED, and that is not this call failing.
		if processExited(l.handle) {
			return nil
		}
		return fmt.Errorf("platform: terminating pid %d: %w", l.pid, err)
	}
	return nil
}

// processExited reports whether the process behind h has exited.
//
// A process whose own exit code happens to be 259 is indistinguishable from a
// running one here. That is a wart in the Windows API rather than in this
// code, and it is the safe direction to be wrong in: the caller goes on to
// call TerminateProcess, which is what it wanted anyway.
func processExited(h windows.Handle) bool {
	var code uint32
	if err := windows.GetExitCodeProcess(h, &code); err != nil {
		return false
	}
	return code != stillActive
}

// Kill terminates the whole tree immediately.
func (g *ProcessGroup) Kill() error { return g.Signal(SignalKill) }

// Sweep is Kill on Windows, and there is nothing for it to change.
//
// On Unix it exists to read one errno differently, because a process group
// there is a number the kernel reclaims and a group holding nothing but its
// leader's zombie answers a signal in a way that is not a failure. A job
// object is not a number: it is a kernel object this group holds a handle to,
// terminating one that holds nothing succeeds, and the leader is reached
// through a handle of its own rather than through its pid. There is no answer
// here that means something different for a sweep than it does for a kill.
//
// Neither agent path calls it. Both have a job object with KillOnClose, so
// closing the group is what takes the tree down and an extra signal would add
// no guarantee; see internal/agent/shell's and internal/agent/exec's Windows
// sweeps. It exists so that a caller written against [ProcessGroup] compiles
// and means the same thing on every platform.
func (g *ProcessGroup) Sweep() error { return g.Signal(SignalKill) }

// Collect reaps the group's leader. On Windows that is the wait and nothing
// else, and the nothing else is the point.
//
// The Unix implementation exists to order a caller's signals against the
// collection, because a process group id there is a number the kernel reclaims
// the moment the last member of the group is reaped — so the collection is what
// takes the group's name away, and everything that signals has to be kept on
// the near side of it.
//
// Nothing here has a name to lose. A job object is a kernel object reached
// through a handle this group holds, and [ProcessGroup.Adopt] opens a handle to
// the leader as well, at the one moment its pid is unambiguous; Windows will
// not reissue a pid while any handle to its process object is open. So neither
// the job nor the leader can come to name anything else while the group can
// still be asked to signal them, whatever any caller does with Wait — and a
// signal sent after the collection is as well aimed as one sent before it. See
// [AwaitExit], which returns ErrUnsupported here for the same reason.
//
// groupErr is therefore always nil: there is no guarantee for this call to
// give up.
func (g *ProcessGroup) Collect(wait func() error) (groupErr, waitErr error) {
	return nil, wait()
}

// SweepAndCollect is [ProcessGroup.Collect]: there is no sweep on Windows.
//
// Both agent callers create their group with GroupConfig.KillOnClose and hold
// the only handle to the job, so closing the group is what takes the tree down
// and an extra TerminateJobObject would add no guarantee to it. See
// internal/agent/exec's and internal/agent/shell's Windows sweeps, which say
// the same thing from the other side.
func (g *ProcessGroup) SweepAndCollect(wait func() error) (groupErr, waitErr error) {
	return g.Collect(wait)
}

// Close releases the job handle and the leader handle. When the group was
// created with GroupConfig.KillOnClose, closing the job is what kills the tree
// — the last handle closing is the trigger.
//
// The leader handle goes first, and only its own reference goes with it: the
// process stays in the job, so a KillOnClose group still takes the tree down on
// the next line. What is given up is the pid reservation, which is exactly
// right — a closed group cannot be asked to signal anything, so it has no
// business holding a pid out of circulation.
func (g *ProcessGroup) Close() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return nil
	}
	g.closed = true

	var errs []error
	if g.leader != 0 {
		if err := windows.CloseHandle(g.leader); err != nil {
			errs = append(errs, fmt.Errorf("platform: closing leader handle: %w", err))
		}
		g.leader = 0
	}
	if g.job != 0 {
		job := g.job
		g.job = 0
		if err := windows.CloseHandle(job); err != nil {
			errs = append(errs, fmt.Errorf("platform: closing job object: %w", err))
		}
	}
	return errors.Join(errs...)
}
