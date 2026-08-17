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
type ProcessGroup struct {
	mu       sync.Mutex
	job      windows.Handle
	pid      uint32
	isolated bool
	closed   bool
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
			uintptr(unsafe.Pointer(&info)),
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
	if _, err := StatProcess(pid); err != nil {
		return nil, err
	}

	g := &ProcessGroup{pid: uint32(pid)} //nolint:gosec // pid is positive, checked above
	if name == "" {
		return g, nil
	}

	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, fmt.Errorf("platform: invalid job object name %q: %w", name, err)
	}
	// LazyProc.Call is an ordinary Go function, so converting namePtr inside
	// its argument list does not pin the string the way the same conversion
	// would in a direct syscall.Syscall call. Nothing reads namePtr after this
	// line, so without KeepAlive the collector is free to reclaim the UTF-16
	// buffer while OpenJobObjectW is reading it.
	handle, _, _ := procOpenJobObject.Call(uintptr(jobObjectAllAccess), 0, uintptr(unsafe.Pointer(namePtr)))
	runtime.KeepAlive(namePtr)
	if handle == 0 {
		// The job is gone: every handle to it closed, which on a job created
		// without kill-on-close leaves the processes running but unmanaged.
		// Degrade to single-process control rather than refusing to adopt.
		return g, nil
	}

	g.job = windows.Handle(handle)
	g.isolated = processInJob(g.job, g.pid)
	if !g.isolated {
		// Reopening a job by name that this process is not in means the name
		// was reused by something else. Do not keep the handle.
		_ = windows.CloseHandle(g.job)
		g.job = 0
	}
	return g, nil
}

func processInJob(job windows.Handle, pid uint32) bool {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return false
	}
	defer func() { _ = windows.CloseHandle(h) }()

	// result is written by the kernel, so it must still be where it was when
	// its address was taken. See the KeepAlive note in openProcessGroup.
	var result int32
	r, _, _ := procIsProcessInJb.Call(uintptr(h), uintptr(job), uintptr(unsafe.Pointer(&result)))
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

// Adopt assigns the started child to the job object. See the type comment for
// the race this cannot close.
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
		return errors.New("platform: process group is closed")
	}

	g.pid = uint32(p.Pid) //nolint:gosec // pid is positive, checked above
	if g.job == 0 {
		return nil
	}

	h, err := windows.OpenProcess(
		windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE|windows.PROCESS_QUERY_LIMITED_INFORMATION,
		false, g.pid)
	if err != nil {
		return fmt.Errorf("platform: opening pid %d to assign it to a job: %w", p.Pid, err)
	}
	defer func() { _ = windows.CloseHandle(h) }()

	if err := windows.AssignProcessToJobObject(g.job, h); err != nil {
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
// The lock is held across the whole call rather than only across the field
// read. g.job is a kernel handle, and copying it out before releasing the lock
// leaves a window in which Close can release it: the value then names nothing,
// or — because Windows reissues handle values as soon as they are free — names
// whatever object the process opened next. Terminating an unrelated job object
// because a Kill and a deferred Close overlapped is a worse outcome than
// either failing or blocking, and `defer g.Close()` beside a Kill from a
// timeout goroutine is the ordinary way to use this type. The Unix
// implementation needs no equivalent because it holds no OS resource.
func (g *ProcessGroup) Signal(sig Signal) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.closed {
		return errors.New("platform: process group is closed")
	}
	if g.pid == 0 {
		return ErrNoProcess
	}

	switch sig {
	case SignalInt:
		if err := windows.GenerateConsoleCtrlEvent(windows.CTRL_BREAK_EVENT, g.pid); err != nil {
			return fmt.Errorf("platform: sending CTRL_BREAK_EVENT to pid %d: %w", g.pid, err)
		}
		return nil
	case SignalTerm, SignalKill:
		return terminate(g.job, g.pid)
	case SignalUnspecified, SignalHup, SignalUSR1, SignalUSR2:
		return fmt.Errorf("%w: %s", ErrSignalUnsupported, sig)
	default:
		return fmt.Errorf("%w: %s", ErrSignalUnsupported, sig)
	}
}

// stillActive is STILL_ACTIVE, the exit code GetExitCodeProcess reports for a
// process that has not exited.
const stillActive = 259

// terminate kills the job, then the leader.
//
// Both, because a child that spawned grandchildren before the job assignment
// landed is still in the agent's care. But the job is the guarantee: when it
// goes down, the tree is gone, and whether the leader could also be terminated
// individually afterwards says nothing about whether the caller's request
// succeeded. TerminateProcess against a process that has already exited fails
// with ERROR_ACCESS_DENIED, so reporting that error turns every successful
// group kill into a failure.
func terminate(job windows.Handle, pid uint32) error {
	if job != 0 {
		if err := windows.TerminateJobObject(job, 1); err != nil {
			// The job did not go down. The leader is then the only thing left
			// to try, and its error is the one worth reporting.
			jobErr := fmt.Errorf("platform: terminating job object: %w", err)
			if leaderErr := terminateProcess(pid); leaderErr != nil {
				return errors.Join(jobErr, leaderErr)
			}
			return jobErr
		}
		// Best effort, and deliberately unchecked: it is normally already dead.
		_ = terminateProcess(pid)
		return nil
	}
	return terminateProcess(pid)
}

// terminateProcess kills a single process, treating "it already exited" as
// success rather than as the access-denied error Windows reports for it.
func terminateProcess(pid uint32) error {
	h, err := windows.OpenProcess(
		windows.PROCESS_TERMINATE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		// Only the errors that actually mean "no such process" may be reported
		// as one. An OpenProcess that fails because this agent may not touch
		// the process — the re-adoption path asks about pids it no longer owns
		// — says the process is there and alive, and reporting that as
		// ErrProcessNotFound tells the supervisor to stop trying and mark a
		// running process dead. See processGone.
		if processGone(err) {
			return fmt.Errorf("platform: pid %d: %w", pid, ErrProcessNotFound)
		}
		return fmt.Errorf("platform: opening pid %d to terminate it: %w", pid, err)
	}
	defer func() { _ = windows.CloseHandle(h) }()

	if processExited(h) {
		return nil
	}
	if err := windows.TerminateProcess(h, 1); err != nil {
		// It can exit on its own between the check and the call.
		if processExited(h) {
			return nil
		}
		return fmt.Errorf("platform: terminating pid %d: %w", pid, err)
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

// Close releases the job handle. When the group was created with
// GroupConfig.KillOnClose, this is what kills the tree — the last handle
// closing is the trigger.
func (g *ProcessGroup) Close() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return nil
	}
	g.closed = true
	if g.job == 0 {
		return nil
	}
	job := g.job
	g.job = 0
	if err := windows.CloseHandle(job); err != nil {
		return fmt.Errorf("platform: closing job object: %w", err)
	}
	return nil
}
