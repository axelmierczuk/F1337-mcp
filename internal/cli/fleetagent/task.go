package fleetagent

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/kardianos/service"
)

// scheduledTask registers the agent as a logon-triggered Scheduled Task, so it
// runs in the operator's own interactive session rather than in session 0.
//
// # Why schtasks.exe and not the COM API
//
// Registering a task means ITaskService, which is COM, and driving COM from Go
// means hand-rolled vtable calls against six interfaces. schtasks.exe is
// present on every Windows this agent supports, takes the same XML the API
// does, and its failures come back as text an operator can act on. The one
// thing it is fussy about — the file must be UTF-16 with a BOM — is handled by
// TaskXMLBytes and is why that function has a comment longer than its body.
//
// # Why the state comes from the runtime report and not from schtasks
//
// Every human-readable field schtasks and its /FO switches print is localised:
// "Ready", "Running" and "Disabled" come back translated on a non-English
// install, and a status command that reads them is one that reports "not
// running" on a German workstation. Existence is read from an exit code, which
// is not translated, and running-ness from the report the daemon itself wrote —
// which is a stronger claim anyway, since it names the process rather than the
// scheduler's opinion of it.
//
// # Why this file is not _windows.go
//
// Nothing in it is a Windows API: it is argv, a temp file and an exit code. No
// runner here can register a task — that needs an elevated token and a real
// Task Scheduler — so if this compiled only on Windows, the argv each step
// invokes and the bytes the file it points schtasks at actually holds would be
// asserted by nothing anywhere. The definition would be a pure function that
// nothing was ever shown to hand to anything. Keeping the type portable and
// the invocation injectable is what closes that gap; see run.
type scheduledTask struct {
	params UnitParams
	// run invokes schtasks.exe with these arguments. nil means runSchtasks,
	// which is what every real install uses. A test supplies its own, and that
	// is the only way anything on any runner here sees the argv.
	run func(args ...string) error
	// endBudget bounds Restart's wait for the instance it ended. Zero means
	// taskEndBudget, which is what every real command uses.
	endBudget time.Duration
	// stateDir is where Status looks for the report the running daemon wrote.
	// nil means reportDir, which prefers the state directory this task was
	// built with.
	stateDir func() string
}

// reportDir is the state directory Status reads the daemon's own record out of.
//
// params.StateDir first, because a registration built by `install` was built
// from a resolved config and `install` takes --config. stateDirForStatus
// re-discovers a config instead, and the two are the same directory only when
// the operator did not move it: `install --config D:\fleet\agent.yaml` on a
// host that also carries C:\ProgramData\fleet\agent.yaml asked the wrong
// directory whether the daemon was running, and got "no", because that
// directory holds another agent's record or none at all.
//
// What that cost is the whole of the replacement. `install` decides three
// things on this answer: whether to warn that removing the task will terminate
// every process the agent supervises, whether to stop it first, and whether to
// start the new registration afterwards. A wrong "not running" skips all three
// — so `/Delete` ends the task anyway, taking the supervised processes with it
// with nothing said, and the agent is left down. The fifth audit round found
// the same mistaken directory in `service status`, where it printed `running`
// with no record to show for it; this is the same gap in the command that acts.
//
// An empty StateDir — a config that does not set one — falls back to the
// discovery every other command uses.
func (t *scheduledTask) reportDir() string {
	if t.stateDir != nil {
		return t.stateDir()
	}
	if t.params.StateDir != "" {
		return t.params.StateDir
	}
	return stateDirForStatus()
}

// schtasks invokes the Task Scheduler command-line tool.
func (t *scheduledTask) schtasks(args ...string) error {
	if t.run != nil {
		return t.run(args...)
	}
	return runSchtasks(args...)
}

// Install writes the task definition, replacing any existing one.
func (t *scheduledTask) Install() error {
	if t.params.Executable == "" {
		return errors.New("scheduled task: no executable to register")
	}
	dir, err := os.MkdirTemp("", "fleet-task-")
	if err != nil {
		return fmt.Errorf("scheduled task: create a temporary directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()

	path := filepath.Join(dir, ServiceName+".xml")
	if err := os.WriteFile(path, TaskXMLBytes(t.params.ScheduledTaskXML()), 0o600); err != nil {
		return fmt.Errorf("scheduled task: write the definition: %w", err)
	}
	// /F replaces an existing task, which is what makes `service install`
	// idempotent here the way it is for the other two mechanisms.
	if err := t.schtasks("/Create", "/TN", ServiceName, "/XML", path, "/F"); err != nil {
		return fmt.Errorf("register the scheduled task: %w", err)
	}
	return nil
}

func (t *scheduledTask) Uninstall() error {
	if err := t.schtasks("/Delete", "/TN", ServiceName, "/F"); err != nil {
		return fmt.Errorf("remove the scheduled task: %w", err)
	}
	return nil
}

func (t *scheduledTask) Start() error {
	if err := t.schtasks("/Run", "/TN", ServiceName); err != nil {
		return fmt.Errorf("start the scheduled task: %w", err)
	}
	return nil
}

// Stop ends the running task.
//
// Task Scheduler ends a task by terminating the processes it started, which is
// not what a service manager stop does and not what this daemon wants: the
// supervised background processes belong to the host, not to the agent. The
// `service stop` command says so before calling this; see runServiceControl.
func (t *scheduledTask) Stop() error {
	if err := t.schtasks("/End", "/TN", ServiceName); err != nil {
		return fmt.Errorf("stop the scheduled task: %w", err)
	}
	return nil
}

// Restart ends the task, waits for what it ended to be gone, and starts it
// again.
//
// The end is best-effort on purpose, which is the difference between this and
// the obvious `if err := Stop(); err != nil { return err }`. `schtasks /End`
// fails when there is no instance to end, and that is exactly the state
// `service install` leaves a task in: replacing the definition means deleting
// the task, which ends it, and install then restarts what it found running.
// Refusing to start because the stop failed leaves the agent down with a
// "note:" line as the only sign of it — the whole point of the restart is to
// be running the new definition, and the start is the half that achieves it.
//
// The wait between them is what makes the start mean anything, and it is there
// because neither verb is what it looks like. `/End` asks the scheduler to
// terminate the instance and returns; it does not wait for it. `/Run` asks the
// scheduler to start one, and this definition sets MultipleInstancesPolicy
// IgnoreNew — deliberately, so a second logon does not start a second daemon —
// which means a run requested while the previous instance is still on its way
// out is *dropped*. schtasks prints "SUCCESS: Attempted to run the scheduled
// task" and exits zero either way, so `service restart` reported success and
// left the agent down, intermittently, with nothing anywhere to read.
//
// It is waited out against the daemon's own record rather than against
// anything schtasks prints, for the reason Status is: every human-readable
// field the scheduler prints is localised, and an exit code cannot say "still
// running". The record is the process saying which process it is, and the
// instance is over when that process is gone.
func (t *scheduledTask) Restart() error {
	stopErr := t.Stop()
	t.awaitEnded()
	if err := t.Start(); err != nil {
		if stopErr != nil {
			return fmt.Errorf("%w (ending it first also failed: %w)", err, stopErr)
		}
		return err
	}
	return nil
}

// taskEndBudget bounds the wait for the instance `/End` was asked to end.
//
// Ending a task is a termination, not a drain — Task Scheduler kills the job —
// so a daemon that is still there after this long is one nothing here is going
// to outlast, and starting anyway is better than refusing to. It is a ceiling
// that is not reached on a host where the end worked.
const taskEndBudget = 5 * time.Second

// taskEndPoll is how often the daemon's record is re-read while waiting.
const taskEndPoll = 50 * time.Millisecond

// awaitEnded waits, bounded, until no daemon is running out of this task's
// state directory. It returns immediately when there is nothing to wait for,
// which is every case except the one it exists for.
func (t *scheduledTask) awaitEnded() {
	budget := t.endBudget
	if budget <= 0 {
		budget = taskEndBudget
	}
	stateDir := t.reportDir()
	deadline := time.Now().Add(budget)
	for liveRuntimeReport(stateDir) != nil {
		if time.Now().After(deadline) {
			return
		}
		time.Sleep(taskEndPoll)
	}
}

// installed reports whether a task is registered under the agent's name.
//
// /XML is asked for rather than a formatted listing because the answer wanted
// here is the exit code, and asking for the definition makes that exit code
// mean "the task exists" on every locale.
//
// A method rather than the free function it used to be, for the reason the rest
// of this type is not build-tagged: composed in task_windows.go it was one more
// argv handed to schtasks.exe that nothing on any runner could see, and it is
// the argv `status` and `install` decide "is this host already registered" on.
func (t *scheduledTask) installed() bool {
	return t.schtasks("/Query", "/TN", ServiceName, "/XML", "ONE") == nil
}

// Status answers existence from schtasks' exit code and running-ness from the
// report the daemon itself wrote; see the file comment for why neither comes
// from what schtasks prints.
func (t *scheduledTask) Status() (service.Status, error) {
	if !t.installed() {
		return service.StatusUnknown, service.ErrNotInstalled
	}
	if liveRuntimeReport(t.reportDir()) != nil {
		return service.StatusRunning, nil
	}
	return service.StatusStopped, nil
}

// runSchtasks invokes schtasks.exe, folding a non-zero exit into an error that
// carries what it printed.
//
// The output is only ever wanted when something went wrong: every command here
// either succeeds or has to explain itself, and what schtasks prints on success
// is a localised sentence saying it worked.
func runSchtasks(args ...string) error {
	exe := "schtasks.exe"
	if root := os.Getenv("SystemRoot"); root != "" {
		// Resolved rather than left to PATH: the daemon and the installer both
		// run with environments this repository deliberately keeps small, and a
		// bare name would be one more thing to be missing.
		exe = filepath.Join(root, "System32", "schtasks.exe")
	}
	out, err := exec.Command(exe, args...).CombinedOutput() //nolint:gosec // fixed argv; the only variable is a temp path this process just wrote
	if err == nil {
		return nil
	}
	if text := strings.TrimSpace(string(out)); text != "" {
		return fmt.Errorf("%w: %s", err, text)
	}
	return err
}
