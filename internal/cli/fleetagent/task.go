package fleetagent

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

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

// Restart ends the task and starts it again.
//
// The end is best-effort on purpose, which is the difference between this and
// the obvious `if err := Stop(); err != nil { return err }`. `schtasks /End`
// fails when there is no instance to end, and that is exactly the state
// `service install` leaves a task in: replacing the definition means deleting
// the task, which ends it, and install then restarts what it found running.
// Refusing to start because the stop failed leaves the agent down with a
// "note:" line as the only sign of it — the whole point of the restart is to
// be running the new definition, and the start is the half that achieves it.
func (t *scheduledTask) Restart() error {
	stopErr := t.Stop()
	if err := t.Start(); err != nil {
		if stopErr != nil {
			return fmt.Errorf("%w (ending it first also failed: %w)", err, stopErr)
		}
		return err
	}
	return nil
}

func (t *scheduledTask) Status() (service.Status, error) {
	if !scheduledTaskInstalled() {
		return service.StatusUnknown, service.ErrNotInstalled
	}
	if liveRuntimeReport(stateDirForStatus()) != nil {
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
