package fleetagent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	agentexec "github.com/axelmierczuk/fleet-mcp/internal/agent/exec"
	"github.com/axelmierczuk/fleet-mcp/internal/fsutil"
	"github.com/axelmierczuk/fleet-mcp/internal/platform"
)

// runtimeReportName is the file the daemon records its own environment in,
// inside the state directory.
const runtimeReportName = "runtime.json"

// runtimeReport is what the running daemon found out about the environment it
// was actually started in.
//
// It exists because `service status` runs as the operator, in the operator's
// session, and everything worth knowing about a confined agent is only
// observable from inside the confinement. Status can see that a service is
// registered and running; it cannot see that the process behind it has a
// machine-only PATH and a service profile for a home directory. So the daemon
// writes down what it found, once, at start, and status reads it back.
//
// The pid and start identity are what keep it honest: a report is a record of
// one process, and a record whose process is gone says nothing about the one
// running now. See liveRuntimeReport.
type runtimeReport struct {
	PID        int       `json:"pid"`
	StartID    string    `json:"start_id"`
	StartedAt  time.Time `json:"started_at"`
	Executable string    `json:"executable"`
	Version    string    `json:"version"`
	// Account is the account the daemon is running as, as the platform names
	// it — not as the service definition named it, which is the point: the two
	// disagreeing is itself worth seeing.
	Account string `json:"account"`
	// Home is the home directory the daemon was started with.
	Home string `json:"home"`
	// SessionZero reports that the daemon is in Windows session 0, isolated
	// from every interactive session. Always false elsewhere.
	SessionZero bool `json:"session_zero"`
	// Profile is what a command spawned by this daemon can see of the per-user
	// installs under Home.
	Profile profileResult `json:"profile"`
}

// collectRuntimeReport records what this process can tell about its own
// environment.
//
// The PATH and home directory come from the base environment the exec service
// hands every command, not from this process's own environment, because the
// claim being recorded is about the commands — "a per-user toolchain resolves
// and runs" is worth nothing if it is asserted against a PATH no command is
// given.
func collectRuntimeReport(ctx context.Context) *runtimeReport {
	base := agentexec.BaseEnv()
	path, _ := agentexec.EnvValue(base, "PATH")
	home, _ := agentexec.EnvValue(base, "HOME")
	if home == "" {
		home, _ = agentexec.EnvValue(base, "USERPROFILE")
	}

	rep := &runtimeReport{
		PID:         os.Getpid(),
		StartedAt:   time.Now().UTC(),
		Version:     reportedVersion(),
		Account:     currentAccount(),
		Home:        home,
		SessionZero: inSessionZero(),
	}
	if exe, err := os.Executable(); err == nil {
		rep.Executable = exe
	}
	if info, err := platform.StatProcess(rep.PID); err == nil {
		rep.StartID = info.StartID
	}
	rep.Profile = profileProbe{Home: home, Path: path}.probe(ctx)
	return rep
}

// runtimeReportPath is where the report lives for a given state directory.
func runtimeReportPath(stateDir string) string {
	return filepath.Join(stateDir, runtimeReportName)
}

// writeRuntimeReport records the report where `service status` will look.
//
// 0644, and nothing in it is a secret: a pid, an account name, a home
// directory, and the names of directories that are or are not on PATH. It has
// to be readable by an operator who is not elevated, because `service status`
// is not an elevated command.
func writeRuntimeReport(stateDir string, rep *runtimeReport) error {
	data, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return fmt.Errorf("encode runtime report: %w", err)
	}
	// The daemon can start before anything has created the state directory —
	// `serve` run by hand against a fresh config does exactly that — and
	// WriteAtomic writes its temp file into the destination directory.
	if err := os.MkdirAll(stateDir, 0o750); err != nil {
		return fmt.Errorf("create %s: %w", stateDir, err)
	}
	return fsutil.WriteAtomic(runtimeReportPath(stateDir), append(data, '\n'), 0o644)
}

// readRuntimeReport loads whatever the last daemon to start wrote.
func readRuntimeReport(stateDir string) (*runtimeReport, error) {
	data, err := os.ReadFile(runtimeReportPath(stateDir))
	if err != nil {
		return nil, err
	}
	rep := &runtimeReport{}
	if err := json.Unmarshal(data, rep); err != nil {
		return nil, fmt.Errorf("parse %s: %w", runtimeReportPath(stateDir), err)
	}
	return rep, nil
}

// liveRuntimeReport returns the report only when the process that wrote it is
// still the process running, and nil for every other outcome.
func liveRuntimeReport(stateDir string) *runtimeReport {
	rep, _ := readLiveRuntimeReport(stateDir)
	return rep
}

// readLiveRuntimeReport is liveRuntimeReport plus the reason it has nothing to
// return, for the one caller that has somewhere to print it.
//
// Fail-closed, and for the reason the supervisor's own pid guard is: a stale
// report is worse than none. The file outlives the daemon — a stopped agent
// leaves its last one behind — and pids come back around, so "the pid in the
// file exists" is not the same question as "the pid in the file is still this
// daemon". platform.SameProcess is the one that asks the second.
//
// A report with no start identity is refused too. It means the daemon could not
// read its own process start time, and a record that cannot be tied to a
// process is exactly the thing this guard exists to keep out of `status`.
//
// The error is separated from those two because they are different answers. No
// file, or a file describing a process that is gone, is an ordinary state and
// says nothing. A file that is there and cannot be read or parsed is `status`
// being unable to reach the only source of every answer it gives about a
// confined agent — and on Linux that is the common case, not the exotic one:
// `install` gives the state directory to the service account at 0750, so an
// operator who is not in that group gets EACCES here. Reported as "no report",
// that silently turned the whole verdict off and still exited zero.
func readLiveRuntimeReport(stateDir string) (*runtimeReport, error) {
	rep, err := readRuntimeReport(stateDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	if !platform.SameProcess(rep.PID, rep.StartID) {
		return nil, nil
	}
	return rep, nil
}
