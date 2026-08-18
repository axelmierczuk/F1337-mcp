package fleetagent

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/axelmierczuk/fleet-mcp/internal/agent"
	"github.com/axelmierczuk/fleet-mcp/internal/fsutil"
	"github.com/axelmierczuk/fleet-mcp/internal/version"
)

// startFailureName is the file a daemon that could not start leaves behind,
// beside the runtime report in the state directory.
const startFailureName = "start-failure.json"

// startFailure is why the last attempt to start this agent did not become a
// running daemon.
//
// It exists because on both Windows mechanisms the reason is otherwise
// destroyed, and #98 is what that costs. A service registered through the SCM
// has its stderr discarded: the daemon prints four precise lines naming the
// listen address, the consequence and three ways out, exits before it can
// perform the SCM's start handshake, and the operator is shown "Error 1053: the
// service did not respond to the start or control request in a timely fashion"
// — a timeout, about an address, with nothing anywhere naming the address. A
// Scheduled Task is worse: `schtasks /Run` succeeds, the daemon dies, and
// nothing is reported at all.
//
// So the daemon writes down why, where `service status` already looks for the
// record a *running* daemon leaves. The two are deliberately separate files:
// runtime.json describes a daemon that started and is a record of one live
// process, and this describes one that did not and has to outlive the process
// that wrote it.
//
// Nothing in it is a secret — a timestamp, this binary's version, a pid, the
// config path, and an error this daemon would have printed to a terminal — and
// it is written 0644 for the reason the runtime report is: `service status` is
// not an elevated command.
type startFailure struct {
	// At is when the start was attempted, in UTC for the reason
	// runtimeReport.StartedAt is.
	At time.Time `json:"at"`
	// Config is the config the daemon was started with, empty when the failure
	// was that there was no config to resolve.
	Config string `json:"config,omitempty"`
	// Version is the binary that failed, which is not always the binary an
	// operator is now running: an upgrade that changed the definition's path is
	// exactly when this record is worth having.
	Version string `json:"version"`
	// PID is the process that failed. It is there so a record can be tied to a
	// line in the event log or a journal entry, not to decide anything: the
	// process is gone by the time anything reads this.
	PID int `json:"pid"`
	// Error is what the daemon would have printed to a terminal, verbatim and
	// including the remedy. The whole point is that it is not paraphrased.
	Error string `json:"error"`
}

// startFailurePath is where the record lives for a given state directory.
func startFailurePath(stateDir string) string {
	return filepath.Join(stateDir, startFailureName)
}

// startFailureSite is where a failure to start would be recorded, answerable
// before the config has loaded and narrowed by each step that learns more.
//
// The state directory is a config field, so a daemon that cannot find or parse
// its config does not know it — and that is one of the failures most worth
// recording. It falls back to the default, which is where `service status`
// looks under the same circumstances; see stateDirForStatus.
type startFailureSite struct {
	configPath string
	stateDir   string
}

// dir is the state directory this failure is recorded in.
func (s startFailureSite) dir() string {
	if s.stateDir != "" {
		return s.stateDir
	}
	return agent.DefaultStateDir()
}

// record writes why the daemon could not start.
//
// Best-effort, for the reason recordRuntime is: this is a daemon that has
// already failed, and a second failure while explaining the first is not worth
// replacing the first one's message with. The state directory may not exist —
// `serve` run by hand against a fresh config, or a config whose directory the
// account cannot write — and the operator still has the error on stderr in
// every case where they can see stderr at all.
func (s startFailureSite) record(err error) {
	if err == nil {
		return
	}
	rec := &startFailure{
		At:      time.Now().UTC(),
		Config:  s.configPath,
		Version: reportedVersion(),
		PID:     os.Getpid(),
		Error:   err.Error(),
	}
	_ = writeStartFailure(s.dir(), rec)
}

// clear removes a record the last failed start left, because this start did
// not fail.
//
// Called once the daemon has bound its listener, which is the first moment
// "this agent started" is true. Without it the first successful start after a
// failed one leaves `service status` reporting a failure that has been fixed,
// which is its own wrong answer and a worse one: an operator who fixed the
// config would read it as their fix not having taken.
func (s startFailureSite) clear() {
	clearStartFailure(s.dir())
}

// writeStartFailure records the failure where `service status` will look.
func writeStartFailure(stateDir string, rec *startFailure) error {
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	// WriteAtomic writes its temp file into the destination directory, and a
	// daemon can fail to start before anything has created that directory.
	if err := os.MkdirAll(stateDir, 0o750); err != nil {
		return err
	}
	return fsutil.WriteAtomic(startFailurePath(stateDir), append(data, '\n'), 0o644)
}

// readStartFailure loads the record, or nil when there is none.
//
// A record that cannot be read or parsed is reported as an error rather than as
// "no failure", for the reason readLiveRuntimeReport separates the two: silence
// about a file that is there is how a command tells an operator everything is
// fine while being unable to ask the question.
func readStartFailure(stateDir string) (*startFailure, error) {
	data, err := os.ReadFile(startFailurePath(stateDir))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	rec := &startFailure{}
	if err := json.Unmarshal(data, rec); err != nil {
		return nil, err
	}
	return rec, nil
}

// clearStartFailure removes the record, ignoring its absence.
func clearStartFailure(stateDir string) {
	_ = os.Remove(startFailurePath(stateDir))
}

// startFailureNotes is what `service status` says about a start that failed.
//
// A pure function of the record, so what an operator is told is asserted on
// every runner while the record itself is only ever written by a daemon that
// failed to start — which on the mechanisms this matters for is a daemon no
// runner here can register. It is the same split as confinementFor.
func startFailureNotes(rec *startFailure) []string {
	if rec == nil {
		return nil
	}
	lines := []string{
		"",
		"LAST START FAILED",
		"  The last attempt to start this agent, at " + rec.At.UTC().Format(time.RFC3339) + ", ended with:",
	}
	for _, line := range strings.Split(strings.TrimRight(rec.Error, "\n"), "\n") {
		lines = append(lines, indented("    ", line))
	}
	lines = append(lines, "")
	if rec.Config != "" {
		lines = append(lines, "  config:  "+rec.Config)
	}
	if rec.Version != "" {
		lines = append(lines, "  version: "+rec.Version)
	}
	lines = append(lines,
		"  Recorded by the daemon itself, because nothing else keeps it: Windows",
		"  reports a service that exits before its start handshake as a timeout —",
		"  error 1053 — and the Task Scheduler reports a task whose process died as",
		"  nothing at all. Fix the cause above and run `fleet-agent service start`.")
	return lines
}

// startupFailureMessage is what a daemon started by a service manager hands
// that manager's own log when it cannot start: the Windows event log, journald,
// or launchd's error path.
//
// It carries the error verbatim, remedy included. The operator reading
// services.msc or `Get-EventLog -LogName Application -Source fleet-agent` is
// the same operator who would have read it on a terminal, and paraphrasing it
// there is what turned "listen on a loopback or private address" into a
// 30-second timeout.
func startupFailureMessage(err error) string {
	if err == nil {
		return ""
	}
	return ServiceName + " " + version.String() + " could not start, and is not running:\n\n" + err.Error()
}
