package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Outcome is the terminal state of an audited operation.
type Outcome string

const (
	// OutcomeOK is a command that ran to completion, whatever it exited with.
	// A non-zero exit is not an audit failure: the exit status is a separate
	// field, and conflating them would lose the difference between "the build
	// failed" and "the agent refused to run the build".
	OutcomeOK Outcome = "ok"
	// OutcomeDenied is a command the policy refused. This is the record the
	// log exists for.
	OutcomeDenied Outcome = "denied"
	// OutcomeTimedOut is a command the agent killed for exceeding its timeout.
	OutcomeTimedOut Outcome = "timed_out"
	// OutcomeCancelled is a command the agent killed because the caller went
	// away.
	OutcomeCancelled Outcome = "cancelled"
	// OutcomeError is a request that failed before or during the spawn: no
	// such executable, an unusable working directory, a cap exceeded.
	OutcomeError Outcome = "error"
)

// Record is one line of the audit log.
//
// # What is deliberately absent
//
// There is no field for environment values, file contents, stdin, command
// output, or the enrollment token, and none may be added. An audit log that
// captures secrets is a new place to steal them from, and it is a place with
// weaker handling than the thing it copied them out of: it is world-readable
// on some hosts by the time an operator has finished debugging it, it is
// shipped off-box, and it is kept long after the credential it captured was
// supposed to have been rotated.
//
// The rule is about the record and not only about its field list, because an
// error string is a field too and a caller chooses much of what goes into one.
// A PATH quoted into "not in PATH (...)" is an environment value however it
// arrived. A writer holding an error that carries environment data must record
// a redacted line and hand the caller the unredacted one — see exec's
// failRedacted, and the test that reverts it.
//
// Argv is recorded, and that is the one place a caller can put a secret into
// this file — "mysql -pHUNTER2" writes it down. That is a real limitation
// rather than an oversight: the argument list is the whole point of an exec
// record, and there is no reliable way to tell a password from a path. Pass
// credentials in the environment, which is never recorded.
type Record struct {
	Time      time.Time `json:"time"`
	Principal string    `json:"principal"`
	// RPC is the fully qualified method, e.g. "sandboxd.v1.ExecService/Exec".
	RPC     string  `json:"rpc"`
	Outcome Outcome `json:"outcome"`

	// Argv is the command as it will be executed, and Path the executable it
	// resolved to. Both are recorded because the policy decision was made on
	// the resolved path and an operator reading the log needs to see what the
	// caller asked for as well as what it got.
	Argv []string `json:"argv,omitempty"`
	Path string   `json:"path,omitempty"`
	// WorkingDir is the directory the command ran in, resolved.
	WorkingDir string `json:"working_dir,omitempty"`
	// Shell records that the command was routed through the platform shell.
	Shell bool `json:"shell,omitempty"`

	// ExitCode is a pointer so that "exited 0" and "never ran" are different
	// records rather than the same one.
	ExitCode   *int32 `json:"exit_code,omitempty"`
	Signal     string `json:"signal,omitempty"`
	TimedOut   bool   `json:"timed_out,omitempty"`
	Truncated  bool   `json:"truncated,omitempty"`
	DurationMS int64  `json:"duration_ms,omitempty"`

	// Rule is the policy entry that decided a refusal.
	Rule string `json:"rule,omitempty"`
	// Error is the failure the caller was told about. It is written by the
	// agent, never echoed from a subprocess, so it cannot carry output.
	Error string `json:"error,omitempty"`

	// Bytes and Lines describe an audited filesystem operation's size, for
	// #8–#10. Never its content.
	Bytes int64 `json:"bytes,omitempty"`
	Lines int64 `json:"lines,omitempty"`
}

// AuditConfig configures the append-only log.
type AuditConfig struct {
	// Path is the JSONL file. Rotated segments live beside it as .1, .2, …
	Path string
	// Enabled turns recording on. A disabled log accepts writes and drops
	// them, so no call site needs a nil check.
	Enabled bool
	// Required fails the RPC whose record could not be written. Without it a
	// write failure is logged by the caller and the call proceeds.
	//
	// This is a real choice rather than a default. An agent that must not act
	// unrecorded is one setting; an agent that must keep serving when its log
	// volume fills is the other. Guessing either one for an operator is how a
	// build fleet goes down at 3am because a disk filled, or how a compliance
	// requirement quietly stops being met.
	Required bool
	// MaxBytes is the size at which the log rotates. Zero disables rotation.
	MaxBytes int64
	// RetainSegments is how many rotated segments are kept. Older ones are
	// deleted at each rotation.
	RetainSegments int
}

// Audit is the append-only JSONL record. It is safe for concurrent use, and
// there must be exactly one per log file in a daemon: rotation renames the
// file out from under every other writer, so a second instance would drop
// records into a segment nobody reads again.
type Audit struct {
	cfg AuditConfig

	mu   sync.Mutex
	file *os.File
	size int64

	// needsSeparator records that the file does not end in a newline, so the
	// next record must start one. See ensureOpenLocked.
	needsSeparator bool
}

// NewAudit builds the log. It does not open the file: see Preflight.
func NewAudit(cfg AuditConfig) *Audit {
	if cfg.Enabled && cfg.Path == "" {
		cfg.Enabled = false
	}
	return &Audit{cfg: cfg}
}

// Enabled reports whether records are being written.
func (a *Audit) Enabled() bool { return a != nil && a.cfg.Enabled }

// Required reports whether a failed write must fail its RPC.
func (a *Audit) Required() bool { return a != nil && a.cfg.Enabled && a.cfg.Required }

// Path returns the configured log path.
func (a *Audit) Path() string {
	if a == nil {
		return ""
	}
	return a.cfg.Path
}

// Preflight opens the log once at startup so a misconfigured path is visible
// then rather than at the first RPC.
//
// It reports the failure; it does not abort. The daemon logs it loudly and
// keeps serving, because a log directory that does not exist yet is a
// different problem from an agent that cannot run commands — and when the
// operator has said records are Required, every affected RPC fails anyway,
// which is the same refusal delivered where the caller can see it. A path that
// becomes writable later starts recording without a restart.
func (a *Audit) Preflight() error {
	if !a.Enabled() {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.ensureOpenLocked()
}

// Write appends one record.
//
// The record is serialised and written under the lock, as a single append, so
// concurrent RPCs produce whole interleaved-free lines rather than fragments
// of two records on one line.
func (a *Audit) Write(rec Record) error {
	if !a.Enabled() {
		return nil
	}
	if rec.Time.IsZero() {
		rec.Time = time.Now().UTC()
	}

	line, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("policy: encode audit record: %w", err)
	}
	line = append(line, '\n')

	a.mu.Lock()
	defer a.mu.Unlock()

	if err := a.ensureOpenLocked(); err != nil {
		return err
	}
	if err := a.rotateIfNeededLocked(int64(len(line))); err != nil {
		return err
	}
	if a.needsSeparator {
		line = append([]byte{'\n'}, line...)
	}

	n, err := a.file.Write(line)
	a.size += int64(n)
	a.needsSeparator = n != len(line)
	if err != nil {
		// Drop the handle so the next write retries the open. A file on a
		// volume that went away does not come back by being written to again.
		_ = a.closeLocked()
		return fmt.Errorf("policy: append audit record to %s: %w", a.cfg.Path, err)
	}
	return nil
}

// Close flushes and releases the file. Further writes reopen it.
func (a *Audit) Close() error {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.closeLocked()
}

func (a *Audit) closeLocked() error {
	if a.file == nil {
		return nil
	}
	err := a.file.Close()
	a.file = nil
	a.size = 0
	if err != nil {
		return fmt.Errorf("policy: close audit log %s: %w", a.cfg.Path, err)
	}
	return nil
}

// ensureOpenLocked opens the log if it is not already open.
func (a *Audit) ensureOpenLocked() error {
	if a.file != nil {
		return nil
	}

	if dir := filepath.Dir(a.cfg.Path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("policy: create audit log directory %s: %w", dir, err)
		}
	}

	// O_APPEND, so every write lands at the end whatever else is holding the
	// file open, and 0600, because the records name the principal and the
	// commands a fleet is running. O_RDWR rather than O_WRONLY only so the
	// last byte can be read back below; appends still go to the end.
	f, err := os.OpenFile(a.cfg.Path, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0o600) //nolint:gosec // the path is operator configuration, not caller input
	if err != nil {
		return fmt.Errorf("policy: open audit log %s: %w", a.cfg.Path, err)
	}

	size := int64(0)
	if info, statErr := f.Stat(); statErr == nil {
		size = info.Size()
	}
	a.file, a.size = f, size
	a.needsSeparator = !endsInNewline(f, size)
	return nil
}

// endsInNewline reports whether the log's last byte terminates a record.
//
// A file that does not end in a newline was cut mid-record: os.File.Write can
// return a positive count together with an error — a full disk is the ordinary
// way — and a process killed between two write syscalls does the same thing.
// Appending straight onto that stump would splice two records into one
// unparseable line, losing the new record as well as the broken one. Starting a
// fresh line instead costs a byte and confines the damage to the record that
// was actually interrupted.
//
// A read failure reads as "ends in a newline": the alternative is a stray blank
// line at the head of every segment on a filesystem that will not seek.
func endsInNewline(f *os.File, size int64) bool {
	if size == 0 {
		return true
	}
	var last [1]byte
	if _, err := f.ReadAt(last[:], size-1); err != nil {
		return true
	}
	return last[0] == '\n'
}

// rotateIfNeededLocked rotates when appending would take the file past
// MaxBytes.
//
// The check is before the write rather than after, so a segment never exceeds
// the cap an operator sized their volume against. A single record larger than
// the cap is written anyway, into an otherwise empty segment: dropping it
// would lose the audit trail for exactly the calls with the longest argument
// lists.
func (a *Audit) rotateIfNeededLocked(incoming int64) error {
	if a.cfg.MaxBytes <= 0 || a.size == 0 || a.size+incoming <= a.cfg.MaxBytes {
		return nil
	}

	if err := a.closeLocked(); err != nil {
		return err
	}

	// Shift the retained segments down, oldest first, then move the live file
	// into .1. Renaming rather than copying means a record is in exactly one
	// file at every instant.
	if a.cfg.RetainSegments > 0 {
		oldest := fmt.Sprintf("%s.%d", a.cfg.Path, a.cfg.RetainSegments)
		if err := os.Remove(oldest); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("policy: remove expired audit segment %s: %w", oldest, err)
		}
		for i := a.cfg.RetainSegments - 1; i >= 1; i-- {
			from := fmt.Sprintf("%s.%d", a.cfg.Path, i)
			to := fmt.Sprintf("%s.%d", a.cfg.Path, i+1)
			if err := os.Rename(from, to); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("policy: rotate audit segment %s: %w", from, err)
			}
		}
		if err := os.Rename(a.cfg.Path, a.cfg.Path+".1"); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("policy: rotate audit log %s: %w", a.cfg.Path, err)
		}
	} else if err := os.Remove(a.cfg.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
		// No segments retained: the cap is a hard ceiling on disk use, and the
		// operator asked for the old records to go.
		return fmt.Errorf("policy: truncate audit log %s: %w", a.cfg.Path, err)
	}

	return a.ensureOpenLocked()
}
