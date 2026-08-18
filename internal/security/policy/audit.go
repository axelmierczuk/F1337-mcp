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

// PrincipalSource says what established a record's principal, so that a
// principal nothing verified can never be read as one that was.
//
// It is written by the agent from its own transport configuration, never from
// anything a caller sends.
type PrincipalSource string

const (
	// PrincipalCertificate means the principal is the common name of a client
	// certificate the agent verified against the fleet CA.
	PrincipalCertificate PrincipalSource = "certificate"
	// PrincipalNetwork means the agent is serving without mTLS and
	// authenticated nobody: the principal names the address the connection came
	// from, and whatever decided it was allowed to arrive is the network.
	PrincipalNetwork PrincipalSource = "network"
)

// Record is one line of the audit log.
//
// # What is deliberately absent
//
// There is no field for environment values, file contents, stdin, command
// output, what an interactive shell session carried, forwarded payload bytes,
// or the enrollment token, and none may be
// added. An audit log that captures secrets is a new place to steal them from,
// and it is a place with weaker handling than the thing it copied them out of:
// it is world-readable on some hosts by the time an operator has finished
// debugging it, it is shipped off-box, and it is kept long after the
// credential it captured was supposed to have been rotated.
//
// Forwarded traffic and interactive sessions are the sharpest cases. A
// tunnelled connection carries whatever the caller sends through it — a
// database password, a bearer token, a private key on its way to a deploy — and
// a shell session carries whatever the operator types and whatever the host
// prints back, which is the same list plus a sudo prompt. So this record counts
// bytes for one and records neither's contents. A log that captured them would
// be a credential store nobody meant to build, sitting on the least protected
// host in the fleet. internal/agent/shell is shaped so that the audit path
// cannot see a session's bytes at all; see its package comment.
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
	// PrincipalSource is how Principal was established.
	//
	// Absent means "certificate", and that reading is stable in both
	// directions: every record written before #85 was made by an agent for
	// which mTLS was mandatory, and every record written since carries the
	// field. So adding it made no historical record ambiguous — which was the
	// requirement, because a log that quietly changes what its oldest lines
	// mean is worse than one that never had the field.
	PrincipalSource PrincipalSource `json:"principal_source,omitempty"`
	// Sandbox is the agent's own fleet name, stamped by [Audit.Write] from
	// [AuditConfig.Sandbox] rather than filled in per record.
	//
	// It is redundant on the host that wrote it and essential everywhere else:
	// these files are shipped off-box and read together, and a line that does
	// not name the machine it came from cannot be acted on.
	Sandbox string `json:"sandbox,omitempty"`
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

	// The network fields below describe one connection the agent opened on a
	// caller's behalf.
	//
	// They are named for the operation and not for the service that performs
	// it. ForwardService writes them today and the SOCKS proxy of #45 will
	// write the same ones: both are the agent connecting somewhere on request,
	// and an operator asking "what did this machine reach, for whom, and how
	// much went through it" is asking one question, not two. A
	// forward_remote_host would have made the answer depend on which feature
	// happened to be used.
	//
	// One record per connection, not per listener. A forward is a listener
	// that carries many connections over hours, and "a forward was opened"
	// answers nothing about what went through it. The record is written when
	// the connection ends, because that is when the volume and the outcome
	// exist — a connection still open is not yet in the log.

	// RemoteHost and RemotePort are the target as the caller asked for it.
	//
	// The requested host is recorded alongside ResolvedAddress because they
	// are different facts and an investigation needs both. The name is what
	// appeared in the caller's request and what an operator will search for;
	// the address is what the packets actually went to, and a name that
	// resolved somewhere unexpected is precisely the case worth seeing.
	// RemoteHost is empty when the caller named no host, which means loopback.
	RemoteHost string `json:"remote_host,omitempty"`
	RemotePort uint32 `json:"remote_port,omitempty"`
	// ResolvedAddress is the address the connection actually went to, taken
	// from the socket rather than from the request: an allow-listed host is
	// dialed by name, so a field filled in from what was asked for would only
	// ever restate RemoteHost and could never show a name that resolved
	// somewhere unexpected — which is the case it exists for. It is empty when
	// the connection never got that far — refused by configuration, or a name
	// that did not resolve — which is how a reader tells "resolved to this"
	// apart from "never resolved".
	ResolvedAddress string `json:"resolved_address,omitempty"`
	// LocalAddress is the local end of the agent's own outbound socket. It is
	// what joins this record to the host's netflow, conntrack or firewall log,
	// which is the whole reason to keep it.
	LocalAddress string `json:"local_address,omitempty"`
	// BytesToRemote and BytesFromRemote are volumes, never content. They are
	// named from the audited host's point of view, so they read the same way
	// for a forwarded connection and a proxied one.
	BytesToRemote   int64 `json:"bytes_to_remote,omitempty"`
	BytesFromRemote int64 `json:"bytes_from_remote,omitempty"`
}

// AuditConfig configures the append-only log.
type AuditConfig struct {
	// Path is the JSONL file. Rotated segments live beside it as .1, .2, …
	Path string
	// Sandbox is the agent's own fleet name, stamped into every record.
	//
	// It is here rather than filled in by each call site so that no service
	// can forget it, and so that adding one does not mean auditing which
	// records name their host. See [Record.Sandbox].
	Sandbox string
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
	if rec.Sandbox == "" {
		rec.Sandbox = a.cfg.Sandbox
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
