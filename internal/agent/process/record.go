package process

import (
	"crypto/sha256"
	"encoding/hex"
	"os/exec"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	sandboxdv1 "github.com/axelmierczuk/sandboxd-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/sandboxd-mcp/internal/platform"
)

// record is one supervised process: the spec it was started from, the state
// machine's current position, the OS handles for the run in progress, and the
// captured output.
//
// Everything mutable is guarded by mu. The lock is held only across field
// updates — never across a spawn, a wait, a signal or a disk write — so a
// process that takes ten seconds to start does not block ListProcesses.
type record struct {
	sup *Supervisor
	id  string
	dir string // per-process state directory: logs and the persisted record

	buf *logBuffer

	mu sync.Mutex

	// Spec. Fixed at start and reused verbatim by a restart, which is what
	// makes RestartProcess "the same process" rather than a similar one.
	name           string
	argv           []string
	workingDir     string
	env            []string
	shell          bool
	probe          *probeSpec
	restartPolicy  sandboxdv1.RestartPolicy
	maxRestarts    uint32
	restartBackoff time.Duration
	maxLogBytes    int64

	// State machine and its observable consequences.
	state        sandboxdv1.ProcessState
	pid          int
	startID      string
	startedAt    time.Time
	exitedAt     time.Time
	exitCode     int32
	signalName   string
	restartCount uint32
	adoptionNote string

	// restartsDisabled records an intentional stop. The supervisor honours it
	// instead of the restart policy, so a caller that asked a process to stop
	// does not watch it come straight back.
	restartsDisabled bool

	// Handles for the run in progress. All nil for a record in a terminal
	// state, and cmd is nil for a re-adopted process — the agent that spawned
	// it is gone, so there is nothing to wait on and liveness is polled.
	cmd     *exec.Cmd
	group   *platform.ProcessGroup
	cap     *capture
	adopted bool

	// exited is closed when the current run has been reaped. It is replaced on
	// each spawn.
	exited chan struct{}

	// changed is closed and replaced on every observable change. Waiters —
	// readiness probes, graceful stops, follows that end when the process does
	// — take the channel, re-read the state, and block on it. Closing rather
	// than sending means every waiter wakes, and none of them can miss an
	// update that happened between the read and the wait.
	changed chan struct{}

	// probeRun is the readiness attempt for the run in progress, so a caller
	// that asked to wait for readiness and the supervisor goroutine that
	// actually probes are not the same goroutine.
	probeRun *probeRun

	// stability is when the current run started, for the restart-counter reset.
	stability time.Time

	// captureOffsets is how much of each raw capture file has been turned into
	// log lines. Persisted so a re-adopting agent resumes rather than replays.
	captureOffsets [2]int64

	// removed is set by RemoveProcess before the record's directory is deleted,
	// so a transition still in flight cannot write the record back into a
	// directory that is being removed.
	removed bool

	// slot is this record's share of the agent-wide concurrency limit, held
	// for as long as it is live and released the moment it is not. It is a
	// release function rather than a bool because the limit lives in the
	// shared policy — the supervisor deliberately keeps no count of its own,
	// so there is nothing here to decrement.
	slot func()

	// persistMu serialises the write itself, and is what makes the removed
	// flag sufficient. Without it a persist that read removed as false could
	// still be inside WriteAtomic when the directory is deleted, and the rename
	// would recreate the record beside a directory that is being removed —
	// which fails the removal with "directory not empty" rather than anything
	// that names the real cause.
	persistMu sync.Mutex
}

// newRecord builds a record in the zero state. It is not yet spawned and not
// yet registered with the supervisor.
func newRecord(sup *Supervisor, id, dir string) *record {
	return &record{
		sup:     sup,
		id:      id,
		dir:     dir,
		exited:  closedChan(),
		changed: make(chan struct{}),
	}
}

func closedChan() chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}

// setState performs a state machine transition. It is the only place in this
// package that assigns r.state.
//
// mutate runs under the lock, after the transition is accepted and before
// anything observes the new state, so a status snapshot never catches a record
// that is CRASHED but still carrying the previous run's exit code.
func (r *record) setState(to sandboxdv1.ProcessState, mutate func()) error {
	r.mu.Lock()
	from := r.state
	if from == to {
		// Idempotent: the exit path and an explicit stop can both conclude the
		// same thing about the same run.
		if mutate != nil {
			mutate()
		}
		r.notifyLocked()
		r.mu.Unlock()
		r.sup.refreshLive()
		r.persist()
		return nil
	}
	if !canTransition(from, to) {
		r.mu.Unlock()
		return errIllegalTransition(from, to)
	}
	r.state = to
	if mutate != nil {
		mutate()
	}
	r.notifyLocked()
	r.mu.Unlock()

	if isLive(from) && !isLive(to) {
		// The one place a concurrency slot is given back, so that every way a
		// process can stop running gives it back — the ones nobody enumerated
		// as much as the ordinary exit. A slot released per terminal path
		// instead would be a slot leaked by whichever path was added later.
		r.dropSlot()
	}

	r.sup.log.Debug("process state",
		"process_id", r.id, "name", r.name, "from", stateName(from), "to", stateName(to))
	// The supervised-process count Health reports is derived from the states,
	// so it is maintained here rather than at each of the dozen call sites that
	// could otherwise forget.
	r.sup.refreshLive()
	r.persist()
	return nil
}

// restoreState sets the state without consulting the transition table. It
// exists for the adoption path alone, which reconstructs a record that a
// previous agent left in some state rather than moving it through one.
func (r *record) restoreState(to sandboxdv1.ProcessState) {
	r.mu.Lock()
	from := r.state
	r.state = to
	r.notifyLocked()
	r.mu.Unlock()
	if isLive(from) && !isLive(to) {
		// Adoption reaches ORPHANED and CRASHED this way rather than through
		// the table, so the slot has to come back here too.
		r.dropSlot()
	}
	r.sup.refreshLive()
}

// holdSlot attaches a concurrency slot to the record.
//
// A record that already holds one keeps it and the redundant slot goes
// straight back. Assigning over the field instead would drop a release nobody
// else holds, and the agent's limit would shrink by one for the life of the
// daemon — the kind of leak that shows up months later as a limit that no
// longer means the number in the config.
func (r *record) holdSlot(release func()) {
	r.mu.Lock()
	held := r.slot != nil
	if !held {
		r.slot = release
	}
	r.mu.Unlock()
	if held {
		release()
	}
}

// dropSlot returns this record's share of the agent-wide concurrency limit.
//
// Safe when none is held and safe to call twice: the release the limiter hands
// out is itself once-only, and clearing the field means a later restart takes
// a fresh slot rather than reusing a spent release.
func (r *record) dropSlot() {
	r.mu.Lock()
	release := r.slot
	r.slot = nil
	r.mu.Unlock()
	if release != nil {
		release()
	}
}

// notifyLocked wakes every waiter. Callers must hold mu.
func (r *record) notifyLocked() {
	close(r.changed)
	r.changed = make(chan struct{})
}

// wait returns the channel that closes on the next observable change, along
// with the state at the moment it was taken. Take both, act on the state, then
// block on the channel: an update landing in between closes the channel the
// caller already holds, so no wake-up is lost.
func (r *record) wait() (<-chan struct{}, sandboxdv1.ProcessState) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.changed, r.state
}

// currentState reads the state.
func (r *record) currentState() sandboxdv1.ProcessState {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.state
}

// persist writes the record to disk. Every transition calls it, so a killed
// agent finds the state it last announced rather than the state it started in.
func (r *record) persist() {
	r.persistMu.Lock()
	defer r.persistMu.Unlock()

	r.mu.Lock()
	removed := r.removed
	r.mu.Unlock()
	if removed {
		return
	}
	if err := r.sup.store.save(r.snapshotPersisted()); err != nil {
		r.sup.log.Error("could not persist process record",
			"process_id", r.id, "name", r.name, "error", err)
	}
}

// status projects the record onto the wire type.
//
// listening_ports is read here rather than cached, because it is the field a
// model uses to find the dev server it just started and a cached answer from
// before the bind is worse than none. It is best effort: the read costs a
// /proc walk on Linux and an lsof on macOS, and both can come back empty.
func (r *record) status() *sandboxdv1.ProcessStatus {
	logBytes, lastLine, _ := r.buf.stats()

	r.mu.Lock()
	st := &sandboxdv1.ProcessStatus{
		ProcessId:     r.id,
		Name:          r.name,
		Argv:          append([]string(nil), r.argv...),
		WorkingDir:    r.workingDir,
		State:         r.state,
		Pid:           int32(r.pid), //nolint:gosec // a pid does not exceed int32 on any supported platform
		ExitCode:      r.exitCode,
		Signal:        r.signalName,
		RestartCount:  r.restartCount,
		RestartPolicy: r.restartPolicy,
		LastLogLine:   lastLine,
		LogBytes:      logBytes,
		AdoptionNote:  r.adoptionNote,
	}
	if !r.startedAt.IsZero() {
		st.StartedAt = timestamppb.New(r.startedAt)
	}
	if !r.exitedAt.IsZero() {
		st.ExitedAt = timestamppb.New(r.exitedAt)
	}
	pid, live := r.pid, isLive(r.state)
	r.mu.Unlock()

	if live && pid > 0 {
		if ports, err := platform.ListeningPorts(pid); err == nil {
			st.ListeningPorts = ports
		}
	}
	return st
}

// snapshotPersisted captures everything the on-disk record holds.
func (r *record) snapshotPersisted() persisted {
	logBytes, _, _ := r.buf.stats()

	r.mu.Lock()
	defer r.mu.Unlock()

	p := persisted{
		ID:               r.id,
		Name:             r.name,
		Argv:             append([]string(nil), r.argv...),
		ArgvHash:         argvHash(r.argv),
		WorkingDir:       r.workingDir,
		Env:              append([]string(nil), r.env...),
		Shell:            r.shell,
		PID:              r.pid,
		StartID:          r.startID,
		JobName:          jobObjectName(r.id),
		State:            stateName(r.state),
		ExitCode:         r.exitCode,
		Signal:           r.signalName,
		RestartCount:     r.restartCount,
		RestartPolicy:    r.restartPolicy.String(),
		MaxRestarts:      r.maxRestarts,
		RestartBackoffMS: r.restartBackoff.Milliseconds(),
		MaxLogBytes:      r.maxLogBytes,
		AdoptionNote:     r.adoptionNote,
		RestartsDisabled: r.restartsDisabled,
		CaptureOffsets:   r.currentOffsetsLocked(),
		LogBytes:         logBytes,
		Probe:            r.probe.persisted(),
	}
	if !r.startedAt.IsZero() {
		p.StartedAt = r.startedAt
	}
	if !r.exitedAt.IsZero() {
		p.ExitedAt = r.exitedAt
	}
	return p
}

// currentOffsetsLocked prefers the live tailer's position over the last one
// recorded, so a record written mid-run does not rewind the capture.
func (r *record) currentOffsetsLocked() [2]int64 {
	if r.cap != nil {
		return r.cap.offsets()
	}
	return r.captureOffsets
}

// argvHash is the secondary sanity check on re-adoption. It is not the
// disambiguator — a process can legitimately re-exec itself with different
// arguments, and start identity is what actually proves a pid is the one the
// record named — but a mismatch is worth recording in the adoption note.
func argvHash(argv []string) string {
	h := sha256.New()
	for _, arg := range argv {
		h.Write([]byte(arg))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// jobObjectName is the kernel object name for a process's Windows job, so an
// agent that restarts can reopen the job and keep control of the tree. It is
// ignored on Unix, where the process group id needs no name.
//
// Session-global, so it carries the process id the agent assigned rather than
// just a service name.
func jobObjectName(id string) string { return "sandboxd-process-" + id }

// sanitizeName turns a caller-supplied label into something usable as a path
// component and as part of a process id.
func sanitizeName(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + ('a' - 'A'))
		default:
			b.WriteRune('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		out = "process"
	}
	const maxNamePart = 48
	if len(out) > maxNamePart {
		out = out[:maxNamePart]
	}
	return out
}
