package process

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/fleet-mcp/internal/agent"
	"github.com/axelmierczuk/fleet-mcp/internal/platform"
	"github.com/axelmierczuk/fleet-mcp/internal/security/policy"
)

// supervisorConfig is every knob the supervisor has, resolved once.
//
// The ones the operator sets come from agent.ProcessConfig. The rest are
// defaults with no config key, kept here rather than as package constants so a
// test can compress a sixty-second stability window into fifty milliseconds
// without the suite depending on wall-clock patience.
// max_concurrent is deliberately absent: it is an agent-wide cap, held by the
// shared policy limiter every service that spawns a process takes slots from,
// and a copy of it here is how an agent ends up running two limits' worth of
// processes. See Supervisor.slots.
type supervisorConfig struct {
	stateDir           string
	maxLogBytes        int64
	ringBufferLines    int
	defaultGracePeriod time.Duration
	maxFollowDuration  time.Duration

	retainSegments int
	// rawCapBytes is when a raw capture file is truncated. See
	// capture.maybeTruncate.
	rawCapBytes int64

	// stabilityWindow is how long a run must last for the restart counter to
	// reset. Without it a service that crashes once a day exhausts its restart
	// budget after max_restarts days and stays down — which is the opposite of
	// what a restart policy is for.
	stabilityWindow       time.Duration
	defaultMaxRestarts    uint32
	defaultRestartBackoff time.Duration
	maxRestartBackoff     time.Duration

	// waitBackoff waits out a restart delay, reporting whether it elapsed;
	// false means the supervisor is shutting down and the restart is off.
	//
	// It is a field so a test can read the duration the supervisor decided on
	// instead of timing how long the wait took. Timing it cannot work: the only
	// clock a test can reach is wall-clock, the gap it measures also contains a
	// process spawn, and on a loaded runner a spawn costs more than the
	// difference between two consecutive backoffs — so a correct supervisor
	// produces intervals in the wrong order. The decision is the property; this
	// is where a test observes it. nil means realBackoffWait, which is what the
	// agent runs.
	waitBackoff func(ctx context.Context, d time.Duration) bool

	tailPollMin time.Duration
	tailPollMax time.Duration
	// drainWindow bounds how long the tailers keep reading after the process
	// has been reaped. Without a bound, a grandchild that inherited the capture
	// file and keeps writing would hold the exit open indefinitely, and the
	// state machine with it.
	drainWindow time.Duration

	probeTimeout     time.Duration
	probeInterval    time.Duration
	httpProbeTimeout time.Duration
	dialTimeout      time.Duration

	defaultTailLines int
}

func defaultSupervisorConfig(cfg *agent.Config) supervisorConfig {
	pc := cfg.Process
	sc := supervisorConfig{
		stateDir:           cfg.StateDir,
		maxLogBytes:        pc.MaxLogBytes,
		ringBufferLines:    pc.RingBufferLines,
		defaultGracePeriod: pc.DefaultGracePeriod.Duration(),
		maxFollowDuration:  pc.MaxFollowDuration.Duration(),

		retainSegments:        3,
		stabilityWindow:       60 * time.Second,
		defaultMaxRestarts:    5,
		defaultRestartBackoff: time.Second,
		maxRestartBackoff:     2 * time.Minute,

		tailPollMin: 5 * time.Millisecond,
		tailPollMax: 200 * time.Millisecond,
		drainWindow: 250 * time.Millisecond,

		probeTimeout:     30 * time.Second,
		probeInterval:    250 * time.Millisecond,
		httpProbeTimeout: 3 * time.Second,
		dialTimeout:      2 * time.Second,

		defaultTailLines: 200,
	}
	sc.rawCapBytes = max(1<<20, sc.maxLogBytes/8)
	return sc
}

// Supervisor owns every supervised process on this host.
//
// The context it spawns against is its own, created here and cancelled only by
// Close. It is never an RPC context, and that is the single most important
// property in this package: a dev server whose lifetime is tied to the call
// that started it dies when the MCP client reconnects, which is the bug the
// whole design exists to avoid.
type Supervisor struct {
	cfg   supervisorConfig
	log   *slog.Logger
	store *store

	// slots is the agent-wide concurrency limit, shared with every other
	// service that spawns a process. The supervisor does not keep a count of
	// its own — a second count is a second limit, and an agent configured for
	// 32 that enforces 32 in two places runs 64.
	//
	// A record holds one slot from the moment it is admitted until it stops
	// running. A restart therefore has to take one again, and at capacity it
	// does not get one: the alternative is a crash loop quietly walking past
	// the operator's number. The refusal is written into the process's own log.
	slots *policy.Policy

	ctx    context.Context
	cancel context.CancelFunc

	mu      sync.Mutex
	records map[string]*record
	order   []string
	closed  bool

	// admitted holds the starts that have passed the name and concurrency
	// checks but whose record is not yet live. Without it those checks are a
	// read-modify-write with the lock dropped in the middle: two StartProcess
	// calls both read "the name is free" and "there is a slot" before either
	// has registered anything, and the agent ends up supervising two processes
	// under one name, or one more than max_concurrent. Neither is recoverable
	// afterwards — the second process is already spawned.
	admitted map[*admission]struct{}

	// wg covers every goroutine the supervisor owns: monitors, probes and
	// restart timers. Close waits on it, which is what keeps a test's goroutine
	// count from growing with the number of processes it started.
	wg sync.WaitGroup

	// live is the supervised-process count HostService.Health reports. liveMu
	// serialises the recompute: without it two transitions finishing at once
	// can interleave their read-compute-store, and the older one's answer wins.
	live   atomic.Int32
	liveMu sync.Mutex
}

// newSupervisor builds a supervisor and re-adopts whatever the state directory
// says was running.
func newSupervisor(cfg supervisorConfig, slots *policy.Policy, log *slog.Logger) (*Supervisor, error) {
	if slots == nil {
		// Not a convenience default. A nil limiter here would mean the
		// supervisor either enforces nothing or invents a limit of its own,
		// and the second of those is the bug this parameter exists to make
		// impossible.
		return nil, errors.New("process: a shared policy limiter is required; see agent.Deps.Policy")
	}
	st, err := newStore(cfg.stateDir)
	if err != nil {
		return nil, err
	}
	if cfg.waitBackoff == nil {
		cfg.waitBackoff = realBackoffWait
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Supervisor{
		cfg:      cfg,
		log:      log,
		slots:    slots,
		store:    st,
		ctx:      ctx,
		cancel:   cancel,
		records:  map[string]*record{},
		admitted: map[*admission]struct{}{},
	}
	s.adoptAll()
	return s, nil
}

// Close stops supervising. It does not stop a single supervised process:
// surviving an agent restart is what they are for, and the systemd unit and
// launchd job this repository installs are configured to leave them alone for
// the same reason.
//
// What it does stop is the agent's own machinery — monitors, probes, log
// tailers — so nothing outlives the daemon on the agent's side.
func (s *Supervisor) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	records := s.recordsLocked()
	s.mu.Unlock()

	s.cancel()
	s.wg.Wait()

	var errs []error
	for _, r := range records {
		r.mu.Lock()
		capt, group := r.cap, r.group
		r.captureOffsets = r.currentOffsetsLocked()
		r.cap, r.group = nil, nil
		r.mu.Unlock()

		if capt != nil {
			capt.close()
			// After the tailers have stopped, not before. close signals them
			// and waits, and a read already in flight completes inside it —
			// so an offset read beforehand names a position the agent has
			// already gone past. Persisting that has the next agent re-read
			// bytes it has turned into log lines once already, and a
			// re-adopted process's history begins with a duplicate of its own
			// last few hundred lines.
			r.mu.Lock()
			r.captureOffsets = capt.offsets()
			r.mu.Unlock()
		}
		if group != nil {
			// Close releases the handle. It never signals: the group was
			// created without KillOnClose precisely so that an agent upgrade
			// does not take down every dev server on the host.
			if err := group.Close(); err != nil {
				errs = append(errs, err)
			}
		}
		// The slot goes back with the daemon that held it. The process keeps
		// running — that is the contract — and the next agent takes a slot for
		// it again when it re-adopts it, so the limit is rebuilt from what is
		// actually there rather than carried across a restart.
		r.dropSlot()
		// Persist last, after the final capture offsets are known, so the next
		// agent resumes reading where this one stopped.
		r.persist()
		if err := r.buf.close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// recordsLocked returns the records in insertion order. Callers hold mu.
func (s *Supervisor) recordsLocked() []*record {
	out := make([]*record, 0, len(s.order))
	for _, id := range s.order {
		if r, ok := s.records[id]; ok {
			out = append(out, r)
		}
	}
	return out
}

// snapshotRecords copies the record list for iteration outside the lock.
func (s *Supervisor) snapshotRecords() []*record {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.recordsLocked()
}

// lookup finds a record by process id.
func (s *Supervisor) lookup(id string) (*record, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[id]
	return r, ok
}

// liveCount is what HostService.Health reports. It is an atomic load, because
// Health is polled on a timer by every connected MCP server and walking a map
// under a mutex for it would be a standing cost on hosts whose actual job is
// running someone's build.
func (s *Supervisor) liveCount() uint32 {
	n := s.live.Load()
	if n < 0 {
		return 0
	}
	return uint32(n)
}

// refreshLive recomputes the live count.
//
// It is called from record.setState, so every transition maintains it, and from
// remove, which is the one way a record leaves the set without a transition.
func (s *Supervisor) refreshLive() {
	s.liveMu.Lock()
	defer s.liveMu.Unlock()

	var n int32
	for _, r := range s.snapshotRecords() {
		if isLive(r.currentState()) {
			n++
		}
	}
	s.live.Store(n)
}

// startSpec is a validated StartProcess request.
type startSpec struct {
	argv           []string
	name           string
	workingDir     string
	env            []string
	shell          bool
	probe          *probeSpec
	restartPolicy  sandboxdv1.RestartPolicy
	maxRestarts    uint32
	restartBackoff time.Duration
	maxLogBytes    int64
}

// slotWait bounds how long a start waits for a free concurrency slot.
//
// Long enough that a slot being handed back at the same moment is not reported
// as a full agent, short enough that "the agent is at its limit" arrives as an
// answer rather than as a call that appears to hang. Blocking indefinitely
// would be worse than either: a StartProcess that waits for a dev server
// somewhere else to exit is a tool call the model cannot interpret.
const slotWait = 250 * time.Millisecond

// acquireSlot takes one slot in the agent-wide concurrency limit, and explains
// the refusal in the operator's vocabulary rather than the limiter's.
func (s *Supervisor) acquireSlot() (release func(), err error) {
	ctx, cancel := context.WithTimeout(s.ctx, slotWait)
	defer cancel()

	release, err = s.slots.Acquire(ctx)
	if err != nil {
		if errors.Is(s.ctx.Err(), context.Canceled) {
			return nil, errors.New("process: supervisor is shutting down")
		}
		return nil, fmt.Errorf("the agent is already running %d processes, which is its process.max_concurrent limit — a limit it shares with every other service that starts one; stop a process or raise process.max_concurrent: %w",
			s.slots.Caps().MaxConcurrent, policy.ErrTooManyProcesses)
	}
	return release, nil
}

// admission is a start that has claimed a process name but whose record is not
// yet visible as live. It is held from the moment the name check passes until
// the record reaches STARTING, so checking the name and taking it are one step
// as far as any other start is concerned.
//
// The concurrency slot is a separate thing and comes from the shared limiter,
// which does its own atomicity; the name has nowhere else to live.
type admission struct{ name string }

// start creates a record, spawns it, and returns it in STARTING (with a probe)
// or RUNNING (without one).
//
// It does not wait for readiness. The caller decides whether to, and does so
// against its own context — the process is already the supervisor's.
func (s *Supervisor) start(spec startSpec, replaceExisting bool) (*record, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, errors.New("process: supervisor is shutting down")
	}

	var replaced *record
	for _, r := range s.recordsLocked() {
		if !isLive(r.currentState()) {
			continue
		}
		if r.nameOf() == spec.name {
			replaced = r
		}
	}
	for adm := range s.admitted {
		if adm.name == spec.name {
			// A concurrent start of the same name that has been admitted but
			// has not spawned yet. It cannot be replaced — there is nothing to
			// stop — and it cannot be allowed to coexist, so this one loses.
			s.mu.Unlock()
			return nil, fmt.Errorf("a process named %q is already being started; wait for it and pass replace_existing if you want to take its place",
				spec.name)
		}
	}
	if replaced != nil && !replaceExisting {
		s.mu.Unlock()
		return nil, fmt.Errorf("a process named %q is already %s (process_id %s); pass replace_existing to stop it and take its place",
			spec.name, strings.ToLower(stateName(replaced.currentState())), replaced.id)
	}
	adm := &admission{name: spec.name}
	s.admitted[adm] = struct{}{}
	s.mu.Unlock()

	// Released the moment the record holds the name itself, and again on every
	// path out of here. Deleting twice is a no-op; not deleting at all would
	// reserve the name for the life of the supervisor.
	release := func() {
		s.mu.Lock()
		delete(s.admitted, adm)
		s.mu.Unlock()
	}
	defer release()

	if replaced != nil {
		s.log.Info("replacing process", "name", spec.name, "process_id", replaced.id)
		if err := s.stopRecord(replaced, s.cfg.defaultGracePeriod); err != nil {
			return nil, fmt.Errorf("could not stop the existing process named %q: %w", spec.name, err)
		}
	}

	// After the replacement, not before: the process being replaced gives its
	// slot back when it stops, so replacing does not need a free one.
	slot, err := s.acquireSlot()
	if err != nil {
		return nil, err
	}
	handed := false
	defer func() {
		if !handed {
			slot()
		}
	}()

	id := s.newProcessID(spec.name)
	dir, err2 := s.store.dir(id)
	if err2 != nil {
		return nil, err2
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("process: create state directory %s: %w", dir, err)
	}

	file, err := newRotatingFile(filepath.Join(dir, "log.jsonl"), spec.maxLogBytes, s.cfg.retainSegments)
	if err != nil {
		return nil, err
	}

	r := newRecord(s, id, dir)
	r.holdSlot(slot)
	handed = true
	r.buf = newLogBuffer(s.cfg.ringBufferLines, file)
	r.name = spec.name
	r.argv = spec.argv
	r.workingDir = spec.workingDir
	r.env = spec.env
	r.shell = spec.shell
	r.probe = spec.probe
	r.restartPolicy = spec.restartPolicy
	r.maxRestarts = spec.maxRestarts
	r.restartBackoff = spec.restartBackoff
	r.maxLogBytes = spec.maxLogBytes

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		_ = r.buf.close()
		return nil, errors.New("process: supervisor is shutting down")
	}
	s.records[id] = r
	s.order = append(s.order, id)
	s.mu.Unlock()

	if err := r.setState(sandboxdv1.ProcessState_PROCESS_STATE_STARTING, nil); err != nil {
		r.dropSlot()
		return nil, err
	}
	// The record is live now, so it holds the name itself and the reservation
	// would double-count it.
	release()

	if err := s.spawn(r, true); err != nil {
		// The record stays, in CRASHED, rather than being deleted. A start that
		// failed is something the caller needs to be able to read about, and a
		// record that vanishes leaves them with an error string and nothing to
		// look at.
		_ = r.setState(sandboxdv1.ProcessState_PROCESS_STATE_CRASHED, func() {
			r.exitedAt = time.Now()
			r.exitCode = -1
		})
		r.buf.note("supervisor: could not start the process: " + err.Error())
		return r, err
	}
	return r, nil
}

// newProcessID derives a stable, unique, path-safe id from the caller's label.
func (s *Supervisor) newProcessID(name string) string {
	return sanitizeName(name) + "-" + uuid.NewString()[:8]
}

// spawn starts one run of a record's command.
//
// fresh distinguishes a first start from a restart: a restart reuses the same
// process id, the same log history and the same record, and only the raw
// capture files start over.
func (s *Supervisor) spawn(r *record, fresh bool) error {
	r.mu.Lock()
	argv, workingDir, env, shell := append([]string(nil), r.argv...), r.workingDir, append([]string(nil), r.env...), r.shell
	dir := r.dir
	r.mu.Unlock()

	// Where this run's output starts, taken before the run exists.
	//
	// The previous run's lines are all in the buffer by now: the monitor drains
	// its tailers before it records the exit, and every path to a respawn goes
	// through that exit. So this is the exact boundary between the two runs, and
	// it is what stops a readiness probe crediting this run with the last one's
	// announcement. See record.runFirstSeq.
	firstSeq := r.buf.nextSequence()

	name, args, err := commandLine(argv, shell)
	if err != nil {
		return err
	}

	stdout, stderr, err := openCaptureFiles(dir, fresh)
	if err != nil {
		return err
	}
	defer func() {
		// The agent's copies of the write handles. The child keeps its own, and
		// keeps them across an agent restart, which is the whole reason output
		// goes to files rather than to a pipe.
		_ = stdout.Close()
		_ = stderr.Close()
	}()

	// exec.Command, deliberately not exec.CommandContext. A supervised process
	// must not be killed when a context somewhere is cancelled — not the RPC's,
	// and not the supervisor's own at shutdown.
	cmd := exec.Command(name, args...) //nolint:gosec // running an operator-supplied command is what this service is
	cmd.Dir = workingDir
	if len(env) > 0 {
		cmd.Env = env
	}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	// No stdin. A background process that reads from the agent's stdin would
	// block forever on a daemon that has none; os/exec gives it the null device.
	cmd.Stdin = nil

	group, err := platform.NewProcessGroup(platform.GroupConfig{
		// Named, not kill-on-close: the name is how a restarted agent reopens
		// the job on Windows, and kill-on-close would destroy the tree the
		// moment the old agent exited.
		Name: r.jobName,
	})
	if err != nil {
		return fmt.Errorf("process: prepare process group: %w", err)
	}
	group.ConfigureCommand(cmd)

	if err := cmd.Start(); err != nil {
		_ = group.Close()
		return fmt.Errorf("process: start %s: %w", name, err)
	}
	if err := group.Adopt(cmd.Process); err != nil {
		// The child is running but not in its group or job. Signals will reach
		// the leader alone, so descendants must be assumed to survive a stop.
		s.log.Warn("process is not isolated in its own group; a stop may leave children behind",
			"process_id", r.id, "pid", cmd.Process.Pid, "error", err)
		r.buf.note("supervisor: could not place the process in its own group; stopping it may leave children behind: " + err.Error())
	}

	// Start identity, read immediately. It is what a later agent compares
	// against to decide whether this pid is still this process, and reading it
	// now — rather than at re-adoption time — is what makes that comparison
	// mean anything.
	startID := ""
	if info, err := platform.StatProcess(cmd.Process.Pid); err == nil {
		startID = info.StartID
	} else {
		s.log.Warn("could not read process start identity; this process cannot be re-adopted after an agent restart",
			"process_id", r.id, "pid", cmd.Process.Pid, "error", err)
	}

	offsets := [2]int64{}
	if !fresh {
		offsets = r.captureOffsets
	}
	capt, err := newCapture(dir, r.buf, offsets, s.cfg.rawCapBytes, s.cfg.tailPollMin, s.cfg.tailPollMax, s.cfg.drainWindow)
	if err != nil {
		// The process is running and cannot be un-started, so this is reported
		// rather than treated as a failed start; it costs the logs, not the
		// process.
		s.log.Error("could not follow process output", "process_id", r.id, "error", err)
	}

	// cmd.Wait runs on its own goroutine, outside the supervisor's WaitGroup.
	// It is the reaper — every spawn has exactly one, which is what stops
	// zombies accumulating — and it cannot be interrupted: a process sleeping
	// for an hour keeps it blocked for an hour. Close must not wait for that,
	// so the goroutine Close does wait for is the monitor below, which selects
	// on this channel and on the supervisor's own context.
	reaped := make(chan error, 1)
	go func() { reaped <- cmd.Wait() }()

	exited := make(chan struct{})
	now := time.Now()

	r.mu.Lock()
	r.cmd = cmd
	r.group = group
	r.cap = capt
	r.adopted = false
	r.exited = exited
	r.pid = cmd.Process.Pid
	r.startID = startID
	r.runFirstSeq = firstSeq
	r.startedAt = now
	r.stability = now
	r.exitedAt = time.Time{}
	r.exitCode = 0
	r.signalName = ""
	r.captureOffsets = offsets
	probe := r.probe
	r.mu.Unlock()

	// Written down before the run is left to get on with it, because the three
	// facts above are the run's identity and nothing else is going to record
	// them. The state machine is already in STARTING — every caller of spawn
	// put it there — so for a process with a probe the next transition is the
	// probe's verdict, and a probe that times out has no verdict to make: the
	// record would sit on disk naming the *previous* run's pid, start identity
	// and log mark for as long as this run lived. An agent killed in that
	// window hands the next one a record it cannot re-adopt — pid 0 on a first
	// start, a dead pid after a restart — so a process that is serving is
	// declared crashed, and the mark the resumed probe needs is the mark of a
	// run that has already ended.
	r.persist()

	if capt != nil {
		capt.start(exited)
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.monitor(r, cmd, exited, reaped)
	}()

	if probe == nil {
		if err := r.setState(sandboxdv1.ProcessState_PROCESS_STATE_RUNNING, nil); err != nil {
			return err
		}
		return nil
	}

	// The probe runs on the supervisor's goroutine and against the supervisor's
	// context, whether or not anybody is waiting for it. wait_for_ready is only
	// about whether StartProcess blocks.
	s.startProbe(r, probe, firstSeq)
	return nil
}

// startProbe attaches a readiness attempt to the record and runs it.
func (s *Supervisor) startProbe(r *record, probe *probeSpec, fromSeq uint64) {
	run := &probeRun{done: make(chan struct{}), fromSeq: fromSeq}
	r.mu.Lock()
	r.probeRun = run
	r.mu.Unlock()

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.superviseProbe(r, probe, run)
	}()
}

// probeRun is one readiness attempt, so that a caller waiting on it and the
// supervisor running it are not the same goroutine.
//
// fromSeq is carried on the attempt rather than read off the record when the
// probe needs it. An attempt is bound to the run it was started for, and a
// probe that read the record instead could — in the window between a run ending
// and the next one spawning — find itself scanning against the *next* run's
// boundary and conclude something about a run that is already over.
type probeRun struct {
	done    chan struct{}
	err     error
	fromSeq uint64
}

// superviseProbe runs a probe to its conclusion and applies it to the state
// machine.
func (s *Supervisor) superviseProbe(r *record, probe *probeSpec, run *probeRun) {
	err := probe.run(s.ctx, r, run.fromSeq, s.cfg.httpProbeTimeout, s.cfg.dialTimeout)
	run.err = err
	defer close(run.done)

	switch {
	case err == nil:
		if setErr := r.setState(sandboxdv1.ProcessState_PROCESS_STATE_READY, nil); setErr != nil {
			// The process exited while the probe was concluding it had passed.
			// The exit is the more recent fact; leave it alone.
			s.log.Debug("probe passed but the process had already exited",
				"process_id", r.id, "error", setErr)
		}
	case errors.Is(err, context.Canceled):
		// The supervisor is shutting down. Nothing to conclude.
	default:
		var exited *probeExitError
		if errors.As(err, &exited) {
			// The monitor has already recorded the exit and the state that goes
			// with it. Nothing here to add.
			return
		}
		// A probe that timed out says nothing about whether the process works.
		// It stays where it is — STARTING, which the proto defines as "spawned,
		// but its readiness probe has not yet passed", and which is exactly
		// true — and it stays running, because killing it would destroy the
		// logs that are the only way to find out why it was slow.
		s.log.Info("readiness probe did not pass", "process_id", r.id, "name", r.nameOf(), "error", err)
		r.buf.note("supervisor: " + err.Error())
	}
}

// monitor waits for one run to end, records how it ended, and applies the
// restart policy.
//
// cmd.Wait is also what reaps the child. Every spawn has exactly one monitor,
// so a hundred short-lived processes leave a hundred reaped children and no
// zombies.
func (s *Supervisor) monitor(r *record, cmd *exec.Cmd, exited chan struct{}, reaped <-chan error) {
	var waitErr error
	select {
	case waitErr = <-reaped:
	case <-s.ctx.Done():
		// The agent is shutting down. The process is not: it keeps running,
		// keeps writing to its capture files, and the next agent re-adopts it.
		// Concluding anything about it here would persist an exit that has not
		// happened.
		return
	}
	close(exited)

	// Let the tailers finish draining what the process wrote before its last
	// breath, so a follow that ends on the exit has the final lines and the
	// crash is diagnosable from the log rather than only from the exit code.
	r.mu.Lock()
	capt := r.cap
	r.mu.Unlock()
	if capt != nil {
		capt.finish()
		r.mu.Lock()
		r.captureOffsets = capt.offsets()
		r.cap = nil
		r.mu.Unlock()
	}

	exitCode, signalName := classifyExit(cmd, waitErr)
	crashed := exitCode != 0 || signalName != ""

	r.mu.Lock()
	ranFor := time.Since(r.stability)
	group := r.group
	r.group = nil
	r.mu.Unlock()
	if group != nil {
		_ = group.Close()
	}

	to := sandboxdv1.ProcessState_PROCESS_STATE_EXITED
	if crashed {
		to = sandboxdv1.ProcessState_PROCESS_STATE_CRASHED
	}
	if err := r.setState(to, func() {
		r.exitedAt = time.Now()
		r.exitCode = exitCode
		r.signalName = signalName
		// r.pid is deliberately left alone: a caller diagnosing a crash wants
		// the pid the process had, and nothing else is going to tell them.
		r.cmd = nil
	}); err != nil {
		s.log.Error("could not record process exit", "process_id", r.id, "error", err)
	}

	s.maybeRestart(r, crashed, ranFor)
}

// maybeRestart applies the restart policy to a run that has just ended.
func (s *Supervisor) maybeRestart(r *record, crashed bool, ranFor time.Duration) {
	r.mu.Lock()
	policy, disabled, maxRestarts, backoff := r.restartPolicy, r.restartsDisabled, r.maxRestarts, r.restartBackoff
	// The counter resets after a run that lasted. A service that crashes once a
	// day is not a service in a crash loop, and charging it a restart it never
	// gets back means it eventually stays down for no reason anyone can see.
	if ranFor >= s.cfg.stabilityWindow && r.restartCount > 0 {
		s.log.Info("resetting restart counter after sustained uptime",
			"process_id", r.id, "name", r.name, "uptime", ranFor.Round(time.Second), "restart_count", r.restartCount)
		r.buf.note(fmt.Sprintf("supervisor: restart counter reset after %s of uptime", ranFor.Round(time.Second)))
		r.restartCount = 0
	}
	count := r.restartCount
	r.mu.Unlock()

	if disabled {
		return
	}
	switch policy {
	case sandboxdv1.RestartPolicy_RESTART_POLICY_ALWAYS:
	case sandboxdv1.RestartPolicy_RESTART_POLICY_ON_FAILURE:
		if !crashed {
			return
		}
	case sandboxdv1.RestartPolicy_RESTART_POLICY_NEVER,
		sandboxdv1.RestartPolicy_RESTART_POLICY_UNSPECIFIED:
		return
	default:
		return
	}

	if count >= maxRestarts {
		reason := fmt.Sprintf("supervisor: giving up after %d restarts (max_restarts); the process stays in its crashed state", count)
		s.log.Warn("restart budget exhausted", "process_id", r.id, "name", r.nameOf(), "max_restarts", maxRestarts)
		r.buf.note(reason)
		if r.currentState() != sandboxdv1.ProcessState_PROCESS_STATE_CRASHED {
			// A clean exit under an "always" policy still ends CRASHED once the
			// supervisor has given up: the process is not running and will not
			// be restarted, and EXITED reads as "this is fine".
			_ = r.setState(sandboxdv1.ProcessState_PROCESS_STATE_CRASHED, nil)
		}
		return
	}

	// A run that has ended holds no slot: the cap counts processes that are
	// running, not records that once were. So a restart has to take one, and at
	// capacity it does not get one — the alternative is a crash loop quietly
	// walking past the number the operator set. The reason goes in the
	// process's own log, where whoever is wondering why it stayed down will
	// find it.
	slot, err := s.acquireSlot()
	if err != nil {
		s.log.Warn("not restarting: no free concurrency slot",
			"process_id", r.id, "name", r.nameOf(), "error", err)
		r.buf.note("supervisor: not restarting: " + err.Error())
		return
	}
	r.holdSlot(slot)

	if err := r.setState(sandboxdv1.ProcessState_PROCESS_STATE_RESTARTING, nil); err != nil {
		r.dropSlot()
		return
	}

	delay := backoffFor(backoff, count, s.cfg.maxRestartBackoff)
	r.buf.note(fmt.Sprintf("supervisor: restarting in %s (restart %d of %d)", delay, count+1, maxRestarts))

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		if !s.cfg.waitBackoff(s.ctx, delay) {
			return
		}

		r.mu.Lock()
		stillDisabled := r.restartsDisabled
		if !stillDisabled {
			r.restartCount++
		}
		r.mu.Unlock()
		if stillDisabled {
			// An explicit stop landed during the backoff. Honour it: the point
			// of disable_restart is that the supervisor does not undo a
			// deliberate stop.
			r.buf.note("supervisor: restart cancelled, the process was stopped deliberately")
			_ = r.setState(sandboxdv1.ProcessState_PROCESS_STATE_CRASHED, nil)
			return
		}

		if err := r.setState(sandboxdv1.ProcessState_PROCESS_STATE_STARTING, nil); err != nil {
			return
		}
		if err := s.spawn(r, true); err != nil {
			s.log.Error("restart failed", "process_id", r.id, "name", r.nameOf(), "error", err)
			r.buf.note("supervisor: restart failed: " + err.Error())
			_ = r.setState(sandboxdv1.ProcessState_PROCESS_STATE_CRASHED, func() {
				r.exitedAt = time.Now()
				r.exitCode = -1
			})
		}
	}()
}

// realBackoffWait is the wait the agent runs: a timer, and the supervisor's
// shutdown. It reports false when the supervisor is closing, which is the
// signal to abandon the restart rather than spawn into a shutdown.
func realBackoffWait(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// backoffFor doubles the base delay per restart, capped. The cap matters more
// than the doubling: without it, a service with a ten-minute base and twenty
// restarts is effectively never coming back.
func backoffFor(base time.Duration, count uint32, capped time.Duration) time.Duration {
	if base <= 0 {
		base = time.Second
	}
	delay := base
	for range count {
		delay *= 2
		if delay >= capped {
			return capped
		}
	}
	if delay > capped {
		return capped
	}
	return delay
}

// classifyExit turns os/exec's answer into an exit code and a signal name.
func classifyExit(cmd *exec.Cmd, waitErr error) (exitCode int32, signalName string) {
	state := cmd.ProcessState
	if state == nil {
		if waitErr != nil {
			return -1, ""
		}
		return 0, ""
	}
	code := int32(state.ExitCode()) //nolint:gosec // an exit code is a small integer

	if sig, ok := exitSignal(state); ok {
		return code, sig
	}
	return code, ""
}

// nameOf reads the record's label.
func (r *record) nameOf() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.name
}

// commandLine resolves argv into an executable and its arguments, optionally
// through the platform shell.
func commandLine(argv []string, shell bool) (name string, args []string, err error) {
	if len(argv) == 0 {
		return "", nil, errors.New("argv is empty")
	}
	if !shell {
		return argv[0], argv[1:], nil
	}
	joined := strings.Join(argv, " ")
	if runtime.GOOS == "windows" {
		comspec := os.Getenv("ComSpec")
		if comspec == "" {
			comspec = "cmd.exe"
		}
		return comspec, []string{"/c", joined}, nil
	}
	return "/bin/sh", []string{"-c", joined}, nil
}

// listFilter is a resolved ListProcesses request.
type listFilter struct {
	states map[sandboxdv1.ProcessState]bool
	name   *regexp.Regexp
}

func (f listFilter) matches(r *record) bool {
	if len(f.states) > 0 && !f.states[r.currentState()] {
		return false
	}
	if f.name != nil && !f.name.MatchString(r.nameOf()) {
		return false
	}
	return true
}

// remove reaps a record.
func (s *Supervisor) remove(r *record, force, deleteLogs bool) error {
	if isLive(r.currentState()) {
		if !force {
			return fmt.Errorf("process %s is %s; pass force to stop it and remove it anyway",
				r.id, strings.ToLower(stateName(r.currentState())))
		}
		if err := s.stopRecord(r, s.cfg.defaultGracePeriod); err != nil {
			return err
		}
		// stopRecord is satisfied by RESTARTING — the run has ended — but a
		// record waiting out a backoff still has a spawn on a timer, and
		// deleting it now would leave that process supervised by nobody. With
		// restarts suppressed the timer stands down into a terminal state.
		if !s.awaitTerminal(r, killGrace) {
			return fmt.Errorf("process %s is %s and did not stop", r.id, stateName(r.currentState()))
		}
	}

	// Mark it removed before anything is deleted. A transition that lands
	// between the delete and the last persist would otherwise write the record
	// straight back into the directory being removed, and the removal then
	// fails with "directory not empty".
	// Taken around the flag so no persist can be in flight when it is set: a
	// write already inside WriteAtomic would otherwise land after the directory
	// had been deleted.
	r.persistMu.Lock()
	r.mu.Lock()
	r.removed = true
	r.mu.Unlock()
	r.persistMu.Unlock()

	s.mu.Lock()
	delete(s.records, r.id)
	for i, id := range s.order {
		if id == r.id {
			s.order = append(s.order[:i], s.order[i+1:]...)
			break
		}
	}
	s.mu.Unlock()

	r.mu.Lock()
	capt := r.cap
	r.cap = nil
	r.mu.Unlock()
	if capt != nil {
		capt.close()
	}
	// Closing the buffer wakes every follower on this process, so a
	// GetProcessLogs in flight returns now rather than waiting out its deadline
	// against a record that no longer exists.
	if err := r.buf.close(); err != nil {
		s.log.Warn("could not close log buffer", "process_id", r.id, "error", err)
	}
	// A removed record is gone whatever state it was in, so its slot goes back
	// here as well as on the transition that should already have released it.
	r.dropSlot()
	s.refreshLive()
	return s.store.remove(r.id, deleteLogs)
}
