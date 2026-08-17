package process

import (
	"errors"
	"fmt"
	"path/filepath"
	"time"

	sandboxdv1 "github.com/axelmierczuk/sandboxd-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/sandboxd-mcp/internal/platform"
)

// Re-adoption is why the supervisor persists anything at all.
//
// Supervised processes outlive the agent by design: an agent upgrade must not
// take down every dev server in the fleet. So on startup the supervisor has to
// work out, for each record it wrote, whether the process behind it is still
// its process — and the only honest answer comes from two facts together.
//
//	1. Does the pid exist?
//	2. Does that pid's start identity match the one recorded at spawn?
//
// Both yes: re-adopt. Either no: ORPHANED, with an adoption_note, and the
// supervisor never signals it again. Checking the pid alone is the mistake that
// matters, because pid reuse is not theoretical on a busy box with a low
// pid_max, and adopting the wrong process means the agent will later signal
// something it does not own. On a machine that also runs real workloads, that
// is how a supervisor kills someone's database.
//
// argv_hash is a secondary sanity check and never a substitute: a process can
// legitimately re-exec itself with different arguments, and start identity is
// the fact that actually distinguishes one process from another.

// adoptPollInterval is how often a re-adopted process is checked for liveness.
//
// A re-adopted process cannot be waited on — the agent that forked it is gone,
// so this one is not its parent and there is no exit status to collect. Polling
// start identity is the portable substitute, and one second is fast enough to
// keep ListProcesses honest without turning a fleet of idle sandboxes into a
// standing load.
const adoptPollInterval = time.Second

// adoptAll reconstructs the supervisor's world from the state directory.
func (s *Supervisor) adoptAll() {
	records, problems := s.store.load()
	for _, err := range problems {
		// A record that will not parse has already cost the agent that process.
		// Refusing to start would cost it the rest of them.
		s.log.Error("skipping an unreadable process record", "error", err)
	}
	for _, p := range records {
		if err := s.adopt(p); err != nil {
			s.log.Error("could not re-adopt process", "process_id", p.ID, "name", p.Name, "error", err)
		}
	}
	s.refreshLive()
}

// adopt rebuilds one record and decides its fate.
func (s *Supervisor) adopt(p persisted) error {
	dir, err := s.store.dir(p.ID)
	if err != nil {
		return err
	}

	maxLogBytes := p.MaxLogBytes
	if maxLogBytes <= 0 {
		maxLogBytes = s.cfg.maxLogBytes
	}
	file, err := newRotatingFile(filepath.Join(dir, "log.jsonl"), maxLogBytes, s.cfg.retainSegments)
	if err != nil {
		return err
	}

	r := newRecord(s, p.ID, dir)
	r.buf = newLogBuffer(s.cfg.ringBufferLines, file)
	r.name = p.Name
	r.argv = p.Argv
	r.workingDir = p.WorkingDir
	r.env = p.Env
	r.shell = p.Shell
	r.probe = probeFromPersisted(p.Probe)
	r.restartPolicy = parsePolicy(p.RestartPolicy)
	r.maxRestarts = p.MaxRestarts
	r.restartBackoff = time.Duration(p.RestartBackoffMS) * time.Millisecond
	r.maxLogBytes = maxLogBytes
	r.pid = p.PID
	r.startID = p.StartID
	r.startedAt = p.StartedAt
	r.exitedAt = p.ExitedAt
	r.exitCode = p.ExitCode
	r.signalName = p.Signal
	r.restartCount = p.RestartCount
	r.restartsDisabled = p.RestartsDisabled
	r.captureOffsets = p.CaptureOffsets
	r.stability = p.StartedAt
	r.adopted = true

	// The history the previous agent wrote, back into the ring, so a caller
	// asking for logs after a restart sees the same tail it saw before it.
	if lines, err := readSegments(file.segments(), s.cfg.ringBufferLines); err != nil {
		s.log.Warn("could not restore log history", "process_id", p.ID, "error", err)
	} else {
		r.buf.restore(lines, p.LogBytes)
	}

	previous := parseState(p.State)
	r.restoreState(previous)

	s.mu.Lock()
	s.records[p.ID] = r
	s.order = append(s.order, p.ID)
	s.mu.Unlock()

	if !isLive(previous) {
		// Already terminal when the agent stopped. Nothing to decide.
		return nil
	}

	note, adopt := s.adoptionDecision(p, previous)
	r.mu.Lock()
	r.adoptionNote = note
	r.mu.Unlock()

	if !adopt {
		r.buf.note("supervisor: " + note)
		s.log.Warn("process not re-adopted", "process_id", p.ID, "name", p.Name, "decision", note)
		r.restoreState(orphanOrTerminal(p, previous))
		r.persist()
		return nil
	}

	s.log.Info("re-adopted process", "process_id", p.ID, "name", p.Name, "pid", p.PID, "state", stateName(previous))
	r.buf.note("supervisor: " + note)

	// Resume capture from where the previous agent stopped reading. The process
	// has been appending to these same files the whole time.
	capt, err := newCapture(dir, r.buf, p.CaptureOffsets, s.cfg.rawCapBytes,
		s.cfg.tailPollMin, s.cfg.tailPollMax, s.cfg.drainWindow)
	if err != nil {
		s.log.Error("could not resume following process output", "process_id", p.ID, "error", err)
	} else {
		exited := make(chan struct{})
		r.mu.Lock()
		r.cap = capt
		r.exited = exited
		r.mu.Unlock()
		capt.start(exited)

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.watchAdopted(r, exited)
		}()
	}
	r.persist()
	return nil
}

// adoptionDecision applies the two-fact test and explains itself.
//
// The explanation is not decoration. It lands in ProcessStatus.adoption_note,
// and it is the only thing that tells a reader why a process they started is
// now marked ORPHANED rather than running.
func (s *Supervisor) adoptionDecision(p persisted, previous sandboxdv1.ProcessState) (note string, adopt bool) {
	if previous == sandboxdv1.ProcessState_PROCESS_STATE_RESTARTING {
		return "the agent restarted while this process was between restarts, so there was no process to re-adopt", false
	}
	if p.PID <= 0 {
		return "the record has no pid, so there is nothing to re-adopt", false
	}

	info, err := platform.StatProcess(p.PID)
	if err != nil {
		if errors.Is(err, platform.ErrProcessNotFound) {
			return fmt.Sprintf("pid %d no longer exists; the process ended while the agent was not running, so its exit status is not recoverable", p.PID), false
		}
		return fmt.Sprintf("could not read pid %d (%v), so the agent cannot prove this process survived and will not act on it", p.PID, err), false
	}

	if p.StartID == "" {
		// Nothing was recorded to compare against, which means the spawn could
		// not read start identity. Adopting on the pid alone is exactly the
		// mistake this procedure exists to avoid.
		return fmt.Sprintf("pid %d exists but no start identity was recorded for it, so it cannot be told apart from a reused pid", p.PID), false
	}
	if info.StartID != p.StartID {
		return fmt.Sprintf("pid %d was reused by another process (start identity %s, expected %s), so this record was not re-adopted and the pid will not be signalled",
			p.PID, info.StartID, p.StartID), false
	}

	note = fmt.Sprintf("re-adopted after an agent restart: pid %d matches the start identity recorded when it was spawned", p.PID)
	if p.ArgvHash != "" && p.ArgvHash != argvHash(p.Argv) {
		// A secondary check, and a weak one on purpose. It cannot see the
		// running process's argv — nothing portable can — so all it catches is
		// a record that was edited or corrupted. That is worth saying and not
		// worth refusing an adoption over.
		note += "; the record's argv hash does not match its argv, so the record may have been edited"
	}
	return note, true
}

// orphanOrTerminal is the state a record that could not be re-adopted lands in.
//
// A process whose pid is gone is terminal, and CRASHED rather than EXITED:
// nothing recorded its exit status, so "finished successfully" would be an
// invention. Everything else — a pid that exists but is not provably this
// process, a read that failed — is ORPHANED, which is the state that says the
// supervisor has stopped reasoning about it and will not signal it.
func orphanOrTerminal(p persisted, previous sandboxdv1.ProcessState) sandboxdv1.ProcessState {
	if previous == sandboxdv1.ProcessState_PROCESS_STATE_RESTARTING {
		return sandboxdv1.ProcessState_PROCESS_STATE_CRASHED
	}
	if p.PID > 0 && platform.ProcessExists(p.PID) {
		return sandboxdv1.ProcessState_PROCESS_STATE_ORPHANED
	}
	return sandboxdv1.ProcessState_PROCESS_STATE_CRASHED
}

// watchAdopted polls a re-adopted process for liveness, because the agent is
// not its parent and cannot wait on it.
//
// When it goes, the record becomes CRASHED with an explanatory line in its own
// log: the exit status of a process this agent did not spawn is not available
// to it, and reporting EXITED — which reads as "finished successfully" — would
// be claiming to know something it does not.
func (s *Supervisor) watchAdopted(r *record, exited chan struct{}) {
	ticker := time.NewTicker(adoptPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
		}

		r.mu.Lock()
		pid, startID, state := r.pid, r.startID, r.state
		r.mu.Unlock()
		if !isLive(state) {
			return
		}
		if platform.SameProcess(pid, startID) {
			continue
		}

		close(exited)
		r.mu.Lock()
		capt := r.cap
		ranFor := time.Since(r.stability)
		r.mu.Unlock()
		if capt != nil {
			capt.finish()
			r.mu.Lock()
			r.captureOffsets = capt.offsets()
			r.cap = nil
			r.mu.Unlock()
		}

		r.buf.note("supervisor: the process is gone; its exit status is not available to an agent that did not spawn it")
		if err := r.setState(sandboxdv1.ProcessState_PROCESS_STATE_CRASHED, func() {
			r.exitedAt = time.Now()
			r.exitCode = -1
		}); err != nil {
			s.log.Error("could not record the exit of a re-adopted process", "process_id", r.id, "error", err)
		}
		s.refreshLive()
		s.maybeRestart(r, true, ranFor)
		return
	}
}
