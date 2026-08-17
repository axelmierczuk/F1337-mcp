package process

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/fleet-mcp/internal/platform"
)

// errAlreadyExited is what a caller gets for signalling a process that is no
// longer there. It is an error, not a panic, and above all it is not a signal
// delivered to whatever now holds that pid.
var errAlreadyExited = errors.New("the process has already exited")

// signalRecord delivers one signal.
//
// group defaults to true at the request layer, because signalling only the
// leader routinely leaves orphans: killing `npm run dev` without its group
// leaves the bundler holding the port, and the next start then fails to bind.
//
// Whatever the caller asked for, the pid is re-validated first. Between the
// supervisor observing "running" and the kernel delivering a signal, the
// process can exit and its pid be reused — and on a busy box with a low
// pid_max that is not a thought experiment. Signalling the wrong process is how
// a supervisor ends up killing someone's database, so the start identity
// recorded at spawn is checked against the pid every time.
func (s *Supervisor) signalRecord(r *record, sig platform.Signal, group bool) error {
	r.mu.Lock()
	pid, startID, existing, state := r.pid, r.startID, r.group, r.state
	jobName := r.jobName
	r.mu.Unlock()

	if state == sandboxdv1.ProcessState_PROCESS_STATE_ORPHANED {
		// The agent could not prove this process is the one it recorded. It
		// does not get to signal it on a hunch.
		return errors.New("the process is ORPHANED: the agent could not prove it is the process it recorded, so it will not signal it")
	}
	if !isLive(state) {
		return errAlreadyExited
	}
	if pid <= 0 {
		return errAlreadyExited
	}
	// Fail closed. SameProcess returns false for a missing process, a read
	// error, and an empty start identity alike, and every one of those means
	// the agent cannot prove the pid is still its own.
	if startID != "" && !platform.SameProcess(pid, startID) {
		return errAlreadyExited
	}
	if startID == "" && !platform.ProcessExists(pid) {
		return errAlreadyExited
	}

	if !group {
		return signalLeader(pid, sig)
	}

	handle := existing
	if handle == nil {
		// A re-adopted process: this agent did not spawn it, so it has no group
		// handle from the spawn. Open one — on Unix by reading the pid's
		// process group, on Windows by reopening the named job object.
		opened, err := platform.OpenProcessGroup(pid, jobName)
		if err != nil {
			if errors.Is(err, platform.ErrProcessNotFound) {
				return errAlreadyExited
			}
			return fmt.Errorf("could not reach the process group of pid %d: %w", pid, err)
		}
		defer func() { _ = opened.Close() }()
		handle = opened
	}

	if err := handle.Signal(sig); err != nil {
		if errors.Is(err, platform.ErrProcessNotFound) {
			return errAlreadyExited
		}
		if errors.Is(err, platform.ErrSignalUnsupported) {
			return fmt.Errorf("signal %s has no meaning on this platform: %w", sig, err)
		}
		return fmt.Errorf("could not signal process group of pid %d: %w", pid, err)
	}
	return nil
}

// signalLeader delivers to the single process, for the caller that explicitly
// asked not to signal the group.
//
// On Windows there is no POSIX delivery at all, so it degrades to a
// single-process group — a job-less handle, which terminates the leader and
// nothing else. That is as close to "just this process" as Windows offers.
func signalLeader(pid int, sig platform.Signal) error {
	osSig, err := sig.OSSignal()
	if err != nil {
		g, openErr := platform.OpenProcessGroup(pid, "")
		if openErr != nil {
			if errors.Is(openErr, platform.ErrProcessNotFound) {
				return errAlreadyExited
			}
			return fmt.Errorf("could not open pid %d: %w", pid, openErr)
		}
		defer func() { _ = g.Close() }()
		if sigErr := g.Signal(sig); sigErr != nil {
			if errors.Is(sigErr, platform.ErrProcessNotFound) {
				return errAlreadyExited
			}
			return fmt.Errorf("could not signal pid %d: %w", pid, sigErr)
		}
		return nil
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		return errAlreadyExited
	}
	if err := proc.Signal(osSig); err != nil {
		if errors.Is(err, os.ErrProcessDone) {
			return errAlreadyExited
		}
		return fmt.Errorf("could not signal pid %d: %w", pid, err)
	}
	return nil
}

// stopRecord performs a graceful stop: ask, wait, compel.
//
// It always suppresses the restart policy, because every caller of it stopped
// the process on purpose — an explicit stop, a replace_existing, a forced
// remove — and the policy undoing the thing that was just asked for is the one
// outcome none of them want. A stop that should be restarted afterwards is not
// this function; it is gracefulStop, which takes the choice.
func (s *Supervisor) stopRecord(r *record, grace time.Duration) error {
	_, err := s.gracefulStop(r, grace, true, true)
	return err
}

// gracefulStop sends TERM, waits out the grace period, and escalates to KILL if
// the process is still there. It reports whether it had to escalate.
func (s *Supervisor) gracefulStop(r *record, grace time.Duration, disableRestart, group bool) (escalated bool, err error) {
	if disableRestart {
		r.mu.Lock()
		r.restartsDisabled = true
		r.mu.Unlock()
	}
	if grace <= 0 {
		grace = s.cfg.defaultGracePeriod
	}

	if err := s.signalRecord(r, platform.SignalTerm, group); err != nil {
		if errors.Is(err, errAlreadyExited) {
			return false, nil
		}
		return false, err
	}
	if s.awaitExit(r, grace) {
		return false, nil
	}

	// The grace period is up and the process is still running. On Unix that
	// means it caught SIGTERM and did not act on it; on Windows the TERM was
	// already a job termination, and a second one is harmless.
	s.log.Info("escalating a graceful stop to KILL",
		"process_id", r.id, "name", r.nameOf(), "grace", grace)
	r.buf.note(fmt.Sprintf("supervisor: process did not exit within %s of SIGTERM, escalating to SIGKILL", grace))

	if err := s.signalRecord(r, platform.SignalKill, group); err != nil {
		if errors.Is(err, errAlreadyExited) {
			// It exited between the timeout and the kill. Nothing escalated.
			return false, nil
		}
		return true, err
	}
	// A SIGKILL that the kernel accepted is not instantaneous from the
	// supervisor's side: the monitor still has to reap the child and run the
	// state transition. Waiting for that is what makes the status this call
	// returns describe a stopped process rather than a doomed one.
	if !s.awaitExit(r, killGrace) {
		return true, fmt.Errorf("process %s did not exit within %s of SIGKILL", r.id, killGrace)
	}
	return true, nil
}

// killGrace bounds the wait after SIGKILL. A process that is not gone within
// this is stuck in the kernel — uninterruptible I/O, a wedged FUSE mount — and
// no amount of further waiting by the agent changes that.
const killGrace = 10 * time.Second

// awaitExit blocks until the record reaches a terminal state or the timeout
// elapses. It reports whether the process actually stopped.
//
// It waits on the record's change broadcast rather than polling, so a process
// that exits in five milliseconds is noticed in five milliseconds and one that
// takes the whole grace period costs one timer.
func (s *Supervisor) awaitExit(r *record, timeout time.Duration) bool {
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()

	for {
		changed, state := r.wait()
		if isTerminal(state) {
			return true
		}
		if state == sandboxdv1.ProcessState_PROCESS_STATE_RESTARTING {
			// The run ended; the record is only still live because the policy
			// is about to start it again. For a stop, that counts as stopped —
			// and if the stop set disable_restart, the respawn will not happen.
			return true
		}
		select {
		case <-changed:
		case <-deadline.C:
			return false
		case <-s.ctx.Done():
			return false
		}
	}
}

// awaitTerminal blocks until the record is in a terminal state, or the timeout
// elapses.
//
// Unlike awaitExit it does not accept RESTARTING. A record waiting out a
// backoff still has a spawn on a timer, and treating that as stopped is how an
// explicit restart or a forced remove ends up racing an automatic restart.
func (s *Supervisor) awaitTerminal(r *record, timeout time.Duration) bool {
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()

	for {
		changed, state := r.wait()
		if isTerminal(state) {
			return true
		}
		select {
		case <-changed:
		case <-deadline.C:
			return false
		case <-s.ctx.Done():
			return false
		}
	}
}

// restart stops a process and starts it again from the same spec, keeping the
// process id, the record and the log history.
//
// The restart counter is deliberately not touched. It counts the restarts the
// supervisor performed under the restart policy, which is what max_restarts
// bounds; charging an explicit request against that budget would let a caller
// exhaust a service's automatic recovery by asking for restarts by hand.
func (s *Supervisor) restart(r *record, grace time.Duration) error {
	if r.currentState() == sandboxdv1.ProcessState_PROCESS_STATE_ORPHANED {
		return errors.New("the process is ORPHANED and cannot be restarted; remove it and start a new one")
	}

	// Suppress the policy across the whole stop, not only the signal. A restart
	// the policy already had pending is holding the record in RESTARTING with a
	// spawn on a timer; with restarts suppressed that timer stands down into
	// CRASHED instead of starting a second copy beside this one.
	r.mu.Lock()
	r.restartsDisabled = true
	r.mu.Unlock()

	if isLive(r.currentState()) {
		if _, err := s.gracefulStop(r, grace, true, true); err != nil {
			return err
		}
	}
	if !s.awaitTerminal(r, killGrace) {
		return fmt.Errorf("process %s is %s and did not stop", r.id, stateName(r.currentState()))
	}

	r.mu.Lock()
	r.restartsDisabled = false
	r.mu.Unlock()

	// The stop gave the slot back, so the start has to take one. At capacity it
	// does not get one, and saying so is better than starting a process the
	// operator's limit says there is no room for.
	slot, err := s.acquireSlot()
	if err != nil {
		return err
	}
	r.holdSlot(slot)

	if err := r.setState(sandboxdv1.ProcessState_PROCESS_STATE_RESTARTING, nil); err != nil {
		r.dropSlot()
		return err
	}
	if err := r.setState(sandboxdv1.ProcessState_PROCESS_STATE_STARTING, nil); err != nil {
		return err
	}
	if err := s.spawn(r, true); err != nil {
		_ = r.setState(sandboxdv1.ProcessState_PROCESS_STATE_CRASHED, func() {
			r.exitedAt = time.Now()
			r.exitCode = -1
		})
		r.buf.note("supervisor: restart failed: " + err.Error())
		s.refreshLive()
		return err
	}
	s.refreshLive()
	return nil
}

// waitForReady blocks on the readiness probe for the run in progress.
//
// ctx is the caller's. Its cancellation stops the wait and nothing else: the
// probe keeps running on the supervisor's goroutine, and the process keeps
// running regardless. That separation is the point — a client that disconnects
// mid-start must not take a dev server down with it.
func (s *Supervisor) waitForReady(ctx context.Context, r *record) error {
	r.mu.Lock()
	run := r.probeRun
	r.mu.Unlock()
	if run == nil {
		return nil
	}
	select {
	case <-run.done:
		return run.err
	case <-ctx.Done():
		return errors.New("the caller stopped waiting for readiness; the process is still running and the probe is still going")
	}
}
