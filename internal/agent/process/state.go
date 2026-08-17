package process

import (
	"fmt"

	sandboxdv1 "github.com/axelmierczuk/sandboxd-mcp/gen/go/sandboxd/v1"
)

// The supervisor's state machine lives here and nowhere else.
//
// Every state assignment a running process can cause goes through
// record.setState, which consults the table below. The alternative — handlers
// writing r.state directly, each one confident about the state it is coming
// from — is how a process ends up READY and dead at the same time: the exit
// path and the probe path both win a race, and the last writer decides what the
// model is told.
//
// There is exactly one other writer, record.restoreState, and it is not a
// transition: adoption reconstructs a record in whatever state the previous
// agent left it, which is a starting position rather than a move from one. It
// is called from adopt.go and nowhere else, and it is why ORPHANED needs no
// inbound edge in the table below.
//
//	                ┌─────────┐
//	                │ STARTING│ ──probe passes──► READY ──┐
//	                └────┬────┘                           │
//	                     │ no probe configured            │
//	                     └──────────────────► RUNNING ────┤
//	                                                      │
//	                    exit 0 ──► EXITED ◄───────────────┤
//	                    exit ≠ 0, killed,                 │
//	                    or probe failed ──► CRASHED ◄─────┘
//	                                            │
//	                                  restart policy allows
//	                                            ▼
//	                                       RESTARTING ──► STARTING
//
// ORPHANED is reachable only from the adoption path (#15) and is terminal: the
// agent could not prove the recorded process survived its restart, so it does
// not act on it again — including not signalling it.

// transitions is the set of legal moves. A move that is not here is a bug in
// the caller, and setState reports it rather than performing it.
var transitions = map[sandboxdv1.ProcessState]map[sandboxdv1.ProcessState]bool{
	// The zero value is where a freshly constructed record starts.
	sandboxdv1.ProcessState_PROCESS_STATE_UNSPECIFIED: {
		sandboxdv1.ProcessState_PROCESS_STATE_STARTING: true,
	},
	sandboxdv1.ProcessState_PROCESS_STATE_STARTING: {
		sandboxdv1.ProcessState_PROCESS_STATE_READY:   true,
		sandboxdv1.ProcessState_PROCESS_STATE_RUNNING: true,
		sandboxdv1.ProcessState_PROCESS_STATE_EXITED:  true,
		sandboxdv1.ProcessState_PROCESS_STATE_CRASHED: true,
	},
	sandboxdv1.ProcessState_PROCESS_STATE_RUNNING: {
		// A probe that passes after the RPC has already returned still moves the
		// process to READY: wait_for_ready false means "do not block", not "do
		// not probe".
		sandboxdv1.ProcessState_PROCESS_STATE_READY:      true,
		sandboxdv1.ProcessState_PROCESS_STATE_EXITED:     true,
		sandboxdv1.ProcessState_PROCESS_STATE_CRASHED:    true,
		sandboxdv1.ProcessState_PROCESS_STATE_RESTARTING: true,
	},
	sandboxdv1.ProcessState_PROCESS_STATE_READY: {
		sandboxdv1.ProcessState_PROCESS_STATE_EXITED:     true,
		sandboxdv1.ProcessState_PROCESS_STATE_CRASHED:    true,
		sandboxdv1.ProcessState_PROCESS_STATE_RESTARTING: true,
	},
	sandboxdv1.ProcessState_PROCESS_STATE_EXITED: {
		// Only an "always" policy, or an explicit RestartProcess.
		sandboxdv1.ProcessState_PROCESS_STATE_RESTARTING: true,
	},
	sandboxdv1.ProcessState_PROCESS_STATE_CRASHED: {
		sandboxdv1.ProcessState_PROCESS_STATE_RESTARTING: true,
	},
	sandboxdv1.ProcessState_PROCESS_STATE_RESTARTING: {
		sandboxdv1.ProcessState_PROCESS_STATE_STARTING: true,
		// The supervisor gave up: max_restarts reached, or the respawn failed.
		sandboxdv1.ProcessState_PROCESS_STATE_CRASHED: true,
	},
	// Terminal. The agent has already decided it cannot prove this process is
	// its own; nothing it observes later changes that, because the observation
	// it would need is the one it could not make.
	sandboxdv1.ProcessState_PROCESS_STATE_ORPHANED: {},
}

// canTransition reports whether from → to is a legal move.
func canTransition(from, to sandboxdv1.ProcessState) bool {
	return transitions[from][to]
}

// errIllegalTransition describes a move the table forbids. It is returned to
// the caller rather than panicking, but it always means a supervisor bug: the
// states a request can reach are checked before any transition is attempted.
func errIllegalTransition(from, to sandboxdv1.ProcessState) error {
	return fmt.Errorf("process: illegal state transition %s -> %s", stateName(from), stateName(to))
}

// terminalStates are the states from which the supervisor will not act on a
// process again without an explicit request.
func isTerminal(s sandboxdv1.ProcessState) bool {
	switch s {
	case sandboxdv1.ProcessState_PROCESS_STATE_EXITED,
		sandboxdv1.ProcessState_PROCESS_STATE_CRASHED,
		sandboxdv1.ProcessState_PROCESS_STATE_ORPHANED:
		return true
	case sandboxdv1.ProcessState_PROCESS_STATE_UNSPECIFIED,
		sandboxdv1.ProcessState_PROCESS_STATE_STARTING,
		sandboxdv1.ProcessState_PROCESS_STATE_READY,
		sandboxdv1.ProcessState_PROCESS_STATE_RUNNING,
		sandboxdv1.ProcessState_PROCESS_STATE_RESTARTING:
		return false
	default:
		return false
	}
}

// isLive reports whether the state means "there is, or is about to be, an OS
// process behind this record". It is what name uniqueness and max_concurrent
// are counted over: a process waiting out its restart backoff still owns its
// name and still occupies a slot.
func isLive(s sandboxdv1.ProcessState) bool {
	switch s {
	case sandboxdv1.ProcessState_PROCESS_STATE_STARTING,
		sandboxdv1.ProcessState_PROCESS_STATE_READY,
		sandboxdv1.ProcessState_PROCESS_STATE_RUNNING,
		sandboxdv1.ProcessState_PROCESS_STATE_RESTARTING:
		return true
	case sandboxdv1.ProcessState_PROCESS_STATE_UNSPECIFIED,
		sandboxdv1.ProcessState_PROCESS_STATE_EXITED,
		sandboxdv1.ProcessState_PROCESS_STATE_CRASHED,
		sandboxdv1.ProcessState_PROCESS_STATE_ORPHANED:
		return false
	default:
		return false
	}
}

// stateName renders a state the way the proto spells it, minus the prefix, for
// error messages an operator reads.
func stateName(s sandboxdv1.ProcessState) string {
	name := sandboxdv1.ProcessState_name[int32(s)]
	if name == "" {
		return fmt.Sprintf("ProcessState(%d)", int32(s))
	}
	const prefix = "PROCESS_STATE_"
	if len(name) > len(prefix) {
		return name[len(prefix):]
	}
	return name
}
