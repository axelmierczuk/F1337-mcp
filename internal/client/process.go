package client

import (
	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
)

// Process state names, as every view of a sandbox's processes reports them:
// the MCP server's fleet_process_list and fleet_process_logs, and the
// processes pane of `fleetctl tui`.
//
// They live here for the same reason the health names one file over do. An
// operator who reads "crashed" in the TUI and then asks the model about the
// same process must be told the same word about the same state; two renderings
// of one enum drift the moment either side gains a state, and the reader has no
// way to tell a renaming from a change.
const (
	ProcessStarting   = "starting"
	ProcessReady      = "ready"
	ProcessRunning    = "running"
	ProcessExited     = "exited"
	ProcessCrashed    = "crashed"
	ProcessRestarting = "restarting"
	ProcessOrphaned   = "orphaned"
	// ProcessUnknown is what an unrecognised state renders as — a state this
	// build has no name for, not a process nothing has looked at.
	ProcessUnknown = "unknown"
)

// ProcessStateName renders a supervised process's state.
//
// Short strings rather than enum names: they land in model context on every
// list call and in a fixed-width table cell in the TUI, and "crashed" says
// everything PROCESS_STATE_CRASHED does in a quarter of the width.
func ProcessStateName(s sandboxdv1.ProcessState) string {
	switch s {
	case sandboxdv1.ProcessState_PROCESS_STATE_STARTING:
		return ProcessStarting
	case sandboxdv1.ProcessState_PROCESS_STATE_READY:
		return ProcessReady
	case sandboxdv1.ProcessState_PROCESS_STATE_RUNNING:
		return ProcessRunning
	case sandboxdv1.ProcessState_PROCESS_STATE_EXITED:
		return ProcessExited
	case sandboxdv1.ProcessState_PROCESS_STATE_CRASHED:
		return ProcessCrashed
	case sandboxdv1.ProcessState_PROCESS_STATE_RESTARTING:
		return ProcessRestarting
	case sandboxdv1.ProcessState_PROCESS_STATE_ORPHANED:
		return ProcessOrphaned
	default:
		return ProcessUnknown
	}
}

// ProcessStateLive reports whether a state means the process is still there.
//
// It is the one derived fact both views need and neither should derive twice:
// uptime is measured to now for a live process and to the exit for a dead one,
// and a pid belongs to a live process only. A view that got this wrong would
// offer a signal aimed at whatever now owns a recycled pid.
func ProcessStateLive(s sandboxdv1.ProcessState) bool {
	switch s {
	case sandboxdv1.ProcessState_PROCESS_STATE_STARTING,
		sandboxdv1.ProcessState_PROCESS_STATE_READY,
		sandboxdv1.ProcessState_PROCESS_STATE_RUNNING,
		sandboxdv1.ProcessState_PROCESS_STATE_RESTARTING,
		sandboxdv1.ProcessState_PROCESS_STATE_ORPHANED:
		return true
	default:
		return false
	}
}
