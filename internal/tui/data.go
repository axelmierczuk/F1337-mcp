package tui

import (
	"context"
	"time"
)

// The values the panes render, and the seam they arrive through.
//
// Every field below is already a string in the form it will be shown in,
// rendered by the same helpers `fleetctl list` and `fleet_info` use. The model
// does no arithmetic on bytes or durations, so a number that reads one way in
// the TUI and another in the CLI is impossible rather than merely unlikely.

// Sandbox is one row of the fleet pane.
type Sandbox struct {
	Name     string
	Address  string
	Platform string
	// Health is one of the client.Health* words.
	Health string
	// Detail is why a sandbox is not serving, when it is not.
	Detail string
	Agent  string
	// LastSeen is a time rather than a rendering, because the fleet pane
	// re-renders it against the current clock every second.
	LastSeen time.Time
	Labels   map[string]string
}

// Process is one row of the processes pane.
type Process struct {
	ID   string
	Name string
	// State is one of the client.Process* words.
	State    string
	PID      int32
	Uptime   string
	Restarts uint32
	Ports    []uint32
	LastLog  string
	// AdoptionNote explains a process the agent could not prove survived its
	// own restart. It is the reason "orphaned" is not a mystery.
	AdoptionNote string
}

// Toolchain is one detected toolchain in the detail pane.
type Toolchain struct {
	Name    string
	Version string
	Path    string
}

// Detail is the host half of the detail pane: what the sandbox says about
// itself right now.
type Detail struct {
	Platform  string
	Kernel    string
	Hostname  string
	Agent     string
	Principal string
	Uptime    string

	CPUCores        uint32
	MemoryTotal     string
	MemoryAvailable string
	DiskTotal       string
	DiskAvailable   string
	Load1m          float64

	AllowedRoots []string
	// Unconfined records that the sandbox enforces no roots at all, which
	// reads exactly like "nowhere is writable" if it is not said out loud.
	Unconfined bool

	// Toolchains is populated only when they were asked for; ToolchainsAsked
	// distinguishes "none detected" from "not looked for".
	Toolchains      []Toolchain
	ToolchainsAsked bool

	RunningProcesses uint32
}

// LogLine is one rendered line of the logs pane.
type LogLine struct {
	// Text is the line as it will be shown, already carrying the "E| " and
	// "S| " stream prefixes fleet_process_logs uses.
	Text string
	// Marker records that this line is not output at all but a note about
	// output that is missing — a gap in the log, rendered inline so the two
	// lines either side of it are not read as adjacent.
	Marker bool
}

// Logs is one bounded window of a process's output.
type Logs struct {
	Lines []LogLine
	// Dropped is how many lines the process outran the agent's buffer by
	// during this window. The gaps themselves are marked in Lines.
	Dropped uint64
	// DeadlineReached records that the window closed because the follow bound
	// elapsed rather than because the process finished, which is the normal
	// case and the reason the pane keeps refreshing.
	DeadlineReached bool
	// Truncated records that this side dropped the oldest lines to stay within
	// its own cap.
	Truncated bool
}

// Source is everything the view needs from the fleet, and the only way it
// reaches one.
//
// It exists so the model can be driven by a fake in tests and by
// internal/client in production, and so that the rule this package is held to —
// that it is a view and not a second implementation — is checkable by reading
// one file (source.go) rather than by auditing every pane.
//
// Every method takes a context and is expected to honour it: the dispatcher
// gives each call its own deadline, and a call that ignored it would be the one
// thing able to stall the view.
type Source interface {
	// Sandboxes lists the fleet with each sandbox's cached health. It performs
	// no agent I/O: health comes from the pool's background cache, which is
	// the only thing in this program that probes on a schedule.
	Sandboxes(ctx context.Context) ([]Sandbox, error)

	// Processes lists the supervised processes on one sandbox.
	Processes(ctx context.Context, sandbox, address string) ([]Process, error)

	// Logs returns one bounded window of a process's output. Bounded is not
	// optional: follow is what the pane wants and an unbounded stream is what
	// it must not have, so the implementation caps both the duration and the
	// number of lines retained.
	Logs(ctx context.Context, sandbox, address, processID string, opts LogOptions) (Logs, error)

	// Detail describes one sandbox's host.
	Detail(ctx context.Context, sandbox, address string, toolchains bool) (Detail, error)

	// Signal sends a signal to a process, or performs a graceful stop.
	Signal(ctx context.Context, sandbox, address, processID string, sig string, graceful bool) error

	// Restart stops a process and starts it again from the same spec.
	Restart(ctx context.Context, sandbox, address, processID string) error
}

// LogOptions bounds one log window.
type LogOptions struct {
	// TailLines is how much history to replay before following.
	TailLines int
	// Follow, with FollowFor, is the bound. FollowFor is always finite and the
	// agent clamps it again to its own maximum.
	Follow    bool
	FollowFor time.Duration
	// MaxLines caps what the window keeps, oldest first, so a process that
	// outruns the pane costs a bounded amount of memory.
	MaxLines int
}
