package agent

import (
	"sync/atomic"

	sandboxdv1 "github.com/axelmierczuk/sandboxd-mcp/gen/go/sandboxd/v1"
)

// Status is the daemon's shared liveness state, read by HostService.Health and
// written by the daemon and by whichever service owns a piece of it.
//
// Health is called on a timer by every connected MCP server, so answering it
// must cost nothing: no filesystem stats, no shelling out, no locks. Every
// operation here is an atomic load or store.
type Status struct {
	state atomic.Int32
	// message is stored behind a pointer so a nil load is distinguishable from
	// an empty string without a second field.
	message atomic.Pointer[string]
	counter atomic.Pointer[processCounter]
}

// processCounter wraps the supervisor's count function so it can live in an
// atomic.Pointer, which needs a named type rather than a bare func.
type processCounter struct{ count func() uint32 }

// NewStatus returns a Status reporting SERVING with no supervised processes.
func NewStatus() *Status {
	s := &Status{}
	s.Set(sandboxdv1.HealthResponse_STATUS_SERVING, "")
	return s
}

// Set records the daemon's health. message is surfaced to callers and should
// be empty when the status is SERVING.
func (s *Status) Set(state sandboxdv1.HealthResponse_Status, message string) {
	s.state.Store(int32(state))
	s.message.Store(&message)
}

// SetProcessCounter registers the function Health calls for the supervised
// process count. The supervisor (#11) calls this from its constructor; until
// it does, Health reports zero running processes.
//
// The function is called on the Health path, so it must be an atomic read of
// an already-maintained counter rather than a walk of the process table.
func (s *Status) SetProcessCounter(count func() uint32) {
	if count == nil {
		s.counter.Store(nil)
		return
	}
	s.counter.Store(&processCounter{count: count})
}

// Snapshot returns the current health, its explanation, and the number of
// supervised processes.
func (s *Status) Snapshot() (state sandboxdv1.HealthResponse_Status, message string, running uint32) {
	state = sandboxdv1.HealthResponse_Status(s.state.Load())
	if m := s.message.Load(); m != nil {
		message = *m
	}
	if c := s.counter.Load(); c != nil {
		running = c.count()
	}
	return state, message, running
}
