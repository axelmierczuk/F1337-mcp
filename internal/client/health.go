package client

import (
	"context"
	"time"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
)

// Health names, as every view of the fleet reports them: the MCP server's
// fleet_list and fleet_info, and `fleetctl list` and `fleetctl info`. They
// live here, beside the type that produces them, so the operator's word for a
// sandbox's state and the model's word for it cannot drift apart — which is
// the whole reason both read health through this package.
const (
	HealthServing     = "serving"
	HealthDegraded    = "degraded"
	HealthDraining    = "draining"
	HealthUnreachable = "unreachable"
	// HealthUnknown means nothing has probed this sandbox yet — not that the
	// probe failed.
	HealthUnknown = "unknown"
)

// HealthName renders a gRPC health status as one of the names above.
func HealthName(status sandboxdv1.HealthResponse_Status) string {
	switch status {
	case sandboxdv1.HealthResponse_STATUS_SERVING:
		return HealthServing
	case sandboxdv1.HealthResponse_STATUS_DEGRADED:
		return HealthDegraded
	case sandboxdv1.HealthResponse_STATUS_DRAINING:
		return HealthDraining
	default:
		return HealthUnknown
	}
}

// HealthStatus is the most recent result of probing a sandbox's
// HostService.Health, cached so fleet_list can report status without a
// round trip per sandbox.
type HealthStatus struct {
	// Reachable is false when the probe itself failed (timeout, connection
	// refused, certificate rejected). Status and Message are meaningless in
	// that case; check Err.
	Reachable        bool
	Status           sandboxdv1.HealthResponse_Status
	Message          string
	AgentVersion     string
	RunningProcesses uint32
	CheckedAt        time.Time
	Err              error
}

// Health returns the cached health status for a pooled sandbox, and false
// if no channel is pooled for that name (Conn/an accessor has never been
// called for it).
func (p *Pool) Health(name string) (HealthStatus, bool) {
	p.mu.Lock()
	e, ok := p.entries[name]
	p.mu.Unlock()
	if !ok {
		return HealthStatus{}, false
	}
	e.healthMu.RLock()
	defer e.healthMu.RUnlock()
	return e.health, true
}

// healthLoop probes health once immediately (so a freshly dialed sandbox
// does not read as unknown for a full interval) and then on cfg.HealthInterval
// until ctx is canceled by Pool.Close or Pool.removeLocked.
func (p *Pool) healthLoop(ctx context.Context, e *entry) {
	defer p.wg.Done()

	p.probeHealth(ctx, e)

	ticker := time.NewTicker(p.cfg.HealthInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.probeHealth(ctx, e)
		}
	}
}

func (p *Pool) probeHealth(ctx context.Context, e *entry) {
	probeCtx, cancel := context.WithTimeout(ctx, p.cfg.HealthTimeout)
	defer cancel()

	client := sandboxdv1.NewHostServiceClient(e.conn)
	resp, err := client.Health(probeCtx, &sandboxdv1.HealthRequest{})

	e.healthMu.Lock()
	defer e.healthMu.Unlock()
	if err != nil {
		e.health = HealthStatus{Reachable: false, CheckedAt: time.Now(), Err: err}
		return
	}
	e.health = HealthStatus{
		Reachable:        true,
		Status:           resp.GetStatus(),
		Message:          resp.GetMessage(),
		AgentVersion:     resp.GetAgentVersion(),
		RunningProcesses: resp.GetRunningProcesses(),
		CheckedAt:        time.Now(),
	}
}
