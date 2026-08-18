package tui

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/fleet-mcp/internal/cli"
	"github.com/axelmierczuk/fleet-mcp/internal/client"
	"github.com/axelmierczuk/fleet-mcp/internal/registry"
)

// The one implementation of [Source] that ships, and the file the claim "this
// is a view, not a second implementation" is checked against.
//
// Nothing here decides anything. Health words come from internal/client,
// process state words come from internal/client, relative times and byte counts
// and durations come from internal/cli — the same functions `fleetctl list`,
// `fleetctl info` and the MCP server's fleet_* tools render with. What is left
// is projection: a wire message into the struct a pane draws.

// fleetLister and agentClients are everything this package is allowed to reach
// the fleet through: the registry listing `fleetctl list` reads, and the three
// pool calls the CLI and the MCP server already make.
//
// Interfaces rather than *registry.Registry and *client.Pool for two reasons.
// They are the whole of what "this is a view, not a second implementation"
// permits, so the rule is checkable by reading one declaration rather than by
// auditing every pane. And they are what makes the things below assertable
// without a fleet: that every call to one sandbox is bounded, that a log
// follow is bounded at the request rather than only in a helper, and that the
// stop key sends the flags an operator's stop means.
type fleetLister interface {
	List() ([]registry.Sandbox, error)
}

type agentClients interface {
	Host(name, address string) (sandboxdv1.HostServiceClient, error)
	Process(name, address string) (sandboxdv1.ProcessServiceClient, error)
	Health(name string) (client.HealthStatus, bool)
}

// fleetSource reads the fleet through the pool and the registry.
type fleetSource struct {
	fleet fleetLister
	pool  agentClients
	// timeout bounds one call to one sandbox. Short on purpose: a fleet holds
	// machines that are asleep, rebuilt or simply gone, and the answer for
	// those is "unreachable" delivered promptly rather than a pane that stalls
	// behind a TCP connect to a black hole.
	timeout time.Duration
}

// defaultCallTimeout bounds one call to one sandbox when the caller named no
// timeout of its own.
const defaultCallTimeout = 3 * time.Second

// NewFleetSource returns the [Source] the TUI runs against.
//
// It takes the concrete registry and pool rather than the interfaces above:
// those exist so this file's behaviour can be asserted, not so a caller can
// substitute a second way of reaching the fleet.
//
// The pool is expected to have been built with a health interval the operator
// chose, because its background health loop is the only thing in this program
// that probes sandboxes on a schedule. See [Source.Sandboxes].
func NewFleetSource(fleet *registry.Registry, pool *client.Pool, timeout time.Duration) Source {
	if timeout <= 0 {
		timeout = defaultCallTimeout
	}
	return &fleetSource{fleet: fleet, pool: pool, timeout: timeout}
}

// Sandboxes lists the fleet and reads each sandbox's cached health.
//
// It issues no RPCs. Calling Host here is what pools a channel for a sandbox
// and starts its background health loop — gRPC connects lazily, so this costs a
// struct and a goroutine, not a handshake — and Health then reads whatever that
// loop last saw. The loops run one per sandbox, in parallel, each bounded by
// the pool's own health timeout, which is why an unreachable machine renders as
// unreachable instead of holding up the other nineteen.
func (s *fleetSource) Sandboxes(_ context.Context) ([]Sandbox, error) {
	sandboxes, err := s.fleet.List()
	if err != nil {
		return nil, err
	}
	out := make([]Sandbox, 0, len(sandboxes))
	for _, sb := range sandboxes {
		row := Sandbox{
			Name:     sb.Name,
			Address:  sb.Address,
			Platform: cli.SafeText(sb.Platform.String()),
			Health:   client.HealthUnknown,
			Agent:    cli.SafeText(sb.AgentVersion),
			LastSeen: sb.LastSeenAt,
			Labels:   sb.Labels,
		}
		// A sandbox whose address cannot be dialed at all — a malformed
		// host:port in the registry — is a fact about the fleet, so it is
		// reported in the row rather than failing the whole listing.
		if _, err := s.pool.Host(sb.Name, sb.Address); err != nil {
			row.Health, row.Detail = client.HealthUnreachable, oneLine(err.Error())
			out = append(out, row)
			continue
		}
		if h, ok := s.pool.Health(sb.Name); ok {
			applyHealth(&row, h)
		}
		out = append(out, row)
	}
	return out, nil
}

// applyHealth projects a cached probe onto a row.
//
// A probe that has not run yet leaves the row "unknown", which is deliberately
// a different word from "unreachable": nothing has looked is not the same as
// looked and found nothing, and an operator who cannot tell them apart will
// chase a machine that is fine.
func applyHealth(row *Sandbox, h client.HealthStatus) {
	if h.CheckedAt.IsZero() {
		return
	}
	if !h.Reachable {
		if h.Err == nil {
			// Dialed, never probed. Still unknown.
			return
		}
		row.Health, row.Detail = client.HealthUnreachable, probeDetail(h.Err)
		return
	}
	row.Health = client.HealthName(h.Status)
	row.Detail = oneLine(h.Message)
	if h.AgentVersion != "" {
		row.Agent = cli.SafeText(h.AgentVersion)
	}
	if h.CheckedAt.After(row.LastSeen) {
		row.LastSeen = h.CheckedAt
	}
}

// probeDetail renders why a sandbox did not answer, in the vocabulary
// client.MapError defines, so the TUI's reason and the CLI's reason for the
// same failure are the same sentence.
func probeDetail(err error) string {
	mapped := client.MapError(err)
	switch {
	case errors.Is(mapped, client.ErrUnreachable), errors.Is(mapped, client.ErrDeadlineExceeded):
		return "no answer within the timeout"
	case errors.Is(mapped, client.ErrCertificateRejected):
		return "certificate rejected"
	default:
		return oneLine(mapped.Error())
	}
}

func (s *fleetSource) Processes(ctx context.Context, sandbox, address string) ([]Process, error) {
	proc, err := s.pool.Process(sandbox, address)
	if err != nil {
		return nil, client.MapError(err)
	}
	callCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	resp, err := proc.ListProcesses(callCtx, &sandboxdv1.ListProcessesRequest{})
	if err != nil {
		return nil, client.MapError(err)
	}
	now := time.Now()
	out := make([]Process, 0, len(resp.GetProcesses()))
	for _, st := range resp.GetProcesses() {
		out = append(out, projectProcess(st, now))
	}
	return out, nil
}

// projectProcess turns a wire status into a row, using the shared state
// vocabulary and the shared duration rendering.
func projectProcess(st *sandboxdv1.ProcessStatus, now time.Time) Process {
	p := Process{
		ID:           st.GetProcessId(),
		Name:         cli.SafeText(st.GetName()),
		State:        client.ProcessStateName(st.GetState()),
		PID:          st.GetPid(),
		Restarts:     st.GetRestartCount(),
		LastLog:      cli.SafeText(st.GetLastLogLine()),
		AdoptionNote: cli.SafeText(st.GetAdoptionNote()),
		Ports:        sortedPorts(st.GetListeningPorts()),
	}
	live := client.ProcessStateLive(st.GetState())
	if started := st.GetStartedAt(); started != nil {
		end := now
		if !live && st.GetExitedAt() != nil {
			end = st.GetExitedAt().AsTime()
		}
		p.Uptime = cli.HumanDuration(end.Sub(started.AsTime()))
	}
	if !live {
		// A process that has exited has no pid, and showing the one it used to
		// hold invites a signal aimed at whatever now owns it.
		p.PID = 0
	}
	return p
}

func sortedPorts(ports []uint32) []uint32 {
	if len(ports) == 0 {
		return nil
	}
	out := append([]uint32(nil), ports...)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Logs fetches one bounded window of a process's output.
//
// Bounded twice over, deliberately. The request carries a finite
// follow_duration, which the agent clamps again to its own maximum, so the
// stream ends on its own with a summary rather than running until something
// closes it. And the rendering keeps at most MaxLines, dropping the oldest, so
// a process that outruns the pane costs a fixed amount of memory. This is the
// same bound fleet_process_logs is under, for the same reason: a call that
// never returns is indistinguishable from a hung agent.
func (s *fleetSource) Logs(ctx context.Context, sandbox, address, processID string, opts LogOptions) (Logs, error) {
	proc, err := s.pool.Process(sandbox, address)
	if err != nil {
		return Logs{}, client.MapError(err)
	}

	// Clamped on both sides here rather than trusted: this is the one request
	// in the program whose duration decides how long a call can last, and the
	// bound has to hold even for a caller that asked for something absurd.
	follow := boundFollow(opts.FollowFor)
	req := &sandboxdv1.GetProcessLogsRequest{
		ProcessId: processID,
		TailLines: uint32(clamp(opts.TailLines, 0, 1<<20)), //nolint:gosec // clamped
		Follow:    follow > 0,
	}
	if follow > 0 {
		req.FollowDuration = durationpb.New(follow)
	}

	// The RPC deadline is the follow bound plus slack, never less: the agent's
	// deadline ends the stream with a summary, ours would end it with a
	// timeout error and no logs at all, so ours must be the later of the two.
	callCtx, cancel := context.WithTimeout(ctx, follow+s.timeout)
	defer cancel()

	stream, err := proc.GetProcessLogs(callCtx, req)
	if err != nil {
		return Logs{}, client.MapError(err)
	}
	return readLogStream(stream, opts.MaxLines)
}

// logReceiver is the half of the gRPC client stream this file uses. Narrowing
// it to Recv is what lets a test render a synthetic stream without a
// connection.
type logReceiver interface {
	Recv() (*sandboxdv1.GetProcessLogsResponse, error)
}

// readLogStream drains a bounded log stream into lines.
//
// Drop markers go inline, in sequence, rather than into a counter at the end: a
// gap between two lines is a fact about those two lines, and a reader who sees
// them adjacent will draw a conclusion from their adjacency. Rendering the
// marker is what stops that, and it is why the pane shows a gap rather than
// silently closing one.
func readLogStream(stream logReceiver, maxLines int) (Logs, error) {
	if maxLines <= 0 {
		maxLines = maxLogLines
	}
	var out Logs
	for {
		resp, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			// Whatever arrived before the failure is still worth showing: a
			// partial window beats a blank pane, and the caller reports the
			// error beside it.
			out.Lines = trimLines(out.Lines, maxLines, &out)
			return out, client.MapError(err)
		}
		if sum := resp.GetSummary(); sum != nil {
			out.Dropped = sum.GetLinesDropped()
			out.DeadlineReached = sum.GetFollowDeadlineReached()
			continue
		}
		line := resp.GetLine()
		if line == nil {
			continue
		}
		if n := line.GetDroppedBefore(); n > 0 {
			out.Lines = append(out.Lines, LogLine{
				Text:   fmt.Sprintf("--- %d line(s) dropped: the process outran the log buffer ---", n),
				Marker: true,
			})
		}
		out.Lines = append(out.Lines, LogLine{Text: renderLogLine(line)})
		out.Lines = trimLines(out.Lines, maxLines, &out)
	}
	return out, nil
}

// trimLines drops the oldest lines to stay within the cap, recording that it
// did. Output is never silently cut.
func trimLines(lines []LogLine, maxLines int, out *Logs) []LogLine {
	if len(lines) <= maxLines {
		return lines
	}
	out.Truncated = true
	return lines[len(lines)-maxLines:]
}

// renderLogLine prefixes a line with its stream, the way fleet_process_logs
// does: stdout unprefixed because it is the common case, stderr "E| ", and the
// supervisor's own lines — a restart, a backoff, a decision to give up — "S| "
// so they are not mistaken for the process's output.
func renderLogLine(line *sandboxdv1.LogLine) string {
	// A log line is the least trustworthy string in this program: it is
	// whatever some process on some machine wrote, and it lands on the
	// operator's terminal. SafeText is what stops an escape sequence in it
	// repositioning the cursor out of the pane.
	text := cli.SafeText(line.GetText())
	if line.GetContinued() {
		// The agent split this line because it exceeded the per-line cap. Say
		// so, or the two halves read as two independent short lines.
		text += " [+]"
	}
	switch line.GetStream() {
	case sandboxdv1.Stream_STREAM_STDERR:
		return "E| " + text
	case sandboxdv1.Stream_STREAM_STDOUT:
		return text
	default:
		return "S| " + text
	}
}

func (s *fleetSource) Detail(ctx context.Context, sandbox, address string, toolchains bool) (Detail, error) {
	host, err := s.pool.Host(sandbox, address)
	if err != nil {
		return Detail{}, client.MapError(err)
	}
	callCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	info, err := host.GetHostInfo(callCtx, &sandboxdv1.GetHostInfoRequest{IncludeToolchains: toolchains})
	if err != nil {
		return Detail{}, client.MapError(err)
	}

	// Every string below is the agent's own account of itself, arriving over
	// the wire and going straight to a terminal, so all of it goes through
	// SafeText.
	p := info.GetPlatform()
	res := info.GetResources()
	d := Detail{
		Platform:        cli.SafeText(registry.Platform{OS: p.GetOs(), Arch: p.GetArch()}.String()),
		Kernel:          cli.SafeText(p.GetKernelVersion()),
		Hostname:        cli.SafeText(p.GetHostname()),
		Agent:           cli.SafeText(info.GetAgentVersion()),
		Principal:       cli.SafeText(info.GetAuthenticatedPrincipal()),
		CPUCores:        res.GetCpuCores(),
		MemoryTotal:     cli.HumanBytes(res.GetMemoryTotalBytes()),
		MemoryAvailable: cli.HumanBytes(res.GetMemoryAvailableBytes()),
		DiskTotal:       cli.HumanBytes(res.GetDiskTotalBytes()),
		DiskAvailable:   cli.HumanBytes(res.GetDiskAvailableBytes()),
		Load1m:          res.GetLoadAverage_1M(),
		ToolchainsAsked: toolchains,
	}
	for _, root := range info.GetAllowedRoots() {
		d.AllowedRoots = append(d.AllowedRoots, cli.SafeText(root))
	}
	d.Unconfined = len(d.AllowedRoots) == 0
	if started := info.GetStartedAt(); started != nil {
		d.Uptime = cli.HumanDuration(time.Since(started.AsTime()))
	}
	for _, tc := range info.GetToolchains() {
		d.Toolchains = append(d.Toolchains, Toolchain{
			Name:    cli.SafeText(tc.GetName()),
			Version: cli.SafeText(tc.GetVersion()),
			Path:    cli.SafeText(tc.GetPath()),
		})
	}
	return d, nil
}

// maxFollow bounds a single log window whatever it was asked for. The agent
// clamps its own follow too; this is the near side of the same rule, and it is
// what keeps a bad schedule from producing a call that outlives the frame it
// was meant to fill.
const maxFollow = time.Minute

// boundFollow is the near side of the rule: no window follows for longer than
// maxFollow, and a negative one does not follow at all.
func boundFollow(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	if d > maxFollow {
		return maxFollow
	}
	return d
}

// gracePeriod is the agent's own default graceful-stop grace period, mirrored
// so the deadline this side applies is never the shorter of the two. A stop
// that gave up first would report a timeout for a stop that was working.
const gracePeriod = 10 * time.Second

func (s *fleetSource) Signal(ctx context.Context, sandbox, address, processID, sig string, graceful bool) error {
	proc, err := s.pool.Process(sandbox, address)
	if err != nil {
		return client.MapError(err)
	}
	named, err := parseSignal(sig)
	if err != nil {
		return err
	}

	timeout := s.timeout
	req := &sandboxdv1.SignalProcessRequest{ProcessId: processID, Signal: named}
	if graceful {
		req.GracefulStop = true
		req.GracePeriod = durationpb.New(gracePeriod)
		// An operator's stop is an intentional stop, so the supervisor must not
		// immediately undo it. This is the one flag the TUI sets that the
		// wire default does not, and it is what makes the key mean "stop".
		req.DisableRestart = true
		// A graceful stop blocks on the agent for the whole grace period
		// before it answers, so the deadline has to clear it.
		timeout = gracePeriod + s.timeout
	}

	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if _, err := proc.SignalProcess(callCtx, req); err != nil {
		return client.MapError(err)
	}
	return nil
}

// parseSignal maps a signal name onto the wire enum. The list is the wire's,
// not this package's: a name the proto does not have is refused here rather
// than sent and rejected on the far side.
func parseSignal(sig string) (sandboxdv1.SignalProcessRequest_Signal, error) {
	switch sig {
	case "TERM":
		return sandboxdv1.SignalProcessRequest_SIGNAL_TERM, nil
	case "KILL":
		return sandboxdv1.SignalProcessRequest_SIGNAL_KILL, nil
	case "INT":
		return sandboxdv1.SignalProcessRequest_SIGNAL_INT, nil
	case "HUP":
		return sandboxdv1.SignalProcessRequest_SIGNAL_HUP, nil
	case "USR1":
		return sandboxdv1.SignalProcessRequest_SIGNAL_USR1, nil
	case "USR2":
		return sandboxdv1.SignalProcessRequest_SIGNAL_USR2, nil
	default:
		return 0, fmt.Errorf("no signal named %q; the agent accepts TERM, KILL, INT, HUP, USR1, USR2", sig)
	}
}

func (s *fleetSource) Restart(ctx context.Context, sandbox, address, processID string) error {
	proc, err := s.pool.Process(sandbox, address)
	if err != nil {
		return client.MapError(err)
	}
	// Restart stops the process first, so it costs a grace period like a stop
	// does. wait_for_ready is left false: the view refreshes anyway, and a
	// restart that blocked on a readiness probe would hold the pane while a
	// dev server took its eight seconds to bind.
	callCtx, cancel := context.WithTimeout(ctx, gracePeriod+s.timeout)
	defer cancel()

	if _, err := proc.RestartProcess(callCtx, &sandboxdv1.RestartProcessRequest{
		ProcessId:   processID,
		GracePeriod: durationpb.New(gracePeriod),
	}); err != nil {
		return client.MapError(err)
	}
	return nil
}
