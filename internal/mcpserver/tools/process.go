package tools

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	sandboxdv1 "github.com/axelmierczuk/sandboxd-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/sandboxd-mcp/internal/mcpserver/selection"
)

// Five tools, not one action-dispatched tool.
//
// A single sandbox_process(action=…) call would need a union-typed argument
// object: argv and ready_probe are meaningless for a signal, signal and
// grace_seconds are meaningless for a start, and process_id is required for
// four of the five and forbidden for the fifth. That is precisely the shape
// models get wrong — the schema cannot express "these six fields apply only
// when action is start", so nothing stops a call that sets none of them. Five
// schemas, each of which is wrong to under-fill, is worth the extra names in
// the tool list.

// Bounds on what one process contributes to a result.
//
// Everything below is the supervised process's own output, so none of these
// lengths are this side's to assume. A list of twenty processes is paid for on
// every check, and one process logging a stack trace on a single line must not
// turn it into a wall of text.
const (
	// maxLastLogLine bounds the trailing output line shown per process.
	maxLastLogLine = 120
	// maxCommandChars bounds the rendered command line in a list row.
	maxCommandChars = 120
	// maxProcessName bounds the label a process was started under. It is the
	// one string in a row that came from the caller rather than from the
	// process, and it is bounded for the same reason the rest are: a name
	// carrying a newline splits a row in two, and the whole claim of this
	// listing is one line per process.
	maxProcessName = 64
	// maxRenderedLogBytes bounds a rendered log block. Beyond it the oldest
	// lines are dropped and the omission is reported in `truncation`.
	maxRenderedLogBytes = 96 * 1024
	// maxRecentLogLines is how much log a failed readiness probe returns
	// alongside ready_error.
	maxRecentLogLines = 20
)

// Defaults for the follow bound. Following is always bounded; the agent clamps
// this again to its own maximum.
const (
	defaultFollowSeconds = 20
	// followSlack is added to the RPC deadline on top of the follow bound, so
	// the deadline that fires is the agent's rather than ours — the agent's
	// ends with a summary, ours ends with a timeout error.
	followSlack = 15 * time.Second
	// maxSecondsArgument bounds every seconds-valued argument before it becomes
	// a Duration. An hour is far past anything useful — the agent clamps a
	// follow to its own maximum and a grace period to its own — and the bound
	// is what stops a caller's large number multiplying into a negative
	// duration and an RPC deadline that has already expired.
	maxSecondsArgument = 3600
)

// defaultGraceSeconds is the agent's own default graceful-stop grace period,
// mirrored here for the same reason probeDeadline mirrors the probe timeout:
// the deadline this side applies must never be the shorter of the two. A stop
// that leaves grace_seconds unset still costs the agent this long before it
// escalates, and a call that gave up first would report a timeout for a stop
// that was working.
const defaultGraceSeconds = 10

// gracePeriodFor is what a graceful stop will actually cost the agent: the
// argument when the caller named one, and the agent's own default when it did
// not. An unset grace_seconds is not a zero grace, and sizing a deadline as
// though it were is how a call gives up on a stop that is still working.
func gracePeriodFor(graceSeconds int) time.Duration {
	if graceSeconds > 0 {
		return time.Duration(graceSeconds) * time.Second
	}
	return defaultGraceSeconds * time.Second
}

// signalDeadline bounds a sandbox_process_signal call.
//
// A graceful stop blocks on the agent for the whole grace period before it
// answers, so the deadline has to clear it. Anything else answers immediately
// and takes the ordinary call timeout.
func signalDeadline(gracefulStop bool, graceSeconds int, callTimeout time.Duration) time.Duration {
	if !gracefulStop {
		return callTimeout
	}
	return max(callTimeout, gracePeriodFor(graceSeconds)+followSlack)
}

// probeAdvice is the one sentence in sandbox_process_start's description that
// prevents a class of "the server is broken" misdiagnoses. A dev server that
// takes eight seconds to bind refuses the connection a model makes one second
// after "started", and the model concludes the server is broken rather than
// that it asked too early.
const probeAdvice = "Strongly recommended: pass ready_probe (usually tcp_port for a server). Without one, \"started\" means only \"spawned\" — a dev server that needs eight seconds to bind will refuse the connection you make one second later, and you will conclude it is broken."

// registerProcess adds the five background-process tools.
func registerProcess(r *Registrar) {
	AddTargeted(r, &mcp.Tool{
		Name:  "sandbox_process_start",
		Title: "Start a background process",
		Description: "Spawn a supervised background process on the sandbox — a dev server, watcher, or worker — that keeps running after this call returns and outlives the MCP session. Use sandbox_exec for a command that should run to completion. " +
			probeAdvice + " With a probe set, this call waits for it to pass unless wait_for_ready is explicitly false; if the probe times out the process is left running and ready_error plus its recent logs come back so you can see why.",
	}, r.processStart)

	AddTargeted(r, &mcp.Tool{
		Name:        "sandbox_process_list",
		Title:       "List background processes",
		Description: "List every process the sandbox's agent is tracking, including ones that have exited but not been reaped. Returns a compact table with state, name, pid, uptime, restart count, listening ports and the last output line, so the fleet's processes can be understood without a logs call per process.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, r.processList)

	AddTargeted(r, &mcp.Tool{
		Name:  "sandbox_process_logs",
		Title: "Read background process logs",
		Description: "Read a supervised process's buffered output, optionally following new output. Following is always bounded by follow_seconds (the agent clamps it to its own maximum), so this call always returns. " +
			"Lines the process wrote to stderr are prefixed \"E| \" and lines the supervisor itself wrote — a restart, a backoff, an adoption note — are prefixed \"S| \"; stdout is unprefixed. A gap caused by the process outrunning the log buffer is marked inline.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, r.processLogs)

	AddTargeted(r, &mcp.Tool{
		Name:  "sandbox_process_signal",
		Title: "Signal a background process",
		Description: "Send a signal to a supervised process, or stop it gracefully with graceful_stop (SIGTERM, wait grace_seconds, then SIGKILL) — the result reports whether it had to escalate to SIGKILL. " +
			"Signals reach the whole process group by default, because signalling only the leader routinely leaves orphans holding the port. Set disable_restart when stopping a process whose restart policy would otherwise bring it straight back.",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: boolPtr(true)},
	}, r.processSignal)

	AddTargeted(r, &mcp.Tool{
		Name:        "sandbox_process_restart",
		Title:       "Restart a background process",
		Description: "Stop a supervised process and start it again from the same spec, keeping its process id and its log history. Waits for the readiness probe to pass again when the process has one, unless wait_for_ready is explicitly false.",
		Annotations: &mcp.ToolAnnotations{IdempotentHint: false},
	}, r.processRestart)
}

// ---------------------------------------------------------------- shared

// ProcessLine is one row of sandbox_process_list.
//
// Every field but the identifiers is omitempty: twenty of these are paid for
// on every list call, and a field that says nothing should cost nothing.
type ProcessLine struct {
	// ProcessID is what every other process tool takes.
	ProcessID string `json:"process_id"`
	// Name is the label the process was started under.
	Name string `json:"name"`
	// State is starting, ready, running, exited, crashed, restarting or
	// orphaned.
	State string `json:"state"`
	// PID is the OS process id, absent once the process has exited.
	PID int32 `json:"pid,omitempty"`
	// Command is the rendered command line, bounded.
	Command string `json:"command,omitempty"`
	// Uptime is how long the current run has been going, or how long the last
	// one lasted for a process that has exited.
	Uptime string `json:"uptime,omitempty"`
	// StartedAt is when the current run started, RFC3339.
	StartedAt string `json:"started_at,omitempty"`
	// ExitCode is the status of a process that has exited.
	ExitCode *int32 `json:"exit_code,omitempty"`
	// Signal names the signal that killed the process, when one did.
	Signal string `json:"signal,omitempty"`
	// RestartCount is how many times the supervisor has restarted it.
	RestartCount uint32 `json:"restart_count,omitempty"`
	// LastLogLine is the most recent output line, bounded.
	LastLogLine string `json:"last_log_line,omitempty"`
	// ListeningPorts are the ports the process holds, best-effort.
	ListeningPorts []uint32 `json:"listening_ports,omitempty"`
	// AdoptionNote explains what the agent concluded about a process that may
	// have survived a daemon restart.
	AdoptionNote string `json:"adoption_note,omitempty"`
}

// ProcessDetail is one process in full, for the tools that act on exactly one.
type ProcessDetail struct {
	ProcessLine
	// Argv is the command and its arguments, unjoined.
	Argv []string `json:"argv,omitempty"`
	// WorkingDir is the directory the process was spawned in.
	WorkingDir string `json:"working_dir,omitempty"`
	// ExitedAt is when the process exited, RFC3339.
	ExitedAt string `json:"exited_at,omitempty"`
	// RestartPolicy is never, on_failure or always.
	RestartPolicy string `json:"restart_policy,omitempty"`
}

// stateString renders a process state. Short strings, not enum names: they
// land in model context on every list call, and "crashed" says everything
// PROCESS_STATE_CRASHED does in a quarter of the tokens.
func stateString(s sandboxdv1.ProcessState) string {
	switch s {
	case sandboxdv1.ProcessState_PROCESS_STATE_STARTING:
		return "starting"
	case sandboxdv1.ProcessState_PROCESS_STATE_READY:
		return "ready"
	case sandboxdv1.ProcessState_PROCESS_STATE_RUNNING:
		return "running"
	case sandboxdv1.ProcessState_PROCESS_STATE_EXITED:
		return "exited"
	case sandboxdv1.ProcessState_PROCESS_STATE_CRASHED:
		return "crashed"
	case sandboxdv1.ProcessState_PROCESS_STATE_RESTARTING:
		return "restarting"
	case sandboxdv1.ProcessState_PROCESS_STATE_ORPHANED:
		return "orphaned"
	default:
		return "unknown"
	}
}

// liveState reports whether a state means the process is still there. Uptime
// is measured to now for these and to the exit for the rest.
func liveState(s sandboxdv1.ProcessState) bool {
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

func policyString(p sandboxdv1.RestartPolicy) string {
	switch p {
	case sandboxdv1.RestartPolicy_RESTART_POLICY_ON_FAILURE:
		return "on_failure"
	case sandboxdv1.RestartPolicy_RESTART_POLICY_ALWAYS:
		return "always"
	case sandboxdv1.RestartPolicy_RESTART_POLICY_NEVER:
		return "never"
	default:
		return ""
	}
}

// parsePolicy maps the tool's enum onto the wire enum.
func parsePolicy(s string) (sandboxdv1.RestartPolicy, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "":
		return sandboxdv1.RestartPolicy_RESTART_POLICY_UNSPECIFIED, nil
	case "never":
		return sandboxdv1.RestartPolicy_RESTART_POLICY_NEVER, nil
	case "on_failure", "on-failure", "onfailure":
		return sandboxdv1.RestartPolicy_RESTART_POLICY_ON_FAILURE, nil
	case "always":
		return sandboxdv1.RestartPolicy_RESTART_POLICY_ALWAYS, nil
	default:
		return 0, fmt.Errorf("restart_policy %q is not one of never, on_failure, always", s)
	}
}

// processLine projects a wire status onto a list row.
func processLine(st *sandboxdv1.ProcessStatus, now time.Time) ProcessLine {
	line := ProcessLine{
		ProcessID:      st.GetProcessId(),
		Name:           clipCell(st.GetName(), maxProcessName),
		State:          stateString(st.GetState()),
		PID:            st.GetPid(),
		Command:        clipCell(strings.Join(st.GetArgv(), " "), maxCommandChars),
		RestartCount:   st.GetRestartCount(),
		LastLogLine:    clipCell(st.GetLastLogLine(), maxLastLogLine),
		ListeningPorts: sortedPorts(st.GetListeningPorts()),
		AdoptionNote:   clipCell(st.GetAdoptionNote(), maxLastLogLine),
		Signal:         st.GetSignal(),
	}
	if started := st.GetStartedAt(); started != nil {
		line.StartedAt = started.AsTime().UTC().Format(time.RFC3339)
		end := now
		if !liveState(st.GetState()) && st.GetExitedAt() != nil {
			end = st.GetExitedAt().AsTime()
		}
		line.Uptime = humanDuration(end.Sub(started.AsTime()))
	}
	// The exit code is meaningless while the process is running, and zero is a
	// real exit code — so it is a pointer, present only once there is one.
	if !liveState(st.GetState()) {
		code := st.GetExitCode()
		line.ExitCode = &code
		// A process that has exited has no pid, and reporting the one it used
		// to hold invites a signal aimed at whatever now owns it.
		line.PID = 0
	}
	return line
}

// processDetail projects a wire status onto the full form.
func processDetail(st *sandboxdv1.ProcessStatus, now time.Time) ProcessDetail {
	d := ProcessDetail{
		ProcessLine:   processLine(st, now),
		Argv:          st.GetArgv(),
		WorkingDir:    st.GetWorkingDir(),
		RestartPolicy: policyString(st.GetRestartPolicy()),
	}
	if exited := st.GetExitedAt(); exited != nil && !liveState(st.GetState()) {
		d.ExitedAt = exited.AsTime().UTC().Format(time.RFC3339)
	}
	return d
}

// clipCell bounds an agent-supplied string for one cell of the listing.
//
// It flattens first and then bounds, which is the difference from [clip] in
// output.go and the reason this is not that: a cell of a fixed-width table is
// one line by definition, so a newline in one — in a process name, in the last
// line of output, in an adoption note — splits its row in two and breaks the
// only claim the listing makes. Bounding a string that still contains a newline
// bounds the wrong thing. Trailing spaces go too, so the last column of a row
// cannot carry padding past the end of the line.
func clipCell(s string, limit int) string {
	return clip(strings.TrimRight(strings.ReplaceAll(strings.ReplaceAll(s, "\r", ""), "\n", " "), " "), limit)
}

// processClient dials the target's ProcessService.
func (r *Registrar) processClient(target *selection.Target) (sandboxdv1.ProcessServiceClient, error) {
	if r.deps.Clients == nil {
		return nil, fmt.Errorf("sandbox %s cannot be reached: no gRPC client is configured", target.Name())
	}
	client, err := r.deps.Clients.Process(target.Name(), target.Address())
	if err != nil {
		return nil, target.Call().Map(err)
	}
	return client, nil
}

// processCallError maps a ProcessService failure, turning a NotFound into an
// error that lists the process ids that do exist.
//
// A model told only "no process with id web" cannot recover: it does not know
// whether the id is stale, misspelled, or on the wrong sandbox, and its next
// move is a list call it should not have had to make. Listing them costs one
// round trip on the failure path and saves a turn on every occurrence.
func (r *Registrar) processCallError(ctx context.Context, target *selection.Target, client sandboxdv1.ProcessServiceClient, processID string, err error) error {
	c := target.Call()
	c.Subject = "process " + processID
	if status.Code(err) != codes.NotFound {
		return c.Map(err)
	}

	known := r.knownProcesses(ctx, target, client)
	switch {
	case len(known) == 0:
		return fmt.Errorf("sandbox %s is tracking no process with id %q, and no processes at all. Start one with sandbox_process_start",
			target.Name(), processID)
	default:
		return fmt.Errorf("sandbox %s is tracking no process with id %q. Tracked process ids: %s",
			target.Name(), processID, strings.Join(known, ", "))
	}
}

// knownProcesses lists "<id> (<name>, <state>)" for every tracked process, for
// the not-found message. A failure here is not reported: the caller is already
// in an error path and a second failure would replace a useful message with a
// less useful one.
func (r *Registrar) knownProcesses(ctx context.Context, target *selection.Target, client sandboxdv1.ProcessServiceClient) []string {
	listCtx, cancel := context.WithTimeout(ctx, r.deps.callTimeout())
	defer cancel()

	resp, err := client.ListProcesses(listCtx, &sandboxdv1.ListProcessesRequest{})
	if err != nil {
		r.deps.logger().Debug("list processes for not-found message", "sandbox", target.Name(), "error", err)
		return nil
	}
	out := make([]string, 0, len(resp.GetProcesses()))
	for _, p := range resp.GetProcesses() {
		out = append(out, fmt.Sprintf("%s (%s, %s)", p.GetProcessId(), p.GetName(), stateString(p.GetState())))
	}
	return out
}

// ---------------------------------------------------------------- start

// ReadyProbeArgs is how a caller says what "ready" means for this process.
//
// It is flat on purpose. Exactly one of the four conditions is set, plus a
// timeout — no nested oneof wrapper, no discriminator field to get wrong. This
// is the highest-leverage schema in the process group: a model that cannot
// construct the probe will omit it, and omitting it is the exact failure the
// feature exists to prevent.
type ReadyProbeArgs struct {
	// LogPattern matches a line on stdout or stderr.
	LogPattern string `json:"log_pattern,omitempty" jsonschema:"ready when a line matching this RE2 pattern appears on stdout or stderr, e.g. \"Listening on\""`
	// TCPPort is the port that must accept a connection.
	TCPPort int `json:"tcp_port,omitempty" jsonschema:"ready when a TCP connection to this port on the sandbox's loopback succeeds; the usual choice for a server"`
	// HTTPGetURL is the URL that must answer below 500.
	HTTPGetURL string `json:"http_get_url,omitempty" jsonschema:"ready when an HTTP GET of this URL returns a status below 500, e.g. \"http://127.0.0.1:3000/healthz\""`
	// UptimeSeconds is how long the process must merely survive.
	UptimeSeconds float64 `json:"uptime_seconds,omitempty" jsonschema:"ready once the process has stayed alive this many seconds; the weakest probe, for a process with nothing better to check"`
	// TimeoutSeconds bounds the wait.
	TimeoutSeconds float64 `json:"timeout_seconds,omitempty" jsonschema:"how long to wait for the probe to pass before reporting ready_error; defaults to the agent's timeout (30s) and is capped at one hour"`
}

// toProto validates the probe and converts it. Exactly one condition must be
// set: zero is the omission this schema exists to prevent, and two is a
// request the agent cannot honour.
func (p *ReadyProbeArgs) toProto() (*sandboxdv1.ReadyProbe, error) {
	if p == nil {
		return nil, nil
	}
	// The two seconds-valued arguments, checked before anything is built from
	// them. They are the durations this side sizes the RPC deadline from, and a
	// negative one is a caller mistake rather than a value to clamp silently —
	// the integer seconds arguments on signal and restart are refused the same
	// way. secondsToDuration bounds the other end.
	if p.UptimeSeconds < 0 {
		return nil, fmt.Errorf("ready_probe.uptime_seconds %g is negative", p.UptimeSeconds)
	}
	if p.TimeoutSeconds < 0 {
		return nil, fmt.Errorf("ready_probe.timeout_seconds %g is negative", p.TimeoutSeconds)
	}

	var set []string
	out := &sandboxdv1.ReadyProbe{}
	if p.LogPattern != "" {
		set = append(set, "log_pattern")
		out.Probe = &sandboxdv1.ReadyProbe_LogPattern{LogPattern: p.LogPattern}
	}
	if p.TCPPort != 0 {
		set = append(set, "tcp_port")
		if p.TCPPort < 1 || p.TCPPort > 65535 {
			return nil, fmt.Errorf("ready_probe.tcp_port %d is out of range; expected 1-65535", p.TCPPort)
		}
		out.Probe = &sandboxdv1.ReadyProbe_TcpPort{TcpPort: uint32(p.TCPPort)} //nolint:gosec // range-checked above
	}
	if p.HTTPGetURL != "" {
		set = append(set, "http_get_url")
		out.Probe = &sandboxdv1.ReadyProbe_HttpGetUrl{HttpGetUrl: p.HTTPGetURL}
	}
	if p.UptimeSeconds > 0 {
		set = append(set, "uptime_seconds")
		out.Probe = &sandboxdv1.ReadyProbe_Uptime{Uptime: durationpb.New(secondsToDuration(p.UptimeSeconds))}
	}

	switch len(set) {
	case 1:
	case 0:
		return nil, errors.New("ready_probe is set but names no condition: set exactly one of log_pattern, tcp_port, http_get_url or uptime_seconds (tcp_port is the usual choice for a server), or omit ready_probe entirely")
	default:
		return nil, fmt.Errorf("ready_probe sets %s; set exactly one condition", strings.Join(set, " and "))
	}

	if p.TimeoutSeconds > 0 {
		out.Timeout = durationpb.New(secondsToDuration(p.TimeoutSeconds))
	}
	return out, nil
}

// secondsToDuration converts a seconds-valued argument, bounded.
//
// The bound is the same maxSecondsArgument every integer seconds argument gets,
// and it is here for the same reason: an hour is far past anything useful, and
// what it really stops is the multiplication. A float64 that large converts to
// an int64 that is implementation-defined when it does not fit — saturating to
// the maximum on arm64, wrapping to the minimum on amd64 — so an unbounded
// timeout_seconds gives an RPC deadline of either three centuries or a duration
// that has already expired, and which one depends on the workstation's
// architecture. Negative values are refused by the caller rather than clamped,
// because a negative timeout is a mistake worth naming.
func secondsToDuration(s float64) time.Duration {
	if s > maxSecondsArgument {
		s = maxSecondsArgument
	}
	return time.Duration(s * float64(time.Second))
}

// ProcessStartArgs are the arguments to sandbox_process_start.
type ProcessStartArgs struct {
	TargetArgs
	// Argv is the executable and its arguments. Not shell-parsed.
	Argv []string `json:"argv" jsonschema:"executable and arguments, not shell-parsed, e.g. [\"npm\",\"run\",\"dev\"]"`
	// Name is the label the process is found again by.
	Name string `json:"name" jsonschema:"short label for this process, e.g. \"web-dev\"; must be unique among running processes unless replace_existing is set"`
	// WorkingDir is where to spawn it.
	WorkingDir string `json:"working_dir,omitempty" jsonschema:"directory on the sandbox to run in; defaults to the agent's working directory"`
	// Env are extra KEY=VALUE entries.
	Env []string `json:"env,omitempty" jsonschema:"extra environment entries as KEY=VALUE, applied over the agent's base environment"`
	// ReadyProbe defines what "ready" means.
	ReadyProbe *ReadyProbeArgs `json:"ready_probe,omitempty" jsonschema:"how to tell this process is usable rather than merely spawned; set exactly one condition. Strongly recommended for anything that binds a port"`
	// WaitForReady blocks until the probe passes. Unset means "yes, if a probe
	// was given".
	WaitForReady *bool `json:"wait_for_ready,omitempty" jsonschema:"block until the ready probe passes; defaults to true whenever ready_probe is set, so a probe you configured is a probe that is waited on"`
	// RestartPolicy controls automatic restarts.
	RestartPolicy string `json:"restart_policy,omitempty" jsonschema:"never (default), on_failure, or always"`
	// MaxRestarts caps automatic restarts.
	MaxRestarts int `json:"max_restarts,omitempty" jsonschema:"maximum automatic restarts before the supervisor gives up; zero means the agent default"`
	// ReplaceExisting stops and replaces a process with the same name.
	ReplaceExisting bool `json:"replace_existing,omitempty" jsonschema:"stop and replace a still-running process that already has this name"`
}

// ProcessStartResult is the sandbox_process_start result.
type ProcessStartResult struct {
	// Echo carries the sandbox this started on.
	Echo
	// Process is the process as the agent now sees it.
	Process ProcessDetail `json:"process"`
	// Ready reports whether the readiness probe passed. It is absent when no
	// probe was configured, where "ready" has no meaning.
	Ready *bool `json:"ready,omitempty"`
	// ReadyError is why the probe did not pass in time. The process is still
	// running: read RecentLogs, then decide whether to stop it.
	ReadyError string `json:"ready_error,omitempty"`
	// RecentLogs is the tail of the process's output, present whenever
	// ReadyError is — a readiness failure with no logs sends the caller
	// straight into another tool call.
	RecentLogs string `json:"recent_logs,omitempty"`
	// Note is what the caller should not have to infer.
	Note string `json:"note,omitempty"`
}

func (r *Registrar) processStart(ctx context.Context, _ *mcp.CallToolRequest, target *selection.Target, in ProcessStartArgs) (ProcessStartResult, error) {
	if len(in.Argv) == 0 {
		return ProcessStartResult{}, errors.New("argv is required: give the executable and its arguments, e.g. [\"npm\",\"run\",\"dev\"]")
	}
	if strings.TrimSpace(in.Name) == "" {
		return ProcessStartResult{}, errors.New("name is required: it is the label every later process call uses to find this process")
	}
	probe, err := in.ReadyProbe.toProto()
	if err != nil {
		return ProcessStartResult{}, err
	}
	policy, err := parsePolicy(in.RestartPolicy)
	if err != nil {
		return ProcessStartResult{}, err
	}
	if in.MaxRestarts < 0 {
		return ProcessStartResult{}, fmt.Errorf("max_restarts %d is negative", in.MaxRestarts)
	}

	// A probe that is configured is a probe that is waited on. Setting one and
	// leaving wait_for_ready unset is a caller who described readiness and then
	// did not use it, which is the same failure as having no probe at all.
	wait := probe != nil
	if in.WaitForReady != nil {
		wait = *in.WaitForReady
	}

	client, err := r.processClient(target)
	if err != nil {
		return ProcessStartResult{}, err
	}

	// The call has to outlive the probe: the agent blocks for the probe timeout
	// before answering, and a fifteen-second unary deadline would cut off a
	// thirty-second probe with a timeout error instead of ready_error.
	timeout := r.deps.callTimeout()
	if wait && probe != nil {
		timeout = probeDeadline(probe) + followSlack
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	resp, err := client.StartProcess(callCtx, &sandboxdv1.StartProcessRequest{
		Argv:            in.Argv,
		Name:            in.Name,
		WorkingDir:      in.WorkingDir,
		Env:             in.Env,
		ReadyProbe:      probe,
		RestartPolicy:   policy,
		MaxRestarts:     uint32(min(max(in.MaxRestarts, 0), 1<<16)), //nolint:gosec // clamped
		WaitForReady:    wait,
		ReplaceExisting: in.ReplaceExisting,
	})
	if err != nil {
		c := target.Call()
		c.Subject = "process " + in.Name
		c.Timeout, c.Limit = timeout, "the start call deadline"
		return ProcessStartResult{}, c.Map(err)
	}

	st := resp.GetStatus()
	out := ProcessStartResult{Process: processDetail(st, time.Now())}

	switch {
	case probe == nil:
		out.Note = "No ready probe was configured, so this process is spawned but not known to be usable. " + probeAdvice
	case !wait:
		out.Note = "Started without waiting: wait_for_ready was false, so the probe result is not in yet. Call sandbox_process_list to see whether the state has reached \"ready\"."
	case resp.GetReadyError() != "":
		out.Ready = boolPtr(false)
		out.ReadyError = resp.GetReadyError()
		// The logs are the point. A readiness failure reported on its own tells
		// the caller only that something is wrong, and its next move is always
		// a logs call — so make it unnecessary.
		out.RecentLogs = r.recentLogs(ctx, target, client, st.GetProcessId())
		out.Note = fmt.Sprintf("The readiness probe did not pass, and the process is deliberately left running so its logs can be read. Stop it with sandbox_process_signal(process_id=%q, graceful_stop=true, disable_restart=true) if it is not going to recover.",
			st.GetProcessId())
	default:
		out.Ready = boolPtr(true)
	}
	return out, nil
}

// probeDeadline is how long the agent may block waiting for this probe.
func probeDeadline(probe *sandboxdv1.ReadyProbe) time.Duration {
	if d := probe.GetTimeout().AsDuration(); d > 0 {
		return d
	}
	// The agent's own default, mirrored here so the deadline this side applies
	// is never the shorter of the two.
	return 30 * time.Second
}

// recentLogs fetches the tail of a process's output for a readiness failure.
// It never fails the call it is decorating: an empty tail is worse than a
// populated one, but not as bad as replacing ready_error with a logs error.
func (r *Registrar) recentLogs(ctx context.Context, target *selection.Target, client sandboxdv1.ProcessServiceClient, processID string) string {
	logCtx, cancel := context.WithTimeout(ctx, r.deps.callTimeout())
	defer cancel()

	stream, err := client.GetProcessLogs(logCtx, &sandboxdv1.GetProcessLogsRequest{
		ProcessId: processID,
		TailLines: maxRecentLogLines,
	})
	if err != nil {
		r.deps.logger().Debug("recent logs after a readiness failure", "sandbox", target.Name(), "error", err)
		return ""
	}
	rendered, _, err := renderLogStream(stream, maxRenderedLogBytes)
	if err != nil {
		r.deps.logger().Debug("recent logs after a readiness failure", "sandbox", target.Name(), "error", err)
	}
	return rendered.Text
}

// ----------------------------------------------------------------- list

// ProcessListArgs are the arguments to sandbox_process_list.
type ProcessListArgs struct {
	TargetArgs
	// States filters by state.
	States []string `json:"states,omitempty" jsonschema:"only list processes in these states: starting, ready, running, exited, crashed, restarting, orphaned"`
	// NamePattern filters by name.
	NamePattern string `json:"name_pattern,omitempty" jsonschema:"only list processes whose name matches this RE2 pattern"`
}

// ProcessListResult is the sandbox_process_list result.
type ProcessListResult struct {
	// Echo carries the sandbox this listing came from.
	Echo
	// Table is the listing rendered as fixed-width columns. It is the field to
	// read: twenty processes are legible here in a way twenty JSON objects are
	// not.
	Table string `json:"table,omitempty"`
	// Processes is the same listing, structured.
	Processes []ProcessLine `json:"processes"`
	// Running counts the processes that are still alive.
	Running int `json:"running"`
	// Hint is present when the listing alone does not say what to do next.
	Hint string `json:"hint,omitempty"`
}

func (r *Registrar) processList(ctx context.Context, _ *mcp.CallToolRequest, target *selection.Target, in ProcessListArgs) (ProcessListResult, error) {
	states, err := parseStates(in.States)
	if err != nil {
		return ProcessListResult{}, err
	}

	client, err := r.processClient(target)
	if err != nil {
		return ProcessListResult{}, err
	}

	callCtx, cancel := context.WithTimeout(ctx, r.deps.callTimeout())
	defer cancel()

	resp, err := client.ListProcesses(callCtx, &sandboxdv1.ListProcessesRequest{
		States:      states,
		NamePattern: in.NamePattern,
	})
	if err != nil {
		c := target.Call()
		c.Timeout, c.Limit = r.deps.callTimeout(), "the list call deadline"
		return ProcessListResult{}, c.Map(err)
	}

	now := time.Now()
	out := ProcessListResult{Processes: make([]ProcessLine, 0, len(resp.GetProcesses()))}
	for _, st := range resp.GetProcesses() {
		if liveState(st.GetState()) {
			out.Running++
		}
		out.Processes = append(out.Processes, processLine(st, now))
	}
	out.Table = renderProcessTable(out.Processes)

	switch {
	case len(out.Processes) == 0 && (len(in.States) > 0 || in.NamePattern != ""):
		out.Hint = "No process matches that filter. Call sandbox_process_list with no filter to see everything the agent is tracking."
	case len(out.Processes) == 0:
		out.Hint = "The agent is tracking no processes. Start one with sandbox_process_start."
	}
	return out, nil
}

// parseStates maps the tool's state names onto the wire enum.
func parseStates(names []string) ([]sandboxdv1.ProcessState, error) {
	if len(names) == 0 {
		return nil, nil
	}
	out := make([]sandboxdv1.ProcessState, 0, len(names))
	for _, name := range names {
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "starting":
			out = append(out, sandboxdv1.ProcessState_PROCESS_STATE_STARTING)
		case "ready":
			out = append(out, sandboxdv1.ProcessState_PROCESS_STATE_READY)
		case "running":
			out = append(out, sandboxdv1.ProcessState_PROCESS_STATE_RUNNING)
		case "exited":
			out = append(out, sandboxdv1.ProcessState_PROCESS_STATE_EXITED)
		case "crashed":
			out = append(out, sandboxdv1.ProcessState_PROCESS_STATE_CRASHED)
		case "restarting":
			out = append(out, sandboxdv1.ProcessState_PROCESS_STATE_RESTARTING)
		case "orphaned":
			out = append(out, sandboxdv1.ProcessState_PROCESS_STATE_ORPHANED)
		default:
			return nil, fmt.Errorf("state %q is not one of starting, ready, running, exited, crashed, restarting, orphaned", name)
		}
	}
	return out, nil
}

// processColumns are the columns of the rendered listing, in order. Each is
// exactly as wide as its widest cell — no minimum widths, because padding a
// column to a width nothing in it needs is a cost paid once per row.
var processColumns = []string{"STATE", "NAME", "PID", "UPTIME", "RST", "PORTS", "LAST LOG"}

// renderProcessTable renders the listing as fixed-width columns.
//
// This is the field the model reads. Twenty processes as JSON objects is a
// wall of repeated keys in which the one crashed process is genuinely hard to
// find; twenty rows of a table is a shape a reader scans in one pass. The
// structured listing is still there for anything that wants to parse it.
func renderProcessTable(rows []ProcessLine) string {
	if len(rows) == 0 {
		return ""
	}

	cells := make([][]string, 0, len(rows))
	for _, row := range rows {
		state := row.State
		if row.ExitCode != nil && *row.ExitCode != 0 {
			state += "(" + strconv.Itoa(int(*row.ExitCode)) + ")"
		}
		pid := "-"
		if row.PID > 0 {
			pid = strconv.Itoa(int(row.PID))
		}
		uptime := row.Uptime
		if uptime == "" {
			uptime = "-"
		}
		ports := "-"
		if len(row.ListeningPorts) > 0 {
			parts := make([]string, 0, len(row.ListeningPorts))
			for _, p := range row.ListeningPorts {
				parts = append(parts, strconv.Itoa(int(p)))
			}
			ports = strings.Join(parts, ",")
		}
		last := row.LastLogLine
		if last == "" && row.AdoptionNote != "" {
			last = "(" + row.AdoptionNote + ")"
		}
		cells = append(cells, []string{
			state, row.Name, pid, uptime,
			strconv.Itoa(int(row.RestartCount)), ports, last,
		})
	}

	widths := make([]int, len(processColumns))
	for i, header := range processColumns {
		widths[i] = len(header)
		for _, row := range cells {
			widths[i] = max(widths[i], len(row[i]))
		}
	}

	var b strings.Builder
	writeRow(&b, processColumns, widths)
	for _, row := range cells {
		writeRow(&b, row, widths)
	}
	// The process id is not a column — it is long, it is the same shape for
	// every row, and it would cost more than the rest of the table put
	// together. It is in `processes`, and the name is what a caller reads.
	b.WriteString("\nprocess_id for each name is in `processes`; every other process tool takes it.")
	return b.String()
}

// writeRow writes one padded row, without trailing whitespace: the last column
// is not padded, because a table of twenty rows pays for every trailing space
// twenty times.
//
// The row is trimmed as well as unpadded. An empty last cell leaves the
// second-to-last column's padding hanging off the end, and a listing where no
// process has produced output yet — which is every listing taken just after a
// fleet of services was started — is exactly the case where every row ends that
// way.
func writeRow(b *strings.Builder, cells []string, widths []int) {
	var row strings.Builder
	for i, cell := range cells {
		if i == len(cells)-1 {
			row.WriteString(cell)
			break
		}
		row.WriteString(cell)
		for pad := widths[i] - len(cell) + 2; pad > 0; pad-- {
			row.WriteByte(' ')
		}
	}
	b.WriteString(strings.TrimRight(row.String(), " "))
	b.WriteByte('\n')
}

// ----------------------------------------------------------------- logs

// ProcessLogsArgs are the arguments to sandbox_process_logs.
type ProcessLogsArgs struct {
	TargetArgs
	// ProcessID names the process.
	ProcessID string `json:"process_id" jsonschema:"process id from sandbox_process_start or sandbox_process_list"`
	// Stream selects stdout, stderr, or both.
	Stream string `json:"stream,omitempty" jsonschema:"stdout, stderr, or both (default). Lines the supervisor itself wrote are returned only for \"both\""`
	// TailLines returns only the last N lines.
	TailLines int `json:"tail_lines,omitempty" jsonschema:"return only the last N lines; zero means the agent default (200)"`
	// Since returns only output at or after a time.
	Since string `json:"since,omitempty" jsonschema:"return only output produced at or after this RFC3339 timestamp"`
	// FilterPattern keeps only matching lines.
	FilterPattern string `json:"filter_pattern,omitempty" jsonschema:"return only lines matching this RE2 pattern"`
	// Follow streams new output after the replay.
	Follow bool `json:"follow,omitempty" jsonschema:"after replaying buffered output, keep streaming new output until follow_seconds elapses"`
	// FollowSeconds bounds the follow.
	FollowSeconds int `json:"follow_seconds,omitempty" jsonschema:"how long to follow for, in seconds; defaults to 20 and is clamped to the agent's maximum. Following is always bounded"`
}

// ProcessLogsResult is the sandbox_process_logs result.
type ProcessLogsResult struct {
	// Echo carries the sandbox these logs came from.
	Echo
	// ProcessID is the process the logs belong to.
	ProcessID string `json:"process_id"`
	// State is the process's state when the stream ended.
	State string `json:"state"`
	// Logs is the rendered output: one line per line, stderr prefixed "E| ",
	// supervisor lines prefixed "S| ", and gaps marked inline.
	Logs string `json:"logs"`
	// LinesReturned is how many lines the rendering contains.
	LinesReturned uint64 `json:"lines_returned"`
	// LinesDropped is how many the process outran the buffer by. Non-zero
	// means the log has a hole in it, and the holes are marked in Logs.
	LinesDropped uint64 `json:"lines_dropped,omitempty"`
	// FollowDeadlineReached reports that the stream ended because the follow
	// bound elapsed rather than because the process finished.
	FollowDeadlineReached bool `json:"follow_deadline_reached,omitempty"`
	// Truncation records output this side dropped to stay within its cap.
	Truncation *LogTruncation `json:"truncation,omitempty"`
	// Note is what the caller should not have to infer.
	Note string `json:"note,omitempty"`
}

// LogTruncation records output cut to keep a result bounded. Output is never
// silently cut.
type LogTruncation struct {
	Truncated    bool   `json:"truncated"`
	BytesOmitted uint64 `json:"bytes_omitted,omitempty"`
	LinesOmitted uint64 `json:"lines_omitted,omitempty"`
}

func (r *Registrar) processLogs(ctx context.Context, _ *mcp.CallToolRequest, target *selection.Target, in ProcessLogsArgs) (ProcessLogsResult, error) {
	if strings.TrimSpace(in.ProcessID) == "" {
		return ProcessLogsResult{}, errors.New("process_id is required; sandbox_process_list reports the ids the agent is tracking")
	}
	stream, err := parseStream(in.Stream)
	if err != nil {
		return ProcessLogsResult{}, err
	}
	if in.TailLines < 0 {
		return ProcessLogsResult{}, fmt.Errorf("tail_lines %d is negative", in.TailLines)
	}

	req := &sandboxdv1.GetProcessLogsRequest{
		ProcessId:     in.ProcessID,
		Stream:        stream,
		TailLines:     uint32(min(max(in.TailLines, 0), 1<<20)), //nolint:gosec // clamped
		FilterPattern: in.FilterPattern,
		Follow:        in.Follow,
	}
	if in.Since != "" {
		since, err := time.Parse(time.RFC3339, in.Since)
		if err != nil {
			return ProcessLogsResult{}, fmt.Errorf("since %q is not an RFC3339 timestamp, e.g. 2026-08-17T09:30:00Z: %w", in.Since, err)
		}
		req.Since = timestamppb.New(since)
	}

	// The RPC deadline is the follow bound plus slack, never less. The agent's
	// deadline ends the stream with a summary; ours would end it with a
	// timeout error and no logs at all, so ours must be the later of the two.
	timeout := r.deps.callTimeout()
	if in.Follow {
		follow := time.Duration(min(in.FollowSeconds, maxSecondsArgument)) * time.Second
		if in.FollowSeconds <= 0 {
			follow = defaultFollowSeconds * time.Second
		}
		req.FollowDuration = durationpb.New(follow)
		timeout = follow + followSlack
	}

	client, err := r.processClient(target)
	if err != nil {
		return ProcessLogsResult{}, err
	}

	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	logs, err := client.GetProcessLogs(callCtx, req)
	if err != nil {
		return ProcessLogsResult{}, r.processCallError(ctx, target, client, in.ProcessID, err)
	}

	rendered, summary, err := renderLogStream(logs, maxRenderedLogBytes)
	if err != nil {
		return ProcessLogsResult{}, r.processCallError(ctx, target, client, in.ProcessID, err)
	}

	out := ProcessLogsResult{
		ProcessID:             in.ProcessID,
		State:                 stateString(summary.GetState()),
		Logs:                  rendered.Text,
		LinesReturned:         summary.GetLinesReturned(),
		LinesDropped:          summary.GetLinesDropped(),
		FollowDeadlineReached: summary.GetFollowDeadlineReached(),
	}
	if rendered.Truncated {
		out.Truncation = &LogTruncation{
			Truncated:    true,
			BytesOmitted: rendered.BytesOmitted,
			LinesOmitted: rendered.LinesOmitted,
		}
	}

	var notes []string
	if out.LinesDropped > 0 {
		notes = append(notes, fmt.Sprintf("%d line(s) were dropped because the process outran the agent's log buffer; each gap is marked inline in `logs`.", out.LinesDropped))
	}
	if in.Follow && out.FollowDeadlineReached {
		notes = append(notes, "Following stopped at its deadline, not because the process finished. Call again to keep watching.")
	}
	if rendered.Empty() && out.LinesDropped == 0 {
		notes = append(notes, "The process has produced no output matching this request.")
	}
	out.Note = strings.Join(notes, " ")
	return out, nil
}

func parseStream(s string) (sandboxdv1.Stream, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "both", "all":
		return sandboxdv1.Stream_STREAM_UNSPECIFIED, nil
	case "stdout", "out":
		return sandboxdv1.Stream_STREAM_STDOUT, nil
	case "stderr", "err":
		return sandboxdv1.Stream_STREAM_STDERR, nil
	default:
		return 0, fmt.Errorf("stream %q is not one of stdout, stderr, both", s)
	}
}

// renderedLogs is a log stream turned into one readable block.
type renderedLogs struct {
	Text         string
	Truncated    bool
	BytesOmitted uint64
	LinesOmitted uint64
	Lines        int
}

func (r renderedLogs) Empty() bool { return r.Lines == 0 }

// logReceiver is the half of the gRPC client stream this file uses. Narrowing
// it to Recv is what lets a test render a synthetic stream without a
// connection.
type logReceiver interface {
	Recv() (*sandboxdv1.GetProcessLogsResponse, error)
}

// renderLogStream consumes a log stream and renders it.
//
// Drop markers go inline, in sequence, rather than into a counter at the end:
// a gap between two lines is a fact about those two lines, and a reader who
// sees them adjacent will draw a conclusion from their adjacency. The marker is
// what stops that.
//
// The block is capped from the front. When a follow produces more than the cap,
// the useful end is the recent one — so the oldest lines go, and the omission
// is stated at the top of what is left rather than reported only in a field.
func renderLogStream(stream logReceiver, capBytes int) (renderedLogs, *sandboxdv1.LogSummary, error) {
	var (
		out     renderedLogs
		summary *sandboxdv1.LogSummary
		lines   []string
		total   int
	)

	for {
		resp, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			// Whatever arrived before the failure is still worth returning:
			// the caller decides whether to report the error, and a partial
			// log beats none.
			out.Text = joinLogLines(lines, out)
			out.Lines = len(lines)
			return out, summary, err
		}
		if s := resp.GetSummary(); s != nil {
			summary = s
			continue
		}
		line := resp.GetLine()
		if line == nil {
			continue
		}
		if n := line.GetDroppedBefore(); n > 0 {
			marker := fmt.Sprintf("--- %d line(s) dropped: the process outran the log buffer ---", n)
			lines = append(lines, marker)
			total += len(marker) + 1
		}
		rendered := renderLogLine(line)
		lines = append(lines, rendered)
		total += len(rendered) + 1

		// Trim from the front as it grows, so a follow that outruns the cap
		// costs a bounded amount of memory rather than the whole stream.
		for total > capBytes && len(lines) > 1 {
			out.Truncated = true
			out.BytesOmitted += uint64(len(lines[0]) + 1) //nolint:gosec // a line length is never negative
			out.LinesOmitted++
			total -= len(lines[0]) + 1
			lines = lines[1:]
		}
	}

	out.Lines = len(lines)
	out.Text = joinLogLines(lines, out)
	return out, summary, nil
}

// joinLogLines assembles the block, stating any omission at the top of it.
func joinLogLines(lines []string, out renderedLogs) string {
	if !out.Truncated {
		return strings.Join(lines, "\n")
	}
	head := fmt.Sprintf("--- %d earlier line(s) omitted to stay within this call's output limit; narrow with tail_lines, since or filter_pattern ---", out.LinesOmitted)
	return head + "\n" + strings.Join(lines, "\n")
}

// renderLogLine prefixes a line with its stream.
//
// stdout is unprefixed and stderr is "E| ", because stdout is the common case
// and a prefix on it would be paid for on every line of every log. Supervisor
// lines — a restart, a backoff, a decision to give up — carry neither stream,
// and are marked "S| " so they are not mistaken for the process's own output.
func renderLogLine(line *sandboxdv1.LogLine) string {
	text := strings.TrimRight(line.GetText(), "\r\n")
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

// --------------------------------------------------------------- signal

// ProcessSignalArgs are the arguments to sandbox_process_signal.
type ProcessSignalArgs struct {
	TargetArgs
	// ProcessID names the process.
	ProcessID string `json:"process_id" jsonschema:"process id from sandbox_process_start or sandbox_process_list"`
	// Signal is the portable signal name.
	Signal string `json:"signal,omitempty" jsonschema:"TERM, KILL, INT, HUP, USR1 or USR2. Ignored when graceful_stop is set"`
	// GracefulStop asks for TERM, wait, KILL.
	GracefulStop bool `json:"graceful_stop,omitempty" jsonschema:"send SIGTERM, wait grace_seconds, then SIGKILL; overrides signal. This is how to stop a server"`
	// GraceSeconds is how long to wait before escalating.
	GraceSeconds int `json:"grace_seconds,omitempty" jsonschema:"how long to wait after SIGTERM before escalating to SIGKILL; zero means the agent default (10s)"`
	// ProcessGroup signals the whole group. Unset means true.
	ProcessGroup *bool `json:"process_group,omitempty" jsonschema:"signal the whole process group rather than just the leader; defaults to true, because signalling the leader alone routinely leaves the child that holds the port behind"`
	// DisableRestart stops the restart policy undoing the stop.
	DisableRestart bool `json:"disable_restart,omitempty" jsonschema:"suppress the restart policy for this stop, so an intentional stop is not immediately undone"`
}

// ProcessSignalResult is the sandbox_process_signal result.
type ProcessSignalResult struct {
	// Echo carries the sandbox this ran on.
	Echo
	// Process is the process after the signal.
	Process ProcessDetail `json:"process"`
	// EscalatedToKill reports that a graceful stop ran out of grace and had to
	// SIGKILL. It is the difference between a clean shutdown and a process
	// that never got to flush anything.
	EscalatedToKill bool `json:"escalated_to_kill,omitempty"`
	// Note is what the caller should not have to infer.
	Note string `json:"note,omitempty"`
}

func (r *Registrar) processSignal(ctx context.Context, _ *mcp.CallToolRequest, target *selection.Target, in ProcessSignalArgs) (ProcessSignalResult, error) {
	if strings.TrimSpace(in.ProcessID) == "" {
		return ProcessSignalResult{}, errors.New("process_id is required; sandbox_process_list reports the ids the agent is tracking")
	}
	if in.GraceSeconds < 0 {
		return ProcessSignalResult{}, fmt.Errorf("grace_seconds %d is negative", in.GraceSeconds)
	}
	graceSeconds := min(in.GraceSeconds, maxSecondsArgument)

	req := &sandboxdv1.SignalProcessRequest{
		ProcessId:      in.ProcessID,
		GracefulStop:   in.GracefulStop,
		DisableRestart: in.DisableRestart,
		ProcessGroup:   in.ProcessGroup,
	}
	if graceSeconds > 0 {
		req.GracePeriod = durationpb.New(time.Duration(graceSeconds) * time.Second)
	}
	if !in.GracefulStop {
		sig, err := parseSignal(in.Signal)
		if err != nil {
			return ProcessSignalResult{}, err
		}
		req.Signal = sig
	}

	client, err := r.processClient(target)
	if err != nil {
		return ProcessSignalResult{}, err
	}

	timeout := signalDeadline(in.GracefulStop, graceSeconds, r.deps.callTimeout())
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	resp, err := client.SignalProcess(callCtx, req)
	if err != nil {
		return ProcessSignalResult{}, r.processCallError(ctx, target, client, in.ProcessID, err)
	}

	out := ProcessSignalResult{
		Process:         processDetail(resp.GetStatus(), time.Now()),
		EscalatedToKill: resp.GetEscalatedToKill(),
	}
	switch {
	case out.EscalatedToKill:
		out.Note = "The process did not exit within the grace period after SIGTERM and was killed with SIGKILL, so it had no chance to flush or clean up."
	case in.GracefulStop:
		out.Note = "The process exited on SIGTERM within its grace period; it was not killed."
	}
	if in.GracefulStop && !in.DisableRestart && out.Process.RestartPolicy != "" && out.Process.RestartPolicy != "never" {
		out.Note += fmt.Sprintf(" Its restart policy is %q and disable_restart was not set, so the supervisor may start it again.", out.Process.RestartPolicy)
	}
	out.Note = strings.TrimSpace(out.Note)
	return out, nil
}

func parseSignal(s string) (sandboxdv1.SignalProcessRequest_Signal, error) {
	switch strings.ToUpper(strings.TrimSpace(strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(s)), "SIG"))) {
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
	case "":
		return 0, errors.New("signal is required unless graceful_stop is set; use graceful_stop=true to stop a server, or name one of TERM, KILL, INT, HUP, USR1, USR2")
	default:
		return 0, fmt.Errorf("signal %q is not one of TERM, KILL, INT, HUP, USR1, USR2", s)
	}
}

// -------------------------------------------------------------- restart

// ProcessRestartArgs are the arguments to sandbox_process_restart.
type ProcessRestartArgs struct {
	TargetArgs
	// ProcessID names the process.
	ProcessID string `json:"process_id" jsonschema:"process id from sandbox_process_start or sandbox_process_list"`
	// GraceSeconds is how long to wait before escalating the stop half.
	GraceSeconds int `json:"grace_seconds,omitempty" jsonschema:"how long to wait after SIGTERM before escalating to SIGKILL while stopping; zero means the agent default"`
	// WaitForReady blocks until the probe passes again. Unset means "yes, if
	// the process has a probe".
	WaitForReady *bool `json:"wait_for_ready,omitempty" jsonschema:"wait for the readiness probe to pass again before returning; defaults to true when the process has a probe"`
}

// ProcessRestartResult is the sandbox_process_restart result.
type ProcessRestartResult struct {
	// Echo carries the sandbox this ran on.
	Echo
	// Process is the process after the restart. Its process_id is the one it
	// had before: a restart is the same process, not a similar one.
	Process ProcessDetail `json:"process"`
	// Ready reports whether the readiness probe passed again.
	Ready *bool `json:"ready,omitempty"`
	// ReadyError is why it did not.
	ReadyError string `json:"ready_error,omitempty"`
	// RecentLogs is the tail of the restarted process's output, present
	// whenever ReadyError is.
	RecentLogs string `json:"recent_logs,omitempty"`
	// Note is what the caller should not have to infer.
	Note string `json:"note,omitempty"`
}

func (r *Registrar) processRestart(ctx context.Context, _ *mcp.CallToolRequest, target *selection.Target, in ProcessRestartArgs) (ProcessRestartResult, error) {
	if strings.TrimSpace(in.ProcessID) == "" {
		return ProcessRestartResult{}, errors.New("process_id is required; sandbox_process_list reports the ids the agent is tracking")
	}
	if in.GraceSeconds < 0 {
		return ProcessRestartResult{}, fmt.Errorf("grace_seconds %d is negative", in.GraceSeconds)
	}
	graceSeconds := min(in.GraceSeconds, maxSecondsArgument)

	client, err := r.processClient(target)
	if err != nil {
		return ProcessRestartResult{}, err
	}

	// Unset means "wait if there is something to wait for". The agent ignores
	// wait_for_ready when the process has no probe, so asking for it
	// unconditionally is safe and is what the caller almost always meant.
	wait := true
	if in.WaitForReady != nil {
		wait = *in.WaitForReady
	}

	req := &sandboxdv1.RestartProcessRequest{ProcessId: in.ProcessID, WaitForReady: wait}
	if graceSeconds > 0 {
		req.GracePeriod = durationpb.New(time.Duration(graceSeconds) * time.Second)
	}

	// Stop plus probe, both of which block on the agent. An unset grace_seconds
	// still costs the agent its own default before it escalates, so the
	// deadline is sized from that rather than from the zero the caller sent.
	timeout := r.deps.callTimeout() + gracePeriodFor(graceSeconds)
	if wait {
		timeout += 30 * time.Second
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	resp, err := client.RestartProcess(callCtx, req)
	if err != nil {
		return ProcessRestartResult{}, r.processCallError(ctx, target, client, in.ProcessID, err)
	}

	st := resp.GetStatus()
	out := ProcessRestartResult{Process: processDetail(st, time.Now())}
	switch {
	case resp.GetReadyError() != "":
		out.Ready = boolPtr(false)
		out.ReadyError = resp.GetReadyError()
		out.RecentLogs = r.recentLogs(ctx, target, client, st.GetProcessId())
		out.Note = "The readiness probe did not pass after the restart. The process is left running so its logs can be read."
	case wait && out.Process.State == "ready":
		out.Ready = boolPtr(true)
	}
	if out.Note == "" {
		out.Note = fmt.Sprintf("Restarted in place: process_id %s is unchanged and its log history is intact. State is now %q.",
			out.Process.ProcessID, out.Process.State)
	}
	return out, nil
}

// sortedPorts is a stable rendering of a port list. The agent enumerates
// sockets in whatever order the platform hands them over, and a table that
// changes shape between two identical calls reads as a change in the process.
func sortedPorts(ports []uint32) []uint32 {
	if len(ports) == 0 {
		return nil
	}
	out := append([]uint32(nil), ports...)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
