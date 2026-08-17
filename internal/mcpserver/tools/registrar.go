// Package tools implements the MCP tools fleet exposes, and the
// registration seam every one of them is built on.
//
// # Registering a tool
//
// Tools are not registered with mcp.AddTool directly. They go through
// [AddTargeted] or [AddFleet], which wrap it and take over the two things no
// handler should be trusted to remember: resolving which sandbox the call
// acts on, and echoing that sandbox back in the result.
//
// The echo is not diagnostic garnish. Silent target confusion — the model
// believing it is on host A while executing on host B — is the most
// destructive failure this system can produce, and it stays invisible until
// something is already broken. So the type system enforces it: an output
// struct that does not embed [Echo] does not satisfy the constraint on
// [AddTargeted], and the package does not compile. The wrapper then
// overwrites the field with the resolved name after the handler returns, so a
// handler can neither omit the echo nor set it to the wrong thing.
//
// A targeted tool looks like this end to end:
//
//	type editArgs struct {
//	    tools.TargetArgs        // supplies the optional `sandbox` argument
//	    Path      string `json:"path" jsonschema:"absolute path on the sandbox"`
//	    OldString string `json:"old_string" jsonschema:"exact text to replace"`
//	    NewString string `json:"new_string" jsonschema:"replacement text"`
//	}
//
//	type editResult struct {
//	    tools.Echo              // supplies the mandatory `sandbox` echo
//	    Diff         string `json:"diff"`
//	    Replacements int    `json:"replacements"`
//	}
//
//	func registerFiles(r *tools.Registrar) {
//	    tools.AddTargeted(r, &mcp.Tool{
//	        Name:        "fleet_edit",
//	        Description: "Replace an exact string in a file on the selected sandbox.",
//	    }, func(ctx context.Context, req *mcp.CallToolRequest, t *selection.Target, in editArgs) (editResult, error) {
//	        files, err := r.Deps().Clients.Files(t.Name(), t.Address())
//	        if err != nil {
//	            // Mapped too: a pool that could not be built fails here, and
//	            // "no control certificate at …" still has to name the sandbox
//	            // the model was targeting.
//	            return editResult{}, t.Call().Map(err)
//	        }
//	        resp, err := files.EditFile(ctx, &sandboxdv1.EditFileRequest{
//	            Path: in.Path, OldString: in.OldString, NewString: in.NewString,
//	        })
//	        if err != nil {
//	            c := t.Call()
//	            c.Subject = "path " + in.Path       // what a NotFound is reported against
//	            return editResult{}, c.Map(err)     // central gRPC → tool error mapping
//	        }
//	        return editResult{Diff: resp.GetDiff(), Replacements: int(resp.GetReplacements())}, nil
//	    })
//	}
//
// The handler never reads in.Sandbox, never calls the resolver, and never
// sets out.Sandbox. Resolution happens before it runs; if it fails, the
// handler is not called at all and the model gets the structured no-target
// error naming fleet_select.
//
// A streaming RPC works the same way — take the stream from the client,
// consume it under the handler's context, and map the first error through
// [selection.Target.Call] exactly as above.
//
// # Errors
//
// Return a plain error and the SDK turns it into a tool error with IsError
// set, which is what the model needs: a failed call it can read and correct,
// not a protocol error that tells it nothing. Map gRPC failures through
// [selection.Target.Call] rather than formatting them per handler, so
// "unreachable" reads the same whichever tool hit it.
package tools

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/fleet-mcp/internal/client"
	"github.com/axelmierczuk/fleet-mcp/internal/mcpserver/selection"
	"github.com/axelmierczuk/fleet-mcp/internal/registry"
)

// DefaultProbeTimeout bounds a single health probe issued by fleet_list.
// It is short on purpose: listing a twenty-machine fleet must not wait on the
// one box somebody powered off.
const DefaultProbeTimeout = 2 * time.Second

// DefaultCallTimeout bounds a unary call that has no timeout of its own,
// such as GetHostInfo behind fleet_info.
const DefaultCallTimeout = 15 * time.Second

// Echo carries the one field every tool result must have: the sandbox that
// actually served the call.
//
// Embed it in every output struct. The registration wrapper sets it; handlers
// must not.
type Echo struct {
	// Sandbox is the resolved sandbox this result came from.
	Sandbox string `json:"sandbox" jsonschema:"name of the sandbox that served this call"`
}

func (e *Echo) setSandbox(name string) { e.Sandbox = name }

// echoer is satisfied only by a pointer to a struct embedding [Echo]. It is
// unexported so that embedding Echo is the only way to satisfy it, which is
// what makes the echo impossible to opt out of.
type echoer interface {
	setSandbox(string)
}

// TargetArgs supplies the optional sandbox argument shared by every targeted
// tool. Embed it in the argument struct; the wrapper reads it.
type TargetArgs struct {
	// Sandbox names the host to act on for this call only, overriding the
	// sticky selection.
	Sandbox string `json:"sandbox,omitempty" jsonschema:"sandbox name or handle to act on; defaults to the current selection"`
}

func (a TargetArgs) targetRef() string { return a.Sandbox }

// targeter is satisfied only by an argument struct embedding [TargetArgs].
type targeter interface {
	targetRef() string
}

// Clients is the subset of *client.Pool the tools use.
//
// It is an interface rather than the concrete pool for two reasons: the pool
// needs a full mTLS configuration to construct, which a unit test should not
// have to mint, and the MCP server has to start usefully on a workstation
// that has no control certificate yet — fleet_list and fleet_add work
// fine without one.
type Clients interface {
	// Host returns a HostServiceClient for the named sandbox.
	Host(name, address string) (sandboxdv1.HostServiceClient, error)
	// Exec returns an ExecServiceClient for the named sandbox.
	Exec(name, address string) (sandboxdv1.ExecServiceClient, error)
	// Files returns a FileServiceClient for the named sandbox.
	Files(name, address string) (sandboxdv1.FileServiceClient, error)
	// Process returns a ProcessServiceClient for the named sandbox.
	Process(name, address string) (sandboxdv1.ProcessServiceClient, error)
	// Forward returns a ForwardServiceClient for the named sandbox.
	Forward(name, address string) (sandboxdv1.ForwardServiceClient, error)
	// Health returns the cached background health for a pooled sandbox, and
	// false if nothing has been dialed for that name yet.
	Health(name string) (client.HealthStatus, bool)
	// Remove drops a sandbox's pooled channel, if any.
	Remove(name string)
}

// Deps is everything a tool handler can reach.
type Deps struct {
	// Fleet is the registry: inventory and persisted sticky selections.
	Fleet *registry.Registry
	// Clients dials sandboxes.
	Clients Clients
	// Resolver applies the selection order.
	Resolver *selection.Resolver
	// Logger writes to stderr. Never to stdout: stdout carries JSON-RPC.
	Logger *slog.Logger
	// ProbeTimeout bounds one health probe. Zero uses DefaultProbeTimeout.
	ProbeTimeout time.Duration
	// CallTimeout bounds a unary call with no timeout of its own. Zero uses
	// DefaultCallTimeout.
	CallTimeout time.Duration
}

func (d Deps) probeTimeout() time.Duration {
	if d.ProbeTimeout > 0 {
		return d.ProbeTimeout
	}
	return DefaultProbeTimeout
}

func (d Deps) callTimeout() time.Duration {
	if d.CallTimeout > 0 {
		return d.CallTimeout
	}
	return DefaultCallTimeout
}

// Bounds on a call that carries content rather than an answer.
const (
	// streamBytesPerSecond is the throughput [Deps.streamTimeout] budgets for.
	//
	// Deliberately pessimistic: it is not a prediction of the link, it is the
	// speed below which waiting longer stops being worth it. A sandbox on the
	// same LAN beats it by two orders of magnitude and never notices this
	// number at all.
	streamBytesPerSecond = 1 << 20 // 1 MiB/s

	// maxStreamAllowance bounds the allowance whatever the size says, so a
	// wrong size from the far side cannot turn a deadline into no deadline.
	maxStreamAllowance = time.Hour
)

// streamTimeout bounds a call that moves size bytes of content.
//
// [Deps.callTimeout] is sized for a call that asks a question — a stat, a host
// probe, a directory listing — and applying it to one that carries a file makes
// the limits these tools advertise unreachable: fleet_transfer will move
// 256 MiB in one call, and 256 MiB inside the 15s unary default is 17 MB/s
// sustained, which no link outside a lab delivers. The failure it produced was
// not a slow transfer either; it was "transferred 40 of 200 files, then the
// call timed out", halfway through a tree.
//
// The deadline still exists, and it is still what stops a hung agent from
// holding a tool call open forever. It just scales with what was asked for.
func (d Deps) streamTimeout(size uint64) time.Duration {
	// Clamped in seconds, before the conversion: a size the far side made up
	// would otherwise overflow the multiplication into a negative duration,
	// which is a context that has already expired.
	seconds := min(size/streamBytesPerSecond, uint64(maxStreamAllowance/time.Second))
	return d.callTimeout() + time.Duration(seconds)*time.Second //nolint:gosec // clamped to an hour's worth of seconds above
}

func (d Deps) logger() *slog.Logger {
	if d.Logger != nil {
		return d.Logger
	}
	return slog.New(slog.DiscardHandler)
}

// Registration records a tool that went through this package, so a test can
// walk what was registered rather than trusting a list someone maintains by
// hand.
type Registration struct {
	// Name is the MCP tool name.
	Name string
	// Targeted reports whether the tool resolves a sandbox before running,
	// as opposed to naming its own subject.
	Targeted bool
}

// Registrar registers tools against an MCP server and remembers what it
// registered.
type Registrar struct {
	server *mcp.Server
	deps   Deps

	// forwards owns every open port forward. It lives on the Registrar rather
	// than inside a handler because a forward outlives the call that opened
	// it: see [Registrar.Close], and forward.go.
	forwards *forwardManager

	mu            sync.Mutex
	registrations []Registration
}

// NewRegistrar returns a Registrar that adds tools to server.
func NewRegistrar(server *mcp.Server, deps Deps) *Registrar {
	return &Registrar{server: server, deps: deps}
}

// Deps returns the dependencies handlers close over.
func (r *Registrar) Deps() Deps { return r.deps }

// Registrations returns every tool registered through this Registrar.
func (r *Registrar) Registrations() []Registration {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Registration, len(r.registrations))
	copy(out, r.registrations)
	return out
}

func (r *Registrar) record(name string, targeted bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.registrations = append(r.registrations, Registration{Name: name, Targeted: targeted})
}

// TargetedHandler is the handler shape for a tool that acts on one sandbox.
//
// The target is already resolved when the handler runs. The returned Out must
// not set its Echo field: [AddTargeted] overwrites it with the resolved name.
type TargetedHandler[In, Out any] func(ctx context.Context, req *mcp.CallToolRequest, target *selection.Target, in In) (Out, error)

// AddTargeted registers a tool that acts on a single resolved sandbox.
//
// In must embed [TargetArgs] and Out must embed [Echo]; both are enforced by
// the type parameters, so a tool that skips either does not compile. Before
// the handler runs, the wrapper resolves the target in the fixed order
// (explicit argument, then sticky default, then a structured error). After it
// returns, the wrapper stamps the resolved sandbox name into the result.
func AddTargeted[In targeter, Out any, POut interface {
	*Out
	echoer
}](r *Registrar, tool *mcp.Tool, h TargetedHandler[In, Out]) {
	mcp.AddTool(r.server, tool, func(ctx context.Context, req *mcp.CallToolRequest, in In) (*mcp.CallToolResult, Out, error) {
		var out Out

		target, err := r.deps.Resolver.Resolve(req, in.targetRef())
		if err != nil {
			return nil, out, err
		}
		r.deps.logger().Debug("tool call resolved",
			"tool", tool.Name, "sandbox", target.Name(), "source", string(target.Source))

		out, err = h(ctx, req, target, in)
		if err != nil {
			return nil, out, err
		}
		// Stamped after the handler, unconditionally, so the echo reports
		// where the call actually went rather than what the handler believed.
		POut(&out).setSandbox(target.Name())
		return nil, out, nil
	})
	r.record(tool.Name, true)
}

// FleetHandler is the handler shape for a fleet tool — one that names its own
// subject instead of resolving a target.
//
// It returns the sandbox name to echo alongside the result. That name is a
// separate return value rather than a field the handler fills in, so the
// compiler requires it in the same way [AddTargeted] does.
type FleetHandler[In, Out any] func(ctx context.Context, req *mcp.CallToolRequest, in In) (out Out, sandbox string, err error)

// AddFleet registers a fleet-group tool: one that operates on the registry
// rather than on a resolved sandbox, and so names its own subject.
//
// fleet_add echoes the sandbox it registered, fleet_remove the one it
// deregistered, fleet_list the one currently selected. Empty is permitted
// here and only here, for the case where nothing is selected — a targeted
// tool cannot reach its handler without a resolved target, so its echo is
// never empty.
func AddFleet[In any, Out any, POut interface {
	*Out
	echoer
}](r *Registrar, tool *mcp.Tool, h FleetHandler[In, Out]) {
	mcp.AddTool(r.server, tool, func(ctx context.Context, req *mcp.CallToolRequest, in In) (*mcp.CallToolResult, Out, error) {
		out, sandbox, err := h(ctx, req, in)
		if err != nil {
			var zero Out
			return nil, zero, err
		}
		POut(&out).setSandbox(sandbox)
		return nil, out, nil
	})
	r.record(tool.Name, false)
}

// Register adds every tool this milestone ships to server.
//
// Later milestones add their groups here; the fleet group is the one that
// must exist for any of the others to be reachable, because it is how a
// sandbox gets selected in the first place.
func Register(server *mcp.Server, deps Deps) *Registrar {
	r := NewRegistrar(server, deps)
	registerFleet(r)
	registerExec(r)
	registerFiles(r)
	registerTransfer(r)
	registerProcess(r)
	registerForward(r)
	return r
}
