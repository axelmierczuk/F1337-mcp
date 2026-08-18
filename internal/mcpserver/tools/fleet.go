package tools

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/fleet-mcp/internal/client"
	"github.com/axelmierczuk/fleet-mcp/internal/mcpserver/mcperr"
	"github.com/axelmierczuk/fleet-mcp/internal/mcpserver/selection"
	"github.com/axelmierczuk/fleet-mcp/internal/registry"
)

// enrollmentHint is what an empty fleet gets told. Adding a sandbox is an
// operator action; the model needs to know that rather than retrying.
const enrollmentHint = "No sandboxes are registered. Enrolling one mints credentials and is an operator action: `fleetctl enroll mint --name <name> --address <host:port>`, then install the agent on the host (docs/quickstart.md). A host that is already enrolled but missing here can be registered with fleet_add."

// unconfinedNote is what a host with no allowed roots is reported as.
//
// An agent reports no roots when its path jail is off, and the jail is off
// whenever ExecService is enabled: a caller with exec does not need
// fleet_write to leave the jail, it runs `sh -c 'echo x > /etc/passwd'`. So
// the two are mutually exclusive, and roots are enforced only on an agent with
// exec disabled.
//
// fleet_select returns roots precisely so the model learns where it may
// write. Answering that question with an absent list is the model-facing
// version of the same false confidence the mutual exclusion exists to remove,
// read from the other end: "no roots" is silently indistinguishable from
// "nowhere is writable", and a model that concludes the host is read-only will
// not even try. So the absence is stated, not implied.
// unauthenticatedNote is what fleet_info says about a sandbox this fleet does
// not authenticate.
//
// Said in the result rather than left to the auth field, because a model reads
// prose and acts on it: "auth: none" is a value it may not weigh, and "nothing
// authenticated this connection" is a sentence it can pass on to the person who
// needs to know.
const unauthenticatedNote = "This sandbox is registered as insecure: the connection to it carries no client certificate and its agent verifies none, so nothing in this fleet authenticated either end. Whatever authenticates it is the network. Commands run here are recorded by the agent against the address they came from rather than a verified identity."

const unconfinedNote = "This sandbox is unconfined: the agent reports no allowed roots, so every path its user can reach is readable and writable. Roots are enforced only on an agent with exec disabled — with exec enabled a command can write anywhere regardless, so the jail is not applied."

// registerFleet adds the five fleet tools.
func registerFleet(r *Registrar) {
	AddFleet(r, &mcp.Tool{
		Name:        "fleet_list",
		Title:       "List sandboxes",
		Description: "List registered sandboxes with platform, health, labels, which one is selected, and what authenticates each connection (auth: mtls or none). Health is cached unless refresh is set.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, r.sandboxList)

	AddFleet(r, &mcp.Tool{
		Name:        "fleet_select",
		Title:       "Select a sandbox",
		Description: "Set the default sandbox for subsequent calls. Returns a handle, the host's platform, the roots it allows writes under, and what authenticates the connection (auth: mtls or none).",
		Annotations: &mcp.ToolAnnotations{IdempotentHint: true},
	}, r.sandboxSelect)

	AddFleet(r, &mcp.Tool{
		Name:        "fleet_add",
		Title:       "Register a sandbox",
		Description: "Register an already-enrolled agent by name and address. Pass insecure for a host whose agent runs without mTLS. Does not enroll: minting credentials is an operator action via fleetctl.",
		Annotations: &mcp.ToolAnnotations{IdempotentHint: false},
	}, r.sandboxAdd)

	AddFleet(r, &mcp.Tool{
		Name:        "fleet_remove",
		Title:       "Deregister a sandbox",
		Description: "Remove a sandbox from the local registry. Does not uninstall the agent or touch the host.",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: boolPtr(true), IdempotentHint: true},
	}, r.sandboxRemove)

	AddTargeted(r, &mcp.Tool{
		Name:        "fleet_info",
		Title:       "Describe a sandbox",
		Description: "Full detail for one sandbox: platform, resources, allowed roots, agent version, uptime, and what authenticates the connection (auth: mtls or none). include_toolchains probes the filesystem and is measurably slower.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, r.sandboxInfo)
}

func boolPtr(b bool) *bool { return &b }

// ---------------------------------------------------------------- list

// ListArgs are the arguments to fleet_list.
type ListArgs struct {
	// Refresh probes each sandbox instead of reading cached health.
	Refresh bool `json:"refresh,omitempty" jsonschema:"probe every sandbox now instead of reporting cached health"`
	// Label filters the listing to sandboxes carrying a label.
	Label string `json:"label,omitempty" jsonschema:"only list sandboxes carrying this label, as key=value"`
}

// SandboxLine is one sandbox in a fleet_list result. Every field is
// omitempty: a twenty-sandbox listing is paid for on every fleet check.
type SandboxLine struct {
	// Name is the fleet-unique name, and what to pass as sandbox.
	Name string `json:"name"`
	// Address is the agent's host:port.
	Address string `json:"address"`
	// Platform is "os/arch", absent until something has probed the host.
	Platform string `json:"platform,omitempty"`
	// Auth is what authenticates the connection to this sandbox: "mtls" when
	// both ends present certificates issued by the fleet CA, "none" when this
	// fleet authenticates neither end and whatever the network provides is the
	// whole of it.
	//
	// Not omitempty, unlike almost everything else on this line. A missing
	// field would read as "mtls" to anything that defaults, and the one value
	// worth paying a few bytes a row for is the one that says nobody is
	// authenticated.
	Auth string `json:"auth"`
	// Health is serving, degraded, draining, unreachable, or unknown.
	Health string `json:"health"`
	// Detail explains a health value that is not serving.
	Detail string `json:"detail,omitempty"`
	// Agent is the agent's version.
	Agent string `json:"agent,omitempty"`
	// LastSeen is how long ago the sandbox last answered a probe.
	LastSeen string `json:"last_seen,omitempty"`
	// Labels are the operator-assigned labels.
	Labels map[string]string `json:"labels,omitempty"`
	// Selected marks the caller's current sticky default.
	Selected bool `json:"selected,omitempty"`
}

// ListResult is the fleet_list result.
type ListResult struct {
	// Echo carries the selected sandbox, empty when nothing is selected.
	Echo
	// Sandboxes is the inventory, in registration order.
	Sandboxes []SandboxLine `json:"sandboxes"`
	// Hint is present when the listing alone does not tell the model what to
	// do next: an empty fleet, or a fleet with nothing selected.
	Hint string `json:"hint,omitempty"`
}

func (r *Registrar) sandboxList(ctx context.Context, req *mcp.CallToolRequest, in ListArgs) (ListResult, string, error) {
	d := r.deps
	sandboxes, err := d.Fleet.List()
	if err != nil {
		return ListResult{}, "", err
	}

	// The selection is checked against the whole inventory, before the label
	// filter narrows it: a selected sandbox that a filter excluded is still
	// selected, and only one that is genuinely gone is stale.
	identity := d.Resolver.IdentityFor(req)
	selected, _, err := d.Resolver.Selected(identity)
	if err != nil {
		return ListResult{}, "", err
	}
	stale := ""
	if selected != "" && !containsName(sandboxes, selected) {
		stale, selected = selected, ""
	}

	if in.Label != "" {
		key, value, err := parseLabelFilter(in.Label)
		if err != nil {
			return ListResult{}, "", err
		}
		filtered := sandboxes[:0:0]
		for _, sb := range sandboxes {
			// The label has to be present, not merely absent-and-therefore-
			// empty: `label="gpu="` asks for the sandboxes whose gpu label is
			// set to nothing, and answering it with every sandbox that has no
			// gpu label at all is the opposite set.
			if v, ok := sb.Labels[key]; ok && v == value {
				filtered = append(filtered, sb)
			}
		}
		sandboxes = filtered
	}

	health := r.healthFor(ctx, sandboxes, in.Refresh)
	now := time.Now()

	out := ListResult{Sandboxes: make([]SandboxLine, 0, len(sandboxes))}
	for _, sb := range sandboxes {
		h := health[sb.Name]
		lastSeen := sb.LastSeenAt
		if h.seenAt.After(lastSeen) {
			lastSeen = h.seenAt
		}
		agent := sb.AgentVersion
		if h.agentVersion != "" {
			agent = h.agentVersion
		}
		out.Sandboxes = append(out.Sandboxes, SandboxLine{
			Name:    sb.Name,
			Address: sb.Address,
			// Platform and agent version are the agent's words too, cached from
			// the last GetHostInfo, so they are bounded on the same terms as
			// the detail column: no single row may run away with the listing.
			Platform: compact(platformString(sb.Platform)),
			Auth:     client.TargetFor(sb).AuthName(),
			Health:   h.status,
			Detail:   h.detail,
			Agent:    compact(agent),
			LastSeen: relativeTime(lastSeen, now),
			Labels:   sb.Labels,
			Selected: sb.Name == selected,
		})
	}

	switch {
	case len(out.Sandboxes) == 0 && in.Label != "":
		out.Hint = fmt.Sprintf("No sandbox carries the label %q. Call fleet_list without a filter to see every registered sandbox.", in.Label)
	case len(out.Sandboxes) == 0:
		out.Hint = enrollmentHint
	case stale != "":
		out.Hint = fmt.Sprintf("The previously selected sandbox %q is no longer registered. Call fleet_select to choose another.", stale)
	case selected == "":
		out.Hint = "No sandbox is selected. Call fleet_select before any tool that acts on a host."
	}

	// The echo for fleet_list is the selected sandbox; empty is the honest
	// answer when nothing is selected, and the hint above says so.
	return out, selected, nil
}

// containsName reports whether a sandbox of this name is registered.
func containsName(sandboxes []registry.Sandbox, name string) bool {
	for _, sb := range sandboxes {
		if sb.Name == name {
			return true
		}
	}
	return false
}

// ------------------------------------------------------------- select

// SelectArgs are the arguments to fleet_select.
type SelectArgs struct {
	// Name is the sandbox to make the default target.
	Name string `json:"name" jsonschema:"name of the sandbox to make the default target"`
}

// SelectResult is the fleet_select result. It carries platform and allowed
// roots so the model learns where it may write without a second call.
type SelectResult struct {
	// Echo carries the newly selected sandbox.
	Echo
	// Handle is an opaque, stable reference usable as the sandbox argument
	// on any later call.
	Handle string `json:"handle"`
	// Address is the agent's host:port.
	Address string `json:"address"`
	// Platform is "os/arch".
	Platform string `json:"platform,omitempty"`
	// PathSeparator is the host's path separator, so paths can be built
	// correctly for a Windows sandbox from a Unix workstation.
	PathSeparator string `json:"path_separator,omitempty"`
	// AllowedRoots are the absolute paths the agent permits access under.
	// Empty when Unconfined; read the two together, never this one alone.
	AllowedRoots []string `json:"allowed_roots,omitempty"`
	// Unconfined reports that the agent enforces no path jail, so every path
	// is writable rather than none. It is stated explicitly because an absent
	// allowed_roots reads exactly like "nowhere is writable".
	Unconfined bool `json:"unconfined,omitempty"`
	// Health is the sandbox's status right now.
	Health string `json:"health"`
	// Auth is what authenticates the connection to this sandbox — "mtls" or
	// "none". See [SandboxLine.Auth].
	//
	// Reported here as well as on fleet_list and fleet_info because this is the
	// call that decides where every later one lands: a model that has just
	// pointed itself at a host should learn what stands between that host and
	// the network at the moment it points, not on the next listing.
	Auth string `json:"auth"`
	// Note explains a selection that succeeded without full detail.
	Note string `json:"note,omitempty"`
}

func (r *Registrar) sandboxSelect(ctx context.Context, req *mcp.CallToolRequest, in SelectArgs) (SelectResult, string, error) {
	d := r.deps
	name := strings.TrimSpace(in.Name)
	if name == "" {
		names, err := d.Resolver.Names()
		if err != nil {
			return SelectResult{}, "", err
		}
		return SelectResult{}, "", &selection.UnknownSandboxError{Ref: in.Name, Available: names}
	}

	target, err := d.Resolver.Select(d.Resolver.IdentityFor(req), name)
	if err != nil {
		return SelectResult{}, "", err
	}

	out := SelectResult{
		Handle:        target.Handle,
		Address:       target.Address(),
		Platform:      platformString(target.Sandbox.Platform),
		PathSeparator: target.Sandbox.Platform.PathSeparator,
		Auth:          target.Client().AuthName(),
		Health:        healthUnknown,
	}

	// A sandbox that cannot be reached still selects: it may be booting, and
	// refusing would leave the model unable to address it once it comes up.
	// Report the health instead of failing.
	info, err := r.hostInfo(ctx, target, false)
	if err != nil {
		out.Health = healthUnreachable
		out.Note = "Selected, but the sandbox did not answer: " + err.Error()
		// Reporting the failure instead of returning it is the point: the
		// selection is already recorded, and a host that is still booting
		// must remain addressable.
		return out, target.Name(), nil //nolint:nilerr // an unreachable sandbox still selects, by design
	}

	out.Platform = protoPlatformString(info.GetPlatform())
	out.PathSeparator = info.GetPlatform().GetPathSeparator()
	out.AllowedRoots = info.GetAllowedRoots()
	out.Health = healthServing
	// select returns roots so the model learns where it may write, which makes
	// the empty case the one that has to be said out loud rather than left to
	// an absent field.
	if len(out.AllowedRoots) == 0 {
		out.Unconfined = true
		out.Note = unconfinedNote
	}
	if target.Sandbox.Insecure {
		// Ahead of the rest of the note: which paths are writable matters, and
		// "nothing authenticated this connection, and the agent records no
		// identity for anything done over it" matters more.
		out.Note = strings.TrimSpace(unauthenticatedNote + " " + out.Note)
	}
	return out, target.Name(), nil
}

// ---------------------------------------------------------------- add

// AddArgs are the arguments to fleet_add.
type AddArgs struct {
	// Name is the fleet-unique name for the sandbox.
	Name string `json:"name" jsonschema:"fleet-unique name for the sandbox; must match the name it was enrolled under"`
	// Address is the agent's host:port.
	Address string `json:"address" jsonschema:"the agent's address as host:port, e.g. build-box.internal:8722"`
	// Labels are free-form operator metadata.
	Labels map[string]string `json:"labels,omitempty" jsonschema:"free-form labels, e.g. {\"arch\":\"arm64\"}"`
	// Insecure registers a sandbox whose agent runs without mTLS.
	//
	// It has to be said here because no single dial can discover it: an agent
	// serving plaintext and one refusing a handshake look the same to a dialer
	// that has not been told which it is talking to. `fleetctl add` narrows that
	// by trying both postures before it writes, which is worth the two dials for
	// an operator who is watching and can act on a refusal — but it only ever
	// confirms a host that is up, so the argument stays required either way.
	// Registering the wrong value costs a failed connection, never a silent
	// downgrade.
	Insecure bool `json:"insecure,omitempty" jsonschema:"the agent on this host runs with tls.enabled false; connect to it without mTLS, which is only safe on a network that authenticates its peers"`
}

// AddResult is the fleet_add result.
type AddResult struct {
	// Echo carries the registered sandbox.
	Echo
	// Address is what was registered.
	Address string `json:"address"`
	// Handle is the opaque reference for the new sandbox.
	Handle string `json:"handle"`
	// Auth is what will authenticate connections to this sandbox — "mtls" or
	// "none". Echoed back so the caller sees which of the two it just
	// registered rather than only which it asked for.
	Auth string `json:"auth"`
	// Note states what registering did not do.
	Note string `json:"note"`
}

// sandboxAdd is the model's half of registering a sandbox. `fleetctl add` is
// the operator's, and both go through [registry.Registry.Register] — one set of
// bounds, one refusal to overwrite, one account of what registering did not do.
// What this handler adds is the model's vocabulary: the remedy names the tool a
// model can call, not the command an operator types.
func (r *Registrar) sandboxAdd(_ context.Context, _ *mcp.CallToolRequest, in AddArgs) (AddResult, string, error) {
	reg, err := r.deps.Fleet.Register(registry.Sandbox{
		Name: in.Name, Address: in.Address, Labels: in.Labels, Insecure: in.Insecure,
	})
	var duplicate *registry.DuplicateError
	switch {
	case errors.As(err, &duplicate):
		return AddResult{}, "", fmt.Errorf("%w. Remove it with fleet_remove first if the address has changed", duplicate)
	case err != nil:
		return AddResult{}, "", err
	}

	return AddResult{
		Address: reg.Sandbox.Address,
		Handle:  selection.HandleFor(reg.Sandbox.Name),
		Auth:    client.TargetFor(reg.Sandbox).AuthName(),
		Note:    reg.Note,
	}, reg.Sandbox.Name, nil
}

// ------------------------------------------------------------- remove

// RemoveArgs are the arguments to fleet_remove.
type RemoveArgs struct {
	// Name is the sandbox to deregister, by name or handle.
	Name string `json:"name" jsonschema:"name or handle of the sandbox to deregister"`
}

// RemoveResult is the fleet_remove result.
type RemoveResult struct {
	// Echo carries the deregistered sandbox.
	Echo
	// SelectionsCleared counts the clients whose sticky default pointed at
	// this sandbox and was dropped.
	SelectionsCleared int `json:"selections_cleared"`
	// ForwardsClosed are the local addresses of the port forwards that reached
	// this sandbox and were torn down with it.
	ForwardsClosed []string `json:"forwards_closed,omitempty"`
	// ProxyClosed is the local address of the SOCKS proxy that reached through
	// this sandbox, torn down with it for the same reason the forwards are.
	ProxyClosed string `json:"proxy_closed,omitempty"`
	// Note states what removal did not do.
	Note string `json:"note"`
}

func (r *Registrar) sandboxRemove(_ context.Context, _ *mcp.CallToolRequest, in RemoveArgs) (RemoveResult, string, error) {
	d := r.deps
	name := strings.TrimSpace(in.Name)

	// Resolve first, so a handle works here too and an unknown name fails
	// with the registered names listed.
	sb, err := d.Resolver.Lookup(name)
	if err != nil {
		return RemoveResult{}, "", err
	}

	// Selections are cleared before the sandbox is removed, so no window
	// exists in which a selection points at something that is gone. The
	// reverse order would leave one, and a dangling selection is worse than
	// none. This reaches every client identity, not just the caller: the
	// client that ran fleet_remove is rarely the only one that had it
	// selected. It goes through the resolver rather than straight to the
	// registry so it also reaches the unidentified client, whose selection is
	// held in memory rather than in the registry file.
	cleared, err := d.Resolver.ClearSelectionsFor(sb.Name)
	if err != nil {
		return RemoveResult{}, "", err
	}
	if err := d.Fleet.Remove(sb.Name); err != nil {
		return RemoveResult{}, "", err
	}
	// The forwards that reached it, before the channel they run over. A forward
	// is owned by this process rather than by the call that opened it, so
	// nothing else would ever close this one — and removing the sandbox closes
	// the pooled channel underneath it, leaving a local port that accepts a
	// connection and then drops it. That is the one outcome a caller cannot
	// diagnose, which is why the tool preflights against it when opening a
	// forward; arriving at it from this end is no better.
	//
	// Order matters, and it is this way round: dropping the channel first
	// leaves a window in which the listener is still accepting and every
	// connection it takes opens a stream on a channel that has just closed —
	// the accepts-and-then-drops symptom, reached in the middle of the code
	// that exists to prevent it. Closing the forwards first also means the
	// per-connection goroutines this joins are joined while the transport they
	// are using is still there.
	var forwardsClosed []string
	if r.forwards != nil {
		forwardsClosed = r.forwards.stopForSandbox(sb.Name)
	}
	// And the proxy, which is the same argument: a SOCKS listener whose sandbox
	// this server can no longer dial accepts every connection and fails it, and
	// a client pointed at a proxy has no way to tell that from the destinations
	// being down.
	var proxyClosed string
	if r.proxies != nil {
		proxyClosed = r.proxies.stopForSandbox(sb.Name)
	}
	if d.Clients != nil {
		d.Clients.Remove(sb.Name)
	}

	note := "Deregistered locally only. The agent is still installed and running on the host; uninstalling it is a separate operator action."
	if len(forwardsClosed) > 0 {
		note += fmt.Sprintf(" %d port forward(s) reaching it were closed with it (%s); a forward to a sandbox this server can no longer dial would accept connections and drop them.",
			len(forwardsClosed), strings.Join(forwardsClosed, ", "))
	}
	if proxyClosed != "" {
		note += fmt.Sprintf(" The SOCKS proxy through it (%s) was closed with it, for the same reason.", proxyClosed)
	}

	return RemoveResult{
		SelectionsCleared: cleared,
		ForwardsClosed:    forwardsClosed,
		ProxyClosed:       proxyClosed,
		Note:              note,
	}, sb.Name, nil
}

// --------------------------------------------------------------- info

// InfoArgs are the arguments to fleet_info.
type InfoArgs struct {
	TargetArgs
	// IncludeToolchains probes the filesystem for installed toolchains.
	IncludeToolchains bool `json:"include_toolchains,omitempty" jsonschema:"probe the host for installed toolchains; measurably slower"`
}

// InfoResources is the capacity half of a fleet_info result, rendered in
// units a reader can use rather than raw byte counts.
type InfoResources struct {
	// CPUCores is the number of logical cores.
	CPUCores uint32 `json:"cpu_cores,omitempty"`
	// MemoryTotal is total RAM.
	MemoryTotal string `json:"memory_total,omitempty"`
	// MemoryAvailable is RAM currently free.
	MemoryAvailable string `json:"memory_available,omitempty"`
	// DiskTotal is total disk.
	DiskTotal string `json:"disk_total,omitempty"`
	// DiskAvailable is disk currently free.
	DiskAvailable string `json:"disk_available,omitempty"`
	// Load1m is the one-minute load average, when the platform reports one.
	Load1m float64 `json:"load_1m,omitempty"`
}

// InfoToolchain is one detected toolchain.
type InfoToolchain struct {
	// Name is the canonical tool name, e.g. "go".
	Name string `json:"name"`
	// Version is what the tool reports.
	Version string `json:"version,omitempty"`
	// Path is the resolved executable.
	Path string `json:"path,omitempty"`
}

// InfoResult is the fleet_info result.
type InfoResult struct {
	// Echo carries the sandbox this describes.
	Echo
	// Address is the agent's host:port.
	Address string `json:"address"`
	// Handle is the opaque reference for this sandbox.
	Handle string `json:"handle"`
	// Platform is "os/arch".
	Platform string `json:"platform,omitempty"`
	// Kernel is the kernel or OS build version.
	Kernel string `json:"kernel,omitempty"`
	// Hostname is what the host calls itself.
	Hostname string `json:"hostname,omitempty"`
	// PathSeparator is the host's path separator.
	PathSeparator string `json:"path_separator,omitempty"`
	// Resources summarises capacity.
	Resources InfoResources `json:"resources,omitzero"`
	// AllowedRoots are the absolute paths the agent permits access under.
	// Empty when Unconfined; read the two together, never this one alone.
	AllowedRoots []string `json:"allowed_roots,omitempty"`
	// Unconfined reports that the agent enforces no path jail, so every path
	// is writable rather than none. It is stated explicitly because an absent
	// allowed_roots reads exactly like "nowhere is writable".
	Unconfined bool `json:"unconfined,omitempty"`
	// Toolchains is populated only when include_toolchains was set.
	Toolchains []InfoToolchain `json:"toolchains,omitempty"`
	// Agent is the agent's version.
	Agent string `json:"agent,omitempty"`
	// Uptime is how long the agent process has been running.
	Uptime string `json:"uptime,omitempty"`
	// Health is the sandbox's status.
	Health string `json:"health"`
	// RunningProcesses counts supervised background processes.
	RunningProcesses uint32 `json:"running_processes,omitempty"`
	// Labels are the operator-assigned labels.
	Labels map[string]string `json:"labels,omitempty"`
	// Principal is the identity the agent authenticated this client as. On a
	// sandbox reached without mTLS the agent authenticated nobody and says so:
	// the value begins "unauthenticated:" and names the address it saw.
	Principal string `json:"principal,omitempty"`
	// Auth is what authenticates the connection to this sandbox — "mtls" or
	// "none". See [SandboxLine.Auth].
	Auth string `json:"auth"`
	// Note explains anything the model should not have to infer.
	Note string `json:"note,omitempty"`
}

func (r *Registrar) sandboxInfo(ctx context.Context, _ *mcp.CallToolRequest, target *selection.Target, in InfoArgs) (InfoResult, error) {
	out := InfoResult{
		Address:  target.Address(),
		Handle:   target.Handle,
		Platform: platformString(target.Sandbox.Platform),
		Labels:   target.Sandbox.Labels,
		Health:   healthUnknown,
		// From the registry, not from the agent's answer: it is this
		// workstation's own account of how it reached the host, it is known
		// before the call and whether or not one succeeds, and an agent's claim
		// about its own authentication is worth exactly nothing on a connection
		// nothing authenticated.
		Auth: target.Client().AuthName(),
	}

	info, err := r.hostInfo(ctx, target, in.IncludeToolchains)
	if err != nil {
		return InfoResult{}, err
	}

	p := info.GetPlatform()
	out.Platform = protoPlatformString(p)
	out.Kernel = p.GetKernelVersion()
	out.Hostname = p.GetHostname()
	out.PathSeparator = p.GetPathSeparator()
	out.AllowedRoots = info.GetAllowedRoots()
	out.Agent = info.GetAgentVersion()
	out.Health = healthServing
	out.Principal = info.GetAuthenticatedPrincipal()

	res := info.GetResources()
	out.Resources = InfoResources{
		CPUCores:        res.GetCpuCores(),
		MemoryTotal:     humanBytes(res.GetMemoryTotalBytes()),
		MemoryAvailable: humanBytes(res.GetMemoryAvailableBytes()),
		DiskTotal:       humanBytes(res.GetDiskTotalBytes()),
		DiskAvailable:   humanBytes(res.GetDiskAvailableBytes()),
		Load1m:          res.GetLoadAverage_1M(),
	}

	if started := info.GetStartedAt(); started != nil {
		out.Uptime = humanDuration(time.Since(started.AsTime()))
	}
	for _, tc := range info.GetToolchains() {
		out.Toolchains = append(out.Toolchains, InfoToolchain{
			Name: tc.GetName(), Version: tc.GetVersion(), Path: tc.GetPath(),
		})
	}
	if len(out.AllowedRoots) == 0 {
		out.Unconfined = true
		out.Note = unconfinedNote
	}
	if target.Sandbox.Insecure {
		// Ahead of the rest of the note: which paths are writable matters, and
		// "nothing authenticated this connection, and the agent records no
		// identity for anything done over it" matters more.
		out.Note = strings.TrimSpace(unauthenticatedNote + " " + out.Note)
	}
	if !in.IncludeToolchains {
		// Appended after, not before: which paths are writable outranks a note
		// about an optional probe, and the model reads the front of a string.
		out.Note = strings.TrimSpace(out.Note + " Toolchains not probed; pass include_toolchains to detect them.")
	}

	// The health probe is the cheap call and this one is the expensive one,
	// so take the running-process count from whatever the cache already has
	// rather than paying for a second round trip.
	//
	// The cached status is the agent's own opinion of itself — serving,
	// degraded, draining — and is worth more than "the call went through", so
	// it wins. A cache with no opinion does not: GetHostInfo just answered,
	// and downgrading that to "unknown" would report a call that worked as
	// one that told us nothing.
	if h, ok := r.deps.Clients.Health(target.Name()); ok && h.Reachable {
		out.RunningProcesses = h.RunningProcesses
		if cached := healthString(h.Status); cached != healthUnknown {
			out.Health = cached
		}
	}

	return out, nil
}

// ------------------------------------------------------- shared plumbing

// hostInfo calls GetHostInfo against a target under the configured call
// timeout, refreshing the registry's cached platform and agent version on
// success. Failures come back through the central error mapping.
func (r *Registrar) hostInfo(ctx context.Context, target *selection.Target, includeToolchains bool) (*sandboxdv1.GetHostInfoResponse, error) {
	d := r.deps
	if d.Clients == nil {
		return nil, fmt.Errorf("sandbox %s cannot be reached: no gRPC client is configured", target.Name())
	}
	host, err := d.Clients.Host(target.Client())
	if err != nil {
		return nil, target.Call().Map(err)
	}

	timeout := d.callTimeout()
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	info, err := host.GetHostInfo(callCtx, &sandboxdv1.GetHostInfoRequest{IncludeToolchains: includeToolchains})
	if err != nil {
		c := target.Call()
		c.Timeout, c.Limit = timeout, "the host-info call deadline"
		return nil, c.Map(err)
	}

	// Cache what the model will ask for again: platform for fleet_list,
	// agent version for compatibility checks. A failure here is not the
	// caller's problem — the answer is already in hand.
	if err := d.Fleet.UpdateHostInfo(target.Name(), registry.Platform{
		OS:            info.GetPlatform().GetOs(),
		Arch:          info.GetPlatform().GetArch(),
		KernelVersion: info.GetPlatform().GetKernelVersion(),
		Hostname:      info.GetPlatform().GetHostname(),
		PathSeparator: info.GetPlatform().GetPathSeparator(),
	}, info.GetAgentVersion()); err != nil {
		d.logger().Warn("cache host info", "sandbox", target.Name(), "error", err)
	}
	if err := d.Fleet.UpdateLastSeen(target.Name(), time.Now().UTC()); err != nil {
		d.logger().Warn("record last seen", "sandbox", target.Name(), "error", err)
	}
	return info, nil
}

// healthView is one sandbox's health as fleet_list reports it.
type healthView struct {
	status       string
	detail       string
	agentVersion string
	seenAt       time.Time
}

// healthFor collects health for every sandbox in the listing.
//
// With refresh set, every sandbox is probed concurrently under its own short
// deadline, so a powered-off box costs the listing that deadline once rather
// than serialising behind it. Without it, the pool's background cache answers
// and nothing is dialed at all — which is what makes "refresh: false issues
// no probes" true rather than merely fast.
func (r *Registrar) healthFor(ctx context.Context, sandboxes []registry.Sandbox, refresh bool) map[string]healthView {
	out := make(map[string]healthView, len(sandboxes))
	d := r.deps

	if d.Clients == nil {
		for _, sb := range sandboxes {
			out[sb.Name] = healthView{status: healthUnknown}
		}
		return out
	}

	if !refresh {
		for _, sb := range sandboxes {
			h, ok := d.Clients.Health(sb.Name)
			switch {
			case !ok:
				out[sb.Name] = healthView{status: healthUnknown}
			case !h.Reachable:
				out[sb.Name] = healthView{status: healthUnreachable, detail: shortDetail(h.Err)}
			default:
				out[sb.Name] = healthView{
					status:       healthString(h.Status),
					detail:       compact(h.Message),
					agentVersion: h.AgentVersion,
					seenAt:       h.CheckedAt,
				}
			}
		}
		return out
	}

	var (
		mu sync.Mutex
		wg sync.WaitGroup
	)
	timeout := d.probeTimeout()
	for _, sb := range sandboxes {
		wg.Add(1)
		go func(sb registry.Sandbox) {
			defer wg.Done()
			view := r.probe(ctx, sb, timeout)
			mu.Lock()
			out[sb.Name] = view
			mu.Unlock()
		}(sb)
	}
	wg.Wait()

	// Persisting last-seen is a read-modify-write of the registry file per
	// sandbox, so it happens once here, after the probes, rather than inside
	// the concurrent section where the file lock would serialise them anyway.
	for name, view := range out {
		if view.seenAt.IsZero() {
			continue
		}
		if err := d.Fleet.UpdateLastSeen(name, view.seenAt.UTC()); err != nil {
			d.logger().Warn("record last seen", "sandbox", name, "error", err)
		}
	}
	return out
}

// probe issues one Health call under its own deadline.
func (r *Registrar) probe(ctx context.Context, sb registry.Sandbox, timeout time.Duration) healthView {
	host, err := r.deps.Clients.Host(client.TargetFor(sb))
	if err != nil {
		return healthView{status: healthUnreachable, detail: shortDetail(err)}
	}

	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	resp, err := host.Health(probeCtx, &sandboxdv1.HealthRequest{})
	if err != nil {
		return healthView{status: healthUnreachable, detail: shortDetail(err)}
	}
	return healthView{
		status:       healthString(resp.GetStatus()),
		detail:       compact(resp.GetMessage()),
		agentVersion: resp.GetAgentVersion(),
		seenAt:       time.Now(),
	}
}

// shortDetail renders why a sandbox is not serving, for the detail column of
// a listing.
//
// It goes through mcperr.Message rather than err.Error() for two reasons.
// First, a raw gRPC error stringifies as "rpc error: code = Unavailable desc =
// connection refused", and that envelope must not reach the model's context —
// which is exactly what the cached-health path used to do, because only the
// live-probe path was mapped. Second, the row this sits in already names the
// sandbox, its address and its health, so the sentence Call.Map builds would
// repeat all three on every line of every fleet check.
func shortDetail(err error) string {
	return compact(mcperr.Message(err))
}

// maxField bounds what one field of one listing row may contribute.
const maxField = 160

// compact bounds an agent-supplied string for a listing, cutting on a rune
// boundary.
//
// Everything a row says about a sandbox except its name and address is the
// agent's own words — the status message when it reports itself degraded, the
// failure message when it cannot be reached, the platform and version cached
// from its last GetHostInfo — so none of those lengths are this side's to
// assume. One machine answering a probe with a stack trace must not turn a
// twenty-machine listing into a wall of text the model pays for on every fleet
// check; the full text is always available from a direct call against that
// sandbox.
func compact(msg string) string {
	msg = strings.TrimSpace(msg)
	if len(msg) <= maxField {
		return msg
	}
	// Cut on a rune boundary: the text is agent-supplied, and slicing mid-rune
	// would put invalid UTF-8 into the result.
	cut := maxField
	for cut > 0 && !utf8.RuneStart(msg[cut]) {
		cut--
	}
	return msg[:cut] + "…"
}

// protoPlatformString renders a proto Platform as "os/arch".
func protoPlatformString(p *sandboxdv1.Platform) string {
	return platformString(registry.Platform{OS: p.GetOs(), Arch: p.GetArch()})
}
