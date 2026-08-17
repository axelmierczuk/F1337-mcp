package tools

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	sandboxdv1 "github.com/axelmierczuk/sandboxd-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/sandboxd-mcp/internal/mcpserver/mcperr"
	"github.com/axelmierczuk/sandboxd-mcp/internal/mcpserver/selection"
	"github.com/axelmierczuk/sandboxd-mcp/internal/registry"
)

// maxSandboxNameLength bounds a name accepted by sandbox_add. It matches the
// bound enrollment applies to the one identifier an unauthenticated host can
// put into a certificate subject, so a name added here is a name that could
// have been enrolled.
const maxSandboxNameLength = 128

// Bounds on the labels sandbox_add accepts. See [checkLabels].
const (
	maxLabels           = 32
	maxLabelKeyLength   = 64
	maxLabelValueLength = 256
)

// enrollmentHint is what an empty fleet gets told. Adding a sandbox is an
// operator action; the model needs to know that rather than retrying.
const enrollmentHint = "No sandboxes are registered. Enrolling one mints credentials and is an operator action: `sandboxctl enroll mint --name <name> --address <host:port>`, then install the agent on the host (docs/quickstart.md). A host that is already enrolled but missing here can be registered with sandbox_add."

// unconfinedNote is what a host with no allowed roots is reported as.
//
// An agent reports no roots when its path jail is off, and the jail is off
// whenever ExecService is enabled: a caller with exec does not need
// sandbox_write to leave the jail, it runs `sh -c 'echo x > /etc/passwd'`. So
// the two are mutually exclusive, and roots are enforced only on an agent with
// exec disabled.
//
// sandbox_select returns roots precisely so the model learns where it may
// write. Answering that question with an absent list is the model-facing
// version of the same false confidence the mutual exclusion exists to remove,
// read from the other end: "no roots" is silently indistinguishable from
// "nowhere is writable", and a model that concludes the host is read-only will
// not even try. So the absence is stated, not implied.
const unconfinedNote = "This sandbox is unconfined: the agent reports no allowed roots, so every path its user can reach is readable and writable. Roots are enforced only on an agent with exec disabled — with exec enabled a command can write anywhere regardless, so the jail is not applied."

// registerFleet adds the five fleet tools.
func registerFleet(r *Registrar) {
	AddFleet(r, &mcp.Tool{
		Name:        "sandbox_list",
		Title:       "List sandboxes",
		Description: "List registered sandboxes with platform, health, labels and which one is selected. Health is cached unless refresh is set.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, r.sandboxList)

	AddFleet(r, &mcp.Tool{
		Name:        "sandbox_select",
		Title:       "Select a sandbox",
		Description: "Set the default sandbox for subsequent calls. Returns a handle plus the host's platform and the roots it allows writes under.",
		Annotations: &mcp.ToolAnnotations{IdempotentHint: true},
	}, r.sandboxSelect)

	AddFleet(r, &mcp.Tool{
		Name:        "sandbox_add",
		Title:       "Register a sandbox",
		Description: "Register an already-enrolled agent by name and address. Does not enroll: minting credentials is an operator action via sandboxctl.",
		Annotations: &mcp.ToolAnnotations{IdempotentHint: false},
	}, r.sandboxAdd)

	AddFleet(r, &mcp.Tool{
		Name:        "sandbox_remove",
		Title:       "Deregister a sandbox",
		Description: "Remove a sandbox from the local registry. Does not uninstall the agent or touch the host.",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: boolPtr(true), IdempotentHint: true},
	}, r.sandboxRemove)

	AddTargeted(r, &mcp.Tool{
		Name:        "sandbox_info",
		Title:       "Describe a sandbox",
		Description: "Full detail for one sandbox: platform, resources, allowed roots, agent version and uptime. include_toolchains probes the filesystem and is measurably slower.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, r.sandboxInfo)
}

func boolPtr(b bool) *bool { return &b }

// ---------------------------------------------------------------- list

// ListArgs are the arguments to sandbox_list.
type ListArgs struct {
	// Refresh probes each sandbox instead of reading cached health.
	Refresh bool `json:"refresh,omitempty" jsonschema:"probe every sandbox now instead of reporting cached health"`
	// Label filters the listing to sandboxes carrying a label.
	Label string `json:"label,omitempty" jsonschema:"only list sandboxes carrying this label, as key=value"`
}

// SandboxLine is one sandbox in a sandbox_list result. Every field is
// omitempty: a twenty-sandbox listing is paid for on every fleet check.
type SandboxLine struct {
	// Name is the fleet-unique name, and what to pass as sandbox.
	Name string `json:"name"`
	// Address is the agent's host:port.
	Address string `json:"address"`
	// Platform is "os/arch", absent until something has probed the host.
	Platform string `json:"platform,omitempty"`
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

// ListResult is the sandbox_list result.
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
		out.Hint = fmt.Sprintf("No sandbox carries the label %q. Call sandbox_list without a filter to see every registered sandbox.", in.Label)
	case len(out.Sandboxes) == 0:
		out.Hint = enrollmentHint
	case stale != "":
		out.Hint = fmt.Sprintf("The previously selected sandbox %q is no longer registered. Call sandbox_select to choose another.", stale)
	case selected == "":
		out.Hint = "No sandbox is selected. Call sandbox_select before any tool that acts on a host."
	}

	// The echo for sandbox_list is the selected sandbox; empty is the honest
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

// SelectArgs are the arguments to sandbox_select.
type SelectArgs struct {
	// Name is the sandbox to make the default target.
	Name string `json:"name" jsonschema:"name of the sandbox to make the default target"`
}

// SelectResult is the sandbox_select result. It carries platform and allowed
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
	return out, target.Name(), nil
}

// ---------------------------------------------------------------- add

// AddArgs are the arguments to sandbox_add.
type AddArgs struct {
	// Name is the fleet-unique name for the sandbox.
	Name string `json:"name" jsonschema:"fleet-unique name for the sandbox; must match the name it was enrolled under"`
	// Address is the agent's host:port.
	Address string `json:"address" jsonschema:"the agent's address as host:port, e.g. build-box.internal:8722"`
	// Labels are free-form operator metadata.
	Labels map[string]string `json:"labels,omitempty" jsonschema:"free-form labels, e.g. {\"arch\":\"arm64\"}"`
}

// AddResult is the sandbox_add result.
type AddResult struct {
	// Echo carries the registered sandbox.
	Echo
	// Address is what was registered.
	Address string `json:"address"`
	// Handle is the opaque reference for the new sandbox.
	Handle string `json:"handle"`
	// Note states what registering did not do.
	Note string `json:"note"`
}

func (r *Registrar) sandboxAdd(_ context.Context, _ *mcp.CallToolRequest, in AddArgs) (AddResult, string, error) {
	name := strings.TrimSpace(in.Name)
	address := strings.TrimSpace(in.Address)

	// Every check runs before the registry is touched, so a malformed call
	// cannot leave a half-registered sandbox behind.
	if err := checkSandboxName(name); err != nil {
		return AddResult{}, "", err
	}
	if err := checkAddress(address); err != nil {
		return AddResult{}, "", err
	}
	if err := checkLabels(in.Labels); err != nil {
		return AddResult{}, "", err
	}

	err := r.deps.Fleet.Add(registry.Sandbox{Name: name, Address: address, Labels: in.Labels})
	switch {
	case errors.Is(err, registry.ErrExists):
		existing, getErr := r.deps.Fleet.Get(name)
		if getErr != nil {
			return AddResult{}, "", err
		}
		return AddResult{}, "", fmt.Errorf("sandbox %q is already registered at %s. Remove it with sandbox_remove first if the address has changed; registering does not overwrite",
			name, existing.Address)
	case err != nil:
		return AddResult{}, "", err
	}

	return AddResult{
		Address: address,
		Handle:  selection.HandleFor(name),
		Note:    "Registered locally only. This does not enroll the host: the agent must already hold a certificate from this fleet's CA, or calls to it will fail the mTLS handshake.",
	}, name, nil
}

// checkSandboxName bounds the identifier that becomes a registry key and a
// certificate subject.
func checkSandboxName(name string) error {
	if name == "" {
		return errors.New("name is required")
	}
	if len(name) > maxSandboxNameLength {
		return fmt.Errorf("name is %d bytes, limit is %d", len(name), maxSandboxNameLength)
	}
	for _, r := range name {
		// Printable, non-space ASCII: a sandbox name is typed on a command
		// line and printed in a table.
		if r <= ' ' || r > '~' {
			return fmt.Errorf("name contains an invalid character %q; use printable ASCII with no spaces", r)
		}
	}
	if strings.HasPrefix(name, "sbx_") {
		return fmt.Errorf("name %q collides with the handle prefix sbx_; choose another", name)
	}
	return nil
}

// checkLabels bounds the free-form metadata a sandbox_add call attaches.
//
// Labels are the one part of the call with no shape of their own, and they are
// paid for twice: once in the registry file that every later operation rewrites
// whole, and again in every sandbox_list result, which lands in model context
// on every fleet check. The labels enrollment attaches come from the operator's
// token and are the operator's business; these come from the model, so they are
// bounded here, before the registry is touched.
func checkLabels(labels map[string]string) error {
	if len(labels) > maxLabels {
		return fmt.Errorf("%d labels given, limit is %d", len(labels), maxLabels)
	}
	for key, value := range labels {
		if key == "" {
			return errors.New(`a label key is empty; labels are key=value metadata, e.g. {"arch":"arm64"}`)
		}
		if len(key) > maxLabelKeyLength {
			return fmt.Errorf("label key %q is %d bytes, limit is %d", compact(key), len(key), maxLabelKeyLength)
		}
		for _, r := range key {
			// A key is typed into the label filter as key=value and printed in
			// a table, so it carries the same restriction a name does.
			if r <= ' ' || r > '~' {
				return fmt.Errorf("label key %q contains an invalid character %q; use printable ASCII with no spaces",
					compact(key), r)
			}
		}
		if len(value) > maxLabelValueLength {
			return fmt.Errorf("label %q has a %d-byte value, limit is %d", key, len(value), maxLabelValueLength)
		}
		for _, r := range value {
			if !unicode.IsPrint(r) {
				return fmt.Errorf("label %q has a value containing an unprintable character %q", key, r)
			}
		}
	}
	return nil
}

// checkAddress validates host:port before the registry is touched. The host
// half becomes the TLS server name the agent's certificate is verified
// against, so an address that is not host:port is a configuration error that
// should be named as one here rather than surfacing later as a handshake
// failure.
func checkAddress(address string) error {
	if address == "" {
		return errors.New("address is required, as host:port")
	}
	if strings.Contains(address, "://") {
		return fmt.Errorf("address %q looks like a URL; give host:port, e.g. build-box.internal:8722", address)
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("address %q is not host:port (e.g. build-box.internal:8722): %w", address, err)
	}
	if host == "" {
		return fmt.Errorf("address %q names no host; the host half is what the agent's certificate is checked against", address)
	}
	if strings.ContainsAny(host, "/\\ ") {
		return fmt.Errorf("address %q has an invalid host %q", address, host)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("address %q has an invalid port %q; expected 1-65535", address, port)
	}
	return nil
}

// ------------------------------------------------------------- remove

// RemoveArgs are the arguments to sandbox_remove.
type RemoveArgs struct {
	// Name is the sandbox to deregister, by name or handle.
	Name string `json:"name" jsonschema:"name or handle of the sandbox to deregister"`
}

// RemoveResult is the sandbox_remove result.
type RemoveResult struct {
	// Echo carries the deregistered sandbox.
	Echo
	// SelectionsCleared counts the clients whose sticky default pointed at
	// this sandbox and was dropped.
	SelectionsCleared int `json:"selections_cleared"`
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
	// client that ran sandbox_remove is rarely the only one that had it
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
	if d.Clients != nil {
		d.Clients.Remove(sb.Name)
	}

	return RemoveResult{
		SelectionsCleared: cleared,
		Note:              "Deregistered locally only. The agent is still installed and running on the host; uninstalling it is a separate operator action.",
	}, sb.Name, nil
}

// --------------------------------------------------------------- info

// InfoArgs are the arguments to sandbox_info.
type InfoArgs struct {
	TargetArgs
	// IncludeToolchains probes the filesystem for installed toolchains.
	IncludeToolchains bool `json:"include_toolchains,omitempty" jsonschema:"probe the host for installed toolchains; measurably slower"`
}

// InfoResources is the capacity half of a sandbox_info result, rendered in
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

// InfoResult is the sandbox_info result.
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
	// Principal is the identity the agent authenticated this client as.
	Principal string `json:"principal,omitempty"`
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
	host, err := d.Clients.Host(target.Name(), target.Address())
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

	// Cache what the model will ask for again: platform for sandbox_list,
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

// healthView is one sandbox's health as sandbox_list reports it.
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
	host, err := r.deps.Clients.Host(sb.Name, sb.Address)
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
