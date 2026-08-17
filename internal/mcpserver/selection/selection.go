// Package selection decides which sandbox a tool call acts on.
//
// MCP 2026-07-28 removed protocol-level sessions: there is no handshake to
// hang per-connection state off, and a server may sit behind a round-robin
// load balancer. The specification's guidance is to mint an explicit handle
// from a tool and have the model pass it back on every call.
//
// A pure handle design is correct and unusable — the model must thread the
// handle through every call, and it will eventually drop it. A pure implicit
// design is usable and incorrect — it breaks with concurrent clients and
// cannot survive a restart. So sandboxd does both, in a fixed order:
//
//  1. The call's explicit sandbox argument (name or handle). Always wins.
//  2. The sticky default recorded for the calling client identity, taken from
//     _meta and persisted in the registry.
//  3. Otherwise a structured error listing the available sandboxes and naming
//     sandbox_select.
//
// There is deliberately no fourth rule. In particular, a fleet of exactly one
// sandbox does not resolve implicitly: implicit targeting is how the wrong
// host gets written to, and a fleet grows from one to two without anyone
// revisiting the tool calls that were written while it had one member.
package selection

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/axelmierczuk/sandboxd-mcp/internal/mcpserver/mcperr"
	"github.com/axelmierczuk/sandboxd-mcp/internal/registry"
)

// MetaKeyClientID is the _meta key a client sets to name itself explicitly.
// It takes precedence over everything else, and is the way two clients that
// report the same implementation name keep independent selections.
const MetaKeyClientID = "io.sandboxd/clientId"

// handlePrefix marks a sandbox reference as a handle rather than a name.
// Sandbox names are operator-chosen and could in principle collide with a
// handle, so resolution checks names first and the prefix keeps the two
// populations visibly distinct.
const handlePrefix = "sbx_"

// maxIdentityLength bounds a client-supplied identity. It becomes a key in
// the registry file; a kilobyte of it helps nobody.
const maxIdentityLength = 128

// Identity is the key a sticky selection is recorded under.
//
// It is namespaced by where it came from ("meta:", "client:", "process:") so
// a client that calls itself "claude-code" can never collide with one whose
// implementation is named "claude-code".
type Identity string

// Source records how a target was chosen, for logging and for the result
// note that tells a model it is running against its sticky default rather
// than something it named.
type Source string

const (
	// SourceArgument means the call named the sandbox explicitly.
	SourceArgument Source = "argument"
	// SourceSticky means the sandbox came from the client's sticky default.
	SourceSticky Source = "selection"
)

// Target is a resolved sandbox: the host a tool call will act on, the handle
// that names it, and how it was chosen.
type Target struct {
	// Sandbox is the registry entry, carrying address, labels, and the
	// platform cached from the last successful GetHostInfo.
	Sandbox registry.Sandbox
	// Handle is the opaque, stable reference for this sandbox.
	Handle string
	// Source is how this target was chosen.
	Source Source
}

// Name returns the resolved sandbox's name.
func (t *Target) Name() string { return t.Sandbox.Name }

// Address returns the resolved sandbox's host:port.
func (t *Target) Address() string { return t.Sandbox.Address }

// Call returns an mcperr.Call pre-filled with this target, so a handler can
// map a gRPC failure without restating which host it was talking to:
//
//	c := t.Call()
//	c.Subject = "path " + in.Path
//	return out, c.Map(err)
func (t *Target) Call() mcperr.Call {
	return mcperr.Call{Sandbox: t.Sandbox.Name, Address: t.Sandbox.Address}
}

// HandleFor returns the opaque handle for a sandbox name.
//
// It is derived from the name rather than minted and stored, which is what
// makes it stable across restarts of both the MCP server and the registry
// with no extra persistence to keep in sync. It is one-way: a handle names a
// sandbox only by matching against the registered names.
func HandleFor(name string) string {
	sum := sha256.Sum256([]byte("sandboxd/handle/v1\x00" + name))
	return handlePrefix + hex.EncodeToString(sum[:8])
}

// NoTargetError is returned when a call names no sandbox and the client has
// no sticky default. It lists what is available and names the tool that fixes
// it, because an error a model cannot act on costs a turn and teaches it
// nothing.
type NoTargetError struct {
	// Available is every registered sandbox name, in registration order.
	Available []string
}

func (e *NoTargetError) Error() string {
	if len(e.Available) == 0 {
		return "no sandbox selected, and none are registered. Enroll a host with `sandboxctl enroll mint` (see docs/quickstart.md), or register an already-enrolled agent with sandbox_add"
	}
	return fmt.Sprintf("no sandbox selected. Call sandbox_select(name=\"%s\") to choose one for subsequent calls, or pass sandbox=\"%s\" to target this call only. Registered: %s",
		e.Available[0], e.Available[0], strings.Join(e.Available, ", "))
}

// UnknownSandboxError is returned when a name or handle does not match a
// registered sandbox.
type UnknownSandboxError struct {
	// Ref is the name or handle that was asked for.
	Ref string
	// Available is every registered sandbox name.
	Available []string
}

func (e *UnknownSandboxError) Error() string {
	if len(e.Available) == 0 {
		return fmt.Sprintf("unknown sandbox %q: no sandboxes are registered. Enroll one with `sandboxctl enroll mint`, or register an already-enrolled agent with sandbox_add", e.Ref)
	}
	return fmt.Sprintf("unknown sandbox %q. Registered: %s", e.Ref, strings.Join(e.Available, ", "))
}

// StaleSelectionError is returned when a client's sticky default names a
// sandbox that is no longer registered — it was removed by another client, or
// by sandboxctl, while this one still pointed at it.
//
// It is distinct from UnknownSandboxError because the model did nothing wrong
// and the fix is different: re-select, do not correct a typo.
type StaleSelectionError struct {
	// Name is the sandbox the stale selection pointed at.
	Name string
	// Available is every registered sandbox name.
	Available []string
}

func (e *StaleSelectionError) Error() string {
	if len(e.Available) == 0 {
		return fmt.Sprintf("the selected sandbox %q is no longer registered, and no others are. Register one with sandbox_add", e.Name)
	}
	return fmt.Sprintf("the selected sandbox %q is no longer registered. Call sandbox_select to choose another. Registered: %s",
		e.Name, strings.Join(e.Available, ", "))
}

// Options configures a Resolver.
type Options struct {
	// FallbackIdentity is used when a request carries no client identity at
	// all. Defaults to a per-process value.
	FallbackIdentity string
}

// Resolver applies the resolution order against a registry.
//
// It holds no in-memory selection state: every sticky default lives in the
// registry file, which is what lets it survive a restart and what keeps two
// MCP servers sharing a config directory from disagreeing about who selected
// what.
type Resolver struct {
	fleet    *registry.Registry
	fallback Identity
}

// NewResolver returns a Resolver backed by fleet. opts may be nil.
func NewResolver(fleet *registry.Registry, opts *Options) *Resolver {
	fallback := ""
	if opts != nil {
		fallback = opts.FallbackIdentity
	}
	if fallback == "" {
		fallback = fmt.Sprintf("process:%d", os.Getpid())
	}
	return &Resolver{fleet: fleet, fallback: Identity(fallback)}
}

// IdentityFor derives the calling client's identity from the request.
//
// In order of precedence:
//
//  1. The io.sandboxd/clientId key in the request's _meta. A client that runs
//     several concurrent sessions and wants each to hold its own selection
//     sets this.
//  2. The client implementation name, which protocol 2026-07-28 carries in
//     _meta as io.modelcontextprotocol/clientInfo and earlier versions carry
//     in the initialize params. This is the common case, and it is keyed on
//     the name alone rather than name+version so that upgrading the client
//     does not silently drop its selection.
//  3. A per-process fallback, for a request that carries no client identity
//     at all. A selection made under it does not survive a restart, which is
//     the honest outcome: there is nothing stable to key it to.
func (r *Resolver) IdentityFor(req *mcp.CallToolRequest) Identity {
	var meta map[string]any
	if req != nil && req.Params != nil {
		meta = req.Params.GetMeta()
	}
	if raw, ok := meta[MetaKeyClientID]; ok {
		if s, ok := raw.(string); ok {
			if id := sanitizeIdentity(s); id != "" {
				return Identity("meta:" + id)
			}
		}
	}
	if req != nil {
		if info := req.ClientInfo(); info != nil {
			if id := sanitizeIdentity(info.Name); id != "" {
				return Identity("client:" + id)
			}
		}
	}
	return r.fallback
}

// sanitizeIdentity bounds and cleans a client-supplied identity before it
// becomes a key in a YAML file: printable ASCII only, no leading or trailing
// space, capped in length.
func sanitizeIdentity(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	var b strings.Builder
	for _, r := range s {
		if r < ' ' || r > '~' {
			continue
		}
		b.WriteRune(r)
		if b.Len() >= maxIdentityLength {
			break
		}
	}
	return strings.TrimSpace(b.String())
}

// Resolve applies the resolution order for req, with explicit taken from the
// call's sandbox argument (empty when it was omitted).
func (r *Resolver) Resolve(req *mcp.CallToolRequest, explicit string) (*Target, error) {
	return r.ResolveFor(r.IdentityFor(req), explicit)
}

// ResolveFor is Resolve with the client identity supplied directly.
func (r *Resolver) ResolveFor(id Identity, explicit string) (*Target, error) {
	if ref := strings.TrimSpace(explicit); ref != "" {
		sb, err := r.Lookup(ref)
		if err != nil {
			return nil, err
		}
		return targetFor(sb, SourceArgument), nil
	}

	name, ok, err := r.fleet.GetSelection(string(id))
	if err != nil {
		return nil, err
	}
	if !ok || name == "" {
		names, err := r.Names()
		if err != nil {
			return nil, err
		}
		return nil, &NoTargetError{Available: names}
	}

	sb, err := r.fleet.Get(name)
	if err != nil {
		if errors.Is(err, registry.ErrNotFound) {
			names, nerr := r.Names()
			if nerr != nil {
				return nil, nerr
			}
			return nil, &StaleSelectionError{Name: name, Available: names}
		}
		return nil, err
	}
	return targetFor(sb, SourceSticky), nil
}

// Lookup resolves a name or handle to a registered sandbox.
func (r *Resolver) Lookup(ref string) (registry.Sandbox, error) {
	ref = strings.TrimSpace(ref)
	sandboxes, err := r.fleet.List()
	if err != nil {
		return registry.Sandbox{}, err
	}
	for _, sb := range sandboxes {
		if sb.Name == ref {
			return sb, nil
		}
	}
	if strings.HasPrefix(ref, handlePrefix) {
		for _, sb := range sandboxes {
			if HandleFor(sb.Name) == ref {
				return sb, nil
			}
		}
	}
	return registry.Sandbox{}, &UnknownSandboxError{Ref: ref, Available: namesOf(sandboxes)}
}

// Select records name as the sticky default for id and returns it as a
// resolved target. An unknown name fails with the registered names listed.
//
// A sandbox that is unreachable still selects: the box may be booting, and
// refusing to select it would leave the model with no way to ask it anything
// once it comes up.
func (r *Resolver) Select(id Identity, name string) (*Target, error) {
	sb, err := r.Lookup(name)
	if err != nil {
		return nil, err
	}
	if err := r.fleet.SetSelection(string(id), sb.Name); err != nil {
		return nil, err
	}
	return targetFor(sb, SourceArgument), nil
}

// Selected returns the sandbox name id currently has selected, if any.
func (r *Resolver) Selected(id Identity) (string, bool, error) {
	return r.fleet.GetSelection(string(id))
}

// Clear removes id's sticky default.
func (r *Resolver) Clear(id Identity) error {
	return r.fleet.ClearSelection(string(id))
}

// Names returns every registered sandbox name, in registration order.
func (r *Resolver) Names() ([]string, error) {
	sandboxes, err := r.fleet.List()
	if err != nil {
		return nil, err
	}
	return namesOf(sandboxes), nil
}

// Registry returns the registry the resolver reads and writes, so a tool
// that needs the fleet inventory does not have to be handed it twice.
func (r *Resolver) Registry() *registry.Registry { return r.fleet }

func targetFor(sb registry.Sandbox, src Source) *Target {
	return &Target{Sandbox: sb, Handle: HandleFor(sb.Name), Source: src}
}

func namesOf(sandboxes []registry.Sandbox) []string {
	names := make([]string, 0, len(sandboxes))
	for _, sb := range sandboxes {
		names = append(names, sb.Name)
	}
	return names
}
