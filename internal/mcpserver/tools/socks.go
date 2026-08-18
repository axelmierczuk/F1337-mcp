package tools

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/fleet-mcp/internal/mcpserver/selection"
	"github.com/axelmierczuk/fleet-mcp/internal/socks"
)

// fleet_socks is `ssh -D`, and saying so is worth more than a paragraph
// explaining it — the same reasoning fleet_forward's description is built on.
//
// What its description has that fleet_forward's does not is the shape of the
// refusal. This tool declines to open a proxy through an agent that permits
// every host, and a model that meets that error without having been told the
// rule beforehand has no way to tell "this needs an operator" from "try again
// differently". So the constraint is in the description, before the first call.
const socksDescription = "Open a SOCKS5 proxy on this workstation that reaches the selected sandbox's network. This is the `ssh -D` equivalent: point any SOCKS-aware client at the local address it returns, and connections through it are made from the sandbox. " +
	"Use it to reach a service the sandbox can see and this workstation cannot — a database on a private subnet, an internal registry, a staging host. Names are resolved on the sandbox, so private names work (with curl, use --socks5-hostname). " +
	"The proxy is owned by this MCP server, not by this call: it stays open across unrelated tool calls until you pass stop=true or the MCP server exits. Every call lists the proxies that are currently open. " +
	"The local listener binds loopback only. CONNECT only: no BIND, no UDP. " +
	"The agent decides where a proxy may reach, in its forward.allowed_hosts setting, and this tool refuses to open one through an agent that permits every host — that is a decision an operator makes for themselves, not one a model inherits. The result reports the hosts the agent does permit."

// maxProxies caps how many local listeners one MCP server holds for proxies. A
// proxy is per sandbox rather than per port, so this is a bound on a fleet's
// worth of them, not on a session's worth of ports.
const maxProxies = 8

// socksPreflightTimeout bounds the one call that reads the agent's forward
// policy before a listener is opened.
const socksPreflightTimeout = 10 * time.Second

// registerSocks adds fleet_socks and gives the Registrar the manager that owns
// the listeners.
func registerSocks(r *Registrar) {
	r.proxies = newSocksManager(r.deps.logger())
	AddTargeted(r, &mcp.Tool{
		Name:        "fleet_socks",
		Title:       "Open a SOCKS5 proxy through a sandbox",
		Description: socksDescription,
	}, r.sandboxSocks)
}

// ------------------------------------------------------------- manager

// socksManager owns every open proxy for the life of the MCP server.
//
// It is deliberately a sibling of forwardManager rather than a generalisation
// of it. The two hold different things — a forward is keyed by its remote host
// and port, a proxy has no remote until a client names one — and the shared
// part, the connection lifetime, is shared already: both go through
// tunnel.Carry.
type socksManager struct {
	log *slog.Logger

	mu      sync.Mutex
	closed  bool
	proxies map[string]*activeProxy
}

func newSocksManager(log *slog.Logger) *socksManager {
	return &socksManager{log: log, proxies: map[string]*activeProxy{}}
}

// activeProxy is one local SOCKS listener and everything running through it.
type activeProxy struct {
	sandbox   string
	server    *socks.Server
	createdAt time.Time
	// allowedHosts is what the agent reported it would permit when the proxy
	// opened. Echoed in every listing so a model choosing destinations is not
	// guessing at them.
	allowedHosts []string

	cancel context.CancelFunc
	// wg covers the accept loop. Every per-connection goroutine is joined by
	// the server's own Close, so this covers only the goroutine this package
	// starts.
	wg sync.WaitGroup
}

// close tears one proxy down: the server first, which closes the listener,
// cancels every connection under it and joins them, and then this package's own
// accept goroutine.
func (p *activeProxy) close() {
	_ = p.server.Close()
	p.cancel()
	p.wg.Wait()
}

// list renders every open proxy. It is returned by every socks call so the
// model can see what is already open without a second tool.
func (m *socksManager) list() []SocksLine {
	m.mu.Lock()
	defer m.mu.Unlock()

	out := make([]SocksLine, 0, len(m.proxies))
	now := time.Now()
	for _, p := range m.proxies {
		stats := p.server.Stats()
		out = append(out, SocksLine{
			Sandbox:      p.sandbox,
			LocalAddress: p.server.Addr(),
			LocalPort:    p.server.Port(),
			AllowedHosts: p.allowedHosts,
			Age:          humanDuration(now.Sub(p.createdAt)),
			Connections:  stats.Accepted,
			OpenNow:      stats.OpenNow,
			LastError:    stats.LastError,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Sandbox < out[j].Sandbox })
	return out
}

func (m *socksManager) get(sandbox string) (*activeProxy, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.proxies[sandbox]
	return p, ok
}

// stop tears down the proxy for a sandbox, if there is one.
func (m *socksManager) stop(sandbox string) (*activeProxy, bool) {
	m.mu.Lock()
	p, ok := m.proxies[sandbox]
	if ok {
		delete(m.proxies, sandbox)
	}
	m.mu.Unlock()
	if !ok {
		return nil, false
	}
	p.close()
	return p, true
}

// add registers a started proxy, refusing once the manager is closed or full.
func (m *socksManager) add(p *activeProxy) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return errors.New("the MCP server is shutting down, so no new proxy was opened")
	}
	if _, exists := m.proxies[p.sandbox]; exists {
		return fmt.Errorf("a proxy for sandbox %s already exists", p.sandbox)
	}
	if len(m.proxies) >= maxProxies {
		return fmt.Errorf("%d proxies are already open, which is this server's maximum; stop one with fleet_socks(stop=true)", maxProxies)
	}
	m.proxies[p.sandbox] = p
	return nil
}

// Close releases every listener. It is idempotent.
func (m *socksManager) Close() error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	proxies := make([]*activeProxy, 0, len(m.proxies))
	for sandbox, p := range m.proxies {
		proxies = append(proxies, p)
		delete(m.proxies, sandbox)
	}
	m.mu.Unlock()

	// Outside the lock: closing joins per-connection goroutines, and holding
	// the manager lock across that would block a concurrent list behind a
	// transfer that is still draining.
	for _, p := range proxies {
		m.log.Debug("releasing SOCKS proxy", "local", p.server.Addr(), "sandbox", p.sandbox)
		p.close()
	}
	return nil
}

// ---------------------------------------------------------------- tool

// SocksArgs are the arguments to fleet_socks.
type SocksArgs struct {
	TargetArgs
	// LocalPort is the port on this workstation. Zero picks a free one.
	LocalPort int `json:"local_port,omitempty" jsonschema:"port to listen on locally; 0 (the default) picks a free port and reports it"`
	// Stop tears the proxy down.
	Stop bool `json:"stop,omitempty" jsonschema:"close this sandbox's proxy instead of opening one"`
}

// SocksLine is one open proxy.
type SocksLine struct {
	// Sandbox is the sandbox the proxy reaches through.
	Sandbox string `json:"sandbox"`
	// LocalAddress is what to point a SOCKS client at.
	LocalAddress string `json:"local_address"`
	// LocalPort is the local half of it.
	LocalPort int `json:"local_port"`
	// AllowedHosts is where the agent will let this proxy reach.
	AllowedHosts []string `json:"allowed_hosts,omitempty"`
	// Age is how long the proxy has been open.
	Age string `json:"age,omitempty"`
	// Connections is how many have been accepted since it opened.
	Connections uint64 `json:"connections,omitempty"`
	// OpenNow is how many are in flight.
	OpenNow int `json:"open_now,omitempty"`
	// LastError is the most recent per-connection failure, if any. A proxy
	// whose listener is fine but whose destinations all refuse looks healthy
	// from the outside; this is where that shows.
	LastError string `json:"last_error,omitempty"`
}

// SocksResult is the fleet_socks result.
type SocksResult struct {
	// Echo carries the sandbox the proxy reaches through.
	Echo
	// LocalAddress is what to point a SOCKS client at, e.g. 127.0.0.1:1080.
	LocalAddress string `json:"local_address,omitempty"`
	// LocalPort is the local half.
	LocalPort int `json:"local_port,omitempty"`
	// AllowedHosts is where the agent will let this proxy reach. It is the
	// answer to the question a caller asks next, so it is in the result rather
	// than only in an error.
	AllowedHosts []string `json:"allowed_hosts,omitempty"`
	// Stopped reports that this call closed a proxy.
	Stopped bool `json:"stopped,omitempty"`
	// Existing reports that the proxy was already open and was reused.
	Existing bool `json:"existing,omitempty"`
	// Active is every proxy this MCP server currently holds, across every
	// sandbox.
	Active []SocksLine `json:"active_proxies"`
	// Note is what the caller should not have to infer.
	Note string `json:"note,omitempty"`
}

func (r *Registrar) sandboxSocks(ctx context.Context, _ *mcp.CallToolRequest, target *selection.Target, in SocksArgs) (SocksResult, error) {
	if in.LocalPort < 0 || in.LocalPort > 65535 {
		return SocksResult{}, fmt.Errorf("local_port %d is out of range; expected 0-65535, where 0 picks a free port", in.LocalPort)
	}
	if in.Stop {
		return r.stopProxy(target.Name())
	}
	return r.startProxy(ctx, target, in.LocalPort)
}

func (r *Registrar) stopProxy(sandbox string) (SocksResult, error) {
	p, ok := r.proxies.stop(sandbox)
	if !ok {
		active := r.proxies.list()
		if len(active) == 0 {
			return SocksResult{}, fmt.Errorf("no proxy is open for sandbox %s, and none are open at all", sandbox)
		}
		return SocksResult{}, fmt.Errorf("no proxy is open for sandbox %s. Open proxies: %s", sandbox, describeProxies(active))
	}
	return SocksResult{
		LocalAddress: p.server.Addr(),
		LocalPort:    p.server.Port(),
		Stopped:      true,
		Active:       r.proxies.list(),
		Note: fmt.Sprintf("Closed %s. The local listener is released and connections that were in flight through it were dropped.",
			p.server.Addr()),
	}, nil
}

func (r *Registrar) startProxy(ctx context.Context, target *selection.Target, localPort int) (SocksResult, error) {
	// An already-open proxy is returned rather than duplicated. A model that
	// opens the same proxy twice has forgotten it did, not asked for a second
	// one, and answering with the address it already has is what lets it carry
	// on.
	if existing, ok := r.proxies.get(target.Name()); ok {
		if localPort != 0 && localPort != existing.server.Port() {
			return SocksResult{}, fmt.Errorf("sandbox %s is already proxied at %s. Stop that proxy first with fleet_socks(stop=true) if it should move to local port %d",
				target.Name(), existing.server.Addr(), localPort)
		}
		return SocksResult{
			LocalAddress: existing.server.Addr(),
			LocalPort:    existing.server.Port(),
			AllowedHosts: existing.allowedHosts,
			Existing:     true,
			Active:       r.proxies.list(),
			Note:         "This proxy was already open, so the existing one was reused.",
		}, nil
	}

	if r.deps.Clients == nil {
		return SocksResult{}, fmt.Errorf("sandbox %s cannot be reached: no gRPC client is configured", target.Name())
	}

	// The policy first, before a listener exists. See [checkSocksPolicy]: this
	// is the decision the tool exists to make, and making it after handing back
	// an address would mean a model holding a proxy that refuses everything.
	policy, err := r.socksPolicy(ctx, target)
	if err != nil {
		return SocksResult{}, err
	}
	if err := checkSocksPolicy(target.Name(), policy); err != nil {
		return SocksResult{}, err
	}

	client, err := r.deps.Clients.Forward(target.Client())
	if err != nil {
		return SocksResult{}, target.Call().Map(err)
	}

	server, err := socks.Listen(localPort, socks.Options{
		Connect: socks.ForwardConnector(client),
		Log:     r.deps.logger(),
	})
	if err != nil {
		return SocksResult{}, err
	}

	// The proxy's context is the manager's, never the tool call's. A proxy tied
	// to the call that opened it would close the moment that call returned,
	// which is the opposite of what it is for.
	proxyCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	p := &activeProxy{
		sandbox:      target.Name(),
		server:       server,
		createdAt:    time.Now(),
		allowedHosts: policy.GetAllowedHosts(),
		cancel:       cancel,
	}
	if err := r.proxies.add(p); err != nil {
		cancel()
		_ = server.Close()
		return SocksResult{}, err
	}

	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		server.Serve(proxyCtx)
	}()

	r.deps.logger().Debug("SOCKS proxy open", "sandbox", target.Name(), "local", server.Addr())

	return SocksResult{
		LocalAddress: server.Addr(),
		LocalPort:    server.Port(),
		AllowedHosts: policy.GetAllowedHosts(),
		Active:       r.proxies.list(),
		Note: fmt.Sprintf("A SOCKS5 proxy through sandbox %s is listening on %s. Point a SOCKS-aware client at it — `curl --socks5-hostname %s http://host/` — and connections are made from %s. "+
			"Names are resolved there, not here, which is what --socks5-hostname selects. It reaches %s and nothing else. "+
			"It stays open until you call fleet_socks(stop=true) or this MCP server exits. The listener is bound to loopback, so it is not reachable from another machine.",
			target.Name(), server.Addr(), server.Addr(), target.Name(), strings.Join(policy.GetAllowedHosts(), ", ")),
	}, nil
}

// socksPolicy asks the agent what it permits.
//
// It is a live call rather than anything cached: the answer decides whether a
// proxy is opened at all, and a stale one would decide it from a configuration
// the agent stopped running some restarts ago.
func (r *Registrar) socksPolicy(ctx context.Context, target *selection.Target) (*sandboxdv1.ForwardPolicy, error) {
	host, err := r.deps.Clients.Host(target.Client())
	if err != nil {
		return nil, target.Call().Map(err)
	}

	probeCtx, cancel := context.WithTimeout(ctx, socksPreflightTimeout)
	defer cancel()

	info, err := host.GetHostInfo(probeCtx, &sandboxdv1.GetHostInfoRequest{})
	if err != nil {
		c := target.Call()
		c.Subject = "the agent's forward policy"
		c.Timeout, c.Limit = socksPreflightTimeout, "the proxy preflight deadline"
		return nil, c.Map(err)
	}
	return info.GetForwardPolicy(), nil
}

// checkSocksPolicy decides whether this tool will open a proxy at all.
//
// # The decision this encodes
//
// `fleetctl socks` will open a proxy through an agent whose allow list is
// empty. This tool will not, and the difference is the whole of #45's open
// question.
//
// An operator running the CLI made the "any host" decision about themselves, on
// a machine they chose, at a moment they were thinking about it. A model
// reaching this tool inherits that decision without anyone having made it about
// a model: the config was very likely written for a throwaway lab box months
// earlier, and nothing since has asked whether the same box should also hand a
// general-purpose network pivot to something that will use it autonomously.
//
// The asymmetry is proportionate because the blast radius is asymmetric. Every
// other tool here is bounded by the sandbox — its filesystem, its processes,
// its ports. A proxy is bounded by the sandbox's *network*, which on a fleet
// spanning a laptop, a home lab and a cloud VPC is a set nobody has enumerated.
// It is the one capability in the set whose reach is not visible from the host
// it runs on.
//
// So the tool requires the operator to have narrowed it — and narrowing it is
// cheap, one line in the agent's config, phrased in the error. What it must
// never do is refuse in a way that reads as a bug: the message names the
// setting, the value, the machine, and the CLI that has no such rule.
//
// This is a guardrail on a model, not a security boundary. The boundary is the
// agent's, applied per connection on the far side. This check runs on the
// workstation and reads what the agent volunteers about itself; an agent that
// lied here would still enforce whatever it actually has.
func checkSocksPolicy(sandbox string, policy *sandboxdv1.ForwardPolicy) error {
	if policy == nil {
		// Only an agent older than this field can answer without one. Such an
		// agent also predates the socks flag, so it would apply its forwarding
		// rules to a proxied connection — bounded, but bounded by a policy this
		// server cannot read, which is not a state to open a pivot from.
		return fmt.Errorf("sandbox %s does not report its forward policy, so this server cannot tell what a proxy through it would reach. Its agent is older than this MCP server; upgrade it, or use `fleetctl socks %s`, which asks the agent per connection", sandbox, sandbox)
	}
	if !policy.GetEnabled() {
		return fmt.Errorf("sandbox %s does not forward at all (forward.enabled is false in its agent configuration), so it cannot serve a proxy", sandbox)
	}
	if !policy.GetSocksEnabled() {
		return fmt.Errorf("sandbox %s does not serve SOCKS proxying (forward.socks_enabled is false in its agent configuration). A proxy would let a caller reach every host that machine's network reaches, so it is off unless an operator turns it on — and an operator turning it on should also list the hosts, addresses or CIDR blocks it may reach in forward.allowed_hosts", sandbox)
	}
	// Both spellings of "unrestricted". The empty list is checked here rather
	// than only trusting the agent's own answer because an agent built before
	// that field reports it as false, and an empty list is the shape this rule
	// was written for: reading only the flag would turn the refusal off for
	// every agent in a mixed fleet.
	if len(policy.GetAllowedHosts()) == 0 || policy.GetUnrestricted() {
		return fmt.Errorf("sandbox %s permits proxying to any host it can reach (%s), and fleet_socks will not open a proxy on those terms. "+
			"A proxy reaches every host that machine's network reaches, which is a wider grant than every other tool here combined, and \"any host\" is a decision an operator made about their own workstation rather than one this tool inherits on your behalf. "+
			"Ask the operator to list the hosts, addresses or CIDR blocks the proxy should reach in forward.allowed_hosts on that agent — `allowed_hosts: [\"db.internal\", \"10.0.4.0/24\"]`. A block covering everything, such as `0.0.0.0/0`, is the same grant written differently and is refused the same way. "+
			"`fleetctl socks %s` is the operator's own path and has no such rule", sandbox, describeUnrestricted(policy), sandbox)
	}
	return nil
}

// describeUnrestricted names the configuration a refusal is about, so an
// operator reading it can find the line rather than the setting.
//
// The two spellings need different sentences: one operator has written nothing
// and has to add something, the other has written something that reads as a
// narrowing and has to replace it. Telling the second one that their
// allowed_hosts "is empty" would send them looking for a line that is right
// there in front of them.
func describeUnrestricted(policy *sandboxdv1.ForwardPolicy) string {
	if hosts := policy.GetAllowedHosts(); len(hosts) > 0 {
		return fmt.Sprintf("forward.socks_enabled is true and forward.allowed_hosts covers every host it can reach — %s — in its agent configuration", strings.Join(hosts, ", "))
	}
	return "forward.socks_enabled is true and forward.allowed_hosts is empty in its agent configuration"
}

// describeProxies renders the open proxies for an error message.
func describeProxies(lines []SocksLine) string {
	parts := make([]string, 0, len(lines))
	for _, l := range lines {
		parts = append(parts, fmt.Sprintf("%s -> %s", l.LocalAddress, l.Sandbox))
	}
	return strings.Join(parts, "; ")
}

// stopForSandbox tears down a sandbox's proxy and returns its local address, or
// "" if it had none.
//
// It exists for fleet_remove, for the same reason forwardManager has one: a
// proxy outlives the call that opened it, so deregistering the sandbox it
// reaches through would otherwise leave a local port that still accepts
// connections and drops every one of them.
func (m *socksManager) stopForSandbox(sandbox string) string {
	p, ok := m.stop(sandbox)
	if !ok {
		return ""
	}
	return p.server.Addr()
}
