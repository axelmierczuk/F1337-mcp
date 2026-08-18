package fleetctl

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/fleet-mcp/internal/cli"
	"github.com/axelmierczuk/fleet-mcp/internal/registry"
	"github.com/axelmierczuk/fleet-mcp/internal/socks"
)

// `fleetctl socks` is `ssh -D`.
//
// It is the operator's half of #45, and it is deliberately the more permissive
// of the two: it will open a proxy through an agent whose allow list is empty,
// where fleet_socks refuses to. See checkSocksPolicy in
// internal/mcpserver/tools/socks.go for the whole of that argument. The short
// version is that an operator running this command is making the decision
// themselves, now, about a machine they chose; a model reaching the MCP tool is
// inheriting one nobody made about a model.
//
// What this command owes in exchange is saying, unmistakably, what it just
// opened. An unrestricted proxy is announced in the banner, not implied by the
// absence of a line.

// socksPolicyTimeout bounds the call that reads the agent's forward policy
// before a listener is opened.
const socksPolicyTimeout = 15 * time.Second

// socksResult is the `socks` document: what was opened, and where it reaches.
//
// It is emitted once, when the proxy is serving, and the command then keeps
// running — so a script reading --json output decodes one value from the stream
// rather than reading to EOF, which will not come until the proxy is stopped.
type socksResult struct {
	Sandbox string `json:"sandbox"`
	Address string `json:"address"`
	// LocalAddress is what to point a SOCKS client at.
	LocalAddress string `json:"local_address"`
	LocalPort    int    `json:"local_port"`
	// AllowedHosts is where the agent will let this proxy reach. Empty means
	// any host it can, which is what Unrestricted says out loud.
	AllowedHosts []string `json:"allowed_hosts,omitempty"`
	// Unrestricted reports the one posture worth a script being able to check:
	// this proxy is bounded by nothing but the sandbox's network.
	Unrestricted bool `json:"unrestricted"`
	// Allow is the client-side narrowing, if any was given.
	Allow []string `json:"allow,omitempty"`
	Note  string   `json:"note"`
}

func newSocksCommand(out io.Writer) *cobra.Command {
	var (
		flags        outputFlags
		control      controlFlags
		registryPath string
		port         int
		allow        []string
	)
	cmd := &cobra.Command{
		Use:   "socks [sandbox]",
		Short: "Run a SOCKS5 proxy that reaches a sandbox's network — the `ssh -D` equivalent",
		Long: "socks runs a SOCKS5 proxy on this workstation. Connections through it are made\n" +
			"from the sandbox, so it reaches services the sandbox can see and this machine\n" +
			"cannot: a database on a private subnet, an internal registry, a staging host.\n\n" +
			"    fleetctl socks build-box --port 1080\n" +
			"    curl --socks5-hostname 127.0.0.1:1080 http://db.internal:8080/\n\n" +
			"Names are resolved on the sandbox, which is what --socks5-hostname selects and\n" +
			"the whole reason to use a proxy rather than a port forward: a private name means\n" +
			"nothing to this machine's resolver.\n\n" +
			"CONNECT only — no BIND, no UDP. The listener binds loopback, so it is not\n" +
			"reachable from another machine. It runs until you stop it (Ctrl-C).\n\n" +
			"Where it may reach is the agent's decision, in forward.socks_enabled and\n" +
			"forward.allowed_hosts on that host. --allow narrows it further on this side,\n" +
			"which is a convenience and not a boundary: the agent checks every connection\n" +
			"regardless, and records it.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fleet, err := openRegistry(registryPath)
			if err != nil {
				return err
			}
			sb, err := soleSandbox(fleet, args)
			if err != nil {
				return err
			}

			narrow, err := socks.ParseAllowList(allow)
			if err != nil {
				return err
			}

			pool, err := control.pool()
			if err != nil {
				return err
			}
			defer func() { _ = pool.Close() }()

			policy, err := socksPolicy(cmd.Context(), pool, sb, control.probeTimeout())
			if err != nil {
				return err
			}
			if err := checkSocksPolicy(sb.Name, policy); err != nil {
				return err
			}

			forward, err := pool.Forward(sb.Name, sb.Address)
			if err != nil {
				return err
			}

			server, err := socks.Listen(port, socks.Options{
				Connect: socks.ForwardConnector(forward),
				Allow:   narrow,
				// stderr, never the command's own writer: the writer carries the
				// result, and a --json consumer parsing one document must not
				// find a log line in the middle of it.
				Log: slog.New(slog.NewTextHandler(cmd.ErrOrStderr(), &slog.HandlerOptions{Level: slog.LevelWarn})),
			})
			if err != nil {
				return err
			}
			defer func() { _ = server.Close() }()

			result := socksResult{
				Sandbox:      sb.Name,
				Address:      sb.Address,
				LocalAddress: server.Addr(),
				LocalPort:    server.Port(),
				AllowedHosts: policy.GetAllowedHosts(),
				Unrestricted: len(policy.GetAllowedHosts()) == 0,
				Allow:        allow,
				Note:         socksNote(sb.Name, server.Addr(), policy.GetAllowedHosts()),
			}
			o := flags.output(out)
			if err := o.Emit(result, func(p *cli.Printer) { printSocksBanner(p, result) }); err != nil {
				return err
			}
			warnUnrestricted(cmd.ErrOrStderr(), o, result)

			return serveSocks(cmd.Context(), server, o, result)
		},
	}
	flags.register(cmd)
	control.register(cmd)
	cmd.Flags().StringVar(&registryPath, "registry", "", "path to the fleet registry (default: <config dir>/registry.yaml)")
	cmd.Flags().IntVar(&port, "port", 0, "local port to listen on; 0 (the default) picks a free one and reports it")
	cmd.Flags().StringArrayVar(&allow, "allow", nil,
		"narrow destinations on this side: a host, host:port, or CIDR block; repeatable. A block is matched against an address the client asked for, never against a name that resolves into it — resolving here is what a proxy exists not to do. Does not replace the agent's own allow list")
	return cmd
}

// serveSocks runs the proxy until the operator stops it.
//
// The shutdown discipline is `serve`'s, and for the same reason: this command
// is also driven by MainContext from a process that outlives it, so a watcher
// goroutine left running would accumulate one per invocation.
func serveSocks(parent context.Context, server *socks.Server, o *output, result socksResult) error {
	ctx, stop := signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)

	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		<-ctx.Done()
		// Close, not merely cancel. The accept loop is parked in Accept, which
		// is not waiting on a context; closing the listener is what ends it,
		// and Close then joins every connection still in flight.
		_ = server.Close()
	}()
	// stop() releases the signal handler and cancels ctx, which is what lets
	// the watcher above finish; waiting on stopped means it is gone before this
	// returns.
	defer func() {
		stop()
		<-stopped
	}()

	server.Serve(ctx)
	// Serve can also end because the listener failed in a way the accept loop
	// gave up on. Closing here is idempotent and makes the join unconditional.
	_ = server.Close()

	stats := server.Stats()
	if o.JSON() {
		// Nothing more. The document was emitted when the proxy opened, and a
		// consumer that decoded it has what it asked for; a second document
		// after an unpredictable delay is a stream shape nobody wants to parse.
		return nil
	}
	p := cli.NewPrinter(o.w)
	p.Printf("\nstopped %s after carrying %d connection(s) for %s\n",
		result.LocalAddress, stats.Accepted, result.Sandbox)
	if stats.LastError != "" {
		p.Printf("last connection error: %s\n", safeText(stats.LastError))
	}
	return p.Err()
}

// socksPolicy asks the agent what it permits, before a listener exists.
//
// Reading it here rather than discovering it on the first connection is what
// lets this command refuse with the setting's name in front of an operator who
// is looking at the terminal, instead of handing back an address and then
// failing every `curl` through it with an error the client renders as a reply
// code.
func socksPolicy(ctx context.Context, pool interface {
	Host(name, address string) (sandboxdv1.HostServiceClient, error)
}, sb registry.Sandbox, timeout time.Duration) (*sandboxdv1.ForwardPolicy, error) {
	host, err := pool.Host(sb.Name, sb.Address)
	if err != nil {
		return nil, fmt.Errorf("reach sandbox %s at %s: %w", sb.Name, sb.Address, err)
	}

	callCtx, cancel := context.WithTimeout(ctx, max(timeout, socksPolicyTimeout))
	defer cancel()

	info, err := host.GetHostInfo(callCtx, &sandboxdv1.GetHostInfoRequest{})
	if err != nil {
		return nil, fmt.Errorf("ask sandbox %s what it permits: %s", sb.Name, probeDetail(err))
	}
	return info.GetForwardPolicy(), nil
}

// checkSocksPolicy refuses a proxy the agent will not serve.
//
// Unlike fleet_socks, an empty allow list is not refused here. It is announced,
// in [printSocksBanner]. See the file comment.
func checkSocksPolicy(sandbox string, policy *sandboxdv1.ForwardPolicy) error {
	if policy == nil {
		return fmt.Errorf("sandbox %s does not report a forward policy: its agent is older than this fleetctl and does not implement SOCKS proxying. Upgrade the agent on that host", sandbox)
	}
	if !policy.GetEnabled() {
		return fmt.Errorf("sandbox %s does not forward at all (forward.enabled is false in its agent configuration), so it cannot serve a proxy", sandbox)
	}
	if !policy.GetSocksEnabled() {
		return fmt.Errorf("sandbox %s does not serve SOCKS proxying: set forward.socks_enabled to true in its agent configuration and restart the agent. "+
			"A proxy lets a caller reach every host that machine's network reaches, so it is off unless you turn it on — and when you do, list the hosts, addresses or CIDR blocks it may reach in forward.allowed_hosts", sandbox)
	}
	return nil
}

// socksNote is the one sentence a reader of the JSON document needs.
func socksNote(sandbox, address string, allowedHosts []string) string {
	if len(allowedHosts) == 0 {
		return fmt.Sprintf("Proxying through %s at %s. This agent's forward.allowed_hosts is empty, so the proxy reaches ANY host %s's network reaches.", sandbox, address, sandbox)
	}
	return fmt.Sprintf("Proxying through %s at %s. It reaches %s and nothing else.", sandbox, address, strings.Join(allowedHosts, ", "))
}

// warnUnrestricted repeats the one line that must not be silenced by a flag.
//
// --json exists so a script can read the address, and a script's operator is
// still a person who needs to know that what just opened is bounded by nothing
// but the sandbox's network. The document says so in a field, which is right
// for the script and invisible to the person watching the terminal — so the
// warning also goes to stderr, where it cannot land in the middle of the
// document a consumer is parsing.
//
// Human output already carries it in the banner, so this is JSON-only rather
// than a second copy of it.
func warnUnrestricted(stderr io.Writer, o *output, r socksResult) {
	if !o.JSON() || !r.Unrestricted {
		return
	}
	p := cli.NewPrinter(stderr)
	p.Printf("warning: this proxy reaches ANY host %s can. Its agent's forward.allowed_hosts is empty.\n", r.Sandbox)
	p.Printf("warning: list the hosts, addresses or CIDR blocks it should reach in forward.allowed_hosts on that agent.\n")
	// Deliberately unchecked: a stderr that cannot be written to must not stop
	// a proxy the operator asked for, and the failure would be reported to the
	// stream that just failed.
	_ = p.Err()
}

func printSocksBanner(p *cli.Printer, r socksResult) {
	p.Printf("SOCKS5 proxy for %s listening on %s\n", r.Sandbox, r.LocalAddress)
	p.Printf("  curl --socks5-hostname %s http://<host>/\n", r.LocalAddress)
	p.Printf("\n")

	if r.Unrestricted {
		// The loudest thing this command has to say. An operator who meant to
		// do this loses nothing by reading it; one who did not has this as the
		// only place they will find out before something uses it.
		p.Printf("THIS PROXY REACHES ANY HOST %s CAN.\n", strings.ToUpper(r.Sandbox))
		p.Printf("Its agent's forward.allowed_hosts is empty, so there is nothing narrowing where\n")
		p.Printf("connections through this proxy may go. That is a reasonable choice for a\n")
		p.Printf("throwaway lab box and a poor one anywhere else — list the hosts, addresses or\n")
		p.Printf("CIDR blocks it should reach in forward.allowed_hosts on that agent.\n")
		p.Printf("Every connection is recorded in the agent's audit log.\n")
	} else {
		p.Printf("The agent permits: %s\n", socks.DescribeAllowList(r.AllowedHosts))
		p.Printf("Anything else is refused by the agent and recorded in its audit log.\n")
	}
	if len(r.Allow) > 0 {
		p.Printf("Narrowed on this side to: %s (a convenience; the agent checks every connection anyway)\n",
			socks.DescribeAllowList(r.Allow))
	}
	p.Printf("\nNames are resolved on %s, not here. Stop the proxy with Ctrl-C.\n", r.Sandbox)
}

// soleSandbox resolves the sandbox to proxy through.
//
// A name given on the command line wins. With none, a fleet holding exactly one
// sandbox uses it — the single-host case is most of them, and making an
// operator name the only machine they have is a step that answers nothing — and
// any other fleet is an error listing the names, because guessing which of
// several networks to open a pivot into is not a decision to make on someone's
// behalf.
func soleSandbox(fleet *registry.Registry, args []string) (registry.Sandbox, error) {
	if len(args) == 1 {
		return lookupSandbox(fleet, args[0])
	}

	all, err := fleet.List()
	if err != nil {
		return registry.Sandbox{}, err
	}
	switch len(all) {
	case 0:
		return registry.Sandbox{}, fmt.Errorf("no sandboxes are enrolled; `fleetctl enroll mint --name <name> --address <host:port>` starts one joining")
	case 1:
		return all[0], nil
	default:
		names := make([]string, 0, len(all))
		for _, sb := range all {
			names = append(names, sb.Name)
		}
		return registry.Sandbox{}, fmt.Errorf("name the sandbox to proxy through; the fleet holds: %s", strings.Join(names, ", "))
	}
}
