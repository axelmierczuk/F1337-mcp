package fleetctl

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/spf13/cobra"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/fleet-mcp/internal/cli"
	"github.com/axelmierczuk/fleet-mcp/internal/client"
	"github.com/axelmierczuk/fleet-mcp/internal/registry"
)

// The operator's view of the fleet goes through internal/client — the same
// package, the same TLS configuration and the same health vocabulary the MCP
// server uses — rather than through anything this file invents.
//
// That is not tidiness. `fleetctl list` is what an operator reaches for when
// the model reports a sandbox as unreachable, and a CLI with its own idea of
// fleet health answers that question about itself instead of about the fleet.
// The two views disagreeing is the single most expensive kind of bug this tool
// could have, because it sends the operator looking in the wrong place.

// defaultProbeTimeout bounds one sandbox's health probe.
//
// It is short on purpose: a fleet holds machines that are asleep, rebuilt, or
// simply gone, and the answer for those is "unreachable" delivered promptly,
// not a listing that stalls behind a TCP connect to a black hole. Probes run
// concurrently, so this is very nearly the whole cost of `list` on the worst
// possible fleet, not the cost per dead host.
const defaultProbeTimeout = 3 * time.Second

// controlFlags are the credentials and deadline every command that reaches an
// agent needs. One struct, registered in one call, so no command re-declares
// --cert or re-derives a default path.
type controlFlags struct {
	caDir    string
	certPath string
	keyPath  string
	timeout  time.Duration
}

func (f *controlFlags) register(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.caDir, "ca-dir", "", "directory holding the CA (default: <config dir>/ca)")
	cmd.Flags().StringVar(&f.certPath, "cert", "", "control certificate presented to agents (default: <config dir>/control.crt)")
	cmd.Flags().StringVar(&f.keyPath, "key", "", "private key for --cert (default: <config dir>/control.key)")
	cmd.Flags().DurationVar(&f.timeout, "timeout", defaultProbeTimeout,
		"how long to wait for each sandbox before reporting it unreachable")
}

// oneShotHealthInterval is what a command that does not read the health cache
// asks the pool's background health loop for: as close to never as a duration
// can say.
//
// The pool starts a health loop per channel and Close waits for it, so a
// default-length background probe against a black-holed host would keep a
// listing alive well past the line it was printing — for `list` and `info`,
// longer than the process lives is the whole requirement. `fleetctl socks`
// runs for hours rather than seconds and wants the same value for the other
// reason: it reaches a sandbox through pool.Forward and never asks what the
// cache thinks, so every probe that loop makes is traffic nobody reads.
//
// `fleetctl tui` is the one command on the other side of this — the cache is
// its health source — and it passes what --refresh chose; see newTUICommand.
const oneShotHealthInterval = time.Hour

// pool builds the gRPC client pool this workstation dials agents with.
//
// healthInterval is a parameter rather than a constant because the two callers
// want opposite things out of the same struct: a one-shot listing needs the
// background loop never to fire, and `fleetctl tui` needs it to be the only
// thing probing on a schedule. One function rather than two so that choice is
// a value at the call site instead of a second copy of the credential loading
// below, which is what it was — thirty lines that had to stay identical and
// nothing to notice if they stopped being.
//
// The per-call probe timeout is --timeout either way.
// warnTo is where the pool announces a connection this fleet does not
// authenticate: the command's error stream, never its own writer, because the
// writer carries the result and a --json consumer parsing one document must not
// find a log line in the middle of it. Same rule `fleetctl socks` applies to
// the proxy's log.
//
// Nil is silent, and `fleetctl tui` passes nil deliberately: it owns the whole
// terminal, and a warning written into it would garble the view rather than
// inform anybody. The posture reaches that operator through the sandbox's
// principal, which reads `unauthenticated:<address>` in the detail pane.
func warnTo(w io.Writer) *slog.Logger {
	if w == nil {
		return nil
	}
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: slog.LevelWarn}))
}

func (f *controlFlags) pool(healthInterval time.Duration, warn *slog.Logger) (*client.Pool, error) {
	if healthInterval <= 0 {
		healthInterval = oneShotHealthInterval
	}
	caDir, err := resolve(f.caDir, defaultCADir)
	if err != nil {
		return nil, err
	}
	// The CA is loaded on the same terms as the leaf below: a workstation whose
	// whole fleet runs without mTLS has never run `ca init` and does not need
	// to, so "there is no CA here" is carried to the dial that needs one rather
	// than failing every command that touches the fleet.
	authority, caErr := loadCA(caDir)

	certPath, err := resolve(f.certPath, defaultControlCertPath)
	if err != nil {
		return nil, err
	}
	keyPath, err := resolve(f.keyPath, defaultControlKeyPath)
	if err != nil {
		return nil, err
	}
	cfg := client.Config{
		HealthTimeout:  f.probeTimeout(),
		HealthInterval: healthInterval,
		Log:            warn,
	}

	certPEM, certErr := readControlCredential(certPath, "control certificate")
	keyPEM, keyErr := readControlCredential(keyPath, "control private key")
	switch {
	case caErr != nil:
		cfg.CredentialErr = caErr
	case certErr != nil:
		// Carried rather than returned, so a fleet whose members all run
		// without mTLS works on a workstation that has never issued itself a
		// leaf — there is nothing missing there, only nothing needed. It
		// becomes the error for a sandbox that *is* reached over mTLS, where it
		// still names the file and the command that creates it.
		cfg.CredentialErr = certErr
	case keyErr != nil:
		cfg.CredentialErr = keyErr
	default:
		cfg.CACertPEM, cfg.CertPEM, cfg.KeyPEM = authority.CertPEM(), certPEM, keyPEM
	}

	return client.NewPool(cfg)
}

// readControlCredential loads a PEM file, turning "no such file" into the
// command that creates it. This is the same message fleet-mcp gives, and it now
// names a command that exists: `ca sign --profile control` generates the
// keypair when it is not given a CSR.
func readControlCredential(path, what string) ([]byte, error) {
	data, err := os.ReadFile(path) //nolint:gosec // the path is this operator's own configuration
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("no %s at %s: run `fleetctl ca sign --profile control` to issue one", what, path)
		}
		return nil, fmt.Errorf("read %s at %s: %w", what, path, err)
	}
	return data, nil
}

// probeTimeout is the per-sandbox deadline, defaulted.
func (f *controlFlags) probeTimeout() time.Duration {
	if f.timeout <= 0 {
		return defaultProbeTimeout
	}
	return f.timeout
}

// ---------------------------------------------------------------- list

// sandboxLine is one row of `fleetctl list`. It deliberately mirrors the MCP
// server's SandboxLine: same fields, same health words, same relative times.
type sandboxLine struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	// Auth is what authenticates the connection to this sandbox: "mtls", or
	// "none" for one this fleet reaches without a certificate at either end.
	// It is a column of its own because an operator looking at a fleet has to
	// be able to see which members are authenticated without opening a config
	// on each host.
	Auth       string            `json:"auth"`
	Platform   string            `json:"platform,omitempty"`
	Health     string            `json:"health"`
	Detail     string            `json:"detail,omitempty"`
	Agent      string            `json:"agent,omitempty"`
	LastSeen   string            `json:"last_seen,omitempty"`
	EnrolledAt string            `json:"enrolled_at,omitempty"`
	Labels     map[string]string `json:"labels,omitempty"`
}

// listResult is the `list` document.
type listResult struct {
	Sandboxes []sandboxLine `json:"sandboxes"`
	// Note explains a listing that could not say everything it wanted to —
	// most often health it could not probe because this workstation holds no
	// control certificate yet.
	Note string `json:"note,omitempty"`
}

func newListCommand(out io.Writer) *cobra.Command {
	var (
		flags        outputFlags
		control      controlFlags
		registryPath string
		noProbe      bool
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List the fleet, with each sandbox's health",
		Long: "list shows every enrolled sandbox and probes each one for health.\n\n" +
			"Probes run concurrently under a per-sandbox deadline, so a powered-off host\n" +
			"is reported as unreachable rather than holding up the listing. Health is\n" +
			"read through the same client the MCP server uses, so this and fleet_list\n" +
			"cannot disagree about whether a sandbox is up.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			fleet, err := openRegistry(registryPath)
			if err != nil {
				return err
			}
			sandboxes, err := fleet.List()
			if err != nil {
				return err
			}

			result := listResult{Sandboxes: make([]sandboxLine, 0, len(sandboxes))}
			health, note := probeFleet(cmd.Context(), sandboxes, &control, warnTo(cmd.ErrOrStderr()), noProbe)
			result.Note = note

			now := time.Now()
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
				result.Sandboxes = append(result.Sandboxes, sandboxLine{
					Name:    sb.Name,
					Address: sb.Address,
					Auth:    client.TargetFor(sb).AuthName(),
					// Platform and agent version are the agent's words too,
					// cached from its last report, so they are bounded on the
					// same terms as the detail column.
					Platform:   oneLine(sb.Platform.String()),
					Health:     h.status,
					Detail:     h.detail,
					Agent:      oneLine(agent),
					LastSeen:   cli.RelativeTime(lastSeen, now),
					EnrolledAt: formatTime(sb.EnrolledAt),
					Labels:     sb.Labels,
				})
			}

			o := flags.output(out)
			return o.Emit(result, func(p *cli.Printer) {
				if len(result.Sandboxes) == 0 {
					p.Println("no sandboxes enrolled")
					p.Println("Enroll one with `fleetctl enroll mint --name <name> --address <host:port>`.")
					return
				}
				rows := make([][]string, 0, len(result.Sandboxes))
				for _, sb := range result.Sandboxes {
					rows = append(rows, []string{
						sb.Name,
						dash(sb.Address),
						sb.Auth,
						dash(sb.Platform),
						dash(sb.Agent),
						sb.Health,
						sb.LastSeen,
						sb.Detail,
					})
				}
				if err := o.table([]string{"NAME", "ADDRESS", "AUTH", "PLATFORM", "AGENT", "HEALTH", "LAST SEEN", "DETAIL"}, rows); err != nil {
					p.Printf("%v\n", err)
					return
				}
				if result.Note != "" {
					p.Printf("\n%s\n", result.Note)
				}
				if note := unauthenticatedListNote(result.Sandboxes); note != "" {
					// After the table and after any note about the listing
					// itself. An operator scanning a column of "none" should
					// not have to know what the column means, and one whose
					// fleet is entirely mTLS never sees this line.
					p.Printf("\n%s\n", note)
				}
			})
		},
	}
	flags.register(cmd)
	control.register(cmd)
	cmd.Flags().StringVar(&registryPath, "registry", "", "path to the fleet registry (default: <config dir>/registry.yaml)")
	cmd.Flags().BoolVar(&noProbe, "no-probe", false, "list from the registry without contacting any sandbox")
	return cmd
}

// unauthenticatedListNote names the members of a listing that nothing in this
// fleet authenticates, and what that means.
//
// It exists because the column alone is not a warning. "none" in a table reads
// as an absence — of a value, of a probe — rather than as the whole of a
// sandbox's authentication, and the operator this is written for is the one who
// inherited a fleet and has never seen the setting before.
func unauthenticatedListNote(lines []sandboxLine) string {
	var names []string
	for _, line := range lines {
		if line.Auth == client.AuthNone {
			names = append(names, line.Name)
		}
	}
	if len(names) == 0 {
		return ""
	}
	return fmt.Sprintf("auth none (%s): reached without mTLS — no certificate is presented and none is verified, so nothing in this fleet authenticates either end.\n"+
		"Whatever authenticates them is the network they sit on. Commands run there are recorded against the address they came from, not a verified identity.",
		strings.Join(names, ", "))
}

// healthView is one sandbox's health, in the same shape the MCP server keeps.
type healthView struct {
	status       string
	detail       string
	agentVersion string
	seenAt       time.Time
	// answered records that the agent itself replied, as distinct from what it
	// replied with.
	//
	// `list` does not need it: every outcome it renders is a word in the
	// status column. `fleetctl add` does, because it asks a different
	// question — "is something serving this address in the posture I was
	// told?" — and the status alone cannot answer it. An agent may legally
	// report STATUS_UNSPECIFIED, which renders as "unknown", the same word a
	// probe that was never made produces. Registering a host on the strength
	// of a probe that never happened is precisely the confusion add exists to
	// prevent, so the fact is recorded rather than inferred from the word.
	answered bool
}

// probeFleet probes every sandbox concurrently and returns what each said,
// plus a note when nothing could be probed at all.
//
// A missing control certificate is a note, not a failure: an operator who has
// run `ca init` but not yet issued themselves a leaf should still be able to
// see which hosts are enrolled and be told, once, what is missing. Failing the
// whole command would answer a question about the fleet with a question about
// this workstation.
func probeFleet(ctx context.Context, sandboxes []registry.Sandbox, control *controlFlags, warn *slog.Logger, noProbe bool) (map[string]healthView, string) {
	out := make(map[string]healthView, len(sandboxes))
	unknown := func(note string) (map[string]healthView, string) {
		for _, sb := range sandboxes {
			out[sb.Name] = healthView{status: client.HealthUnknown}
		}
		return out, note
	}

	switch {
	case len(sandboxes) == 0:
		return out, ""
	case noProbe:
		return unknown("Health is unknown: --no-probe was given, so no sandbox was contacted.")
	}

	pool, err := control.pool(oneShotHealthInterval, warn)
	if err != nil {
		return unknown("Health is unknown: " + err.Error())
	}
	defer func() { _ = pool.Close() }()

	var (
		mu sync.Mutex
		wg sync.WaitGroup
	)
	timeout := control.probeTimeout()
	for _, sb := range sandboxes {
		wg.Add(1)
		go func(sb registry.Sandbox) {
			defer wg.Done()
			view := probeOne(ctx, pool, sb, timeout)
			mu.Lock()
			out[sb.Name] = view
			mu.Unlock()
		}(sb)
	}
	wg.Wait()

	if credErr := pool.CredentialErr(); credErr != nil && anyAuthenticated(sandboxes) {
		// Said once, under the table, rather than left to be pieced together
		// from a column of "unknown": this is a fact about this workstation
		// rather than about the fleet, and it has one fix. In the loader's own
		// words, because those name the file and the command that makes it —
		// `ca init` when there is no CA at all, `ca sign` when there is.
		//
		// Only when some sandbox actually needed it: a fleet that runs entirely
		// without mTLS was probed in full, and telling that operator about a
		// certificate they will never issue is noise about a fleet that is fine.
		return out, "Health is unknown for the sandboxes reached over mTLS: " + credErr.Error()
	}
	return out, ""
}

// anyAuthenticated reports whether any of these sandboxes is reached over mTLS,
// and so needs a credential this workstation may not have.
func anyAuthenticated(sandboxes []registry.Sandbox) bool {
	for _, sb := range sandboxes {
		if !sb.Insecure {
			return true
		}
	}
	return false
}

// probeOne issues one Health call under its own deadline. It is the same call,
// through the same pool, that the MCP server's fleet_list makes.
func probeOne(ctx context.Context, pool *client.Pool, sb registry.Sandbox, timeout time.Duration) healthView {
	host, err := pool.Host(client.TargetFor(sb))
	switch {
	case errors.Is(err, client.ErrNoCredentials):
		// Nothing was dialled, so this is "nothing has looked", not "looked and
		// found nothing" — the distinction the health vocabulary exists to
		// keep, and the one that stops an operator chasing a machine that is
		// fine because their own workstation has no leaf.
		//
		// No detail: the reason is the same for every such row and is said
		// once, under the table, where it can name the command that fixes it.
		return healthView{status: client.HealthUnknown}
	case err != nil:
		return healthView{status: client.HealthUnreachable, detail: probeDetail(err)}
	}

	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	resp, err := host.Health(probeCtx, &sandboxdv1.HealthRequest{})
	if err != nil {
		return healthView{status: client.HealthUnreachable, detail: probeDetail(err)}
	}
	return healthView{
		status:       client.HealthName(resp.GetStatus()),
		detail:       oneLine(resp.GetMessage()),
		agentVersion: oneLine(resp.GetAgentVersion()),
		seenAt:       time.Now(),
		answered:     true,
	}
}

// probeDetail renders why a sandbox did not answer, short enough for a table
// cell. It goes through client.MapError so the vocabulary matches what the MCP
// server reports for the same failure, rather than a raw
// "rpc error: code = Unavailable desc = …".
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

// maxDetail bounds what one sandbox may contribute to a listing. Everything in
// the detail column is the agent's own words, and one machine answering with a
// stack trace must not turn a twenty-machine listing into a wall of text.
const maxDetail = 80

// safeText makes an agent-supplied string safe to print.
//
// Control characters are dropped, not just newlines. Enrollment bounds what a
// host may say about itself for exactly this reason — "a terminal escape in a
// fleet listing is a lie about the fleet" — but everything here arrives from a
// live agent long after enrollment checked anything, and lands in the same
// table. A sandbox is a machine running someone else's code; its opinion of
// itself does not get to move the operator's cursor.
func safeText(msg string) string {
	var b strings.Builder
	b.Grow(len(msg))
	space := false
	for _, r := range msg {
		switch {
		case unicode.IsSpace(r):
			space = b.Len() > 0
		case unicode.IsControl(r), unicode.Is(unicode.Cf, r):
			// Dropped without becoming a space: a discarded escape must not
			// split one word into two that then look like separate columns.
		default:
			if space {
				b.WriteRune(' ')
				space = false
			}
			b.WriteRune(r)
		}
	}
	return b.String()
}

// oneLine is safeText bounded to a table cell. `info` describes one host and
// can afford the full text; `list` has a row per sandbox and cannot.
func oneLine(msg string) string {
	out := safeText(msg)
	if len(out) <= maxDetail {
		return out
	}
	// Cut on a rune boundary: slicing mid-rune would put invalid UTF-8 into
	// the JSON document a script is about to parse.
	cut := maxDetail
	for cut > 0 && !utf8.RuneStart(out[cut]) {
		cut--
	}
	return out[:cut] + "…"
}

// ---------------------------------------------------------------- info

// infoResources is the capacity half of an `info` result, in units a reader
// can use rather than raw byte counts.
type infoResources struct {
	CPUCores        uint32  `json:"cpu_cores,omitempty"`
	MemoryTotal     string  `json:"memory_total,omitempty"`
	MemoryAvailable string  `json:"memory_available,omitempty"`
	DiskTotal       string  `json:"disk_total,omitempty"`
	DiskAvailable   string  `json:"disk_available,omitempty"`
	Load1m          float64 `json:"load_1m,omitempty"`
}

// infoToolchain is one detected toolchain.
type infoToolchain struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Path    string `json:"path,omitempty"`
}

// infoResult describes one sandbox. It reports what the registry knows even
// when the host does not answer, because "enrolled at, address, and not
// responding" is exactly what an operator needs when a host is down.
type infoResult struct {
	Name          string `json:"name"`
	Address       string `json:"address"`
	Health        string `json:"health"`
	Detail        string `json:"detail,omitempty"`
	Platform      string `json:"platform,omitempty"`
	Kernel        string `json:"kernel,omitempty"`
	Hostname      string `json:"hostname,omitempty"`
	PathSeparator string `json:"path_separator,omitempty"`
	Agent         string `json:"agent,omitempty"`
	Uptime        string `json:"uptime,omitempty"`
	// Auth is what authenticates the connection to this sandbox — "mtls" or
	// "none" — read from the registry rather than from the host's answer, so
	// it is reported for a host that never replies.
	Auth             string            `json:"auth"`
	RunningProcesses uint32            `json:"running_processes,omitempty"`
	Principal        string            `json:"principal,omitempty"`
	Resources        infoResources     `json:"resources,omitzero"`
	AllowedRoots     []string          `json:"allowed_roots,omitempty"`
	Unconfined       bool              `json:"unconfined,omitempty"`
	Toolchains       []infoToolchain   `json:"toolchains,omitempty"`
	Labels           map[string]string `json:"labels,omitempty"`
	EnrolledAt       string            `json:"enrolled_at,omitempty"`
	LastSeen         string            `json:"last_seen,omitempty"`
}

func newInfoCommand(out io.Writer) *cobra.Command {
	var (
		flags        outputFlags
		control      controlFlags
		registryPath string
		toolchains   bool
	)
	cmd := &cobra.Command{
		Use:   "info <name>",
		Short: "Describe one sandbox in full",
		Long: "info reports everything known about one sandbox: what the registry recorded\n" +
			"at enrollment, and what the host says about itself right now.\n\n" +
			"A host that does not answer is described anyway, from the registry, with\n" +
			"health \"unreachable\" and the reason. That is a description, not a failure,\n" +
			"so the command still exits 0; scripts should read the health field.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fleet, err := openRegistry(registryPath)
			if err != nil {
				return err
			}
			sb, err := lookupSandbox(fleet, args[0])
			if err != nil {
				return err
			}

			// The platform and the agent version are the host's own words even
			// here: enrollment bounded what it said about itself once, but
			// fleet_info overwrites both from a live GetHostInfo every time the
			// model asks, and nothing checks them on that path. So the registry
			// is not a clean source for them, and this — the reading a host that
			// does not answer produces — is the one place they reach a terminal
			// without the live path's safeText.
			//
			// The name and the address are not in that class: they come from
			// `enroll mint`, and enrollment is what writes them.
			result := infoResult{
				Name:       sb.Name,
				Address:    sb.Address,
				Auth:       client.TargetFor(sb).AuthName(),
				Health:     client.HealthUnknown,
				Platform:   safeText(sb.Platform.String()),
				Kernel:     safeText(sb.Platform.KernelVersion),
				Hostname:   safeText(sb.Platform.Hostname),
				Agent:      safeText(sb.AgentVersion),
				Labels:     sb.Labels,
				EnrolledAt: formatTime(sb.EnrolledAt),
				LastSeen:   cli.RelativeTime(sb.LastSeenAt, time.Now()),
			}
			fillHostInfo(cmd.Context(), &result, sb, &control, warnTo(cmd.ErrOrStderr()), toolchains)

			return flags.output(out).Emit(result, func(p *cli.Printer) { printInfo(p, result, toolchains) })
		},
	}
	flags.register(cmd)
	control.register(cmd)
	cmd.Flags().StringVar(&registryPath, "registry", "", "path to the fleet registry (default: <config dir>/registry.yaml)")
	cmd.Flags().BoolVar(&toolchains, "toolchains", false, "probe the host for installed toolchains; measurably slower")
	return cmd
}

// fillHostInfo asks the sandbox about itself, leaving the registry's own
// answers in place when it does not reply.
func fillHostInfo(ctx context.Context, result *infoResult, sb registry.Sandbox, control *controlFlags, warn *slog.Logger, toolchains bool) {
	pool, err := control.pool(oneShotHealthInterval, warn)
	if err != nil {
		result.Health, result.Detail = client.HealthUnknown, err.Error()
		return
	}
	defer func() { _ = pool.Close() }()

	host, err := pool.Host(client.TargetFor(sb))
	switch {
	case errors.Is(err, client.ErrNoCredentials):
		result.Health, result.Detail = client.HealthUnknown, err.Error()
		return
	case err != nil:
		result.Health, result.Detail = client.HealthUnreachable, probeDetail(err)
		return
	}

	timeout := control.probeTimeout()
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	info, err := host.GetHostInfo(callCtx, &sandboxdv1.GetHostInfoRequest{IncludeToolchains: toolchains})
	if err != nil {
		result.Health, result.Detail = client.HealthUnreachable, probeDetail(err)
		return
	}

	// Every string below is the agent's own account of itself, arriving over the
	// wire and going straight to a terminal, so all of it goes through safeText.
	p := info.GetPlatform()
	result.Platform = safeText(registry.Platform{OS: p.GetOs(), Arch: p.GetArch()}.String())
	result.Kernel = safeText(p.GetKernelVersion())
	result.Hostname = safeText(p.GetHostname())
	result.PathSeparator = safeText(p.GetPathSeparator())
	result.Agent = safeText(info.GetAgentVersion())
	result.Principal = safeText(info.GetAuthenticatedPrincipal())
	for _, root := range info.GetAllowedRoots() {
		result.AllowedRoots = append(result.AllowedRoots, safeText(root))
	}
	result.Unconfined = len(result.AllowedRoots) == 0
	result.Health = client.HealthServing
	result.LastSeen = "just now"

	res := info.GetResources()
	result.Resources = infoResources{
		CPUCores:        res.GetCpuCores(),
		MemoryTotal:     cli.HumanBytes(res.GetMemoryTotalBytes()),
		MemoryAvailable: cli.HumanBytes(res.GetMemoryAvailableBytes()),
		DiskTotal:       cli.HumanBytes(res.GetDiskTotalBytes()),
		DiskAvailable:   cli.HumanBytes(res.GetDiskAvailableBytes()),
		Load1m:          res.GetLoadAverage_1M(),
	}
	if started := info.GetStartedAt(); started != nil {
		result.Uptime = cli.HumanDuration(time.Since(started.AsTime()))
	}
	for _, tc := range info.GetToolchains() {
		result.Toolchains = append(result.Toolchains, infoToolchain{
			Name:    safeText(tc.GetName()),
			Version: safeText(tc.GetVersion()),
			Path:    safeText(tc.GetPath()),
		})
	}

	// The agent's own opinion of itself — serving, degraded, draining — is
	// worth more than "the call went through", so take it when the cheap probe
	// has one. GetHostInfo just succeeded, so a probe with no opinion must not
	// downgrade this to unknown.
	probeCtx, probeCancel := context.WithTimeout(ctx, timeout)
	defer probeCancel()
	if health, err := host.Health(probeCtx, &sandboxdv1.HealthRequest{}); err == nil {
		if named := client.HealthName(health.GetStatus()); named != client.HealthUnknown {
			result.Health = named
		}
		result.Detail = safeText(health.GetMessage())
		result.RunningProcesses = health.GetRunningProcesses()
	}
}

// unauthenticatedInfoNote is what `fleetctl info` says about a sandbox this
// fleet does not authenticate.
const unauthenticatedInfoNote = "auth none: this sandbox is reached without mTLS. No client certificate is presented and its agent verifies none,\n" +
	"so nothing in this fleet authenticates either end — whatever does is the network it sits on. The agent records\n" +
	"commands run here against the address they came from rather than a verified identity."

func printInfo(p *cli.Printer, r infoResult, toolchainsRequested bool) {
	field := func(label, value string) {
		if value != "" {
			p.Printf("%-14s %s\n", label+":", value)
		}
	}
	field("name", r.Name)
	field("address", r.Address)
	// Directly under the address, because it is a property of reaching it.
	field("auth", r.Auth)
	field("health", r.Health)
	field("detail", r.Detail)
	field("platform", r.Platform)
	field("kernel", r.Kernel)
	field("hostname", r.Hostname)
	field("agent", r.Agent)
	field("uptime", r.Uptime)
	if r.RunningProcesses > 0 {
		field("processes", fmt.Sprintf("%d running", r.RunningProcesses))
	}
	field("principal", r.Principal)
	field("enrolled", r.EnrolledAt)
	field("last seen", r.LastSeen)

	if r.Auth == client.AuthNone {
		// The field above says which posture this is; this says what it costs.
		// An operator reading `fleetctl info` about one host is the reader most
		// likely to be deciding whether that host is safe where it is.
		p.Printf("\n%s\n", unauthenticatedInfoNote)
	}

	if r.Resources.CPUCores > 0 || r.Resources.MemoryTotal != "" || r.Resources.DiskTotal != "" {
		p.Printf("\nresources:\n")
		if r.Resources.CPUCores > 0 {
			p.Printf("  cpu:    %d cores\n", r.Resources.CPUCores)
		}
		if r.Resources.MemoryTotal != "" {
			p.Printf("  memory: %s available of %s\n", dash(r.Resources.MemoryAvailable), r.Resources.MemoryTotal)
		}
		if r.Resources.DiskTotal != "" {
			p.Printf("  disk:   %s available of %s\n", dash(r.Resources.DiskAvailable), r.Resources.DiskTotal)
		}
		if r.Resources.Load1m > 0 {
			p.Printf("  load:   %.2f (1m)\n", r.Resources.Load1m)
		}
	}

	if len(r.Labels) > 0 {
		p.Printf("\nlabels:\n")
		for _, key := range sortedKeys(r.Labels) {
			p.Printf("  %s=%s\n", key, r.Labels[key])
		}
	}

	if len(r.Toolchains) > 0 {
		p.Printf("\ntoolchains:\n")
		for _, tc := range r.Toolchains {
			p.Printf("  %-10s %s %s\n", tc.Name, dash(tc.Version), tc.Path)
		}
	} else if toolchainsRequested && r.Health == client.HealthServing {
		p.Printf("\ntoolchains:  none detected\n")
	}

	switch {
	case r.Unconfined && r.Health == client.HealthServing:
		// Said out loud, because an absent roots list reads exactly like
		// "nowhere is writable" when it means the opposite.
		p.Printf("\nallowed roots: none — this sandbox is unconfined. Roots are enforced only on\n")
		p.Printf("an agent with exec disabled; with exec on, a command reaches any path the\n")
		p.Printf("agent's account can. See docs/security.md.\n")
	case len(r.AllowedRoots) > 0:
		p.Printf("\nallowed roots:\n")
		for _, root := range r.AllowedRoots {
			p.Printf("  %s\n", root)
		}
	}
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// -------------------------------------------------------------- remove

// removeResult is what a deregistration did — and, in its note, what it did
// not.
type removeResult struct {
	Name              string `json:"name"`
	Address           string `json:"address,omitempty"`
	SelectionsCleared int    `json:"selections_cleared"`
	Note              string `json:"note"`
}

// removeNote states the thing an operator most often assumes removal did.
const removeNote = "Deregistered locally only. The agent is still installed and running on the host, and its certificate is still valid: uninstalling it is a separate action on that machine."

func newRemoveCommand(out io.Writer) *cobra.Command {
	var (
		flags        outputFlags
		registryPath string
	)
	cmd := &cobra.Command{
		Use:   "remove <name>",
		Short: "Deregister a sandbox from the fleet registry",
		Long: "remove drops a sandbox from this workstation's registry and clears any\n" +
			"client selection pointing at it.\n\n" +
			"It does not touch the host. The agent keeps running and keeps its\n" +
			"certificate, so a removed sandbox can be re-registered without re-enrolling.\n" +
			"To stop it serving, uninstall the agent on the host, or rotate the CA.",
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			fleet, err := openRegistry(registryPath)
			if err != nil {
				return err
			}
			sb, err := lookupSandbox(fleet, args[0])
			if err != nil {
				return err
			}

			// Selections first, so no window exists in which a selection points
			// at a sandbox that is already gone. The reverse order leaves one,
			// and a dangling selection is worse than none.
			cleared, err := fleet.ClearSelectionsFor(sb.Name)
			if err != nil {
				return err
			}
			if err := fleet.Remove(sb.Name); err != nil {
				return err
			}

			return flags.output(out).Emit(removeResult{
				Name:              sb.Name,
				Address:           sb.Address,
				SelectionsCleared: cleared,
				Note:              removeNote,
			}, func(p *cli.Printer) {
				p.Printf("removed %s (%s)\n", sb.Name, dash(sb.Address))
				if cleared > 0 {
					p.Printf("cleared %d client selection(s) pointing at it\n", cleared)
				}
				p.Printf("\n%s\n", removeNote)
			})
		},
	}
	flags.register(cmd)
	cmd.Flags().StringVar(&registryPath, "registry", "", "path to the fleet registry (default: <config dir>/registry.yaml)")
	return cmd
}

// lookupSandbox resolves a name, answering an unknown one with the names that
// do exist rather than with the name that does not.
func lookupSandbox(fleet *registry.Registry, name string) (registry.Sandbox, error) {
	sb, err := fleet.Get(name)
	if err == nil {
		return sb, nil
	}
	if !errors.Is(err, registry.ErrNotFound) {
		return registry.Sandbox{}, err
	}

	all, listErr := fleet.List()
	if listErr != nil || len(all) == 0 {
		return registry.Sandbox{}, fmt.Errorf("no sandbox named %q is enrolled; `fleetctl list` shows the fleet", name)
	}
	names := make([]string, 0, len(all))
	for _, sb := range all {
		names = append(names, sb.Name)
	}
	return registry.Sandbox{}, fmt.Errorf("no sandbox named %q is enrolled; the fleet holds: %s", name, strings.Join(names, ", "))
}
