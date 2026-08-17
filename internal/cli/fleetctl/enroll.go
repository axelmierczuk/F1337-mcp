package fleetctl

import (
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/axelmierczuk/fleet-mcp/internal/cli"

	"github.com/axelmierczuk/fleet-mcp/internal/security/ca"
	"github.com/axelmierczuk/fleet-mcp/internal/security/enroll"
)

// defaultControlPort is the port `serve` listens on, and so the port a mint
// assumes the enrolling host will dial unless told otherwise.
const defaultControlPort = "9443"

// defaultAgentListen is what install.sh defaults the agent's listener to. The
// generated install command repeats it explicitly whenever the token authorizes
// a different port, which is the case that would otherwise enroll a host that
// then listens somewhere the control plane will not look.
const defaultAgentListen = "0.0.0.0:8722"

// installScriptURL is the installer the generated command pipes into a shell.
const installScriptURL = "https://raw.githubusercontent.com/axelmierczuk/fleet-mcp/main/install.sh"

// installScriptURLWindows is its PowerShell counterpart.
const installScriptURLWindows = "https://raw.githubusercontent.com/axelmierczuk/fleet-mcp/main/install.ps1"

func newEnrollCommand(out io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "enroll",
		Short: "Mint, inspect, and revoke single-use enrollment tokens",
		RunE:  func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	cmd.AddCommand(
		newEnrollMintCommand(out),
		newEnrollListCommand(out),
		newEnrollRevokeCommand(out),
	)
	return cmd
}

// mintResult is everything a mint produced. The token appears here and only
// here: `enroll list` never shows it again, in any output mode.
type mintResult struct {
	Token          string            `json:"token"`
	TokenID        string            `json:"token_id"`
	Name           string            `json:"name"`
	Labels         map[string]string `json:"labels,omitempty"`
	Addresses      []string          `json:"addresses,omitempty"`
	ExpiresAt      string            `json:"expires_at"`
	TTL            string            `json:"ttl"`
	CAFingerprint  string            `json:"ca_fingerprint"`
	Control        string            `json:"control"`
	Listen         string            `json:"listen"`
	InstallCommand string            `json:"install_command"`
	InstallWindows string            `json:"install_command_windows"`
}

func newEnrollMintCommand(out io.Writer) *cobra.Command {
	var (
		flags     outputFlags
		name      string
		caDir     string
		tokenPath string
		control   string
		listen    string
		labels    map[string]string
		addresses []string
		ttl       time.Duration
	)
	cmd := &cobra.Command{
		Use:   "mint",
		Short: "Mint a single-use enrollment token for a new sandbox",
		Long: "mint generates a token, stores only its hash, and prints the token once —\n" +
			"assembled into the exact command to run on the target host.\n\n" +
			"The --address values are the endpoints the enrolling host is authorized to\n" +
			"be certified for. An enrolling host cannot widen this set, which is what\n" +
			"stops one token from yielding a certificate that impersonates another\n" +
			"fleet member.",
		Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			// The CA is loaded before anything is minted. A token without the
			// fingerprint that goes with it is unusable — `fleet-agent enroll`
			// refuses to run unpinned — so a mint that quietly omitted it would
			// hand the operator a secret they cannot spend and would have to
			// re-mint. Loading first also means a fleet with no CA is told to
			// run `ca init` instead of being handed a token for a fleet that
			// does not exist yet.
			dir, err := resolve(caDir, defaultCADir)
			if err != nil {
				return err
			}
			authority, err := loadCA(dir)
			if err != nil {
				return err
			}
			fingerprint := ca.FormatFingerprint(authority.Fingerprint())

			storePath, err := resolve(tokenPath, defaultTokenPath)
			if err != nil {
				return err
			}
			store, err := enroll.OpenTokenStore(storePath)
			if err != nil {
				return err
			}

			controlAddr, guessed, err := controlAddress(control)
			if err != nil {
				return err
			}
			// Both endpoints are checked before anything is minted. A token is
			// single-use and the store is what records it, so failing after the
			// mint costs the operator a token and a re-run to learn about a
			// typo in a flag.
			//
			// An empty host is allowed here and not for --control: this one
			// says which interfaces the agent binds, and ":8722" means all.
			if listen != "" {
				if err := checkEndpoint("--listen", listen, false); err != nil {
					return err
				}
			}

			token, rec, err := store.Mint(enroll.MintOptions{
				Name:      name,
				Labels:    labels,
				Addresses: addresses,
				TTL:       ttl,
			})
			if err != nil {
				return err
			}

			agentListen := listen
			if agentListen == "" {
				agentListen = listenFor(rec.Addresses)
			}
			result := mintResult{
				Token:         token,
				TokenID:       rec.ID,
				Name:          rec.Name,
				Labels:        rec.Labels,
				Addresses:     rec.Addresses,
				ExpiresAt:     formatTime(rec.ExpiresAt),
				TTL:           rec.ExpiresAt.Sub(rec.IssuedAt).String(),
				CAFingerprint: fingerprint,
				Control:       controlAddr,
				Listen:        agentListen,
			}
			result.InstallCommand = unixInstallCommand(result)
			result.InstallWindows = windowsInstallCommand(result)

			return flags.output(out).Emit(result, func(p *cli.Printer) {
				p.Printf("token:          %s\n", result.Token)
				p.Printf("token-id:       %s\n", result.TokenID)
				p.Printf("name:           %s\n", result.Name)
				p.Printf("expires:        %s (in %s)\n", result.ExpiresAt, result.TTL)
				if len(result.Addresses) > 0 {
					p.Printf("addresses:      %s\n", strings.Join(result.Addresses, ", "))
				}
				p.Printf("ca-fingerprint: %s\n", result.CAFingerprint)

				p.Printf("\nRun this on the host, as-is:\n\n%s\n", result.InstallCommand)
				p.Printf("\nWindows, in an elevated PowerShell:\n\n%s\n", result.InstallWindows)

				p.Printf("\nThis token is shown once and is redeemable once. Revoke it with\n")
				p.Printf("`fleetctl enroll revoke %s` if it does not reach the host.\n", result.TokenID)
				if guessed {
					p.Printf("\nNOTE: --control was not given, so the command above says %s,\n", result.Control)
					p.Printf("      this machine's hostname. Re-mint with --control HOST:PORT if the\n")
					p.Printf("      target host reaches this control plane by some other name.\n")
				}
				if len(result.Addresses) == 0 {
					// Say this at mint time rather than letting the agent fail
					// later: the leaf will carry only the sandbox name, so a
					// control plane dialling by address will reject it.
					p.Printf("\nNOTE: no --address was given, so the issued certificate will name only\n")
					p.Printf("      %q. Re-mint with --address HOST:PORT if the control plane\n", result.Name)
					p.Printf("      will dial this sandbox by address.\n")
				}
			})
		},
	}
	flags.register(cmd)
	cmd.Flags().StringVar(&name, "name", "", "sandbox name to reserve for this token")
	cmd.Flags().StringVar(&caDir, "ca-dir", "", "directory holding the CA, for the fingerprint the host must pin (default: <config dir>/ca)")
	cmd.Flags().StringVar(&tokenPath, "token-store", "", "path to the token store (default: <config dir>/enrollment-tokens.yaml)")
	cmd.Flags().StringVar(&control, "control", "", "host:port the enrolling host dials this control plane by (default: this machine's hostname on :"+defaultControlPort+")")
	cmd.Flags().StringVar(&listen, "listen", "", "address the agent will serve on (default: derived from --address, else "+defaultAgentListen+")")
	cmd.Flags().StringToStringVar(&labels, "label", nil, "operator metadata as key=value; repeatable")
	cmd.Flags().StringArrayVar(&addresses, "address", nil, "host:port this sandbox is authorized to be certified for; repeatable")
	cmd.Flags().DurationVar(&ttl, "ttl", enroll.DefaultTokenTTL, "how long the token stays redeemable")
	_ = cmd.MarkFlagRequired("name")
	return cmd
}

// controlAddress resolves the address the enrolling host will dial, and reports
// whether it had to be guessed.
//
// The guess is this machine's hostname, which is the same one `serve` puts into
// its certificate when no --advertise is given — so the generated command and
// the listener agree by construction rather than by the operator remembering to
// keep them in step.
func controlAddress(flagValue string) (addr string, guessed bool, err error) {
	if flagValue != "" {
		if err := checkEndpoint("--control", flagValue, true); err != nil {
			return "", false, err
		}
		return flagValue, false, nil
	}
	hostname, err := os.Hostname()
	if err != nil {
		return "", false, fmt.Errorf("determine this machine's hostname for the install command: %w (pass --control HOST:PORT)", err)
	}
	guess := net.JoinHostPort(hostname, defaultControlPort)
	if err := checkEndpoint("--control", guess, true); err != nil {
		return "", false, fmt.Errorf("this machine's hostname does not make a usable control address: %w", err)
	}
	return guess, true, nil
}

// checkEndpoint rejects a host:port that would not survive the trip into the
// generated install command.
//
// Quoting keeps a shell from *acting* on an odd value, and shellQuote does
// that. What quoting cannot do is stop a value beginning with "-" from being
// read as a flag by the installer it is handed to — `--control -x:9443` reaches
// install.sh as an option, not as an address — so that shape is refused here,
// where the operator is still in front of the command, rather than on a host
// they are about to walk away from. The numeric port is the same argument in
// milder form: net.SplitHostPort is happy with "workstation:https", and the
// agent that has to dial it is not.
func checkEndpoint(flag, value string, requireHost bool) error {
	if strings.HasPrefix(value, "-") {
		return fmt.Errorf("%s %q starts with '-', which the installer would read as a flag rather than an address", flag, value)
	}
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		return fmt.Errorf("%s %q is not host:port (e.g. workstation.internal:%s)", flag, value, defaultControlPort)
	}
	if strings.HasPrefix(host, "-") {
		return fmt.Errorf("%s %q names a host starting with '-', which the installer would read as a flag", flag, value)
	}
	if requireHost && host == "" {
		return fmt.Errorf("%s %q names no host; the enrolling machine has to have something to dial", flag, value)
	}
	if n, convErr := strconv.Atoi(port); convErr != nil || n < 1 || n > 65535 {
		return fmt.Errorf("%s %q does not name a port between 1 and 65535", flag, value)
	}
	return nil
}

// listenFor derives the agent's listen address from the endpoints the token
// authorizes. An operator who wrote `--address build-box.internal:9000` has
// already said which port the agent serves on; making them repeat it as
// --listen is the kind of edit "paste this" is supposed to remove.
func listenFor(addresses []string) string {
	for _, addr := range addresses {
		if _, port, err := net.SplitHostPort(addr); err == nil && port != "" {
			if n, convErr := strconv.Atoi(port); convErr == nil && n > 0 && n < 65536 {
				return net.JoinHostPort("0.0.0.0", port)
			}
		}
	}
	return defaultAgentListen
}

// unixInstallCommand assembles the whole install-and-enroll invocation, so the
// operator copies one block rather than splicing a token, an address and a
// fingerprint into an example from the docs.
func unixInstallCommand(r mintResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "  curl -fsSL %s \\\n", installScriptURL)
	fmt.Fprintf(&b, "    | sh -s -- --token %s \\\n", shellQuote(r.Token))
	fmt.Fprintf(&b, "        --control %s \\\n", shellQuote(r.Control))
	fmt.Fprintf(&b, "        --ca-fingerprint %s \\\n", shellQuote(r.CAFingerprint))
	fmt.Fprintf(&b, "        --listen %s", shellQuote(r.Listen))
	return b.String()
}

// windowsInstallCommand is the same thing for a Windows host.
func windowsInstallCommand(r mintResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "  $s = irm %s\n", installScriptURLWindows)
	fmt.Fprintf(&b, "  & ([scriptblock]::Create($s)) -Token %s `\n", powerShellQuote(r.Token))
	fmt.Fprintf(&b, "      -Control %s `\n", powerShellQuote(r.Control))
	fmt.Fprintf(&b, "      -CaFingerprint %s `\n", powerShellQuote(r.CAFingerprint))
	fmt.Fprintf(&b, "      -Listen %s", powerShellQuote(r.Listen))
	return b.String()
}

// shellQuote wraps a value in single quotes when it holds anything a shell
// would act on. The values here are a token, an address and a hex fingerprint,
// none of which normally needs it — but --control is operator input, and a
// command whose whole purpose is to be pasted must not be the place where that
// input becomes shell syntax.
func shellQuote(s string) string {
	if s != "" && !strings.ContainsFunc(s, isShellUnsafe) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// isShellUnsafe reports whether a rune needs quoting. The safe set is an
// allow list rather than a list of metacharacters: a token, an address and a
// hex fingerprint are all drawn from it, so anything outside is unexpected and
// quoting it costs nothing.
func isShellUnsafe(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		return false
	case strings.ContainsRune(".:-_/+=", r):
		return false
	default:
		return true
	}
}

// powerShellQuote is shellQuote for PowerShell, where a single-quoted string
// escapes an embedded quote by doubling it.
func powerShellQuote(s string) string {
	if s == shellQuote(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// tokenLine is one row of `enroll list`. It carries no token material: the
// record it is built from never held any, and the id is derived from the stored
// hash rather than from the token.
type tokenLine struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	State     string            `json:"state"`
	IssuedAt  string            `json:"issued_at"`
	ExpiresAt string            `json:"expires_at"`
	UsedAt    string            `json:"used_at,omitempty"`
	RevokedAt string            `json:"revoked_at,omitempty"`
	Addresses []string          `json:"addresses,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
}

// tokenListResult is the `enroll list` document.
type tokenListResult struct {
	Tokens []tokenLine `json:"tokens"`
}

func newEnrollListCommand(out io.Writer) *cobra.Command {
	var (
		flags     outputFlags
		tokenPath string
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List minted enrollment tokens and their state",
		Long: "list shows every token still held, with its id, state and expiry.\n\n" +
			"It never shows a token's value, in any output mode. The store keeps only a\n" +
			"hash, so there is nothing to show: a token exists in plaintext once, in the\n" +
			"output of `enroll mint`.",
		Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			storePath, err := resolve(tokenPath, defaultTokenPath)
			if err != nil {
				return err
			}
			store, err := enroll.OpenTokenStore(storePath)
			if err != nil {
				return err
			}
			records, err := store.List()
			if err != nil {
				return err
			}

			now := time.Now().UTC()
			result := tokenListResult{Tokens: make([]tokenLine, 0, len(records))}
			for _, rec := range records {
				result.Tokens = append(result.Tokens, tokenLine{
					ID:        rec.ID,
					Name:      rec.Name,
					State:     rec.State(now),
					IssuedAt:  formatTime(rec.IssuedAt),
					ExpiresAt: formatTime(rec.ExpiresAt),
					UsedAt:    formatTime(rec.UsedAt),
					RevokedAt: formatTime(rec.RevokedAt),
					Addresses: rec.Addresses,
					Labels:    rec.Labels,
				})
			}

			o := flags.output(out)
			return o.Emit(result, func(p *cli.Printer) {
				if len(result.Tokens) == 0 {
					p.Println("no enrollment tokens")
					return
				}
				rows := make([][]string, 0, len(result.Tokens))
				for _, tok := range result.Tokens {
					rows = append(rows, []string{
						tok.ID,
						dash(tok.Name),
						tok.State,
						tok.ExpiresAt,
						dash(strings.Join(tok.Addresses, ",")),
					})
				}
				if err := o.table([]string{"ID", "NAME", "STATE", "EXPIRES", "ADDRESSES"}, rows); err != nil {
					p.Printf("%v\n", err)
				}
			})
		},
	}
	flags.register(cmd)
	cmd.Flags().StringVar(&tokenPath, "token-store", "", "path to the token store (default: <config dir>/enrollment-tokens.yaml)")
	return cmd
}

// revokeResult is what a revocation did.
type revokeResult struct {
	ID        string `json:"id"`
	Name      string `json:"name,omitempty"`
	State     string `json:"state"`
	RevokedAt string `json:"revoked_at"`
}

func newEnrollRevokeCommand(out io.Writer) *cobra.Command {
	var (
		flags     outputFlags
		tokenPath string
	)
	cmd := &cobra.Command{
		Use:   "revoke <token-id>",
		Short: "Invalidate an unused enrollment token",
		Long: "revoke withdraws a token that has not been redeemed, by the id `enroll list`\n" +
			"prints. The token itself is not accepted here and could not be: the store\n" +
			"holds only a hash of it.\n\n" +
			"The record is marked rather than deleted, so a later attempt to use the\n" +
			"token is reported as revoked rather than as unrecognised.",
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			storePath, err := resolve(tokenPath, defaultTokenPath)
			if err != nil {
				return err
			}
			store, err := enroll.OpenTokenStore(storePath)
			if err != nil {
				return err
			}
			rec, err := store.Revoke(args[0])
			if err != nil {
				return err
			}

			return flags.output(out).Emit(revokeResult{
				ID:        rec.ID,
				Name:      rec.Name,
				State:     enroll.StateRevoked,
				RevokedAt: formatTime(rec.RevokedAt),
			}, func(p *cli.Printer) {
				p.Printf("revoked token %s", rec.ID)
				if rec.Name != "" {
					p.Printf(" (reserved %q)", rec.Name)
				}
				p.Printf("\nIt can no longer be redeemed. Mint another with `fleetctl enroll mint`.\n")
			})
		},
	}
	flags.register(cmd)
	cmd.Flags().StringVar(&tokenPath, "token-store", "", "path to the token store (default: <config dir>/enrollment-tokens.yaml)")
	return cmd
}
