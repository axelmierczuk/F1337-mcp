// Package sandboxdagent implements the sandboxd-agent CLI: enrollment, the
// daemon itself, and registration with the platform's service manager.
package sandboxdagent

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/spf13/cobra"

	sandboxdv1 "github.com/axelmierczuk/sandboxd-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/sandboxd-mcp/internal/agent"
	"github.com/axelmierczuk/sandboxd-mcp/internal/cli"
	"github.com/axelmierczuk/sandboxd-mcp/internal/fsutil"
	"github.com/axelmierczuk/sandboxd-mcp/internal/security/ca"
	"github.com/axelmierczuk/sandboxd-mcp/internal/security/enroll"
	"github.com/axelmierczuk/sandboxd-mcp/internal/version"
)

// enrollTimeout bounds the whole exchange. Enrollment is one round trip
// against a control plane the operator just named; if it has not completed in
// this long, something is wrong that waiting will not fix.
const enrollTimeout = 30 * time.Second

// Main runs sandboxd-agent and returns the process exit code.
func Main(args []string, out io.Writer) int {
	return MainContext(context.Background(), args, out)
}

// MainContext is Main with a cancellable context.
//
// serve is a long-running command, and cancelling the context is how a caller
// that is not a signal — a test, or an embedding process — stops it. The
// daemon derives its own signal handling from this context, so the two paths
// converge rather than competing.
func MainContext(ctx context.Context, args []string, out io.Writer) int {
	root := NewRootCommand(out)
	root.SetArgs(args)
	if err := root.ExecuteContext(ctx); err != nil {
		return 1
	}
	return 0
}

// NewRootCommand builds the command tree, writing all output to out.
func NewRootCommand(out io.Writer) *cobra.Command {
	root := &cobra.Command{
		Use:               "sandboxd-agent",
		Short:             "Daemon that runs on each sandbox host",
		SilenceUsage:      true,
		DisableAutoGenTag: true,
		RunE:              func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	root.SetOut(out)
	root.SetErr(os.Stderr)
	root.AddCommand(
		newEnrollCommand(out),
		newServeCommand(),
		newServiceCommand(out),
		newVersionCommand(out),
	)
	return root
}

func newVersionCommand(out io.Writer) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the agent version",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			p := cli.NewPrinter(out)
			p.Printf("sandboxd-agent %s\n", version.String())
			return p.Err()
		},
	}
}

// enrollFlags is the enroll command's inputs, gathered into a struct because
// there are now more of them than a positional call can carry legibly.
type enrollFlags struct {
	server      string
	control     string
	token       string
	fingerprint string
	name        string
	listen      string
	dir         string
	addresses   []string
	roots       []string
}

func newEnrollCommand(out io.Writer) *cobra.Command {
	var f enrollFlags
	cmd := &cobra.Command{
		Use:   "enroll",
		Short: "Join a fleet: generate a keypair, redeem a token, and write the agent config",
		Long: "enroll generates this host's keypair locally and sends only a CSR, so the\n" +
			"private key never leaves the machine. The control plane's certificate is\n" +
			"verified against --ca-fingerprint during the TLS handshake, before the\n" +
			"token is transmitted.\n\n" +
			"It then writes agent.yaml beside the issued certificate. --root fills in\n" +
			"allowed_roots, which is enforced only when exec.enabled is false: a caller\n" +
			"that can run commands reaches any path without FileService.",
		Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error { return runEnroll(out, f) },
	}
	cmd.Flags().StringVar(&f.control, "control", "", "control plane's enrollment endpoint, as host:port")
	cmd.Flags().StringVar(&f.server, "server", "", "alias for --control")
	cmd.Flags().StringVar(&f.token, "token", "", "single-use enrollment token from `sandboxctl enroll mint`")
	cmd.Flags().StringVar(&f.fingerprint, "ca-fingerprint", "", "SHA-256 fingerprint of the fleet CA, from `sandboxctl ca fingerprint`")
	cmd.Flags().StringVar(&f.name, "name", "", "requested sandbox name; only for a token that reserved none (default: the token's name)")
	cmd.Flags().StringVar(&f.listen, "listen", agent.DefaultListen, "address this agent will serve on once enrolled")
	cmd.Flags().StringVar(&f.dir, "dir", "", "directory to write the certificate, key, and config into (default: the system config directory when elevated, else <config dir>/agent)")
	cmd.Flags().StringArrayVar(&f.addresses, "address", nil, "host:port the control plane will dial this agent by; repeatable")
	cmd.Flags().StringArrayVar(&f.roots, "root", nil, "absolute path the agent may read and write under; repeatable. Enforced only when exec.enabled is false")
	_ = cmd.MarkFlagRequired("token")
	return cmd
}

func runEnroll(out io.Writer, f enrollFlags) error {
	server, token, fingerprint := f.control, f.token, f.fingerprint
	if server == "" {
		server = f.server
	}
	if server == "" {
		return fmt.Errorf("--control is required: the control plane's enrollment endpoint, as host:port")
	}
	name, listen, dir, addresses := f.name, f.listen, f.dir, f.addresses

	if fingerprint == "" {
		// Refuse rather than default to unpinned. Without the pin, anything
		// that can answer on the network collects the token, and the token is
		// the only thing standing between an attacker and a fleet identity.
		return fmt.Errorf("--ca-fingerprint is required; get it from `sandboxctl ca fingerprint`")
	}
	pinned, err := ca.ParseFingerprint(fingerprint)
	if err != nil {
		return err
	}

	// --name is sent only when the operator gave one. The token normally
	// reserves the sandbox's name, and a host that fills the field in from its
	// own hostname is asking the control plane to enroll it as something other
	// than what the token authorizes — which the control plane refuses.
	requestedName := name

	agentDir, err := resolveAgentDir(dir)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(agentDir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", agentDir, err)
	}
	stateDir, logDir := resolveRuntimeDirs(agentDir, dir)

	// The keypair is generated here and stays here. Only the CSR crosses the
	// network, so neither a compromised control plane nor a leaked token can
	// produce this host's private key.
	key, err := enroll.GenerateKey()
	if err != nil {
		return err
	}
	dnsNames, ips := splitAddresses(addresses)
	csrDER, err := enroll.BuildCSR(key, requestedName, dnsNames, ips)
	if err != nil {
		return err
	}

	cc, err := enroll.Dial(enroll.DialOptions{Address: server, CAFingerprint: pinned})
	if err != nil {
		return err
	}
	defer func() { _ = cc.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), enrollTimeout)
	defer cancel()

	resp, err := sandboxdv1.NewEnrollmentServiceClient(cc).Enroll(ctx, &sandboxdv1.EnrollRequest{
		Token:           token,
		CsrDer:          csrDER,
		RequestedName:   requestedName,
		Platform:        localPlatform(),
		ListenAddresses: addresses,
		AgentVersion:    version.String(),
	})
	if err != nil {
		return fmt.Errorf("enroll against %s: %w", server, err)
	}

	certPath := filepath.Join(agentDir, "agent.crt")
	keyPath := filepath.Join(agentDir, "agent.key")
	caPath := filepath.Join(agentDir, "ca.crt")
	configPath := filepath.Join(agentDir, "agent.yaml")

	keyPEM, err := enroll.MarshalKey(key)
	if err != nil {
		return err
	}
	if err := fsutil.WriteAtomic(keyPath, keyPEM, 0o600); err != nil {
		return err
	}
	if err := fsutil.WriteAtomic(certPath, resp.GetCertificatePem(), 0o644); err != nil {
		return err
	}
	if err := fsutil.WriteAtomic(caPath, resp.GetCaBundlePem(), 0o644); err != nil {
		return err
	}

	cfg := &agent.Config{
		Name:   resp.GetAssignedName(),
		Listen: listen,
		TLS: agent.TLSConfig{
			Certificate:     certPath,
			PrivateKey:      keyPath,
			CABundle:        caPath,
			RequireClientOU: ca.ProfileControl.OrganizationalUnit(),
		},
		AllowedRoots: cleanRoots(f.roots),
		StateDir:     stateDir,
		Audit:        agent.AuditConfig{Path: filepath.Join(logDir, "audit.jsonl"), Enabled: true},
		EnrolledAt:   time.Now().UTC().Format(time.RFC3339),
		Addresses:    addresses,
	}
	if err := cfg.Save(configPath); err != nil {
		return err
	}

	p := cli.NewPrinter(out)
	p.Printf("enrolled as %q\n", resp.GetAssignedName())
	if requestedName != "" && resp.GetAssignedName() != requestedName {
		// The control plane resolves collisions rather than refusing, so say
		// plainly that the name is not the one that was asked for.
		p.Printf("note: requested %q, but that name was taken\n", requestedName)
	}
	p.Printf("certificate: %s (expires %s)\n", certPath, resp.GetNotAfter().AsTime().Format(time.RFC3339))
	p.Printf("config:      %s\n", configPath)
	if err := summarizeLeaf(p, resp.GetCertificatePem()); err != nil {
		return err
	}
	// allowed_roots is only a boundary on an agent with exec disabled, and
	// enroll writes the default config, which has exec on. Saying "the roots
	// confine this agent" here would be the first place the false confidence
	// gets planted.
	if len(cfg.AllowedRoots) > 0 {
		p.Printf("roots:       %v\n", cfg.AllowedRoots)
	}
	p.Println("NOTE: exec is enabled, so allowed_roots is not enforced: a caller runs")
	p.Println("      [\"sh\",\"-c\",\"...\"] and reaches any path this account can. Set")
	p.Println("      exec.enabled: false in the config to make the roots a real jail.")
	return p.Err()
}

// resolveAgentDir returns where the agent's certificate, key, and config live.
//
// With --dir, that. Without it, an elevated enrollment writes to the
// machine-wide location, because the service installed straight afterwards
// runs as a dedicated account that cannot read root's home directory — an
// unelevated one writes to the operator's own config directory, which is the
// only place it can.
func resolveAgentDir(flagValue string) (string, error) {
	if flagValue != "" {
		return flagValue, nil
	}
	if isElevated() {
		return agent.SystemConfigDir(), nil
	}
	return agent.UserConfigDir()
}

// resolveRuntimeDirs returns where process state and logs belong for an
// enrollment written to agentDir. A machine-wide install uses the platform's
// system locations; anything else keeps them beside the config, where the
// enrolling user can actually write.
func resolveRuntimeDirs(agentDir, dirFlag string) (stateDir, logDir string) {
	if dirFlag == "" && isElevated() {
		return agent.DefaultStateDir(), agent.DefaultLogDir()
	}
	return filepath.Join(agentDir, "state"), filepath.Join(agentDir, "logs")
}

// cleanRoots normalises --root values to absolute, cleaned paths and drops
// empties, so allowed_roots is written in the form the jail compares against.
func cleanRoots(roots []string) []string {
	var out []string
	for _, root := range roots {
		if root == "" {
			continue
		}
		abs, err := filepath.Abs(root)
		if err != nil {
			abs = filepath.Clean(root)
		}
		out = append(out, abs)
	}
	return out
}

// splitAddresses separates host:port strings into the DNS and IP names the
// CSR requests. The control plane decides which of them the leaf actually
// carries; asking is not receiving.
func splitAddresses(addrs []string) (dnsNames []string, ips []net.IP) {
	for _, addr := range addrs {
		host := addr
		if h, _, err := net.SplitHostPort(addr); err == nil {
			host = h
		}
		if host == "" || host == "0.0.0.0" || host == "::" {
			continue
		}
		if ip := net.ParseIP(host); ip != nil {
			ips = append(ips, ip)
			continue
		}
		dnsNames = append(dnsNames, host)
	}
	return dnsNames, ips
}

func localPlatform() *sandboxdv1.Platform {
	hostname, _ := os.Hostname()
	return &sandboxdv1.Platform{
		Os:            runtime.GOOS,
		Arch:          runtime.GOARCH,
		Hostname:      hostname,
		PathSeparator: string(filepath.Separator),
	}
}

// summarizeLeaf prints the names the issued certificate is actually valid
// for. The control plane may authorize fewer than were requested, and finding
// that out now beats finding it out from a handshake failure later.
func summarizeLeaf(p *cli.Printer, certPEM []byte) error {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return fmt.Errorf("control plane returned a certificate that is not PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse issued certificate: %w", err)
	}
	names := append([]string(nil), leaf.DNSNames...)
	for _, ip := range leaf.IPAddresses {
		names = append(names, ip.String())
	}
	p.Printf("valid for:   %v\n", names)
	return nil
}
