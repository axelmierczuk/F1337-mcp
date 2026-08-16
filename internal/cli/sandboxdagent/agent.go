// Package sandboxdagent implements the sandboxd-agent CLI. For milestone M0
// that is the enroll command: the one-shot exchange that turns a bare host
// into a fleet member holding its own certificate.
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
	"gopkg.in/yaml.v3"

	sandboxdv1 "github.com/axelmierczuk/sandboxd-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/sandboxd-mcp/internal/cli"
	"github.com/axelmierczuk/sandboxd-mcp/internal/fsutil"
	"github.com/axelmierczuk/sandboxd-mcp/internal/registry"
	"github.com/axelmierczuk/sandboxd-mcp/internal/security/ca"
	"github.com/axelmierczuk/sandboxd-mcp/internal/security/enroll"
	"github.com/axelmierczuk/sandboxd-mcp/internal/version"
)

// enrollTimeout bounds the whole exchange. Enrollment is one round trip
// against a control plane the operator just named; if it has not completed in
// this long, something is wrong that waiting will not fix.
const enrollTimeout = 30 * time.Second

// Config is the agent's on-disk configuration, written by enroll and read by
// the daemon (milestone M1).
type Config struct {
	Name       string   `yaml:"name"`
	Listen     string   `yaml:"listen"`
	CertFile   string   `yaml:"cert_file"`
	KeyFile    string   `yaml:"key_file"`
	CAFile     string   `yaml:"ca_file"`
	EnrolledAt string   `yaml:"enrolled_at"`
	Addresses  []string `yaml:"addresses,omitempty"`
}

// Main runs sandboxd-agent and returns the process exit code.
func Main(args []string, out io.Writer) int {
	root := NewRootCommand(out)
	root.SetArgs(args)
	if err := root.Execute(); err != nil {
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
	root.AddCommand(newEnrollCommand(out))
	return root
}

func newEnrollCommand(out io.Writer) *cobra.Command {
	var (
		server      string
		token       string
		fingerprint string
		name        string
		listen      string
		dir         string
		addresses   []string
	)
	cmd := &cobra.Command{
		Use:   "enroll",
		Short: "Join a fleet: generate a keypair, redeem a token, and write the agent config",
		Long: "enroll generates this host's keypair locally and sends only a CSR, so the\n" +
			"private key never leaves the machine. The control plane's certificate is\n" +
			"verified against --ca-fingerprint during the TLS handshake, before the\n" +
			"token is transmitted.",
		Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			return runEnroll(out, server, token, fingerprint, name, listen, dir, addresses)
		},
	}
	cmd.Flags().StringVar(&server, "server", "", "control plane's enrollment endpoint, as host:port")
	cmd.Flags().StringVar(&token, "token", "", "single-use enrollment token from `sandboxctl enroll mint`")
	cmd.Flags().StringVar(&fingerprint, "ca-fingerprint", "", "SHA-256 fingerprint of the fleet CA, from `sandboxctl ca fingerprint`")
	cmd.Flags().StringVar(&name, "name", "", "requested sandbox name; only for a token that reserved none (default: the token's name)")
	cmd.Flags().StringVar(&listen, "listen", ":9443", "address this agent will serve on once enrolled")
	cmd.Flags().StringVar(&dir, "dir", "", "directory to write the certificate, key, and config into (default: <config dir>/agent)")
	cmd.Flags().StringArrayVar(&addresses, "address", nil, "host:port the control plane will dial this agent by; repeatable")
	_ = cmd.MarkFlagRequired("server")
	_ = cmd.MarkFlagRequired("token")
	return cmd
}

func runEnroll(out io.Writer, server, token, fingerprint, name, listen, dir string, addresses []string) error {
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

	cfg := Config{
		Name:       resp.GetAssignedName(),
		Listen:     listen,
		CertFile:   certPath,
		KeyFile:    keyPath,
		CAFile:     caPath,
		EnrolledAt: time.Now().UTC().Format(time.RFC3339),
		Addresses:  addresses,
	}
	cfgData, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("encode agent config: %w", err)
	}
	if err := fsutil.WriteAtomic(configPath, cfgData, 0o600); err != nil {
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
	return p.Err()
}

// resolveAgentDir returns where the agent's certificate, key, and config
// live: the operator's --dir if given, else an "agent" subdirectory of the
// same config directory the rest of sandboxd resolves.
func resolveAgentDir(flagValue string) (string, error) {
	if flagValue != "" {
		return flagValue, nil
	}
	dir, err := registry.ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "agent"), nil
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
