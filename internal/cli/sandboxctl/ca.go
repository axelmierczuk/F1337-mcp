package sandboxctl

import (
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/axelmierczuk/fleet-mcp/internal/cli"

	"github.com/axelmierczuk/fleet-mcp/internal/security/ca"
)

func newCACommand(out io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ca",
		Short: "Initialise the fleet CA, print its fingerprint, or sign a CSR",
		RunE:  func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	cmd.AddCommand(newCAInitCommand(out), newCAFingerprintCommand(out), newCASignCommand(out))
	return cmd
}

func newCAInitCommand(out io.Writer) *cobra.Command {
	var (
		dir   string
		force bool
	)
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Generate the fleet certificate authority",
		Long: "init generates an ECDSA P-256 CA keypair and self-signed certificate.\n" +
			"It refuses to overwrite an existing CA without --force, because replacing\n" +
			"one orphans every certificate it ever issued.",
		Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			caDir, err := resolve(dir, defaultCADir)
			if err != nil {
				return err
			}
			authority, err := ca.Init(caDir, force)
			if err != nil {
				return err
			}
			p := cli.NewPrinter(out)
			p.Printf("CA initialised at %s\n", caDir)
			p.Printf("SHA256 Fingerprint=%s\n\n", ca.FormatFingerprint(authority.Fingerprint()))
			p.Printf("Give this fingerprint to each enrolling host as --ca-fingerprint.\n")
			return p.Err()
		},
	}
	cmd.Flags().StringVar(&dir, "ca-dir", "", "directory to hold the CA (default: <config dir>/ca)")
	cmd.Flags().BoolVar(&force, "force", false, "overwrite an existing CA, orphaning every certificate it issued")
	return cmd
}

func newCAFingerprintCommand(out io.Writer) *cobra.Command {
	var dir string
	cmd := &cobra.Command{
		Use:   "fingerprint",
		Short: "Print the SHA-256 fingerprint of the CA certificate, for pinning",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			caDir, err := resolve(dir, defaultCADir)
			if err != nil {
				return err
			}
			authority, err := ca.Load(caDir)
			if err != nil {
				return err
			}
			p := cli.NewPrinter(out)
			p.Printf("SHA256 Fingerprint=%s\n", ca.FormatFingerprint(authority.Fingerprint()))
			return p.Err()
		},
	}
	cmd.Flags().StringVar(&dir, "ca-dir", "", "directory holding the CA (default: <config dir>/ca)")
	return cmd
}

// newCASignCommand signs a CSR the operator supplies, which is how a leaf is
// rotated before expiry: the host generates a fresh key and CSR, the operator
// signs it, and no enrollment token is minted or spent. Tokens bootstrap an
// identity the fleet does not yet know about; renewing one it already knows
// should not need a fresh bootstrap secret.
func newCASignCommand(out io.Writer) *cobra.Command {
	var (
		dir       string
		csrPath   string
		subject   string
		profile   string
		outPath   string
		addresses []string
		ttl       time.Duration
	)
	cmd := &cobra.Command{
		Use:   "sign",
		Short: "Sign a CSR into a leaf certificate, for rotation without re-enrollment",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			var signProfile ca.Profile
			switch profile {
			case "agent":
				signProfile = ca.ProfileAgent
			case "control":
				signProfile = ca.ProfileControl
			default:
				return fmt.Errorf("unknown profile %q: expected agent or control", profile)
			}

			caDir, err := resolve(dir, defaultCADir)
			if err != nil {
				return err
			}
			authority, err := ca.Load(caDir)
			if err != nil {
				return err
			}

			csrBytes, err := readFile(csrPath)
			if err != nil {
				return err
			}
			csrDER, err := ca.DecodeCSR(csrBytes)
			if err != nil {
				return err
			}

			dnsNames, ips := hostsToSANs(subject, addresses)
			if signProfile == ca.ProfileControl {
				// A control leaf is a client certificate, identified by its
				// subject; SANs on it would name hosts it never serves.
				dnsNames, ips = nil, nil
			}
			_, certPEM, err := authority.SignCSR(csrDER, ca.SignOptions{
				Profile:     signProfile,
				Subject:     subject,
				DNSNames:    dnsNames,
				IPAddresses: ips,
				TTL:         ttl,
			})
			if err != nil {
				return err
			}

			if outPath == "" {
				p := cli.NewPrinter(out)
				p.Write(certPEM)
				return p.Err()
			}
			if err := os.WriteFile(outPath, certPEM, 0o644); err != nil { //nolint:gosec // a certificate is public by design
				return fmt.Errorf("write %s: %w", outPath, err)
			}
			p := cli.NewPrinter(out)
			p.Printf("wrote %s (valid for %s)\n", outPath, ttl)
			return p.Err()
		},
	}
	cmd.Flags().StringVar(&dir, "ca-dir", "", "directory holding the CA (default: <config dir>/ca)")
	cmd.Flags().StringVar(&csrPath, "csr", "", "path to a PEM- or DER-encoded certificate signing request")
	cmd.Flags().StringVar(&subject, "subject", "", "common name for the issued leaf (a sandbox name, for an agent leaf)")
	cmd.Flags().StringVar(&profile, "profile", "agent", "certificate profile: agent (server auth) or control (client auth)")
	cmd.Flags().StringVar(&outPath, "out", "", "write the leaf here instead of standard output")
	cmd.Flags().StringArrayVar(&addresses, "address", nil, "host:port the agent listens on; repeatable (agent profile only)")
	cmd.Flags().DurationVar(&ttl, "ttl", ca.DefaultLeafTTL, "how long the issued leaf is valid")
	_ = cmd.MarkFlagRequired("csr")
	_ = cmd.MarkFlagRequired("subject")
	return cmd
}

// hostsToSANs turns the subject and the operator-supplied addresses into the
// SAN set for an agent leaf.
func hostsToSANs(subject string, addresses []string) (dnsNames []string, ips []net.IP) {
	hosts := append([]string{subject}, addresses...)
	seen := map[string]bool{}
	for _, entry := range hosts {
		host := entry
		if h, _, err := net.SplitHostPort(entry); err == nil {
			host = h
		}
		if host == "" || seen[host] {
			continue
		}
		seen[host] = true
		if ip := net.ParseIP(host); ip != nil {
			ips = append(ips, ip)
			continue
		}
		dnsNames = append(dnsNames, host)
	}
	return dnsNames, ips
}

// formatTime renders a timestamp the way every command in this CLI prints one,
// so an operator comparing two outputs is comparing the same shape.
func formatTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}
