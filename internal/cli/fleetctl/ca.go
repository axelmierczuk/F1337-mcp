package fleetctl

import (
	"crypto/ecdsa"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/axelmierczuk/fleet-mcp/internal/cli"
	"github.com/axelmierczuk/fleet-mcp/internal/fsutil"

	"github.com/axelmierczuk/fleet-mcp/internal/security/ca"
	"github.com/axelmierczuk/fleet-mcp/internal/security/enroll"
)

func newCACommand(out io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ca",
		Short: "Initialise the fleet CA, print its fingerprint, sign a CSR, or rotate it",
		RunE:  func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	cmd.AddCommand(
		newCAInitCommand(out),
		newCAFingerprintCommand(out),
		newCASignCommand(out),
		newCARotateCommand(out),
	)
	return cmd
}

// caInitResult is what `ca init` produced.
type caInitResult struct {
	Directory   string `json:"directory"`
	Fingerprint string `json:"ca_fingerprint"`
	NotAfter    string `json:"not_after"`
}

func newCAInitCommand(out io.Writer) *cobra.Command {
	var (
		flags outputFlags
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
			fingerprint := ca.FormatFingerprint(authority.Fingerprint())

			return flags.output(out).Emit(caInitResult{
				Directory:   caDir,
				Fingerprint: fingerprint,
				NotAfter:    formatTime(authority.Certificate().NotAfter),
			}, func(p *cli.Printer) {
				// The fingerprint is set apart rather than listed among the
				// other facts, because every subsequent enrollment needs it and
				// an operator who does not have it in front of them pins
				// nothing — which silently removes the protection the whole
				// design rests on. It costs four lines here and saves the fleet.
				p.Printf("CA initialised at %s\n\n", caDir)
				p.Println(fingerprintBanner(fingerprint))
				p.Printf("\nGive this fingerprint to every enrolling host as --ca-fingerprint.\n")
				p.Printf("Read it again at any time with `fleetctl ca fingerprint`.\n")
			})
		},
	}
	flags.register(cmd)
	cmd.Flags().StringVar(&dir, "ca-dir", "", "directory to hold the CA (default: <config dir>/ca)")
	cmd.Flags().BoolVar(&force, "force", false, "overwrite an existing CA, orphaning every certificate it issued")
	return cmd
}

// fingerprintBanner boxes a fingerprint so it survives a screenful of scrolling
// output and can be copied in one selection.
func fingerprintBanner(fingerprint string) string {
	const label = "  SHA256 Fingerprint="
	rule := "  " + repeat('=', len(label)+len(fingerprint))
	return rule + "\n" + label + fingerprint + "\n" + rule
}

func repeat(c byte, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = c
	}
	return string(b)
}

// caFingerprintResult is what `ca fingerprint` reports. The issuing CA is
// named on its own rather than as the first element of a list, because it is
// the one an enrolling host must pin: the others verify certificates that
// already exist and cannot certify a new host.
type caFingerprintResult struct {
	Fingerprint string   `json:"ca_fingerprint"`
	Subject     string   `json:"subject"`
	NotAfter    string   `json:"not_after"`
	Rotating    bool     `json:"rotating"`
	AlsoTrusted []string `json:"also_trusted,omitempty"`
	Staged      string   `json:"staged_fingerprint,omitempty"`
}

func newCAFingerprintCommand(out io.Writer) *cobra.Command {
	var (
		flags outputFlags
		dir   string
	)
	cmd := &cobra.Command{
		Use:   "fingerprint",
		Short: "Print the SHA-256 fingerprint of the CA certificate, for pinning",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			caDir, err := resolve(dir, defaultCADir)
			if err != nil {
				return err
			}
			authority, err := loadCA(caDir)
			if err != nil {
				return err
			}
			state, err := ca.Status(caDir)
			if err != nil {
				return err
			}

			result := caFingerprintResult{
				Fingerprint: ca.FormatFingerprint(authority.Fingerprint()),
				Subject:     authority.Certificate().Subject.CommonName,
				NotAfter:    formatTime(authority.Certificate().NotAfter),
				Rotating:    state.Overlapping(),
			}
			if state.Staged != nil {
				result.Staged = ca.FormatFingerprint(ca.Fingerprint(state.Staged))
			}
			for _, root := range authority.TrustedRoots()[1:] {
				result.AlsoTrusted = append(result.AlsoTrusted, ca.FormatFingerprint(ca.Fingerprint(root)))
			}

			return flags.output(out).Emit(result, func(p *cli.Printer) {
				p.Printf("SHA256 Fingerprint=%s\n", result.Fingerprint)
				if !result.Rotating {
					return
				}
				// Mid-rotation the bundle trusts more than one root, and which
				// of them an enrolling host must pin is not a detail to leave
				// implicit: only the issuer can certify a new host.
				p.Printf("\nA CA rotation is in progress. Pin the fingerprint above — it is the CA\n")
				p.Printf("that signs new certificates. These roots are also trusted, so certificates\n")
				p.Printf("already issued under them keep working:\n")
				for _, other := range result.AlsoTrusted {
					marker := ""
					if other == result.Staged {
						marker = "  (staged, not yet issuing)"
					}
					p.Printf("  %s%s\n", other, marker)
				}
			})
		},
	}
	flags.register(cmd)
	cmd.Flags().StringVar(&dir, "ca-dir", "", "directory holding the CA (default: <config dir>/ca)")
	return cmd
}

// newCASignCommand signs a CSR the operator supplies, which is how a leaf is
// rotated before expiry: the host generates a fresh key and CSR, the operator
// signs it, and no enrollment token is minted or spent. Tokens bootstrap an
// identity the fleet does not yet know about; renewing one it already knows
// should not need a fresh bootstrap secret.
//
// The control profile additionally generates the keypair here when no --csr is
// given, and only the control profile does. That leaf belongs to this
// workstation, so its key has nowhere else to be generated — and without this
// there was no command at all that produced control.crt, which is what
// fleet-mcp and `fleetctl list` present to every agent. An agent leaf is the
// opposite case: its key must never leave the host it identifies, so asking for
// one here is refused rather than quietly obliged.
func newCASignCommand(out io.Writer) *cobra.Command {
	var (
		flags     outputFlags
		dir       string
		csrPath   string
		subject   string
		profile   string
		outPath   string
		keyOut    string
		addresses []string
		ttl       time.Duration
	)
	cmd := &cobra.Command{
		Use:   "sign",
		Short: "Sign a CSR into a leaf certificate, for rotation without re-enrollment",
		Long: "sign issues a leaf under the fleet CA.\n\n" +
			"With --profile control and no --csr, it also generates the keypair and\n" +
			"writes control.crt and control.key into the config directory: that is the\n" +
			"identity fleet-mcp and `fleetctl list` present to agents, and it belongs\n" +
			"on this workstation. An agent leaf always needs a --csr, because the\n" +
			"host's private key must never leave the host.",
		Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			signProfile, err := parseProfile(profile)
			if err != nil {
				return err
			}
			if subject == "" {
				if signProfile != ca.ProfileControl {
					return fmt.Errorf("--subject is required: the common name for the issued leaf (the sandbox name, for an agent leaf)")
				}
				subject = defaultControlSubject
			}

			caDir, err := resolve(dir, defaultCADir)
			if err != nil {
				return err
			}
			authority, err := loadCA(caDir)
			if err != nil {
				return err
			}

			generatedKey, csrDER, err := signingRequest(csrPath, signProfile, subject)
			if err != nil {
				return err
			}

			dnsNames, ips := hostsToSANs(subject, addresses)
			if signProfile == ca.ProfileControl {
				// A control leaf is a client certificate, identified by its
				// subject; SANs on it would name hosts it never serves.
				dnsNames, ips = nil, nil
			}
			leaf, certPEM, err := authority.SignCSR(csrDER, ca.SignOptions{
				Profile:     signProfile,
				Subject:     subject,
				DNSNames:    dnsNames,
				IPAddresses: ips,
				TTL:         ttl,
			})
			if err != nil {
				return err
			}

			certPath, keyPath, err := signOutputPaths(outPath, keyOut, generatedKey != nil)
			if err != nil {
				return err
			}

			result := signResult{
				Subject:  subject,
				Profile:  profile,
				NotAfter: formatTime(leaf.NotAfter),
			}
			if certPath == "" {
				// Nowhere to write it: hand the certificate back on standard
				// output. Reachable only without a generated keypair, because
				// signOutputPaths gives a generated one a file — a private key
				// written to a terminal is a private key in a scrollback buffer.
				result.CertificatePEM = string(certPEM)
				return flags.output(out).Emit(result, func(p *cli.Printer) { p.Write(certPEM) })
			}

			if generatedKey != nil {
				keyPEM, err := enroll.MarshalKey(generatedKey)
				if err != nil {
					return err
				}
				if err := writeSecret(keyPath, keyPEM); err != nil {
					return err
				}
				result.Key = keyPath
			}
			if err := writeCertificate(certPath, certPEM); err != nil {
				return err
			}
			result.Certificate = certPath

			return flags.output(out).Emit(result, func(p *cli.Printer) {
				p.Printf("certificate: %s (expires %s)\n", certPath, formatTime(leaf.NotAfter))
				if result.Key != "" {
					p.Printf("private key: %s\n", result.Key)
				}
				p.Printf("subject:     %s (%s profile)\n", subject, profile)
			})
		},
	}
	flags.register(cmd)
	cmd.Flags().StringVar(&dir, "ca-dir", "", "directory holding the CA (default: <config dir>/ca)")
	cmd.Flags().StringVar(&csrPath, "csr", "", "path to a PEM- or DER-encoded certificate signing request (required except for --profile control)")
	cmd.Flags().StringVar(&subject, "subject", "", "common name for the issued leaf (a sandbox name, for an agent leaf)")
	cmd.Flags().StringVar(&profile, "profile", "agent", "certificate profile: agent (server auth) or control (client auth)")
	cmd.Flags().StringVar(&outPath, "out", "", "write the leaf here (default: standard output, or <config dir>/control.crt for a generated control leaf)")
	cmd.Flags().StringVar(&keyOut, "key-out", "", "write a generated private key here (default: <config dir>/control.key)")
	cmd.Flags().StringArrayVar(&addresses, "address", nil, "host:port the agent listens on; repeatable (agent profile only)")
	cmd.Flags().DurationVar(&ttl, "ttl", ca.DefaultLeafTTL, "how long the issued leaf is valid")
	return cmd
}

// signResult is what `ca sign` produced. CertificatePEM is filled in only when
// the leaf went to standard output rather than to a file, so a scripted caller
// gets the certificate from the same place either way.
type signResult struct {
	Certificate    string `json:"certificate,omitempty"`
	CertificatePEM string `json:"certificate_pem,omitempty"`
	Key            string `json:"private_key,omitempty"`
	Subject        string `json:"subject"`
	Profile        string `json:"profile"`
	NotAfter       string `json:"not_after"`
}

// defaultControlSubject is the common name a generated control leaf carries.
// The agent authorizes on the organizational unit, not this, so it is a label
// for a human reading an audit line — which is why it names the thing that
// presents it.
const defaultControlSubject = "fleet-mcp"

func parseProfile(name string) (ca.Profile, error) {
	switch name {
	case "agent":
		return ca.ProfileAgent, nil
	case "control":
		return ca.ProfileControl, nil
	default:
		return 0, fmt.Errorf("unknown profile %q: expected agent or control", name)
	}
}

// signingRequest returns the CSR to sign, generating a keypair for it when the
// operator gave no --csr and the profile allows it.
func signingRequest(csrPath string, profile ca.Profile, subject string) (*ecdsa.PrivateKey, []byte, error) {
	if csrPath != "" {
		csrBytes, err := readFile(csrPath)
		if err != nil {
			return nil, nil, err
		}
		csrDER, err := ca.DecodeCSR(csrBytes)
		if err != nil {
			return nil, nil, err
		}
		return nil, csrDER, nil
	}

	if profile != ca.ProfileControl {
		return nil, nil, fmt.Errorf("--csr is required for an agent leaf: the host generates its own keypair and sends only a CSR, so its private key never leaves it")
	}

	key, err := enroll.GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	// No SANs: a control leaf is a client certificate, identified by its
	// subject and its organizational unit.
	csrDER, err := enroll.BuildCSR(key, subject, nil, nil)
	if err != nil {
		return nil, nil, err
	}
	return key, csrDER, nil
}

// signOutputPaths decides where the leaf and any generated key are written.
// An empty certificate path means standard output, which a generated keypair
// rules out: the key would have nowhere to go.
func signOutputPaths(outPath, keyOut string, generated bool) (certPath, keyPath string, err error) {
	if !generated {
		if keyOut != "" {
			return "", "", fmt.Errorf("--key-out only applies when fleetctl generates the keypair; with --csr the key already exists on the host that made it")
		}
		return outPath, "", nil
	}

	certPath, keyPath = outPath, keyOut
	if certPath == "" {
		if certPath, err = defaultControlCertPath(); err != nil {
			return "", "", err
		}
	}
	if keyPath == "" {
		if keyPath, err = defaultControlKeyPath(); err != nil {
			return "", "", err
		}
	}
	return certPath, keyPath, nil
}

// caRotateResult is what one step of a rotation left behind.
type caRotateResult struct {
	Step        string   `json:"step"`
	Directory   string   `json:"directory"`
	Fingerprint string   `json:"ca_fingerprint"`
	Staged      string   `json:"staged_fingerprint,omitempty"`
	AlsoTrusted []string `json:"also_trusted,omitempty"`
	// Retired counts the roots this step dropped from the trust bundle, so a
	// `--retire` that had nothing to do is distinguishable from one that did.
	Retired int `json:"retired"`
}

func newCARotateCommand(out io.Writer) *cobra.Command {
	var (
		flags    outputFlags
		dir      string
		activate bool
		retire   bool
	)
	cmd := &cobra.Command{
		Use:   "rotate",
		Short: "Replace the fleet CA in three steps, without invalidating live certificates",
		Long: "rotate replaces the CA without a flag day. It is three commands, not one,\n" +
			"because the middle step is you copying a file to machines this tool cannot\n" +
			"reach:\n\n" +
			"  1. fleetctl ca rotate              generate the next CA and add it to the\n" +
			"                                     trust bundle. Nothing is signed under it\n" +
			"                                     yet, so nothing can break.\n" +
			"     -- distribute <ca-dir>/ca.crt to every agent and restart them --\n" +
			"  2. fleetctl ca rotate --activate   start signing under the new CA. Existing\n" +
			"                                     certificates keep verifying, because the\n" +
			"                                     old root is still trusted.\n" +
			"     -- re-issue every leaf: re-enroll hosts, or `ca sign` a fresh CSR --\n" +
			"  3. fleetctl ca rotate --retire     drop the old root. Anything still holding\n" +
			"                                     a certificate under it stops working now.\n\n" +
			"docs/security.md has the full procedure, including how to check that step 3\n" +
			"is safe to run.",
		Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			if activate && retire {
				return fmt.Errorf("--activate and --retire are separate steps of one rotation; run them one at a time")
			}
			caDir, err := resolve(dir, defaultCADir)
			if err != nil {
				return err
			}
			// Read the state before the step as well as after: `--retire` on a
			// CA that trusts one root already is a no-op, and afterwards it is
			// indistinguishable from a retirement that removed something.
			//
			// Status reads the trust bundle, so this also reports a directory
			// with no CA at all as such rather than as a rotation problem.
			before, err := ca.Status(caDir)
			if err != nil {
				return actionable(caDir, err)
			}
			// Stage and Retire load the CA themselves and cannot do their work
			// without a signing key that matches the bundle, so a directory
			// that does not load is reported here in the operator's terms.
			//
			// An activation with something staged to activate is the one
			// exception, and deliberately: it is what finishes an activation
			// interrupted between its two writes, and that state is precisely
			// the certificate-and-key mismatch Load refuses. Loading here put
			// the repair behind the damage — ca.Activate was taught to read the
			// bundle directly for exactly this reason, and this guard meant no
			// operator could reach it. An --activate with nothing staged has
			// nothing to repair, so it is described like any other command.
			if !activate || !before.Staging() {
				if _, err := loadCA(caDir); err != nil {
					return err
				}
			}

			step, state, err := runRotationStep(caDir, activate, retire)
			if err != nil {
				return err
			}

			result := caRotateResult{
				Step:        step,
				Directory:   caDir,
				Fingerprint: ca.FormatFingerprint(ca.Fingerprint(state.Issuer)),
				Retired:     retiredCount(step, before, state),
			}
			if state.Staged != nil {
				result.Staged = ca.FormatFingerprint(ca.Fingerprint(state.Staged))
			}
			for _, root := range state.Superseded {
				result.AlsoTrusted = append(result.AlsoTrusted, ca.FormatFingerprint(ca.Fingerprint(root)))
			}

			return flags.output(out).Emit(result, func(p *cli.Printer) {
				printRotationStep(p, caDir, step, result)
			})
		},
	}
	flags.register(cmd)
	cmd.Flags().StringVar(&dir, "ca-dir", "", "directory holding the CA (default: <config dir>/ca)")
	cmd.Flags().BoolVar(&activate, "activate", false, "step 2: start signing under the staged CA")
	cmd.Flags().BoolVar(&retire, "retire", false, "step 3: drop every root but the issuing CA — breaks anything still on an old certificate")
	return cmd
}

// retiredCount is how many roots this step dropped from the trust bundle.
//
// Only a retirement can drop one, so only a retirement is counted. Reading it
// as the difference in superseded roots across any step made `--json` report a
// negative retirement for `--activate`, which *gains* a superseded root: the
// outgoing issuer becomes one.
func retiredCount(step string, before, after ca.Rotation) int {
	if step != "retire" {
		return 0
	}
	return len(before.Superseded) - len(after.Superseded)
}

func runRotationStep(caDir string, activate, retire bool) (string, ca.Rotation, error) {
	switch {
	case activate:
		state, err := ca.Activate(caDir)
		return "activate", state, err
	case retire:
		state, err := ca.Retire(caDir)
		return "retire", state, err
	default:
		state, err := ca.Stage(caDir)
		return "stage", state, err
	}
}

// printRotationStep says what just happened and what the operator must do
// before the next step. A rotation is a sequence an operator runs across days,
// and the command that just ran is the only thing that knows where in it they
// are.
func printRotationStep(p *cli.Printer, caDir, step string, result caRotateResult) {
	switch step {
	case "stage":
		p.Printf("Staged the next fleet CA. It is trusted; it is not yet issuing.\n\n")
		p.Println(fingerprintBanner(result.Staged))
		p.Printf("\nThe CA still signing new certificates is %s\n\n", result.Fingerprint)
		p.Printf("Next, before `ca rotate --activate`:\n")
		p.Printf("  1. Copy %s to every agent, over the file its\n", caDirFile(caDir))
		p.Printf("     config names as tls.ca_bundle, and restart the agent.\n")
		p.Printf("  2. Restart fleet-mcp, so it reloads the bundle too.\n\n")
		p.Printf("An agent that has not been given the new bundle will reject this control\n")
		p.Printf("plane the moment you activate. Do not skip step 1.\n")
	case "activate":
		p.Printf("The new fleet CA is now issuing.\n\n")
		p.Println(fingerprintBanner(result.Fingerprint))
		p.Printf("\nHand this fingerprint to every host enrolling from now on; the old one no\n")
		p.Printf("longer names the CA that signs.\n\n")
		p.Printf("Certificates issued by the previous CA still verify, so the fleet keeps\n")
		p.Printf("working. Re-issue them at your own pace:\n")
		p.Printf("  - re-enroll a host, or\n")
		p.Printf("  - `fleetctl ca sign --csr <fresh CSR> --subject <name>` on the host's CSR.\n")
		p.Printf("  - `fleetctl ca sign --profile control` for this workstation's own leaf.\n\n")
		p.Printf("Run `fleetctl ca rotate --retire` only once nothing holds a certificate from\n")
		p.Printf("the old CA. Nothing here can tell you that: a leaf's issuer lives on the host\n")
		p.Printf("that holds it, not in this registry, so keep track of the re-issues yourself.\n")
		p.Printf("docs/security.md has the order that keeps step 3 recoverable.\n")
	case "retire":
		if result.Retired == 0 {
			p.Printf("Nothing to retire: %s is already the only trusted root.\n", result.Fingerprint)
			return
		}
		p.Printf("Retired %d root(s). Only the issuing CA is trusted now.\n\n", result.Retired)
		p.Println(fingerprintBanner(result.Fingerprint))
		p.Printf("\nDistribute %s once more, so agents stop trusting\n", caDirFile(caDir))
		p.Printf("the retired root as well.\n")
	}
}

func caDirFile(caDir string) string { return filepath.Join(caDir, "ca.crt") }

// writeSecret writes private key material at 0600, replacing whatever was
// there.
//
// It goes through fsutil.WriteAtomic rather than os.WriteFile because
// os.WriteFile applies its mode only when it *creates* the file: re-issuing
// over a control.key that something had left group- or world-readable — a
// restored backup, an rsync without -p — wrote the new key straight into the
// old permissions and reported success. WriteAtomic creates a fresh 0600 file
// beside the destination and renames it over, so the mode is the one asked for
// whatever was there before, and the bytes never exist at any other mode or
// through any path an attacker could have pre-created.
func writeSecret(path string, data []byte) error {
	if err := fsutil.WriteAtomic(path, data, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// writeCertificate writes an issued leaf at 0644, replacing whatever was there.
//
// Through the same primitive as the key beside it, and for the second half of
// the same reason. `ca sign --profile control` replaces control.crt and
// control.key together, and fleet-mcp and `fleetctl list` read them together as
// a pair: os.WriteFile truncates the certificate before it writes, so a control
// plane starting inside that window read an empty control.crt and refused to
// run. It also applies its mode only on create, so the leaf inherited whatever
// mode the file it replaced happened to have.
func writeCertificate(path string, data []byte) error {
	if err := fsutil.WriteAtomic(path, data, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
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
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
