package fleetctl

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/axelmierczuk/fleet-mcp/internal/cli"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/fleet-mcp/internal/registry"
	"github.com/axelmierczuk/fleet-mcp/internal/security/ca"
	"github.com/axelmierczuk/fleet-mcp/internal/security/enroll"
)

// serverCertTTL is how long the control plane's own serving certificate is
// valid. It is short relative to an agent leaf because re-issuing it costs
// nothing: the process holds the CA and mints a new one on the next start.
const serverCertTTL = 30 * 24 * time.Hour

func newServeCommand(out io.Writer) *cobra.Command {
	var (
		listen       string
		caDir        string
		tokenPath    string
		registryPath string
		advertise    []string
		leafTTL      time.Duration
	)
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Serve the enrollment endpoint for hosts joining the fleet",
		Long: "serve exposes EnrollmentService over server-authenticated TLS.\n\n" +
			"The listener presents a CA-signed leaf rather than the CA certificate\n" +
			"itself, so the key that underwrites every identity in the fleet is not\n" +
			"loaded into the one process unauthenticated hosts can reach.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			dir, err := resolve(caDir, defaultCADir)
			if err != nil {
				return err
			}
			authority, err := ca.Load(dir)
			if err != nil {
				return err
			}

			storePath, err := resolve(tokenPath, defaultTokenPath)
			if err != nil {
				return err
			}
			tokens, err := enroll.OpenTokenStore(storePath)
			if err != nil {
				return err
			}

			fleet, err := openRegistry(registryPath)
			if err != nil {
				return err
			}

			hosts, err := advertisedHosts(advertise, listen)
			if err != nil {
				return err
			}
			serverCert, err := authority.ServerCertificate(hosts, serverCertTTL)
			if err != nil {
				return err
			}

			svc := &enroll.Service{
				Tokens:  tokens,
				CA:      authority,
				Names:   fleet,
				Fleet:   fleetRecorder{registry: fleet},
				LeafTTL: leafTTL,
				Log:     slog.New(slog.NewTextHandler(out, &slog.HandlerOptions{Level: slog.LevelInfo})),
			}

			server := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
				Certificates: []tls.Certificate{serverCert},
				MinVersion:   tls.VersionTLS12,
			})))
			sandboxdv1.RegisterEnrollmentServiceServer(server, svc)

			lis, err := net.Listen("tcp", listen)
			if err != nil {
				return fmt.Errorf("listen on %s: %w", listen, err)
			}

			p := cli.NewPrinter(out)
			p.Printf("enrollment endpoint listening on %s\n", lis.Addr())
			p.Printf("serving certificate valid for: %v\n", hosts)
			p.Printf("ca-fingerprint: %s\n", ca.FormatFingerprint(authority.Fingerprint()))
			if err := p.Err(); err != nil {
				return err
			}

			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			go func() {
				<-ctx.Done()
				// GracefulStop lets an enrollment already in flight finish:
				// its token is marked used, so cutting the connection would
				// spend it for nothing.
				server.GracefulStop()
			}()

			if err := server.Serve(lis); err != nil {
				return fmt.Errorf("serve: %w", err)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&listen, "listen", ":9443", "address to serve the enrollment endpoint on")
	cmd.Flags().StringVar(&caDir, "ca-dir", "", "directory holding the CA (default: <config dir>/ca)")
	cmd.Flags().StringVar(&tokenPath, "token-store", "", "path to the token store (default: <config dir>/enrollment-tokens.yaml)")
	cmd.Flags().StringVar(&registryPath, "registry", "", "path to the fleet registry (default: <config dir>/registry.yaml)")
	cmd.Flags().StringArrayVar(&advertise, "advertise", nil, "hostname or IP enrolling agents dial this control plane by; repeatable")
	cmd.Flags().DurationVar(&leafTTL, "leaf-ttl", ca.DefaultLeafTTL, "validity period of the agent leaves this control plane issues")
	return cmd
}

// advertisedHosts resolves the names the control plane's serving certificate
// must cover. An explicit --advertise wins; otherwise the host from --listen is
// used, and a wildcard listen address falls back to the machine's hostname,
// which is what an operator most likely typed into the agent.
func advertisedHosts(advertise []string, listen string) ([]string, error) {
	if len(advertise) > 0 {
		return advertise, nil
	}
	host := listen
	if h, _, err := net.SplitHostPort(listen); err == nil {
		host = h
	}
	if host != "" && host != "0.0.0.0" && host != "::" {
		return []string{host}, nil
	}
	hostname, err := os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("determine hostname for the serving certificate: %w (pass --advertise to name it explicitly)", err)
	}
	return []string{hostname}, nil
}

// fleetRecorder adapts the registry to enroll.Recorder. It lives here, in the
// wiring, so internal/security/enroll keeps the CA as its only dependency.
type fleetRecorder struct {
	registry *registry.Registry
}

func (f fleetRecorder) Record(sb enroll.EnrolledSandbox) error {
	err := f.registry.Add(registry.Sandbox{
		Name:    sb.Name,
		Address: sb.Address,
		Labels:  sb.Labels,
		Platform: registry.Platform{
			OS:            sb.OS,
			Arch:          sb.Arch,
			KernelVersion: sb.KernelVersion,
			Hostname:      sb.Hostname,
			PathSeparator: sb.PathSeparator,
		},
		AgentVersion: sb.AgentVersion,
		EnrolledAt:   time.Now().UTC(),
	})
	if errors.Is(err, registry.ErrExists) {
		// Translate, so the service picks the next free name instead of
		// failing the enrollment. Losing this race is ordinary: the registry
		// add is what reserves a name, and the collision check that ran before
		// it cannot see a host that enrolled in between.
		return fmt.Errorf("%w: %s", enroll.ErrNameTaken, sb.Name)
	}
	return err
}

func newListCommand(out io.Writer) *cobra.Command {
	var registryPath string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List the sandboxes recorded in the fleet registry",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			fleet, err := openRegistry(registryPath)
			if err != nil {
				return err
			}
			sandboxes, err := fleet.List()
			if err != nil {
				return err
			}
			p := cli.NewPrinter(out)
			if len(sandboxes) == 0 {
				p.Println("no sandboxes enrolled")
				return p.Err()
			}

			tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
			table := cli.NewPrinter(tw)
			table.Println("NAME\tADDRESS\tPLATFORM\tAGENT\tENROLLED")
			for _, sb := range sandboxes {
				platform := sb.Platform.OS
				if sb.Platform.Arch != "" {
					platform += "/" + sb.Platform.Arch
				}
				if platform == "" {
					platform = "-"
				}
				agentVersion := sb.AgentVersion
				if agentVersion == "" {
					agentVersion = "-"
				}
				table.Printf("%s\t%s\t%s\t%s\t%s\n",
					sb.Name, sb.Address, platform, agentVersion, formatTime(sb.EnrolledAt))
			}
			if err := table.Err(); err != nil {
				return err
			}
			return tw.Flush()
		},
	}
	cmd.Flags().StringVar(&registryPath, "registry", "", "path to the fleet registry (default: <config dir>/registry.yaml)")
	return cmd
}
