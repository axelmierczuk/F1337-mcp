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
		Short: "Serve the enrollment endpoint for hosts joining the fleet — then stop it",
		Long: "serve exposes EnrollmentService over server-authenticated TLS.\n\n" +
			"Run it while you are enrolling hosts and stop it afterwards. It is the one\n" +
			"endpoint an unauthenticated caller can reach, and a fleet is enrolled in\n" +
			"minutes and runs for months — so an enrollment endpoint left listening is\n" +
			"attack surface that buys nothing for almost all of its uptime.\n\n" +
			"The listener presents a CA-signed leaf rather than the CA certificate\n" +
			"itself, so the key that underwrites every identity in the fleet is not\n" +
			"loaded into the one process unauthenticated hosts can reach.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			dir, err := resolve(caDir, defaultCADir)
			if err != nil {
				return err
			}
			authority, err := loadCA(dir)
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
			// Serve closes the listener itself, so this is normally a no-op —
			// but not every path from here reaches Serve. Returning because the
			// banner could not be written used to leave the socket open and the
			// port bound for as long as the process lived, which for the shell
			// that drives this through MainContext is until the operator quits.
			defer func() { _ = lis.Close() }()

			p := cli.NewPrinter(out)
			p.Printf("enrollment endpoint listening on %s\n", lis.Addr())
			p.Printf("serving certificate valid for: %v\n", hosts)
			p.Printf("ca-fingerprint: %s\n", ca.FormatFingerprint(authority.Fingerprint()))
			// Said here as well as in the docs and the help text, because this
			// is the only one of the three an operator is looking at while the
			// endpoint is actually up.
			p.Printf("\nStop this once your hosts have enrolled (Ctrl-C). It is the only endpoint\n")
			p.Printf("an unauthenticated caller can reach, and it is needed for minutes, not months.\n")
			if err := p.Err(); err != nil {
				return err
			}

			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			stopped := make(chan struct{})
			go func() {
				defer close(stopped)
				<-ctx.Done()
				// GracefulStop lets an enrollment already in flight finish:
				// its token is marked used, so cutting the connection would
				// spend it for nothing.
				server.GracefulStop()
			}()
			// stop() releases the signal handler and cancels ctx; waiting on
			// stopped means the goroutine it started is gone too. serve owns no
			// goroutine once it returns — which matters because MainContext
			// exists so a long-lived process can drive this, and a watcher that
			// outlives each invocation accumulates one per run.
			defer func() {
				stop()
				<-stopped
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
