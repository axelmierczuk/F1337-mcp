// Package fleetmcp implements the fleet-mcp CLI: the MCP server an
// agent CLI launches over stdio.
//
// Only `serve` writes to the protocol stream, and it writes nothing else to
// stdout. Help and version output go to the writer the caller supplies —
// which is stdout for an interactive invocation, where no JSON-RPC session
// exists to corrupt.
package fleetmcp

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/axelmierczuk/fleet-mcp/internal/mcpserver"
	"github.com/axelmierczuk/fleet-mcp/internal/registry"
)

// Main runs fleet-mcp and returns the process exit code.
func Main(args []string, out io.Writer) int {
	root := NewRootCommand(out)
	root.SetArgs(args)
	if err := root.Execute(); err != nil {
		return 1
	}
	return 0
}

// NewRootCommand builds the command tree, writing non-protocol output to out.
func NewRootCommand(out io.Writer) *cobra.Command {
	root := &cobra.Command{
		Use:   "fleet-mcp",
		Short: "MCP server exposing a fleet of sandbox machines",
		Long: "fleet-mcp is the MCP server an agent CLI launches over stdio. It owns\n" +
			"the fleet registry and the current selection, and turns MCP tool calls into\n" +
			"gRPC calls against fleet-agent instances.",
		SilenceUsage:      true,
		DisableAutoGenTag: true,
		RunE:              func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	root.SetOut(out)
	root.SetErr(os.Stderr)
	root.AddCommand(newServeCommand())
	return root
}

func newServeCommand() *cobra.Command {
	var (
		configDir    string
		registryPath string
		caCert       string
		cert         string
		key          string
		logLevel     string
	)
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Serve MCP over stdio",
		Long: "serve speaks newline-delimited JSON-RPC on stdin and stdout, and exits when\n" +
			"stdin closes. All logging goes to stderr: stdout carries the protocol stream\n" +
			"and nothing else.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			level, err := parseLogLevel(logLevel)
			if err != nil {
				return err
			}
			dir, err := resolveConfigDir(configDir)
			if err != nil {
				return err
			}

			// A client disconnecting closes stdin, which is the normal exit
			// path. Interrupt is the other one, and it must tear the pool
			// down rather than leaving connections to agents open.
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt)
			defer stop()

			server, err := mcpserver.New(mcpserver.Options{
				ConfigDir:    dir,
				RegistryPath: registryPath,
				CACertPath:   caCert,
				CertPath:     cert,
				KeyPath:      key,
				LogLevel:     level,
			})
			if err != nil {
				return err
			}
			return server.Run(ctx)
		},
	}

	cmd.Flags().StringVar(&configDir, "config-dir", "",
		"directory holding the registry and credentials (default: $FLEET_CONFIG_DIR, else the per-user config directory)")
	cmd.Flags().StringVar(&registryPath, "registry", "", "path to the fleet registry (default: <config dir>/registry.yaml)")
	cmd.Flags().StringVar(&caCert, "ca-cert", "", "fleet CA certificate (default: <config dir>/ca/ca.crt)")
	cmd.Flags().StringVar(&cert, "cert", "", "control certificate presented to agents (default: <config dir>/control.crt)")
	cmd.Flags().StringVar(&key, "key", "", "private key for --cert (default: <config dir>/control.key)")
	cmd.Flags().StringVar(&logLevel, "log-level", "info", "log verbosity written to stderr: debug, info, warn, error")
	return cmd
}

// resolveConfigDir honours the flag first and FLEET_CONFIG_DIR after it,
// via registry.ConfigDir, so one directory holds the registry, the CA and the
// control leaf no matter which of the three binaries opened it.
func resolveConfigDir(flagValue string) (string, error) {
	if flagValue != "" {
		return filepath.Clean(flagValue), nil
	}
	return registry.ConfigDir()
}

func parseLogLevel(name string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "debug":
		return slog.LevelDebug, nil
	case "", "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("unknown log level %q: expected debug, info, warn or error", name)
	}
}
