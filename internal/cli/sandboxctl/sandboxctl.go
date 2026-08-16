// Package sandboxctl implements the operator CLI for the sandboxd control
// plane: certificate authority management, enrollment token minting, and the
// enrollment listener.
//
// All of it lives here rather than behind an MCP tool because every command in
// this package either holds or hands out a credential, and nothing a model can
// reach should be able to mint one.
package sandboxctl

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/axelmierczuk/sandboxd-mcp/internal/registry"
)

// Main runs sandboxctl and returns the process exit code.
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
		Use:   "sandboxctl",
		Short: "Operator CLI for the sandboxd control plane",
		Long: "sandboxctl manages the fleet certificate authority, mints single-use\n" +
			"enrollment tokens, and serves the endpoint hosts join the fleet through.",
		SilenceUsage: true,
		// Errors are printed once, by Execute's caller path below, rather
		// than twice with a usage dump in between.
		SilenceErrors:     false,
		RunE:              func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
		DisableAutoGenTag: true,
	}
	root.SetOut(out)
	root.SetErr(os.Stderr)

	root.AddCommand(
		newCACommand(out),
		newEnrollCommand(out),
		newServeCommand(out),
		newListCommand(out),
	)
	return root
}

// defaultCADir is where the CA lives unless --ca-dir says otherwise. It sits
// inside the config directory but in its own subdirectory, because it holds
// key material and the registry beside it deliberately does not.
func defaultCADir() (string, error) {
	dir, err := registry.ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "ca"), nil
}

func defaultTokenPath() (string, error) {
	dir, err := registry.ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "enrollment-tokens.yaml"), nil
}

// resolve returns flagValue when set, else the default, so every command can
// take an explicit path without repeating the fallback.
func resolve(flagValue string, fallback func() (string, error)) (string, error) {
	if flagValue != "" {
		return flagValue, nil
	}
	return fallback()
}

func openRegistry(path string) (*registry.Registry, error) {
	if path == "" {
		var err error
		path, err = registry.DefaultPath()
		if err != nil {
			return nil, err
		}
	}
	return registry.Open(path)
}

// readFile keeps the error message consistent across commands that take a path
// from the operator.
func readFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path is operator-supplied on the command line
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return data, nil
}
