package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/axelmierczuk/fleet-mcp/internal/registry"
)

// ConfigFileName is the agent config's basename in every location it is
// searched for.
const ConfigFileName = "agent.yaml"

// EnvConfig names an environment variable holding an explicit config path. It
// is how the service unit passes the path the installer baked in without
// depending on the daemon rediscovering it.
const EnvConfig = "SANDBOXD_AGENT_CONFIG"

// SystemConfigDir returns the machine-wide configuration directory, as
// documented at the top of examples/agent.yaml.
//
// These are the paths the installer writes to when run with elevation. A
// per-user enrollment (`sandboxd-agent enroll` without root) lands under
// UserConfigDir instead, and DefaultConfigPath prefers whichever actually
// exists.
func SystemConfigDir() string {
	switch runtime.GOOS {
	case "windows":
		if dir := os.Getenv("ProgramData"); dir != "" {
			return filepath.Join(dir, "sandboxd")
		}
		return filepath.Join(`C:\ProgramData`, "sandboxd")
	case "darwin":
		return "/Library/Application Support/sandboxd"
	default:
		return "/etc/sandboxd"
	}
}

// DefaultStateDir returns where supervised process records and other daemon
// state are persisted. Uninstall deliberately leaves this directory alone.
func DefaultStateDir() string {
	switch runtime.GOOS {
	case "windows":
		return filepath.Join(SystemConfigDir(), "state")
	case "darwin":
		return "/Library/Application Support/sandboxd/state"
	default:
		return "/var/lib/sandboxd"
	}
}

// DefaultLogDir returns where the agent's audit log and, on platforms whose
// service manager does not capture stdout itself, its service logs are
// written.
func DefaultLogDir() string {
	switch runtime.GOOS {
	case "windows":
		return filepath.Join(SystemConfigDir(), "logs")
	case "darwin":
		return "/Library/Logs/sandboxd"
	default:
		return "/var/log/sandboxd"
	}
}

// UserConfigDir returns the per-user enrollment directory, which is where
// `sandboxd-agent enroll` writes when no --dir is given.
func UserConfigDir() (string, error) {
	dir, err := registry.ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "agent"), nil
}

// DefaultConfigPath resolves which config the daemon should read, in the order
// an operator would expect it to be found:
//
//  1. $SANDBOXD_AGENT_CONFIG, if set.
//  2. The machine-wide path, if a file is actually there.
//  3. The per-user enrollment directory.
//
// It returns the per-user path even when nothing exists yet, so the error a
// caller reports names a concrete file rather than a search.
func DefaultConfigPath() (string, error) {
	if path := os.Getenv(EnvConfig); path != "" {
		return path, nil
	}
	systemPath := filepath.Join(SystemConfigDir(), ConfigFileName)
	if _, err := os.Stat(systemPath); err == nil {
		return systemPath, nil
	}
	userDir, err := UserConfigDir()
	if err != nil {
		return "", err
	}
	userPath := filepath.Join(userDir, ConfigFileName)
	if _, err := os.Stat(userPath); err == nil {
		return userPath, nil
	}
	// Nothing exists. Name the machine-wide path, which is where an installed
	// agent's config belongs and the one an operator is most likely to create.
	return systemPath, nil
}

// ResolveConfigPath returns explicit when it is non-empty, and otherwise the
// discovered default.
func ResolveConfigPath(explicit string) (string, error) {
	if explicit != "" {
		abs, err := filepath.Abs(explicit)
		if err != nil {
			return "", fmt.Errorf("agent: resolve config path %s: %w", explicit, err)
		}
		return abs, nil
	}
	return DefaultConfigPath()
}
