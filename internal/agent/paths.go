package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/axelmierczuk/fleet-mcp/internal/legacypath"
	"github.com/axelmierczuk/fleet-mcp/internal/registry"
)

// ConfigFileName is the agent config's basename in every location it is
// searched for.
const ConfigFileName = "agent.yaml"

// EnvConfig names an environment variable holding an explicit config path. It
// is how the service unit passes the path the installer baked in without
// depending on the daemon rediscovering it.
const EnvConfig = "FLEET_AGENT_CONFIG"

// LegacyEnvConfig is what EnvConfig was called before the fleet rebrand. A
// service unit installed by an older agent still passes it, and that unit is
// not rewritten until `fleet-agent service install` runs again, so it is
// honoured when it is the only one set.
const LegacyEnvConfig = "SANDBOXD_AGENT_CONFIG"

// SystemConfigDir returns the machine-wide configuration directory, as
// documented at the top of examples/agent.yaml.
//
// These are the paths the installer writes to when run with elevation. A
// per-user enrollment (`fleet-agent enroll` without root) lands under
// UserConfigDir instead, and DefaultConfigPath prefers whichever actually
// exists.
//
// Every one of these directories was named "sandboxd" before the rebrand, and
// on a host that enrolled back then it is where the agent's certificates and
// key still are. The pre-rebrand path is used when it holds something and the
// new one does not; see internal/legacypath.
func SystemConfigDir() string {
	switch runtime.GOOS {
	case "windows":
		dir := os.Getenv("ProgramData")
		if dir == "" {
			dir = `C:\ProgramData`
		}
		return legacypath.Dir(filepath.Join(dir, "fleet"), filepath.Join(dir, "sandboxd"))
	case "darwin":
		return legacypath.Dir("/Library/Application Support/fleet", "/Library/Application Support/sandboxd")
	default:
		return legacypath.Dir("/etc/fleet", "/etc/sandboxd")
	}
}

// DefaultStateDir returns where supervised process records and other daemon
// state are persisted. Uninstall deliberately leaves this directory alone.
func DefaultStateDir() string {
	switch runtime.GOOS {
	case "windows":
		// Derived from SystemConfigDir, which has already resolved which of the
		// two names this host actually uses.
		return filepath.Join(SystemConfigDir(), "state")
	case "darwin":
		return legacypath.Dir("/Library/Application Support/fleet/state", "/Library/Application Support/sandboxd/state")
	default:
		return legacypath.Dir("/var/lib/fleet", "/var/lib/sandboxd")
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
		return legacypath.Dir("/Library/Logs/fleet", "/Library/Logs/sandboxd")
	default:
		return legacypath.Dir("/var/log/fleet", "/var/log/sandboxd")
	}
}

// UserConfigDir returns the per-user enrollment directory, which is where
// `fleet-agent enroll` writes when no --dir is given.
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
//  1. $FLEET_AGENT_CONFIG (or the deprecated $SANDBOXD_AGENT_CONFIG), if set.
//  2. The machine-wide path, if a file is actually there.
//  3. The per-user enrollment directory.
//
// It returns the per-user path even when nothing exists yet, so the error a
// caller reports names a concrete file rather than a search.
func DefaultConfigPath() (string, error) {
	if path := legacypath.Env(EnvConfig, LegacyEnvConfig); path != "" {
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
