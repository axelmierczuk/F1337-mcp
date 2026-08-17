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

// EnvConfig names an environment variable holding an explicit config path, for
// a caller that wants to pin one without passing --config on every invocation:
// a shell profile, a CI job, a container image.
//
// The service units this repository installs do not use it — all three pass
// `serve --config <path>` in argv (see UnitParams.Arguments) — so an installed
// daemon does not depend on it.
const EnvConfig = "FLEET_AGENT_CONFIG"

// LegacyEnvConfig is what EnvConfig was called before the fleet rebrand. It is
// honoured when it is the only one set, because an operator who exported it in
// a profile, a CI job or a container image gets no warning from the rename
// otherwise — the daemon would simply stop seeing the path it was given and
// fall back to searching.
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

// systemConfigDir is [SystemConfigDir], indirected so a test can pin the
// resolution and assert that the directories nested inside it follow it. The
// tests in this package are all sequential — paths_test.go uses t.Setenv, which
// forbids t.Parallel — so a package-level seam is safe here.
var systemConfigDir = SystemConfigDir

// DefaultStateDir returns where supervised process records and other daemon
// state are persisted. Uninstall deliberately leaves this directory alone.
func DefaultStateDir() string {
	switch runtime.GOOS {
	case "windows", "darwin":
		// Both nest state *inside* the config directory, so it has to come off
		// the same resolution rather than a second, independent one.
		//
		// Resolving the two separately lets them disagree, and the disagreement
		// is self-inflicting: the supervisor creates <state>/processes on every
		// start, so a host whose old state directory happened to be empty gets
		// the new one created — which makes the new *config* directory non-empty
		// and flips SystemConfigDir to it on the next call, stranding a
		// pre-rebrand agent.yaml a few characters away. That is exactly the "my
		// whole fleet vanished" shape internal/legacypath exists to prevent.
		return filepath.Join(systemConfigDir(), "state")
	default:
		// Linux keeps state under its own root, so there is nothing to nest and
		// nothing to keep in step.
		return legacypath.Dir("/var/lib/fleet", "/var/lib/sandboxd")
	}
}

// DefaultLogDir returns where the agent's audit log and, on platforms whose
// service manager does not capture stdout itself, its service logs are
// written.
func DefaultLogDir() string {
	switch runtime.GOOS {
	case "windows":
		// Nested inside the config directory, so it follows the same resolution;
		// see DefaultStateDir.
		return filepath.Join(systemConfigDir(), "logs")
	case "darwin":
		// /Library/Logs is its own root on macOS, not a child of the config
		// directory, so it resolves independently and cannot fall out of step
		// with it.
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
