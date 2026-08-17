package registry

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/axelmierczuk/fleet-mcp/internal/legacypath"
)

// ErrNotFound is returned when a sandbox or selection does not exist.
var ErrNotFound = errors.New("registry: not found")

// ErrExists is returned by Add when a sandbox with the same name is already
// registered.
var ErrExists = errors.New("registry: sandbox already exists")

func isNotFound(err error) bool { return errors.Is(err, ErrNotFound) }

// Platform is a cached, best-effort description of a sandbox host, filled in
// from the most recent HostService.GetHostInfo call. It intentionally
// duplicates the shape of sandboxd.v1.Platform rather than importing the
// generated package, so that the registry — a leaf package with no
// blockers — does not pull in the gRPC and protobuf dependency graph.
type Platform struct {
	OS            string `json:"os,omitempty" yaml:"os,omitempty"`
	Arch          string `json:"arch,omitempty" yaml:"arch,omitempty"`
	KernelVersion string `json:"kernel_version,omitempty" yaml:"kernel_version,omitempty"`
	Hostname      string `json:"hostname,omitempty" yaml:"hostname,omitempty"`
	PathSeparator string `json:"path_separator,omitempty" yaml:"path_separator,omitempty"`
}

// String renders a platform as "os/arch", or the empty string when nothing has
// ever reported one. Both the MCP tools and fleetctl print it, and a sandbox
// that reads "linux/amd64" in one view and "linux amd64" in the other is a
// difference an operator has to stop and account for.
func (p Platform) String() string {
	switch {
	case p.OS != "" && p.Arch != "":
		return p.OS + "/" + p.Arch
	case p.OS != "":
		return p.OS
	default:
		return p.Arch
	}
}

// Sandbox is a single fleet member as persisted in the registry.
type Sandbox struct {
	// Name is the fleet-unique identifier used to target this sandbox.
	Name string `json:"name" yaml:"name"`
	// Address is host:port for the agent's gRPC listener.
	Address string `json:"address" yaml:"address"`
	// Labels are free-form operator-assigned metadata (e.g. "arch=arm64").
	Labels map[string]string `json:"labels,omitempty" yaml:"labels,omitempty"`
	// Platform is cached from the last successful GetHostInfo call. Zero
	// value until the first probe succeeds.
	Platform Platform `json:"platform,omitempty" yaml:"platform,omitempty"`
	// EnrolledAt is when this sandbox joined the fleet.
	EnrolledAt time.Time `json:"enrolled_at" yaml:"enrolled_at"`
	// LastSeenAt is when the sandbox last answered a health probe.
	LastSeenAt time.Time `json:"last_seen_at,omitempty" yaml:"last_seen_at,omitempty"`
	// AgentVersion is cached from the last successful GetHostInfo call.
	AgentVersion string `json:"agent_version,omitempty" yaml:"agent_version,omitempty"`
}

// EnvConfigDir names the environment variable holding an explicit config
// directory.
const EnvConfigDir = "FLEET_CONFIG_DIR"

// LegacyEnvConfigDir is what EnvConfigDir was called before the fleet rebrand.
// It is still honoured when it is the only one set; see internal/legacypath.
const LegacyEnvConfigDir = "SANDBOXD_CONFIG_DIR"

// ConfigDir resolves the directory fleet persists its config under:
//
//  1. $FLEET_CONFIG_DIR, if set.
//  2. $XDG_CONFIG_HOME/fleet, if XDG_CONFIG_HOME is set (Unix).
//  3. %APPDATA%\fleet (Windows).
//  4. ~/.config/fleet (everywhere else).
//
// Each of those was called "sandboxd" before the rebrand. A host that enrolled
// under the old name keeps its registry and credentials there, so the
// deprecated variable is honoured when it is the only one set, and the old
// directory is used when it holds something and the new one does not.
// internal/legacypath has the full rule and does the logging.
func ConfigDir() (string, error) {
	if dir := legacypath.Env(EnvConfigDir, LegacyEnvConfigDir); dir != "" {
		return dir, nil
	}

	if runtime.GOOS == "windows" {
		if appData := os.Getenv("APPDATA"); appData != "" {
			return legacypath.Dir(filepath.Join(appData, "fleet"), filepath.Join(appData, "sandboxd")), nil
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("registry: resolve home directory: %w", err)
		}
		roaming := filepath.Join(home, "AppData", "Roaming")
		return legacypath.Dir(filepath.Join(roaming, "fleet"), filepath.Join(roaming, "sandboxd")), nil
	}

	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return legacypath.Dir(filepath.Join(xdg, "fleet"), filepath.Join(xdg, "sandboxd")), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("registry: resolve home directory: %w", err)
	}
	return legacypath.Dir(
		filepath.Join(home, ".config", "fleet"),
		filepath.Join(home, ".config", "sandboxd"),
	), nil
}

// DefaultPath returns the path to the registry file inside ConfigDir().
func DefaultPath() (string, error) {
	dir, err := ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "registry.yaml"), nil
}
