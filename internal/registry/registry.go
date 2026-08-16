package registry

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// ErrNotFound is returned when a sandbox or selection does not exist.
var ErrNotFound = errors.New("registry: not found")

// ErrExists is returned by Add when a sandbox with the same name is already
// registered.
var ErrExists = errors.New("registry: sandbox already exists")

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

// ConfigDir resolves the directory sandboxd persists its config under:
//
//  1. $SANDBOXD_CONFIG_DIR, if set.
//  2. $XDG_CONFIG_HOME/sandboxd, if XDG_CONFIG_HOME is set (Unix).
//  3. %APPDATA%\sandboxd (Windows).
//  4. ~/.config/sandboxd (everywhere else).
func ConfigDir() (string, error) {
	if dir := os.Getenv("SANDBOXD_CONFIG_DIR"); dir != "" {
		return dir, nil
	}

	if runtime.GOOS == "windows" {
		if appData := os.Getenv("APPDATA"); appData != "" {
			return filepath.Join(appData, "sandboxd"), nil
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("registry: resolve home directory: %w", err)
		}
		return filepath.Join(home, "AppData", "Roaming", "sandboxd"), nil
	}

	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "sandboxd"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("registry: resolve home directory: %w", err)
	}
	return filepath.Join(home, ".config", "sandboxd"), nil
}

// DefaultPath returns the path to the registry file inside ConfigDir().
func DefaultPath() (string, error) {
	dir, err := ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "registry.yaml"), nil
}
