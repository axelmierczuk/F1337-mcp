package registry

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// schemaVersion is bumped when the on-disk shape changes incompatibly.
const schemaVersion = 1

// state is the on-disk shape of the registry file.
type state struct {
	Version    int               `yaml:"version"`
	Sandboxes  []Sandbox         `yaml:"sandboxes"`
	Selections map[string]string `yaml:"selections"` // client identity -> sandbox name
}

// Registry is the MCP server's persistent view of the fleet: which sandboxes
// exist, how to reach them, and which one each client currently has
// selected.
//
// Every method reads the current file, applies its change, and writes the
// result back atomically, so the registry always reflects the latest state
// on disk (including changes made by another Registry handle pointed at the
// same path) and a crash between the write and the rename never leaves a
// half-written file. Mutating methods on a single Registry are additionally
// serialized by an in-process mutex, so concurrent goroutines sharing one
// Registry handle never race on the read-modify-write cycle.
type Registry struct {
	path string
	mu   sync.Mutex
}

// Open returns a Registry backed by the file at path, creating the parent
// directory (mode 0700) if it does not exist. If a file already exists at
// path, it is parsed eagerly so a truncated or malformed registry is
// reported immediately rather than on first use.
func Open(path string) (*Registry, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("registry: create config directory for %s: %w", path, err)
	}
	r := &Registry{path: path}
	if _, err := os.Stat(path); err == nil {
		if _, err := r.load(); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("registry: stat %s: %w", path, err)
	}
	return r, nil
}

// Path returns the file path this Registry persists to.
func (r *Registry) Path() string {
	return r.path
}

func (r *Registry) load() (state, error) {
	data, err := os.ReadFile(r.path)
	if err != nil {
		if os.IsNotExist(err) {
			return state{Version: schemaVersion, Selections: map[string]string{}}, nil
		}
		return state{}, fmt.Errorf("registry: read %s: %w", r.path, err)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return state{Version: schemaVersion, Selections: map[string]string{}}, nil
	}

	var s state
	if err := yaml.Unmarshal(data, &s); err != nil {
		return state{}, fmt.Errorf("registry: parse %s: %w", r.path, err)
	}
	if s.Selections == nil {
		s.Selections = map[string]string{}
	}
	return s, nil
}

// save writes s to disk atomically: encode to a temp file in the same
// directory, fix its permissions, then rename over the destination. Rename
// within a directory is atomic on every platform this project targets, so a
// reader never observes a partially written file.
func (r *Registry) save(s state) error {
	if s.Version == 0 {
		s.Version = schemaVersion
	}
	data, err := yaml.Marshal(s)
	if err != nil {
		return fmt.Errorf("registry: encode %s: %w", r.path, err)
	}

	dir := filepath.Dir(r.path)
	tmp, err := os.CreateTemp(dir, ".registry-*.tmp")
	if err != nil {
		return fmt.Errorf("registry: create temp file in %s: %w", dir, err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }() // no-op once the rename below succeeds

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("registry: write %s: %w", tmpPath, err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("registry: chmod %s: %w", tmpPath, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("registry: close %s: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, r.path); err != nil {
		return fmt.Errorf("registry: rename %s to %s: %w", tmpPath, r.path, err)
	}
	return nil
}

// Add registers a new sandbox. It fails with ErrExists if the name is
// already taken. EnrolledAt defaults to now if unset.
func (r *Registry) Add(sb Sandbox) error {
	if sb.Name == "" {
		return fmt.Errorf("registry: sandbox name is required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	s, err := r.load()
	if err != nil {
		return err
	}
	for _, existing := range s.Sandboxes {
		if existing.Name == sb.Name {
			return fmt.Errorf("%w: %s", ErrExists, sb.Name)
		}
	}
	if sb.EnrolledAt.IsZero() {
		sb.EnrolledAt = time.Now().UTC()
	}
	s.Sandboxes = append(s.Sandboxes, sb)
	return r.save(s)
}

// Remove deletes a sandbox by name. It fails with ErrNotFound if the name is
// not registered.
func (r *Registry) Remove(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	s, err := r.load()
	if err != nil {
		return err
	}
	idx := -1
	for i, sb := range s.Sandboxes {
		if sb.Name == name {
			idx = i
			break
		}
	}
	if idx == -1 {
		return fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	s.Sandboxes = append(s.Sandboxes[:idx], s.Sandboxes[idx+1:]...)
	return r.save(s)
}

// Get returns a sandbox by name. It fails with ErrNotFound if the name is
// not registered.
func (r *Registry) Get(name string) (Sandbox, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	s, err := r.load()
	if err != nil {
		return Sandbox{}, err
	}
	for _, sb := range s.Sandboxes {
		if sb.Name == name {
			return sb, nil
		}
	}
	return Sandbox{}, fmt.Errorf("%w: %s", ErrNotFound, name)
}

// List returns every registered sandbox, in registration order.
func (r *Registry) List() ([]Sandbox, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	s, err := r.load()
	if err != nil {
		return nil, err
	}
	out := make([]Sandbox, len(s.Sandboxes))
	copy(out, s.Sandboxes)
	return out, nil
}

// UpdateLastSeen sets the last-seen timestamp for a sandbox. It fails with
// ErrNotFound if the name is not registered.
func (r *Registry) UpdateLastSeen(name string, seenAt time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	s, err := r.load()
	if err != nil {
		return err
	}
	for i := range s.Sandboxes {
		if s.Sandboxes[i].Name == name {
			s.Sandboxes[i].LastSeenAt = seenAt
			return r.save(s)
		}
	}
	return fmt.Errorf("%w: %s", ErrNotFound, name)
}

// UpdateHostInfo refreshes the cached platform and agent version for a
// sandbox, as reported by the most recent HostService.GetHostInfo call. It
// fails with ErrNotFound if the name is not registered.
func (r *Registry) UpdateHostInfo(name string, platform Platform, agentVersion string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	s, err := r.load()
	if err != nil {
		return err
	}
	for i := range s.Sandboxes {
		if s.Sandboxes[i].Name == name {
			s.Sandboxes[i].Platform = platform
			s.Sandboxes[i].AgentVersion = agentVersion
			return r.save(s)
		}
	}
	return fmt.Errorf("%w: %s", ErrNotFound, name)
}

// SetSelection records the sticky default sandbox for a client identity,
// persisted so it survives a process restart. Two different client
// identities against the same registry never observe each other's
// selection.
func (r *Registry) SetSelection(clientID, sandboxName string) error {
	if clientID == "" {
		return fmt.Errorf("registry: client identity is required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	s, err := r.load()
	if err != nil {
		return err
	}
	if s.Selections == nil {
		s.Selections = map[string]string{}
	}
	s.Selections[clientID] = sandboxName
	return r.save(s)
}

// GetSelection returns the sticky default sandbox for a client identity, if
// one has been set.
func (r *Registry) GetSelection(clientID string) (name string, ok bool, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	s, err := r.load()
	if err != nil {
		return "", false, err
	}
	name, ok = s.Selections[clientID]
	return name, ok, nil
}

// ClearSelection removes the sticky default sandbox for a client identity,
// if one is set. It is not an error to clear a selection that does not
// exist.
func (r *Registry) ClearSelection(clientID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	s, err := r.load()
	if err != nil {
		return err
	}
	delete(s.Selections, clientID)
	return r.save(s)
}
