package registry

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/axelmierczuk/fleet-mcp/internal/fsutil"
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
// Every operation reads the current file, applies its change, and writes the
// result back atomically, so the registry always reflects the latest state on
// disk and a crash between the write and the rename never leaves a
// half-written file.
//
// The read-modify-write cycle is serialized twice over: an in-process mutex
// covers goroutines sharing one Registry, and an advisory file lock covers
// separate processes sharing one config directory. The second matters because
// the sticky selection is keyed by client identity precisely so that several
// MCP servers can share a config directory — without the file lock, two of
// them interleaving read-modify-write would silently drop one's update.
type Registry struct {
	path string
	mu   sync.Mutex
}

// Open returns a Registry backed by the file at path, creating the parent
// directory (mode 0700) if it does not exist. If a file already exists at
// path, it is parsed eagerly so a truncated or malformed registry is
// reported immediately rather than on first use.
//
// That eager parse takes the same cross-process lock every other access takes.
// It reads a file concurrent writers replace by rename, and a read outside the
// lock races that rename: on Windows a handle opened for reading carries no
// FILE_SHARE_DELETE, so the overlap fails either this read with a sharing
// violation or the writer's MoveFileEx — and a caller whose Open failed never
// makes the write it opened the registry to make. enroll.OpenTokenStore, the
// sibling implementation of this same pattern, has always taken the lock here.
func Open(path string) (*Registry, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("registry: create config directory for %s: %w", path, err)
	}
	r := &Registry{path: path}
	if _, err := os.Stat(path); err == nil {
		if err := r.read(func(*state) error { return nil }); err != nil {
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

// mutate runs fn against the current on-disk state and writes the result
// back, holding the in-process mutex and the cross-process file lock for the
// whole cycle. An error from fn aborts the write, leaving the file untouched.
func (r *Registry) mutate(fn func(s *state) error) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	release, err := fsutil.Lock(r.path)
	if err != nil {
		return err
	}
	defer func() { _ = release() }()

	s, err := r.load()
	if err != nil {
		return err
	}
	if err := fn(&s); err != nil {
		return err
	}
	return r.save(s)
}

// read runs fn against the current on-disk state without writing it back.
func (r *Registry) read(fn func(s *state) error) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	release, err := fsutil.Lock(r.path)
	if err != nil {
		return err
	}
	defer func() { _ = release() }()

	s, err := r.load()
	if err != nil {
		return err
	}
	return fn(&s)
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
// directory, fix its permissions, then rename over the destination.
func (r *Registry) save(s state) error {
	if s.Version == 0 {
		s.Version = schemaVersion
	}
	data, err := yaml.Marshal(s)
	if err != nil {
		return fmt.Errorf("registry: encode %s: %w", r.path, err)
	}
	if err := fsutil.WriteAtomic(r.path, data, 0o600); err != nil {
		return fmt.Errorf("registry: save %s: %w", r.path, err)
	}
	return nil
}

// Add registers a new sandbox. It fails with ErrExists if the name is
// already taken. EnrolledAt defaults to now if unset.
func (r *Registry) Add(sb Sandbox) error {
	if sb.Name == "" {
		return fmt.Errorf("registry: sandbox name is required")
	}
	return r.mutate(func(s *state) error {
		for _, existing := range s.Sandboxes {
			if existing.Name == sb.Name {
				return fmt.Errorf("%w: %s", ErrExists, sb.Name)
			}
		}
		if sb.EnrolledAt.IsZero() {
			sb.EnrolledAt = time.Now().UTC()
		}
		s.Sandboxes = append(s.Sandboxes, sb)
		return nil
	})
}

// Remove deletes a sandbox by name. It fails with ErrNotFound if the name is
// not registered.
func (r *Registry) Remove(name string) error {
	return r.mutate(func(s *state) error {
		for i, sb := range s.Sandboxes {
			if sb.Name == name {
				s.Sandboxes = append(s.Sandboxes[:i], s.Sandboxes[i+1:]...)
				return nil
			}
		}
		return fmt.Errorf("%w: %s", ErrNotFound, name)
	})
}

// Get returns a sandbox by name. It fails with ErrNotFound if the name is
// not registered.
func (r *Registry) Get(name string) (Sandbox, error) {
	var out Sandbox
	err := r.read(func(s *state) error {
		for _, sb := range s.Sandboxes {
			if sb.Name == name {
				out = sb
				return nil
			}
		}
		return fmt.Errorf("%w: %s", ErrNotFound, name)
	})
	if err != nil {
		return Sandbox{}, err
	}
	return out, nil
}

// Exists reports whether a sandbox is registered under this name. A read
// error is reported as "taken", because refusing to reuse a name the registry
// cannot rule out is the safe direction for a caller about to issue a
// certificate for it.
func (r *Registry) Exists(name string) bool {
	_, err := r.Get(name)
	return err == nil || !isNotFound(err)
}

// List returns every registered sandbox, in registration order.
func (r *Registry) List() ([]Sandbox, error) {
	var out []Sandbox
	err := r.read(func(s *state) error {
		out = make([]Sandbox, len(s.Sandboxes))
		copy(out, s.Sandboxes)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// UpdateLastSeen sets the last-seen timestamp for a sandbox. It fails with
// ErrNotFound if the name is not registered.
func (r *Registry) UpdateLastSeen(name string, seenAt time.Time) error {
	return r.mutate(func(s *state) error {
		for i := range s.Sandboxes {
			if s.Sandboxes[i].Name == name {
				s.Sandboxes[i].LastSeenAt = seenAt
				return nil
			}
		}
		return fmt.Errorf("%w: %s", ErrNotFound, name)
	})
}

// UpdateHostInfo refreshes the cached platform and agent version for a
// sandbox, as reported by the most recent HostService.GetHostInfo call. It
// fails with ErrNotFound if the name is not registered.
func (r *Registry) UpdateHostInfo(name string, platform Platform, agentVersion string) error {
	return r.mutate(func(s *state) error {
		for i := range s.Sandboxes {
			if s.Sandboxes[i].Name == name {
				s.Sandboxes[i].Platform = platform
				s.Sandboxes[i].AgentVersion = agentVersion
				return nil
			}
		}
		return fmt.Errorf("%w: %s", ErrNotFound, name)
	})
}

// maxClientIDLength bounds an identity that becomes a key in the registry
// file. See [Registry.SetSelection].
const maxClientIDLength = 256

// SetSelection records the sticky default sandbox for a client identity,
// persisted so it survives a process restart. Two different client
// identities against the same registry never observe each other's
// selection.
//
// The identity is bounded here as well as by its producer. Whether an identity
// is durable enough to persist is the caller's judgement — this file has no way
// to tell "client:some-editor" from "process:4242", and teaching it would put
// one package's naming scheme inside another's storage — but whether a string
// is fit to become a key in a YAML file that every later operation rewrites
// whole is this file's business, exactly as refusing an empty sandbox name is.
// A megabyte of identity, or one carrying a NUL, is a caller's bug wherever it
// came from, and it costs every subsequent read and write once it is on disk.
func (r *Registry) SetSelection(clientID, sandboxName string) error {
	if clientID == "" {
		return fmt.Errorf("registry: client identity is required")
	}
	if len(clientID) > maxClientIDLength {
		return fmt.Errorf("registry: client identity is %d bytes, limit is %d", len(clientID), maxClientIDLength)
	}
	for _, ch := range clientID {
		if ch < ' ' || ch == 0x7f {
			return fmt.Errorf("registry: client identity contains a control character %q", ch)
		}
	}
	return r.mutate(func(s *state) error {
		if s.Selections == nil {
			s.Selections = map[string]string{}
		}
		s.Selections[clientID] = sandboxName
		return nil
	})
}

// GetSelection returns the sticky default sandbox for a client identity, if
// one has been set.
func (r *Registry) GetSelection(clientID string) (name string, ok bool, err error) {
	err = r.read(func(s *state) error {
		name, ok = s.Selections[clientID]
		return nil
	})
	if err != nil {
		return "", false, err
	}
	return name, ok, nil
}

// ClearSelection removes the sticky default sandbox for a client identity,
// if one is set. It is not an error to clear a selection that does not
// exist.
func (r *Registry) ClearSelection(clientID string) error {
	return r.mutate(func(s *state) error {
		delete(s.Selections, clientID)
		return nil
	})
}

// ClearSelectionsFor removes every client's sticky default that points at
// sandboxName, returning how many were cleared.
//
// Selections are keyed by client identity, so deregistering a sandbox has to
// reach all of them: the client that ran sandbox_remove is rarely the only
// one that had it selected, and a selection left pointing at a sandbox that
// no longer exists is worse than no selection at all. Callers should clear
// before removing, so the intermediate state is "registered but unselected"
// rather than "selected but missing".
func (r *Registry) ClearSelectionsFor(sandboxName string) (int, error) {
	cleared := 0
	err := r.mutate(func(s *state) error {
		cleared = 0
		for clientID, selected := range s.Selections {
			if selected == sandboxName {
				delete(s.Selections, clientID)
				cleared++
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return cleared, nil
}
