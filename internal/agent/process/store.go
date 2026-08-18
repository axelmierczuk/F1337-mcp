package process

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/fleet-mcp/internal/fsutil"
)

// recordFileName is the persisted record inside a process's own directory.
//
// One file per process, rather than one file for the supervisor. Two reasons:
// a transition writes only the record it changed, so a busy supervisor does not
// serialise every state change behind one rewrite; and a record that somehow
// becomes unparseable costs the agent that process rather than all of them.
const recordFileName = "record.json"

// persisted is the on-disk form of a record. Field names are stable: an agent
// upgrade reads what the previous version wrote, and losing a process's record
// means losing the agent's ability to re-adopt it.
type persisted struct {
	ID         string   `json:"process_id"`
	Name       string   `json:"name"`
	Argv       []string `json:"argv"`
	ArgvHash   string   `json:"argv_hash"`
	WorkingDir string   `json:"working_dir"`
	Env        []string `json:"env,omitempty"`
	Shell      bool     `json:"shell,omitempty"`

	// PID and StartID are the pid-reuse guard. StartID is platform.ProcessInfo's
	// opaque start identity; a record whose pid exists but whose start identity
	// differs names a process this agent never started.
	PID     int    `json:"pid"`
	StartID string `json:"start_id,omitempty"`
	// RunFirstSeq is the log sequence the running run's output starts at, so a
	// probe resumed by the next agent can still tell that run's output from the
	// output of the runs before it. Absent in records written before it existed,
	// where zero reads as "the whole retained buffer" — see record.runFirstSeq.
	RunFirstSeq uint64 `json:"run_first_seq,omitempty"`
	// JobName is the Windows job object this process's tree lives in, so a
	// restarted agent can reopen it. Empty and unused on Unix.
	JobName string `json:"job_name,omitempty"`

	State     string    `json:"state"`
	StartedAt time.Time `json:"started_at,omitzero"`
	ExitedAt  time.Time `json:"exited_at,omitzero"`
	ExitCode  int32     `json:"exit_code"`
	Signal    string    `json:"signal,omitempty"`

	RestartCount     uint32 `json:"restart_count"`
	RestartPolicy    string `json:"restart_policy"`
	MaxRestarts      uint32 `json:"max_restarts"`
	RestartBackoffMS int64  `json:"restart_backoff_ms"`
	RestartsDisabled bool   `json:"restarts_disabled,omitempty"`

	MaxLogBytes int64           `json:"max_log_bytes"`
	Probe       *persistedProbe `json:"ready_probe,omitempty"`

	AdoptionNote string `json:"adoption_note,omitempty"`

	// CaptureOffsets is how far the agent had read each raw capture file. A
	// re-adopting agent resumes from here instead of replaying output it has
	// already turned into log lines.
	CaptureOffsets [2]int64 `json:"capture_offsets"`
	LogBytes       uint64   `json:"log_bytes"`
}

// persistedProbe is a ReadyProbe flattened for storage.
type persistedProbe struct {
	Kind       string `json:"kind"`
	Pattern    string `json:"pattern,omitempty"`
	Port       uint32 `json:"port,omitempty"`
	URL        string `json:"url,omitempty"`
	UptimeMS   int64  `json:"uptime_ms,omitempty"`
	TimeoutMS  int64  `json:"timeout_ms,omitempty"`
	IntervalMS int64  `json:"interval_ms,omitempty"`
}

// store is the supervisor's durable record directory.
type store struct {
	root string // <state_dir>/processes
}

func newStore(stateDir string) (*store, error) {
	root := filepath.Join(stateDir, "processes")
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("process: create state directory %s: %w", root, err)
	}
	return &store{root: root}, nil
}

// dir is a process's own directory: its record and its logs.
func (s *store) dir(id string) (string, error) {
	name, err := logDirName(id)
	if err != nil {
		return "", err
	}
	return filepath.Join(s.root, name), nil
}

// save writes a record atomically.
//
// Atomic because the failure this guards against is not a disk error, it is
// SIGKILL landing between two write syscalls. A sibling temp file plus a rename
// means a reader — including the next agent, on the startup path where every
// supervised process's fate is decided — sees either the previous record or the
// new one, and never half of each.
func (s *store) save(p persisted) error {
	dir, err := s.dir(p.ID)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("process: create record directory %s: %w", dir, err)
	}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return fmt.Errorf("process: encode record %s: %w", p.ID, err)
	}
	data = append(data, '\n')
	return fsutil.WriteAtomic(filepath.Join(dir, recordFileName), data, 0o600)
}

// load reads every record the state directory holds, oldest start first so the
// supervisor's in-memory ordering is reproducible.
//
// A record that will not parse is reported and skipped rather than failing the
// load. The agent has already lost that process either way; refusing to start
// would lose the rest of them too.
func (s *store) load() ([]persisted, []error) {
	entries, err := os.ReadDir(s.root)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, []error{fmt.Errorf("process: read state directory %s: %w", s.root, err)}
	}

	var out []persisted
	var problems []error
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		path := filepath.Join(s.root, entry.Name(), recordFileName)
		data, err := os.ReadFile(path) //nolint:gosec // path is the agent's own state directory
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				problems = append(problems, fmt.Errorf("process: read record %s: %w", path, err))
			}
			continue
		}
		var p persisted
		if err := json.Unmarshal(data, &p); err != nil {
			problems = append(problems, fmt.Errorf("process: parse record %s: %w", path, err))
			continue
		}
		if p.ID == "" {
			problems = append(problems, fmt.Errorf("process: record %s has no process id", path))
			continue
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].StartedAt.Equal(out[j].StartedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].StartedAt.Before(out[j].StartedAt)
	})
	return out, problems
}

// remove deletes a record, and optionally the logs beside it.
//
// Without deleteLogs the directory stays: the record is what the supervisor
// tracks, and an operator who reaped a crashed process still wants the output
// that explains why it crashed.
func (s *store) remove(id string, deleteLogs bool) error {
	dir, err := s.dir(id)
	if err != nil {
		return err
	}
	if deleteLogs {
		if err := os.RemoveAll(dir); err != nil {
			return fmt.Errorf("process: remove %s: %w", dir, err)
		}
		return nil
	}
	if err := os.Remove(filepath.Join(dir, recordFileName)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("process: remove record for %s: %w", id, err)
	}
	return nil
}

// parseState turns a persisted state name back into the enum. An unrecognised
// name — a record written by a newer agent, then read by an older one — reads
// as ORPHANED, which is the conservative answer: the supervisor will not act on
// a process it cannot classify.
func parseState(name string) sandboxdv1.ProcessState {
	if v, ok := sandboxdv1.ProcessState_value["PROCESS_STATE_"+name]; ok {
		return sandboxdv1.ProcessState(v)
	}
	return sandboxdv1.ProcessState_PROCESS_STATE_ORPHANED
}

// parsePolicy turns a persisted policy name back into the enum, defaulting to
// never — the policy that cannot surprise anyone.
func parsePolicy(name string) sandboxdv1.RestartPolicy {
	if v, ok := sandboxdv1.RestartPolicy_value[name]; ok && v != 0 {
		return sandboxdv1.RestartPolicy(v)
	}
	return sandboxdv1.RestartPolicy_RESTART_POLICY_NEVER
}
