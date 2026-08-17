//go:build integration

package e2e

import (
	"encoding/base64"
	"testing"
)

// The tool results below are declared here rather than imported from
// internal/mcpserver/tools on purpose.
//
// These are the shapes a client decodes, and a client does not import the
// server's Go types — it reads JSON. A test that unmarshalled into the
// server's own structs would agree with any field rename, which is exactly the
// change worth failing on: a renamed field is a broken client. Only the fields
// a scenario actually reads are declared, so this stays a statement about what
// the suite depends on rather than a second copy of the schema.

type sandboxLine struct {
	Name     string `json:"name"`
	Address  string `json:"address"`
	Platform string `json:"platform"`
	Health   string `json:"health"`
	Selected bool   `json:"selected"`
}

type listResult struct {
	Sandbox   string        `json:"sandbox"`
	Sandboxes []sandboxLine `json:"sandboxes"`
	Hint      string        `json:"hint"`
}

type selectResult struct {
	Sandbox      string   `json:"sandbox"`
	Handle       string   `json:"handle"`
	Address      string   `json:"address"`
	Platform     string   `json:"platform"`
	AllowedRoots []string `json:"allowed_roots"`
	Unconfined   bool     `json:"unconfined"`
	Health       string   `json:"health"`
}

type infoResult struct {
	Sandbox      string   `json:"sandbox"`
	Address      string   `json:"address"`
	Handle       string   `json:"handle"`
	Platform     string   `json:"platform"`
	Hostname     string   `json:"hostname"`
	AllowedRoots []string `json:"allowed_roots"`
	Unconfined   bool     `json:"unconfined"`
	Agent        string   `json:"agent"`
	Health       string   `json:"health"`
	Principal    string   `json:"principal"`
}

type execResult struct {
	Sandbox    string `json:"sandbox"`
	ExitCode   int32  `json:"exit_code"`
	Stdout     string `json:"stdout"`
	Stderr     string `json:"stderr"`
	DurationMs int64  `json:"duration_ms"`
	TimedOut   bool   `json:"timed_out"`
	Signal     string `json:"signal"`
	Note       string `json:"note"`
}

type readResult struct {
	Sandbox       string `json:"sandbox"`
	Path          string `json:"path"`
	Content       string `json:"content"`
	ContentBase64 string `json:"content_base64"`
	TotalLines    uint64 `json:"total_lines"`
	Size          string `json:"size"`
}

type writeResult struct {
	Sandbox      string `json:"sandbox"`
	Path         string `json:"path"`
	BytesWritten uint64 `json:"bytes_written"`
	Created      bool   `json:"created"`
}

type editResult struct {
	Sandbox      string `json:"sandbox"`
	Path         string `json:"path"`
	Replacements uint32 `json:"replacements"`
	Diff         string `json:"diff"`
}

type processDetail struct {
	ProcessID      string   `json:"process_id"`
	Name           string   `json:"name"`
	State          string   `json:"state"`
	PID            int32    `json:"pid"`
	Command        string   `json:"command"`
	ExitCode       *int32   `json:"exit_code"`
	Signal         string   `json:"signal"`
	RestartCount   uint32   `json:"restart_count"`
	LastLogLine    string   `json:"last_log_line"`
	ListeningPorts []uint32 `json:"listening_ports"`
	AdoptionNote   string   `json:"adoption_note"`
	Argv           []string `json:"argv"`
	WorkingDir     string   `json:"working_dir"`
}

type processStartResult struct {
	Sandbox    string        `json:"sandbox"`
	Process    processDetail `json:"process"`
	Ready      *bool         `json:"ready"`
	ReadyError string        `json:"ready_error"`
	RecentLogs string        `json:"recent_logs"`
	Note       string        `json:"note"`
}

type processListResult struct {
	Sandbox   string          `json:"sandbox"`
	Table     string          `json:"table"`
	Processes []processDetail `json:"processes"`
	Running   int             `json:"running"`
}

type processLogsResult struct {
	Sandbox               string `json:"sandbox"`
	ProcessID             string `json:"process_id"`
	State                 string `json:"state"`
	Logs                  string `json:"logs"`
	LinesReturned         uint64 `json:"lines_returned"`
	LinesDropped          uint64 `json:"lines_dropped"`
	FollowDeadlineReached bool   `json:"follow_deadline_reached"`
	Note                  string `json:"note"`
}

type processSignalResult struct {
	Sandbox         string        `json:"sandbox"`
	Process         processDetail `json:"process"`
	EscalatedToKill bool          `json:"escalated_to_kill"`
	Note            string        `json:"note"`
}

type forwardLine struct {
	Sandbox      string `json:"sandbox"`
	LocalAddress string `json:"local_address"`
	LocalPort    int    `json:"local_port"`
	RemotePort   int    `json:"remote_port"`
	Connections  uint64 `json:"connections"`
	LastError    string `json:"last_error"`
}

type forwardResult struct {
	Sandbox      string        `json:"sandbox"`
	LocalAddress string        `json:"local_address"`
	LocalPort    int           `json:"local_port"`
	RemotePort   int           `json:"remote_port"`
	Stopped      bool          `json:"stopped"`
	Existing     bool          `json:"existing"`
	Active       []forwardLine `json:"active_forwards"`
}

type transferResult struct {
	Sandbox     string `json:"sandbox"`
	Direction   string `json:"direction"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Files       int    `json:"files"`
	Bytes       uint64 `json:"bytes"`
	Unchanged   int    `json:"unchanged"`
	Excluded    int    `json:"excluded"`
	Note        string `json:"note"`
}

func decodeBase64(t *testing.T, s string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("decode base64 content: %v", err)
	}
	return string(raw)
}
