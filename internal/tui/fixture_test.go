package tui

import (
	"fmt"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/axelmierczuk/fleet-mcp/internal/client"
)

// Fixtures, so that every test in this package describes one fleet and the
// golden files are diffable against each other rather than against six
// different fleets.

// fixedNow is the clock every frame in this package is rendered against.
// Relative times are part of what the fleet pane shows, so a golden file that
// used the wall clock would differ on every run.
var fixedNow = time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)

// demoFleet is a small fleet with one of everything worth drawing: a serving
// host, a degraded one, an unreachable one, and one nothing has probed.
func demoFleet() []Sandbox {
	return []Sandbox{
		{
			Name: "alpha", Address: "10.0.0.11:9443", Platform: "linux/amd64",
			Health: client.HealthServing, Agent: "v0.4.1",
			LastSeen: fixedNow.Add(-3 * time.Second),
		},
		{
			Name: "beta-builder", Address: "10.0.0.12:9443", Platform: "darwin/arm64",
			Health: client.HealthDegraded, Detail: "disk 94% full", Agent: "v0.4.1",
			LastSeen: fixedNow.Add(-40 * time.Second),
		},
		{
			Name: "gamma", Address: "10.0.0.13:9443", Platform: "windows/amd64",
			Health: client.HealthUnreachable, Detail: "no answer within the timeout", Agent: "v0.4.0",
			LastSeen: fixedNow.Add(-2 * time.Hour),
		},
		{
			Name: "delta", Address: "10.0.0.14:9443",
			Health: client.HealthUnknown, LastSeen: time.Time{},
		},
	}
}

// bigFleet is twenty sandboxes, which is the size the issue names.
func bigFleet() []Sandbox {
	health := []string{client.HealthServing, client.HealthServing, client.HealthServing, client.HealthDegraded, client.HealthUnreachable}
	out := make([]Sandbox, 0, 20)
	for i := range 20 {
		h := health[i%len(health)]
		sb := Sandbox{
			Name:     fmt.Sprintf("node-%02d", i+1),
			Address:  fmt.Sprintf("10.0.1.%d:9443", i+1),
			Platform: "linux/amd64",
			Health:   h,
			Agent:    "v0.4.1",
			LastSeen: fixedNow.Add(-time.Duration(i) * time.Second),
		}
		if h == client.HealthUnreachable {
			sb.Detail = "no answer within the timeout"
		}
		out = append(out, sb)
	}
	return out
}

func demoProcesses() []Process {
	return []Process{
		{
			ID: "p-web", Name: "web-dev-server", State: client.ProcessReady, PID: 4211,
			Uptime: "12m4s", Ports: []uint32{8080, 8443}, LastLog: "listening on :8080",
		},
		{
			ID: "p-worker", Name: "queue-worker", State: client.ProcessRunning, PID: 4300,
			Uptime: "3m10s", Restarts: 2, LastLog: "picked up job 4471",
		},
		{
			ID: "p-fuzz", Name: "fuzzer", State: client.ProcessCrashed,
			Uptime: "1h2m", Restarts: 5, LastLog: "signal: killed",
		},
		{
			ID: "p-adopt", Name: "old-watcher", State: client.ProcessOrphaned, PID: 900,
			Uptime: "2d3h", AdoptionNote: "pid 900 reused by another process, marked orphaned",
		},
	}
}

func demoDetail() Detail {
	return Detail{
		Platform: "linux/amd64", Kernel: "6.8.0-41-generic", Hostname: "alpha",
		Agent: "v0.4.1", Principal: "control@fleet", Uptime: "6d4h",
		CPUCores: 8, MemoryTotal: "31.3 GiB", MemoryAvailable: "18.9 GiB",
		DiskTotal: "915.8 GiB", DiskAvailable: "402.1 GiB", Load1m: 1.24,
		AllowedRoots: []string{"/srv/build", "/tmp/fleet"},
	}
}

func demoLogs() Logs {
	return Logs{
		Lines: []LogLine{
			{Text: "listening on :8080"},
			{Text: "GET /healthz 200 1ms"},
			{Text: "--- 412 line(s) dropped: the process outran the log buffer ---", Marker: true},
			{Text: "E| upstream timeout after 30s"},
			{Text: "S| restarting under policy on_failure (attempt 2)"},
			{Text: "GET / 200 4ms"},
		},
		Dropped:         412,
		DeadlineReached: true,
	}
}

// demoModel is a model with data in every pane, at the given size.
func demoModel(width, height int) Model {
	m := NewModel(DefaultSchedule, false)
	m.width, m.height = width, height
	m.now = fixedNow
	m.sandboxes, m.sbLoaded = demoFleet(), true
	m.processes, m.procFor = demoProcesses(), "alpha"
	m.detail, m.detailFor = demoDetail(), "alpha"
	m.logs, m.logFor = demoLogs(), logTarget{sandbox: "alpha", processID: "p-web"}
	m.sbState.last = fixedNow
	m.procState.last = fixedNow
	m.detailState.last = fixedNow
	m.logState.last = fixedNow
	return m
}

// key builds the message bubbletea delivers for a keystroke.
func key(s string) tea.KeyMsg {
	switch s {
	case "enter":
		return tea.KeyMsg{Type: tea.KeyEnter}
	case "tab":
		return tea.KeyMsg{Type: tea.KeyTab}
	case "shift+tab":
		return tea.KeyMsg{Type: tea.KeyShiftTab}
	case "up":
		return tea.KeyMsg{Type: tea.KeyUp}
	case "down":
		return tea.KeyMsg{Type: tea.KeyDown}
	case "pgup":
		return tea.KeyMsg{Type: tea.KeyPgUp}
	case "pgdown":
		return tea.KeyMsg{Type: tea.KeyPgDown}
	case "home":
		return tea.KeyMsg{Type: tea.KeyHome}
	case "end":
		return tea.KeyMsg{Type: tea.KeyEnd}
	case "esc":
		return tea.KeyMsg{Type: tea.KeyEsc}
	case "ctrl+c":
		return tea.KeyMsg{Type: tea.KeyCtrlC}
	case "ctrl+r":
		return tea.KeyMsg{Type: tea.KeyCtrlR}
	default:
		return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
	}
}

// press applies a sequence of keystrokes, returning the model and the effects
// the last one produced.
func press(m Model, keys ...string) (Model, []Effect) {
	var effects []Effect
	for _, k := range keys {
		m, effects = m.Step(key(k))
	}
	return m, effects
}

// mutating reports the mutating effects in a batch, which is what the
// confirmation tests count.
func mutating(effects []Effect) []Effect {
	var out []Effect
	for _, e := range effects {
		if e.Kind.Mutating() {
			out = append(out, e)
		}
	}
	return out
}

// sizeMsg is the message bubbletea sends when the terminal is resized.
func sizeMsg(w, h int) tea.WindowSizeMsg { return tea.WindowSizeMsg{Width: w, Height: h} }
