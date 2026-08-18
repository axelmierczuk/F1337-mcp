package fleetagent_test

import (
	"errors"
	"os"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axelmierczuk/fleet-mcp/internal/cli/fleetagent"
)

// The Scheduled Task's invocations, which nothing on any runner here can let
// happen.
//
// Registering a task needs an elevated token and a real Task Scheduler, so
// until #79 the rendered XML was asserted in full and the argv it was handed to
// was asserted nowhere — a definition that was a pure function of UnitParams
// and was never shown to reach anything. These drive the same lifecycle
// `service install`, `start`, `stop` and `uninstall` drive, with schtasks.exe
// replaced by a recorder that sees exactly what it would have.

// schtasksRecorder captures the argv, and the bytes of any file the argv points
// schtasks at — read at the moment schtasks would read it, which is the only
// moment the temp file exists.
type schtasksRecorder struct {
	calls [][]string
	xml   []byte
	fail  func(args []string) error
}

func (r *schtasksRecorder) run(args ...string) error {
	r.calls = append(r.calls, append([]string(nil), args...))
	for i, arg := range args {
		if strings.EqualFold(arg, "/XML") && i+1 < len(args) {
			data, err := os.ReadFile(args[i+1]) //nolint:gosec // a path this package just wrote under os.MkdirTemp
			if err == nil {
				r.xml = data
			}
		}
	}
	if r.fail != nil {
		return r.fail(args)
	}
	return nil
}

func (r *schtasksRecorder) verbs() []string {
	out := make([]string, 0, len(r.calls))
	for _, call := range r.calls {
		out = append(out, call[0])
	}
	return out
}

// Install registers the definition under the agent's name, replacing whatever
// is there — and the file it points schtasks at holds the UTF-16 bytes
// schtasks insists on, not the UTF-8 string the renderer returns.
func TestScheduledTask_InstallHandsSchtasksTheDefinition(t *testing.T) {
	p := params()
	p.User = `WORKSTATION\axel`
	rec := &schtasksRecorder{}

	require.NoError(t, fleetagent.NewScheduledTaskForTest(p, rec.run).Install())
	require.Len(t, rec.calls, 1)

	call := rec.calls[0]
	assert.Equal(t, "/Create", call[0])
	assert.Equal(t, []string{"/TN", fleetagent.ServiceName}, call[1:3])
	assert.Equal(t, "/XML", call[3])
	assert.Contains(t, call, "/F",
		"without /F a second `service install` fails on a task that already exists, and re-running an installer is the most ordinary thing an operator does")

	// The bytes, not the string. schtasks rejects a UTF-8 file with an error
	// that names neither the encoding nor the file.
	require.NotEmpty(t, rec.xml, "schtasks was pointed at a file; that file has to hold the definition")
	require.Equal(t, []byte{0xFF, 0xFE}, rec.xml[:2], "UTF-16 little-endian, with the byte-order mark")
	units := make([]uint16, 0, (len(rec.xml)-2)/2)
	for i := 2; i+1 < len(rec.xml); i += 2 {
		units = append(units, uint16(rec.xml[i])|uint16(rec.xml[i+1])<<8)
	}
	assert.Equal(t, p.ScheduledTaskXML(), string(utf16.Decode(units)),
		"the file has to hold the definition this UnitParams renders, not a stale or empty one")
}

// A UnitParams with nothing to run is refused before a temp file or an
// invocation happens, rather than registering a task that fails at logon.
func TestScheduledTask_InstallRefusesWithNoExecutable(t *testing.T) {
	rec := &schtasksRecorder{}
	err := fleetagent.NewScheduledTaskForTest(fleetagent.UnitParams{}, rec.run).Install()
	require.Error(t, err)
	assert.Empty(t, rec.calls, "nothing may be registered when there is nothing to register")
}

// The rest of the lifecycle: the verb each command sends, addressed by name.
func TestScheduledTask_LifecycleVerbs(t *testing.T) {
	for _, tc := range []struct {
		name string
		call func(fleetagent.ScheduledTaskForTest) error
		verb string
	}{
		{"uninstall", func(s fleetagent.ScheduledTaskForTest) error { return s.Uninstall() }, "/Delete"},
		{"start", func(s fleetagent.ScheduledTaskForTest) error { return s.Start() }, "/Run"},
		{"stop", func(s fleetagent.ScheduledTaskForTest) error { return s.Stop() }, "/End"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := &schtasksRecorder{}
			require.NoError(t, tc.call(fleetagent.NewScheduledTaskForTest(params(), rec.run)))
			require.Len(t, rec.calls, 1)
			assert.Equal(t, tc.verb, rec.calls[0][0])
			assert.Contains(t, rec.calls[0], fleetagent.ServiceName, "the task has to be addressed by name")
		})
	}
}

// Restart starts the task even when ending it failed, and that is the whole
// point of it.
//
// `schtasks /End` has nothing to end when the task is not running, which is
// exactly the state `service install` leaves it in: replacing the definition
// means deleting the task, and deleting a task ends it. A Restart that treated
// the end as a precondition would leave the agent down after every re-install,
// with a "note: could not be restarted" line as the only sign.
func TestScheduledTask_RestartStartsEvenWhenThereWasNothingToEnd(t *testing.T) {
	rec := &schtasksRecorder{fail: func(args []string) error {
		if args[0] == "/End" {
			return errors.New("the system cannot find the file specified")
		}
		return nil
	}}

	require.NoError(t, fleetagent.NewScheduledTaskForTest(params(), rec.run).Restart(),
		"a task that was not running is not a reason to refuse to start it")
	assert.Equal(t, []string{"/End", "/Run"}, rec.verbs())
}

// And a start that genuinely fails is still a failure, carrying both halves so
// an operator is not left guessing which one broke.
func TestScheduledTask_RestartReportsAFailedStart(t *testing.T) {
	rec := &schtasksRecorder{fail: func([]string) error { return errors.New("access is denied") }}

	err := fleetagent.NewScheduledTaskForTest(params(), rec.run).Restart()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "start the scheduled task")
	assert.Contains(t, err.Error(), "ending it first also failed")
	assert.Equal(t, []string{"/End", "/Run"}, rec.verbs())
}
