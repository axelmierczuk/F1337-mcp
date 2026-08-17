package host_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axelmierczuk/fleet-mcp/internal/agent/host"
)

// hangEnv makes the test binary re-exec itself as a tool that never returns.
//
// A hanging binary is what the budget exists for, and there is no program
// guaranteed to hang on Linux, macOS and Windows alike — so the test binary
// plays the part itself. TestMain routes the re-exec.
const hangEnv = "SANDBOXD_TEST_TOOLCHAIN_HANG"

func TestMain(m *testing.M) {
	switch os.Getenv(hangEnv) {
	case "hang":
		select {}
	case "version":
		os.Stdout.WriteString("fake version 9.9.9\nextra line that must not be reported\n")
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// selfAs returns a LookPath that resolves every tool to this test binary, and
// a Run that invokes it in the given mode.
func selfAs(t *testing.T, mode string) (func(string) (string, error), func(context.Context, string, []string) ([]byte, error)) {
	t.Helper()
	self, err := os.Executable()
	require.NoError(t, err)

	lookPath := func(string) (string, error) { return self, nil }
	run := func(ctx context.Context, path string, args []string) ([]byte, error) {
		cmd := exec.CommandContext(ctx, path, args...)
		cmd.Env = append(os.Environ(), hangEnv+"="+mode)
		cmd.WaitDelay = time.Second
		return cmd.Output()
	}
	return lookPath, run
}

// The acceptance criterion: a probed binary that hangs must not hang the RPC.
// The budget bounds the whole sweep, not each probe within it.
func TestProbe_HungToolStaysWithinBudget(t *testing.T) {
	lookPath, run := selfAs(t, "hang")

	p := &host.Prober{
		// Six tools, each of which would block forever.
		Tools:    manyTools(6),
		Budget:   1500 * time.Millisecond,
		PerProbe: 400 * time.Millisecond,
		LookPath: lookPath,
		Run:      run,
	}

	start := time.Now()
	found := p.Probe(context.Background())
	elapsed := time.Since(start)

	// Six probes at 400ms each would be 2.4s if only the per-probe timeout
	// applied. The budget is what holds it to 1.5s, and that difference is the
	// property under test.
	assert.Less(t, elapsed, 2*time.Second, "the sweep must be bounded by the total budget, not by the sum of the per-probe timeouts")

	// It returns what it has rather than failing: every tool was found on the
	// PATH, so each probe that ran reports presence without a version.
	assert.NotEmpty(t, found)
	for _, tc := range found {
		assert.NotEmpty(t, tc.GetPath())
		assert.Empty(t, tc.GetVersion(), "a tool that would not answer must be reported as present but unversioned")
	}
}

// A caller's own deadline is respected too: the budget is a ceiling, not a
// floor.
func TestProbe_HonoursCallerDeadline(t *testing.T) {
	lookPath, run := selfAs(t, "hang")
	p := &host.Prober{
		Tools:    manyTools(6),
		Budget:   30 * time.Second,
		PerProbe: 20 * time.Second,
		LookPath: lookPath,
		Run:      run,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
	defer cancel()

	start := time.Now()
	p.Probe(ctx)
	assert.Less(t, time.Since(start), 5*time.Second, "the caller's deadline must cut the sweep short")
}

// A tool that answers is reported with its first line of output, and only its
// first line.
func TestProbe_ReportsFirstLineOnly(t *testing.T) {
	lookPath, run := selfAs(t, "version")
	p := &host.Prober{
		Tools:    []host.Tool{{Name: "go", Args: nil}},
		LookPath: lookPath,
		Run:      run,
	}

	found := p.Probe(context.Background())
	require.Len(t, found, 1)
	assert.Equal(t, "go", found[0].GetName())
	assert.Equal(t, "fake version 9.9.9", found[0].GetVersion())
	assert.NotContains(t, found[0].GetVersion(), "extra line")
}

// A tool that is not on the PATH is simply absent, not an error and not an
// empty entry.
func TestProbe_MissingToolIsOmitted(t *testing.T) {
	p := &host.Prober{
		Tools:    []host.Tool{{Name: "definitely-not-installed"}},
		LookPath: func(string) (string, error) { return "", exec.ErrNotFound },
	}
	assert.Empty(t, p.Probe(context.Background()))
}

// A tool present but broken is reported as present. The model choosing a
// sandbox cares that cargo exists more than it cares about the version string.
func TestProbe_BrokenToolReportsPresence(t *testing.T) {
	var calls atomic.Int64
	p := &host.Prober{
		Tools:    []host.Tool{{Name: "cargo"}},
		LookPath: func(string) (string, error) { return "/usr/bin/cargo", nil },
		Run: func(context.Context, string, []string) ([]byte, error) {
			calls.Add(1)
			return nil, errors.New("exit status 127")
		},
	}

	found := p.Probe(context.Background())
	require.Len(t, found, 1)
	assert.Equal(t, "cargo", found[0].GetName())
	assert.Equal(t, "/usr/bin/cargo", found[0].GetPath())
	assert.Empty(t, found[0].GetVersion())
	assert.EqualValues(t, 1, calls.Load())
}

// The defaults name the tools issue #5 asks for.
func TestDefaultTools(t *testing.T) {
	var names []string
	for _, tool := range host.DefaultTools {
		names = append(names, tool.Name)
		assert.NotEmpty(t, tool.Args, "every tool needs the arguments that make it print a version")
	}
	assert.Equal(t, []string{"go", "node", "python3", "cargo", "docker", "git"}, names)

	// `docker version` talks to the daemon and blocks when it is wedged;
	// `docker --version` is the client's own version and does not.
	for _, tool := range host.DefaultTools {
		if tool.Name == "docker" {
			assert.Equal(t, []string{"--version"}, tool.Args)
		}
	}
}

// A real sweep over the real PATH finishes inside the default budget.
func TestProbe_DefaultsFinishPromptly(t *testing.T) {
	p := host.NewProber()
	start := time.Now()
	found := p.Probe(context.Background())
	assert.Less(t, time.Since(start), host.DefaultProbeBudget+2*time.Second)

	for _, tc := range found {
		assert.NotEmpty(t, tc.GetName())
		assert.False(t, strings.Contains(tc.GetVersion(), "\n"), "a version must be a single line")
	}
}

// The probe environment carries PATH and nothing that identifies a user or
// holds a credential — and, on Windows, the handful of variables a process
// cannot start without.
//
// A bare PATH is correct on Unix and wrong on Windows: a child launched without
// SystemRoot fails to initialise, so every toolchain on every Windows host
// would be reported as present-but-unversioned. The allowlist is asserted here
// on every platform because that failure cannot be reproduced on the ones CI
// mostly runs.
func TestProbeEnv_PassesPathAndNothingSecret(t *testing.T) {
	values := map[string]string{
		"PATH":                  "/usr/bin",
		"SystemRoot":            `C:\Windows`,
		"windir":                `C:\Windows`,
		"COMSPEC":               `C:\Windows\system32\cmd.exe`,
		"PATHEXT":               ".COM;.EXE",
		"NUMBER_OF_PROCESSORS":  "8",
		"TEMP":                  `C:\Temp`,
		"TMP":                   `C:\Temp`,
		"AWS_SECRET_ACCESS_KEY": "hunter2",
		"GITHUB_TOKEN":          "ghp_hunter2",
		"HOME":                  "/root",
	}
	env := host.BuildProbeEnvForTest(func(name string) string { return values[name] })

	assert.Contains(t, env, "PATH=/usr/bin")
	for _, secret := range []string{"AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "HOME"} {
		for _, entry := range env {
			assert.False(t, strings.HasPrefix(entry, secret+"="),
				"the daemon's environment must not reach a version probe: %s", entry)
		}
	}

	// Whatever this platform's allowlist names is passed through when set, and
	// omitted when not.
	for _, name := range host.ProbePassthroughForTest() {
		if values[name] == "" {
			continue
		}
		assert.Contains(t, env, name+"="+values[name],
			"%s must reach the child on this platform", name)
	}
	if runtime.GOOS == "windows" {
		assert.Contains(t, host.ProbePassthroughForTest(), "SystemRoot",
			"a Windows child started without SystemRoot fails to initialise")
	}

	// Nothing is emitted for a variable that is not set.
	empty := host.BuildProbeEnvForTest(func(string) string { return "" })
	assert.Equal(t, []string{"PATH="}, empty)
}

func manyTools(n int) []host.Tool {
	tools := make([]host.Tool, 0, n)
	for i := 0; i < n; i++ {
		tools = append(tools, host.Tool{Name: "tool" + string(rune('a'+i))})
	}
	return tools
}
