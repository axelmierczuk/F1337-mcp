package host

import (
	"bytes"
	"context"
	"os/exec"
	"strings"
	"time"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
)

// DefaultProbeBudget bounds the whole toolchain sweep, not each probe within
// it.
//
// Per-probe timeouts alone are not a bound: six tools that each hang for their
// own limit is six times the limit, and the caller waits for all of it. The
// budget is the promise GetHostInfo makes; the per-probe limit only stops one
// broken tool from eating it.
const DefaultProbeBudget = 3 * time.Second

// DefaultPerProbeTimeout bounds one `--version` invocation.
const DefaultPerProbeTimeout = 1500 * time.Millisecond

// Tool is a binary worth reporting the presence and version of, and the
// arguments that make it print one.
type Tool struct {
	Name string
	Args []string
}

// DefaultTools is the set named in issue #5: enough to tell whether a sandbox
// can build the project in front of the model.
//
// `docker --version` is the client's own version and does not talk to the
// daemon. `docker version` does, and on a host whose daemon is wedged it
// blocks — which is exactly the hang this budget exists to survive, so it is
// not worth walking into deliberately for a marginally better string.
var DefaultTools = []Tool{
	{Name: "go", Args: []string{"version"}},
	{Name: "node", Args: []string{"--version"}},
	{Name: "python3", Args: []string{"--version"}},
	{Name: "cargo", Args: []string{"--version"}},
	{Name: "docker", Args: []string{"--version"}},
	{Name: "git", Args: []string{"--version"}},
}

// Prober detects installed toolchains within a fixed time budget.
//
// The zero value is not usable; use NewProber. The LookPath and Run fields are
// injection points for tests, which need a binary that hangs on demand and
// cannot rely on one existing on every CI platform.
type Prober struct {
	// Tools is the set to probe. Nil means DefaultTools.
	Tools []Tool
	// Budget bounds the entire sweep. Zero means DefaultProbeBudget.
	Budget time.Duration
	// PerProbe bounds one invocation. Zero means DefaultPerProbeTimeout.
	PerProbe time.Duration

	// LookPath resolves a tool name to an absolute path. Nil means
	// exec.LookPath.
	LookPath func(string) (string, error)
	// Run executes a resolved tool and returns its version output. Nil means
	// runVersion.
	Run func(ctx context.Context, path string, args []string) ([]byte, error)
}

// NewProber returns a Prober with the defaults filled in.
func NewProber() *Prober {
	return &Prober{Tools: DefaultTools, Budget: DefaultProbeBudget, PerProbe: DefaultPerProbeTimeout}
}

// Probe returns the toolchains it could detect before the budget expired.
//
// It returns what it has rather than an error when time runs out. A partial
// answer is useful — the model can still see that Go is installed — and an
// error would tell the caller nothing except that one machine somewhere has a
// broken binary on its PATH.
//
// Probes run sequentially and in the order given, so a truncated result is a
// prefix rather than an arbitrary subset. Running them in parallel would fit
// more into the budget at the cost of spawning six processes at once on a host
// that is already struggling, which is not a trade worth making for a call
// whose output is advisory.
func (p *Prober) Probe(ctx context.Context) []*sandboxdv1.Toolchain {
	tools := p.Tools
	if tools == nil {
		tools = DefaultTools
	}
	budget := p.Budget
	if budget <= 0 {
		budget = DefaultProbeBudget
	}
	perProbe := p.PerProbe
	if perProbe <= 0 {
		perProbe = DefaultPerProbeTimeout
	}
	lookPath := p.LookPath
	if lookPath == nil {
		lookPath = exec.LookPath
	}
	run := p.Run
	if run == nil {
		run = runVersion
	}

	budgetCtx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	found := make([]*sandboxdv1.Toolchain, 0, len(tools))
	for _, tool := range tools {
		if budgetCtx.Err() != nil {
			break
		}
		path, err := lookPath(tool.Name)
		if err != nil {
			continue
		}

		probeCtx, cancelProbe := context.WithTimeout(budgetCtx, perProbe)
		out, err := run(probeCtx, path, tool.Args)
		cancelProbe()
		if err != nil {
			// The binary is on the PATH but would not tell us its version:
			// report that it exists, because the model choosing a sandbox
			// cares more about presence than about the string.
			found = append(found, &sandboxdv1.Toolchain{Name: tool.Name, Path: path})
			continue
		}
		found = append(found, &sandboxdv1.Toolchain{
			Name:    tool.Name,
			Version: firstLine(out),
			Path:    path,
		})
	}
	return found
}

// runVersion invokes a tool's version command with a minimal environment; see
// probeEnv for what is passed through and why.
func runVersion(ctx context.Context, path string, args []string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, path, args...) //nolint:gosec // path came from LookPath over the configured tool list
	cmd.Env = probeEnv()
	// A tool that ignores SIGKILL on its context cancellation would otherwise
	// keep Wait blocked past the deadline, which is the hang this bounds.
	cmd.WaitDelay = time.Second

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	// python3 historically printed its version to stderr, and some tools still
	// do; treat either stream as the answer.
	if stdout.Len() > 0 {
		return stdout.Bytes(), nil
	}
	return stderr.Bytes(), nil
}

func firstLine(out []byte) string {
	line, _, _ := bytes.Cut(out, []byte("\n"))
	return strings.TrimSpace(string(line))
}
