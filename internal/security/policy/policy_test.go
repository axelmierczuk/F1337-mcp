package policy_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/axelmierczuk/sandboxd-mcp/internal/security/policy"
)

func TestNew_DefaultIsAllowAll(t *testing.T) {
	p, err := policy.New(policy.Config{})
	require.NoError(t, err)
	require.False(t, p.Restricted(), "an agent with no lists runs whatever it is asked to, and says so")

	require.NoError(t, p.Check(policy.Command{Argv: []string{"rm"}, Requested: "rm", Path: "/bin/rm", Target: "/bin/rm"}))
}

func TestNew_RefusesRulesItCouldNotEnforce(t *testing.T) {
	for name, cfg := range map[string]policy.Config{
		"empty deny entry":   {Deny: []string{"rm", ""}},
		"blank deny entry":   {Deny: []string{"   "}},
		"empty allow entry":  {Allow: []string{""}},
		"malformed pattern":  {Deny: []string{"rm[a-"}},
		"default over max":   {Caps: policy.Caps{DefaultTimeout: time.Hour, MaxTimeout: time.Minute}},
		"malformed in allow": {Allow: []string{"[["}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := policy.New(cfg)
			require.Error(t, err, "a rule that can never match must not be accepted silently")
		})
	}
}

func TestEvaluate_MatchesTheResolvedPathNotTheStringAsGiven(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the /bin/../bin/sh spelling is a POSIX path; the Windows equivalent is covered by TestResolve_*")
	}

	p, err := policy.New(policy.Config{Deny: []string{"sh"}})
	require.NoError(t, err)

	// What a caller would send to walk past a naive deny list. Resolve cleans
	// it to /bin/sh, whose base name is what the rule names.
	cmd, err := policy.Resolve([]string{"/bin/../bin/sh", "-c", "true"}, "/", os.Getenv("PATH"), "")
	require.NoError(t, err)
	require.Equal(t, "/bin/sh", cmd.Path)

	decision := p.Evaluate(cmd)
	require.False(t, decision.Allowed)
	require.Equal(t, "sh", decision.Rule)
}

func TestEvaluate_DenyBeatsAllow(t *testing.T) {
	p, err := policy.New(policy.Config{Allow: []string{"tool"}, Deny: []string{"tool"}})
	require.NoError(t, err)

	decision := p.Evaluate(policy.Command{Argv: []string{"tool"}, Requested: "tool", Path: "/usr/bin/tool"})
	require.False(t, decision.Allowed)
	require.Equal(t, "tool", decision.Rule)
}

func TestEvaluate_AllowListRefusesWhatItDoesNotName(t *testing.T) {
	p, err := policy.New(policy.Config{Allow: []string{"/usr/bin/make", "go"}})
	require.NoError(t, err)

	require.True(t, p.Evaluate(policy.Command{Requested: "make", Path: "/usr/bin/make"}).Allowed)
	require.True(t, p.Evaluate(policy.Command{Requested: "go", Path: "/usr/local/go/bin/go"}).Allowed)

	refused := p.Evaluate(policy.Command{Requested: "curl", Path: "/usr/bin/curl"})
	require.False(t, refused.Allowed)
	require.Contains(t, refused.Reason, "allow list")
	require.Contains(t, refused.Reason, "curl")
}

func TestEvaluate_MatchesTheSymlinkTarget(t *testing.T) {
	p, err := policy.New(policy.Config{Deny: []string{"dash"}})
	require.NoError(t, err)

	// /bin/sh on a Debian host: the name says sh, the file is dash. A deny
	// list naming either one has to catch it.
	cmd := policy.Command{Requested: "sh", Path: "/bin/sh", Target: "/usr/bin/dash"}
	decision := p.Evaluate(cmd)
	require.False(t, decision.Allowed)
	require.Equal(t, "dash", decision.Rule)
}

func TestEvaluate_MatchesGlobsAndFullArgv(t *testing.T) {
	p, err := policy.New(policy.Config{Deny: []string{"/usr/sbin/*", "git push"}})
	require.NoError(t, err)

	require.False(t, p.Evaluate(policy.Command{Requested: "shutdown", Path: "/usr/sbin/shutdown"}).Allowed)
	require.True(t, p.Evaluate(policy.Command{Requested: "git", Path: "/usr/bin/git", Argv: []string{"git", "status"}}).Allowed)

	pushed := p.Evaluate(policy.Command{Requested: "git", Path: "/usr/bin/git", Argv: []string{"git", "push"}})
	require.False(t, pushed.Allowed, "a rule may name a subcommand as well as an executable")
	require.Equal(t, "git push", pushed.Rule)
}

func TestTimeout_DefaultsAndCeiling(t *testing.T) {
	p, err := policy.New(policy.Config{Caps: policy.Caps{
		DefaultTimeout: 30 * time.Second,
		MaxTimeout:     time.Minute,
	}})
	require.NoError(t, err)

	got, err := p.Timeout(0)
	require.NoError(t, err)
	require.Equal(t, 30*time.Second, got, "zero means the agent default")

	got, err = p.Timeout(10 * time.Second)
	require.NoError(t, err)
	require.Equal(t, 10*time.Second, got)

	_, err = p.Timeout(time.Hour)
	require.ErrorIs(t, err, policy.ErrTimeoutTooLong)
	require.Contains(t, err.Error(), "1m0s", "the error names the maximum, so the caller can ask for something it will get")

	_, err = p.Timeout(-time.Second)
	require.Error(t, err)
}

func TestOutputCap_ClampsRatherThanRefusing(t *testing.T) {
	p, err := policy.New(policy.Config{Caps: policy.Caps{MaxOutputBytes: 1024}})
	require.NoError(t, err)

	require.EqualValues(t, 1024, p.OutputCap(0), "zero means the agent default")
	require.EqualValues(t, 512, p.OutputCap(512), "a smaller request is honoured")
	require.EqualValues(t, 1024, p.OutputCap(1<<30),
		"a larger one is clamped, and the truncation in the result is what reports it")

	unlimited, err := policy.New(policy.Config{})
	require.NoError(t, err)
	require.EqualValues(t, 0, unlimited.OutputCap(0), "no cap configured means no cap")
}

func TestAcquire_BoundsConcurrencyCentrally(t *testing.T) {
	p, err := policy.New(policy.Config{Caps: policy.Caps{MaxConcurrent: 2}})
	require.NoError(t, err)

	first, err := p.Acquire(context.Background())
	require.NoError(t, err)
	second, err := p.Acquire(context.Background())
	require.NoError(t, err)
	require.Equal(t, 2, p.InUse())

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err = p.Acquire(ctx)
	require.ErrorIs(t, err, policy.ErrTooManyProcesses)

	first()
	first() // releasing twice must not hand out a slot nobody holds
	require.Equal(t, 1, p.InUse())

	third, err := p.Acquire(context.Background())
	require.NoError(t, err)
	second()
	third()
	require.Equal(t, 0, p.InUse())
}

func TestAcquire_UnboundedWhenUnset(t *testing.T) {
	p, err := policy.New(policy.Config{})
	require.NoError(t, err)

	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			release, err := p.Acquire(context.Background())
			if err == nil {
				release()
			}
		}()
	}
	wg.Wait()
}

// --- resolution -----------------------------------------------------------

func TestResolve_FindsAnExecutableOnPath(t *testing.T) {
	dir := t.TempDir()
	name, script := writeExecutable(t, dir, "tool")

	cmd, err := policy.Resolve([]string{name}, dir, dir, ".bat;.exe")
	require.NoError(t, err)
	require.True(t, cmd.Found())
	require.Equal(t, script, cmd.Path)
}

func TestResolve_ResolvesARelativeCommandAgainstTheWorkingDirectory(t *testing.T) {
	dir := t.TempDir()
	name, script := writeExecutable(t, dir, "tool")

	cmd, err := policy.Resolve([]string{"." + string(filepath.Separator) + name}, dir, "", ".bat;.exe")
	require.NoError(t, err)
	require.Equal(t, script, cmd.Path, "a relative argv[0] means what the caller thinks it means: relative to working_dir")
}

func TestResolve_DoesNotSearchTheWorkingDirectoryForABareName(t *testing.T) {
	dir := t.TempDir()
	name, _ := writeExecutable(t, dir, "tool")

	// PATH deliberately empty: a bare name must not pick up a file that
	// happens to be sitting in the working directory, or a caller who can
	// write there chooses which binary a command resolves to.
	_, err := policy.Resolve([]string{name}, dir, "", ".bat;.exe")
	require.ErrorIs(t, err, policy.ErrNotFound)
}

func TestResolve_MissingCommandStillReturnsSomethingToAudit(t *testing.T) {
	cmd, err := policy.Resolve([]string{"definitely-not-here"}, t.TempDir(), "", "")
	require.ErrorIs(t, err, policy.ErrNotFound)
	require.Contains(t, err.Error(), "definitely-not-here", "the error names the command, not just 'not found'")
	require.False(t, cmd.Found())
	require.Equal(t, "definitely-not-here", cmd.Requested,
		"a command that does not exist is still evaluated and audited under the name that was asked for")
}

func TestResolve_RefusesAnEmptyArgv(t *testing.T) {
	_, err := policy.Resolve(nil, "", "", "")
	require.Error(t, err)
}

func TestResolve_ADirectoryIsNotAnExecutable(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "subdir")
	require.NoError(t, os.Mkdir(sub, 0o750))

	_, err := policy.Resolve([]string{sub}, dir, "", "")
	require.ErrorIs(t, err, policy.ErrNotFound)
}

// writeExecutable creates a runnable file and returns the name to ask for and
// the path it must resolve to.
func writeExecutable(t *testing.T, dir, base string) (name, path string) {
	t.Helper()
	name = base
	if runtime.GOOS == "windows" {
		name = base + ".bat"
	}
	path = filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o700))
	return name, path
}
