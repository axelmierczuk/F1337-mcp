package fleetagent

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

// profileVisibility is what a spawned command can see of the things the
// operator installed under their own profile.
type profileVisibility string

const (
	// profileUnknown means nothing was installed per-user for the probe to
	// look for. It is not a pass and not a failure: there is nothing to
	// conclude, and saying so is better than inventing either answer.
	profileUnknown profileVisibility = "unknown"
	// profileVisible means a per-user directory is on the PATH a spawned
	// command gets, and — when the probe recognised a program in it — that
	// program resolved to a file under the home directory and ran.
	profileVisible profileVisibility = "visible"
	// profileHidden means per-user toolchains are installed and none of the
	// directories holding them is on that PATH. This is the session-0 shape:
	// PATH is perfectly well populated, with the machine's directories only.
	profileHidden profileVisibility = "hidden"
)

// profileResult is the probe's answer, recorded verbatim in the runtime report.
type profileResult struct {
	Visibility profileVisibility `json:"visibility"`
	// Ran is the absolute path of the per-user program the probe resolved on
	// the PATH a spawned command would get, and then executed. Empty when
	// nothing the probe recognises was installed there.
	//
	// This field is the difference between "PATH is not empty" and "the agent
	// can run what the operator runs". A path here is a program that exists
	// only under a home directory, was found by name, and exited zero.
	Ran string `json:"ran,omitempty"`
	// Unreachable are the per-user directories that exist on disk and that
	// PATH does not reach — the ones an operator can act on.
	Unreachable []string `json:"unreachable,omitempty"`
}

// userToolchain is a program the probe knows how to run and what to pass it.
//
// The list is short on purpose. Executing something is what makes the answer
// worth anything, and the probe will only execute a program it recognises by
// name: a bin directory belongs to the operator, and running whatever happens
// to be in it is not a thing a daemon should do at startup.
type userToolchain struct {
	Name    string
	Version []string
}

// userToolchains are the per-user installs common enough to be worth probing
// for. Version arguments are the ones that print and exit.
var userToolchains = []userToolchain{
	{Name: "cargo", Version: []string{"--version"}},
	{Name: "rustc", Version: []string{"--version"}},
	{Name: "rustup", Version: []string{"--version"}},
	{Name: "node", Version: []string{"--version"}},
	{Name: "deno", Version: []string{"--version"}},
	{Name: "bun", Version: []string{"--version"}},
	{Name: "uv", Version: []string{"--version"}},
	{Name: "pyenv", Version: []string{"--version"}},
	{Name: "rbenv", Version: []string{"--version"}},
	{Name: "go", Version: []string{"version"}},
}

// userBinDirs are the directories a toolchain installs its commands into when
// it is installed for one user rather than for the machine, relative to that
// user's home directory.
//
// It is a heuristic and it is meant to be: the probe draws no conclusion from a
// directory that is absent, so a list that misses somebody's favourite version
// manager costs an "unknown" rather than a wrong answer. What it must not do is
// name a directory that is *not* per-user, because a machine-wide directory
// being off PATH would then read as a confined agent.
func userBinDirs(goos string) []string {
	if goos == "windows" {
		return []string{
			`.cargo\bin`,
			`go\bin`,
			`.local\bin`,
			`.bun\bin`,
			`.deno\bin`,
			`.volta\bin`,
			`.dotnet\tools`,
			`scoop\shims`,
			`.pyenv\pyenv-win\bin`,
			`.pyenv\pyenv-win\shims`,
			`AppData\Roaming\npm`,
			`AppData\Roaming\nvm`,
			`AppData\Local\pnpm`,
			`AppData\Local\Yarn\bin`,
			// Always on an interactive user's PATH and never on a service's,
			// which makes it the one entry here that every Windows account has.
			`AppData\Local\Microsoft\WindowsApps`,
		}
	}
	return []string{
		".cargo/bin",
		"go/bin",
		".local/bin",
		"bin",
		".bun/bin",
		".deno/bin",
		".volta/bin",
		".dotnet/tools",
		".npm-global/bin",
		".yarn/bin",
		".pyenv/shims",
		".rbenv/shims",
	}
}

// profileProbe answers one question: can a command this agent spawns reach what
// the operator installed under their own profile?
//
// PATH being non-empty proves nothing. A session-0 service has a PATH; it is
// the machine's, and that is exactly the failure. So the probe looks on disk
// first, for directories that only ever exist per-user, and only then asks
// whether the PATH a spawned command would get reaches them.
type profileProbe struct {
	// Home is the home directory to look under — the daemon's own, because the
	// daemon's home is the operator's precisely when the install is right.
	Home string
	// Path is the PATH a spawned command would be given.
	Path string
	// GOOS selects the directory list. Empty means runtime.GOOS.
	GOOS string
	// Budget bounds the whole probe. Zero means defaultProfileBudget.
	Budget time.Duration

	// Tools is the set of programs the probe may execute. Nil means
	// userToolchains.
	Tools []userToolchain
	// Run executes a resolved program and reports whether it worked. Nil means
	// runProbe. Injected so a test can assert what the probe chose to run
	// without depending on a toolchain being installed on the runner.
	Run func(ctx context.Context, path string, args []string) error
}

// defaultProfileBudget bounds the whole probe, including every program it
// executes. It runs on the daemon's start path, so it is not allowed to be the
// reason a service manager decides the daemon failed to start.
const defaultProfileBudget = 3 * time.Second

// probe returns what this agent can see of the per-user installs under Home.
func (p profileProbe) probe(ctx context.Context) profileResult {
	goos := p.GOOS
	if goos == "" {
		goos = runtime.GOOS
	}
	if p.Home == "" || isFilesystemRoot(p.Home) {
		return profileResult{Visibility: profileUnknown}
	}

	var present []string
	for _, rel := range userBinDirs(goos) {
		dir := filepath.Join(p.Home, filepath.FromSlash(strings.ReplaceAll(rel, `\`, "/")))
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			present = append(present, dir)
		}
	}
	if len(present) == 0 {
		return profileResult{Visibility: profileUnknown}
	}

	reachable, unreachable := splitByPath(present, p.Path, goos)
	if len(reachable) == 0 {
		sort.Strings(unreachable)
		return profileResult{Visibility: profileHidden, Unreachable: unreachable}
	}

	sort.Strings(unreachable)
	result := profileResult{Visibility: profileVisible, Unreachable: unreachable}
	if ran, ok := p.runOne(ctx, reachable, goos); ok {
		result.Ran = ran
	}
	return result
}

// runOne resolves a recognised program by name against the probe's PATH,
// checks that what it resolved to really is the copy under Home, and runs it.
//
// Resolving is not enough on its own. A directory can be on PATH and hold a
// file the account cannot execute, and on Windows a name resolves only if
// PATHEXT admits its extension — both of which produce an agent that finds the
// operator's toolchain and still cannot run it.
func (p profileProbe) runOne(ctx context.Context, reachable []string, goos string) (string, bool) {
	tools := p.Tools
	if tools == nil {
		tools = userToolchains
	}
	run := p.Run
	if run == nil {
		run = runProbe
	}
	budget := p.Budget
	if budget <= 0 {
		budget = defaultProfileBudget
	}
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	for _, tool := range tools {
		if ctx.Err() != nil {
			return "", false
		}
		if !existsIn(reachable, tool.Name, goos) {
			continue
		}
		resolved, err := lookPathIn(tool.Name, p.Path, goos)
		if err != nil {
			continue
		}
		// The whole claim is "a binary installed only under the home directory
		// is found and runs". A name that resolves to the machine-wide copy
		// proves the opposite, so it is not allowed to count.
		if !underDir(p.Home, resolved) {
			continue
		}
		if err := run(ctx, resolved, tool.Version); err != nil {
			continue
		}
		return resolved, true
	}
	return "", false
}

// runProbe executes a resolved program and reports whether it exited zero.
//
// The environment is deliberately the daemon's own: the question the probe asks
// is what a command spawned by *this process* can reach, and handing it a
// synthesised environment would answer a different one.
func runProbe(ctx context.Context, path string, args []string) error {
	cmd := exec.CommandContext(ctx, path, args...) //nolint:gosec // path is a recognised tool name resolved out of the probe's own PATH
	cmd.WaitDelay = time.Second
	return cmd.Run()
}

// splitByPath divides directories into the ones PATH reaches and the ones it
// does not.
func splitByPath(dirs []string, pathEnv, goos string) (reachable, unreachable []string) {
	onPath := map[string]bool{}
	for _, entry := range strings.Split(pathEnv, string(pathListSeparator(goos))) {
		if entry = strings.TrimSpace(entry); entry != "" {
			onPath[pathKey(entry, goos)] = true
		}
	}
	for _, dir := range dirs {
		if onPath[pathKey(dir, goos)] {
			reachable = append(reachable, dir)
		} else {
			unreachable = append(unreachable, dir)
		}
	}
	return reachable, unreachable
}

// pathKey normalises a directory for comparison. Windows paths fold and may be
// quoted in PATH; Unix paths do neither.
func pathKey(dir, goos string) string {
	dir = strings.Trim(dir, `"`)
	dir = filepath.Clean(dir)
	if goos == "windows" {
		return strings.ToLower(strings.TrimSuffix(dir, `\`))
	}
	return dir
}

func pathListSeparator(goos string) rune {
	if goos == "windows" {
		return ';'
	}
	return ':'
}

// windowsExts are the extensions a bare name may resolve to when PATHEXT is not
// readable. It is the Windows default, minus the scripting ones a probe has no
// business executing.
var windowsExts = []string{".com", ".exe", ".bat", ".cmd"}

// existsIn reports whether any of dirs holds a program called name.
func existsIn(dirs []string, name, goos string) bool {
	for _, dir := range dirs {
		for _, candidate := range nameCandidates(name, goos) {
			if info, err := os.Stat(filepath.Join(dir, candidate)); err == nil && !info.IsDir() {
				return true
			}
		}
	}
	return false
}

// nameCandidates is the filenames a bare command name can have on this
// platform.
func nameCandidates(name, goos string) []string {
	if goos != "windows" {
		return []string{name}
	}
	exts := windowsExts
	if fromEnv := os.Getenv("PATHEXT"); fromEnv != "" {
		exts = nil
		for _, ext := range strings.Split(fromEnv, ";") {
			if ext = strings.ToLower(strings.TrimSpace(ext)); ext != "" {
				exts = append(exts, ext)
			}
		}
	}
	out := make([]string, 0, len(exts))
	for _, ext := range exts {
		out = append(out, name+ext)
	}
	return out
}

// lookPathIn resolves a bare command name against an explicit PATH.
//
// os/exec cannot do this: exec.LookPath reads the current process's PATH, and
// the question here is about the PATH a command spawned by the daemon would
// get. Mutating the process environment to borrow LookPath would race every
// other goroutine in the daemon.
func lookPathIn(name, pathEnv, goos string) (string, error) {
	for _, dir := range strings.Split(pathEnv, string(pathListSeparator(goos))) {
		dir = strings.Trim(strings.TrimSpace(dir), `"`)
		if dir == "" {
			continue
		}
		for _, candidate := range nameCandidates(name, goos) {
			full := filepath.Join(dir, candidate)
			info, err := os.Stat(full)
			if err != nil || info.IsDir() {
				continue
			}
			if goos != "windows" && info.Mode().Perm()&0o111 == 0 {
				continue
			}
			return full, nil
		}
	}
	return "", exec.ErrNotFound
}

// isFilesystemRoot reports whether home is a volume root rather than somebody's
// home directory.
//
// Every question this probe asks is "is this thing under the home directory",
// and a root answers yes to all of them. HOME=/ makes $HOME/bin mean /bin — a
// machine directory that exists on every Unix and is on every PATH — so the
// probe finds a "per-user" install, finds it reachable, and reports the agent's
// environment as visible when nothing per-user is involved at all; underDir,
// the check that is supposed to catch exactly that, is vacuous against a root.
// The daemon then executes whichever of node, go or cargo happens to be in
// /bin, once per start, and calls it evidence.
//
// It is not hypothetical: a container started for a uid with no passwd entry
// gets HOME=/, and a service manager that starts the daemon without a home
// directory hands it whatever the account's entry says. A root is not a home,
// so there is nothing installed per-user under it to conclude anything from,
// and "unknown" is the honest answer.
//
// A pure function of the string, so the rule is assertable from every runner:
// a Windows drive root has to be recognised on a Linux one.
func isFilesystemRoot(home string) bool {
	trimmed := strings.TrimRight(strings.ReplaceAll(strings.TrimSpace(home), `\`, "/"), "/")
	if trimmed == "" {
		// "/", "\", "//" and friends: everything was separator.
		return home != ""
	}
	// "C:" — what "C:\" and "C:/" trim down to.
	return len(trimmed) == 2 && trimmed[1] == ':' &&
		(trimmed[0] >= 'a' && trimmed[0] <= 'z' || trimmed[0] >= 'A' && trimmed[0] <= 'Z')
}

// underDir reports whether path is inside dir.
func underDir(dir, path string) bool {
	rel, err := filepath.Rel(filepath.Clean(dir), filepath.Clean(path))
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
