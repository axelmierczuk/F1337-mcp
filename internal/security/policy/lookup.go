package policy

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/axelmierczuk/sandboxd-mcp/internal/platform"
)

// ErrNotFound reports that argv[0] names no executable this agent can run. It
// carries the name and where it was looked for, because "exec: not found" with
// nothing else in it is the least useful error this service can return.
var ErrNotFound = errors.New("policy: executable not found")

// Command is a resolved command: what the caller asked to run, and what the
// kernel would actually execute.
type Command struct {
	// Argv is the argument vector as it will be passed to the OS. For a
	// shell-routed request this is the shell's argv, not the caller's — see
	// Resolve's documentation.
	Argv []string

	// Requested is argv[0] as the caller wrote it.
	Requested string

	// Path is the absolute, lexically cleaned path the lookup found. Empty
	// when nothing was found.
	Path string

	// Target is Path with symlinks resolved, which on most hosts is where
	// /bin/sh actually lands. Equal to Path when there is nothing to resolve,
	// and empty when the path could not be resolved.
	Target string
}

// Found reports whether an executable was located.
func (c Command) Found() bool { return c.Path != "" }

// maxArgvPrefixes bounds how many leading runs of the argv are offered as
// names. A rule naming a subcommand names it in the first few words; the cap
// keeps a caller from making rule matching quadratic by sending a thousand
// arguments.
const maxArgvPrefixes = 16

// names is every spelling of this command that a policy rule may match.
func (c Command) names() []string {
	names := make([]string, 0, 6+min(len(c.Argv), maxArgvPrefixes))
	add := func(s string) {
		if s != "" && !contains(names, s) {
			names = append(names, s)
		}
	}
	add(c.Requested)
	add(c.Path)
	add(filepath.Base(c.Path))
	add(c.Target)
	add(filepath.Base(c.Target))

	if len(c.Argv) > 1 {
		// Every leading run of the argv, so a rule can name a subcommand — "go
		// test", "git push" — and still match a command that carries arguments
		// after it.
		//
		// Prefixes rather than one joined line with a glob on the end, because
		// filepath.Match's * does not cross a path separator: "go test*"
		// matches "go test" and "go test -v", and not "go test ./...". A rule
		// about a subcommand is at its most useful for exactly the commands
		// whose arguments are paths, so a line-glob would work right up until
		// it mattered.
		line := c.Argv[0]
		for _, arg := range c.Argv[1:min(len(c.Argv), maxArgvPrefixes)] {
			line += " " + arg
			add(line)
		}
		// And the whole command line, which the cap above may have stopped
		// short of. add dedupes, so a short argv contributes it once.
		add(strings.Join(c.Argv, " "))
	}
	return names
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// describe renders the command for an error message, without dumping an
// argument list that may be long.
func (c Command) describe() string {
	if c.Path != "" && c.Path != c.Requested {
		return fmt.Sprintf("%s (%s)", c.Requested, c.Path)
	}
	return c.Requested
}

// Resolve locates the executable an argv names, the way the kernel will.
//
// name is resolved as follows:
//
//   - A name containing a path separator is taken as a path, made absolute
//     against dir — the working directory the command will run in, so a
//     relative argv[0] means what the caller thinks it means.
//   - Any other name is searched for in pathEnv, which is the PATH the child
//     will run with, not the daemon's. Those differ whenever a request sets
//     PATH in its environment, and looking up in one while executing in the
//     other is how a policy decision ends up being about a different file
//     than the one that runs.
//   - The working directory is never searched. os/exec has refused an
//     implicit "." since Go 1.19 for the reason that applies twice over here:
//     a caller who can write a file into the working directory could otherwise
//     choose which binary a bare name resolves to.
//
// pathExt is Windows's PATHEXT and is ignored elsewhere.
//
// A Command is returned even when nothing was found, so that a policy decision
// can still be made — and audited — against the name the caller asked for. Use
// Command.Found to tell the two apart; the error is ErrNotFound.
func Resolve(argv []string, dir, pathEnv, pathExt string) (Command, error) {
	if len(argv) == 0 || argv[0] == "" {
		return Command{}, errors.New("policy: argv is empty")
	}

	cmd := Command{Argv: argv, Requested: argv[0]}
	exts := extensions(pathExt)

	if strings.ContainsAny(argv[0], pathSeparators) {
		abs, err := platform.NormalizePath(dir, argv[0])
		if err != nil {
			return cmd, fmt.Errorf("policy: resolving %q: %w", argv[0], err)
		}
		found, ok := findExecutable(abs, exts)
		if !ok {
			return cmd, fmt.Errorf("%w: %q is not an executable file", ErrNotFound, argv[0])
		}
		cmd.Path = found
		cmd.Target = evalSymlinks(found)
		return cmd, nil
	}

	for _, entry := range filepath.SplitList(pathEnv) {
		if entry == "" {
			continue
		}
		abs, err := platform.NormalizePath(dir, entry)
		if err != nil {
			// A PATH entry the agent will not interpret — a UNC share, say —
			// is skipped rather than fatal: the rest of PATH is still usable,
			// and refusing the whole call would make one bad entry in an
			// inherited PATH break every command.
			continue
		}
		found, ok := findExecutable(filepath.Join(abs, argv[0]), exts)
		if !ok {
			continue
		}
		cmd.Path = found
		cmd.Target = evalSymlinks(found)
		return cmd, nil
	}

	return cmd, fmt.Errorf("%w: %q is not in PATH (%s)", ErrNotFound, argv[0], pathEnv)
}

// evalSymlinks returns path with symlinks resolved, or the path itself when
// they cannot be.
//
// A failure here is not an error: the policy decision is made against every
// name the command has, and losing one of them can only make a deny rule less
// likely to match — which the operator can see — where treating it as fatal
// would refuse a command for a reason that has nothing to do with the request.
func evalSymlinks(path string) string {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return path
	}
	return resolved
}
