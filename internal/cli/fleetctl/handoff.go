package fleetctl

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// Handing `fleetctl tui` to the one binary that links a terminal UI.
//
// See the head of tui.go for why there are two binaries at all. What matters
// here is that there is only one *command*: the operator types `fleetctl tui`,
// and this file makes that reach the view. fleet-tui is not a second thing to
// learn, a second thing to point at a fleet, or a second place a credential can
// be configured — it is fleetctl's own command tree, built from this same
// package, with the view linked in. Which is why the argv is forwarded
// unchanged rather than rebuilt from parsed flags: a re-serialised command line
// is a second implementation of every flag this command takes, and the first
// one to drift would do it silently.

// helperName is the binary that links the view. It ships in the same archive as
// fleetctl and fleet-mcp, and `make build` puts it in the same directory.
const helperName = "fleet-tui"

// errNoHelper is what a fleetctl that cannot find its helper fails with.
var errNoHelper = errors.New("fleetctl tui needs " + helperName)

// handOff replaces this process with the helper, passing it this process's
// command line unchanged.
//
// On Unix it does not return: the helper *is* this process afterwards, same
// pid, same process group, same controlling terminal. That is not an
// optimisation. `fleetctl tui` promises the terminal is restored on every exit
// path including a signal, and a wrapper process sitting between the operator's
// shell and the program that owns the terminal is one more place that promise
// can be broken — a SIGKILL to the pid the shell knows about would leave the
// view running on a terminal nothing will put back. There is nothing to flush
// or close before it: the hand-off happens before the registry is opened and
// before any agent is dialled.
//
// Windows has no exec, so there the helper is a child and this process waits
// for it. See handoff_windows.go.
func handOff(args []string) error {
	path, err := findHelper()
	if err != nil {
		return err
	}
	return execHelper(path, args)
}

// findHelper locates the helper the way an installed layout puts it: next to
// fleetctl, and failing that on PATH.
//
// Both, because both are real. `go install` and the fleet-tools archive put the
// two binaries in one directory, which is the case "next to fleetctl" covers
// without consulting anything the operator could get wrong. A distribution that
// splits them across directories is what PATH is for.
//
// There is deliberately no third way — no environment variable naming the
// helper. #44 chose one command over two so that there would not be a second
// place to get a fleet's configuration wrong, and a variable that decides which
// binary a credential-holding CLI execs would be exactly that, with a worse
// failure than a misconfiguration.
func findHelper() (string, error) { return findHelperVia(os.Executable, exec.LookPath) }

// findHelperVia is [findHelper] with its two views of the outside world passed
// in, because neither can be arranged around a test: os.Executable answers with
// the test binary, and PATH is the machine's.
func findHelperVia(executable func() (string, error), lookPath func(string) (string, error)) (string, error) {
	self, err := executable()
	if err == nil {
		// The resolved path too: an install that symlinks fleetctl into a bin
		// directory leaves the helper beside the *target*, not beside the link.
		candidates := []string{self}
		if resolved, err := filepath.EvalSymlinks(self); err == nil && resolved != self {
			candidates = append(candidates, resolved)
		}
		for _, c := range candidates {
			beside := filepath.Join(filepath.Dir(c), exeName(helperName))
			if isExecutableFile(beside) {
				return beside, nil
			}
		}
	}
	if path, err := lookPath(helperName); err == nil {
		return path, nil
	}
	return "", fmt.Errorf(
		"%w, which draws the view, and it is not next to fleetctl or on PATH. "+
			"It ships in the same archive as fleetctl; from source: "+
			"`go install github.com/axelmierczuk/fleet-mcp/cmd/%s@latest`. "+
			"`fleetctl list` and `fleetctl info` need nothing extra",
		errNoHelper, helperName)
}

// isExecutableFile reports whether path is something this process could exec.
//
// A directory named fleet-tui, or a file with the bit unset, is not a helper —
// and answering "found" for one of those turns a clear message about a missing
// binary into an exec failure from the operating system.
func isExecutableFile(path string) bool {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false
	}
	// Windows decides by extension, and exeName has already applied it.
	if runtime.GOOS == "windows" {
		return true
	}
	return info.Mode().Perm()&0o111 != 0
}

// exeName is the file name a binary has on this platform.
func exeName(name string) string {
	if runtime.GOOS == "windows" {
		return name + ".exe"
	}
	return name
}
