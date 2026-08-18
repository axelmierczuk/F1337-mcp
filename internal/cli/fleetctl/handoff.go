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
//
// The order is the guarantee, and it is asserted: beside fleetctl is the only
// one of the two places that came out of the same archive, `make build` or
// `go install` as the binary doing the looking, so it answers first. What is
// left is a helper of a *different* version found on PATH — or beside a
// fleetctl that was upgraded on its own — being exec'd without a word. Nothing
// here detects that, and nothing cheap can: the version a binary reports is
// only knowable by running it, and running it is what we are deciding whether
// to do. A handshake through the environment would only ever catch a helper
// newer than the check, which is not the direction that hurts.
//
// One thing it does detect, because the failure is otherwise silent: a helper
// that is this same binary. See [isSameBinary].
func findHelper() (string, error) { return findHelperVia(runningBinary, exec.LookPath) }

// runningBinary is where this process's own binary is.
func runningBinary() (string, error) { return binaryFrom(os.Executable, os.Args) }

// binaryFrom is [runningBinary] with its two views of the outside world passed
// in, because neither can be arranged around a test.
//
// os.Executable is the answer, and argv[0] is the fallback for the hosts where
// it has none: on Linux it reads /proc/self/exe, which a chroot or a container
// image without /proc does not have. That fallback is not a convenience.
// Answering "I do not know" costs both halves of the lookup at once. It
// disables [isSameBinary] entirely — every candidate compares as "not me", and
// with it goes the guard against a fleetctl installed under the helper's name
// exec'ing itself for ever, which is the one failure this command exists to
// prevent and the one that leaves nothing on screen to read. And it skips the
// whole "beside fleetctl" half of [findHelperVia], which needs a directory to
// look in, so a helper sitting next to this binary is answered with the
// sentence saying it is *not* next to fleetctl. [execHelper] hands the resolved
// helper path over as argv[0], so on the far side of a hand-off argv[0] names
// exactly the file that was run and the second attempt refuses instead of
// making a third; see [helperArgv].
//
// Only when argv[0] names a path, which is execve's own rule: a command with a
// separator in it was resolved as a path, relative ones against this process's
// working directory — and nothing has changed that directory, because the
// hand-off is the first thing `tui` does, before the registry is opened. A bare
// `fleetctl` is not a path at all; it is a PATH lookup somebody else did, and
// resolving it here would make whatever the operator happens to be standing
// next to this process's identity. That one stays "I do not know", and the
// lookup still consults PATH for a real helper.
func binaryFrom(executable func() (string, error), args []string) (string, error) {
	if path, err := executable(); err == nil && path != "" {
		return path, nil
	}
	if len(args) > 0 && namesAPath(args[0]) {
		if path, err := filepath.Abs(args[0]); err == nil {
			return path, nil
		}
	}
	return "", errors.New("this host cannot say what binary is running")
}

// namesAPath reports whether arg0 is a path rather than a name that was looked
// up on PATH. See [binaryFrom] for why the difference decides anything.
func namesAPath(arg0 string) bool {
	for i := 0; i < len(arg0); i++ {
		if os.IsPathSeparator(arg0[i]) {
			return true
		}
	}
	return false
}

// findHelperVia is [findHelper] with its two views of the outside world passed
// in, because neither can be arranged around a test: [runningBinary] answers
// with the test binary, and PATH is the machine's.
func findHelperVia(executable func() (string, error), lookPath func(string) (string, error)) (string, error) {
	self, err := executable()
	if err != nil {
		self = ""
	}
	// Set to a candidate that was rejected only for being this binary, so the
	// refusal can name the file to delete rather than say "there is nothing
	// there" about a fleet-tui the operator can see.
	itself := ""
	if self != "" {
		// The resolved path too, and in this order: the directory the
		// operator's own invocation named answers first, and the target's is
		// the fallback that makes a managed install work — a package manager
		// symlinks fleetctl into a bin directory and leaves the helper beside
		// the *target*, not beside the link. Ordinary installs have one
		// directory and both agree; when they differ, the one the invocation
		// named is the one the operator can see.
		candidates := []string{self}
		if resolved, err := filepath.EvalSymlinks(self); err == nil && resolved != self {
			candidates = append(candidates, resolved)
		}
		for _, c := range candidates {
			beside := filepath.Join(filepath.Dir(c), exeName(helperName))
			if !isExecutableFile(beside) {
				continue
			}
			// continue, not a refusal: a real helper on PATH is still found
			// and used. The mistake this catches is one file being wrong, not
			// the install being unusable, and refusing here would turn a
			// packager's `cp` into "you have no fleet-tui" on a machine that
			// has one. Pinned, because reversing it is invisible otherwise:
			// see TestARealHelperOnPathIsUsedWhenTheOneBesideFleetctlIsThisBinary.
			if isSameBinary(self, beside) {
				// The first of the two directories, for the same reason the
				// lookup itself tries them in this order: an operator can see
				// the directory their own invocation named and has no reason to
				// know what it resolves to. Overwriting here named the target's
				// copy and sent them looking in a tree they never installed.
				if itself == "" {
					itself = beside
				}
				continue
			}
			return beside, nil
		}
	}
	// err == nil, not "a path came back": exec.LookPath answers with a path
	// *and* an error for a match found through a relative PATH entry, "."
	// among them. A CLI that holds the operator's control key does not exec
	// whatever the working directory happens to contain.
	if path, err := lookPath(helperName); err == nil {
		if !isSameBinary(self, path) {
			return path, nil
		}
		// The same mistake one directory further out, and it has to be
		// recorded here too: a fleetctl whose only fleet-tui is on PATH and is
		// itself would otherwise be told there is nothing there, about a file
		// it can see. Recorded rather than returned, because the beside
		// candidate names the install the operator is likelier to have made.
		if itself == "" {
			itself = path
		}
	}
	if itself != "" {
		return "", fmt.Errorf(
			"%w, and the %s at %s is this same binary. A copy, a rename or a symlink of "+
				"fleetctl does not draw the view — the view is linked into a different program. "+
				"Install it: `go install github.com/axelmierczuk/fleet-mcp/cmd/%s@latest`. "+
				"`fleetctl list` and `fleetctl info` need nothing extra",
			errNoHelper, helperName, itself, helperName)
	}
	return "", fmt.Errorf(
		"%w, which draws the view, and it is not next to fleetctl or on PATH. "+
			"It ships in the same archive as fleetctl; from source: "+
			"`go install github.com/axelmierczuk/fleet-mcp/cmd/%s@latest`. "+
			"`fleetctl list` and `fleetctl info` need nothing extra",
		errNoHelper, helperName)
}

// helperArgv is the command line the helper is handed.
//
// argv[0] is the resolved path and not the helper's own name, and that is a
// guard rather than a convention. On a host where os.Executable has no answer —
// a chroot, a container image built without /proc — argv[0] is the only thing
// the process on the far side can name itself from, and [binaryFrom] takes it
// only when it names a path. Hand a bare name over and [isSameBinary] answers
// "not me" about every candidate there, so a fleetctl installed under the
// helper's name execs itself, and the process that replaces it knows no better
// and does it again: the loop, on the one class of host where nothing on screen
// would ever say why.
//
// A function rather than a line inside each [execHelper] because there are two
// of those, and because nothing that runs on an ordinary host notices when it
// is wrong: os.Executable answers there, before argv[0] is ever consulted, so
// every scenario in this repository stays green either way. See
// TestTheHandOffHandsTheFarSideAnIdentityItCanUse, which is the join between
// the half that chooses argv[0] and the half that reads it.
func helperArgv(path string, args []string) []string {
	return append([]string{path}, args...)
}

// isSameBinary reports whether path is the binary that is running.
//
// It is not a helper if it is us. A fleetctl installed under the helper's name
// — a copy, a rename, or a symlink made by someone who read "fleet-tui is
// fleetctl's own command tree" as "the same binary" — finds itself beside
// itself and execs itself, and then does it again: same pid, no output, no
// error, no view, for ever. Exec is exactly what makes it invisible, since
// there is no child to notice and no exit for the operator's shell to report;
// what they see is `fleetctl tui` hanging on a terminal, which is the failure
// this whole command was split out to stop.
//
// By name first, because that is the case: dir/fleet-tui found from
// dir/fleet-tui is the same string. os.SameFile after it, for the hard link
// and the symlink into another directory, which are the same file under two
// names.
//
// A plain `cp` is the one shape this cannot see from here — a copy is a
// different file at a different path, and telling it from a real helper would
// mean running it, which is the decision being made. It is caught one exec
// later instead, by the copy's own [runningBinary] naming the very file the
// lookup is about to choose again, and that is not luck on either kind of host:
// where os.Executable answers it names the file that was exec'd, and where it
// does not, [helperArgv] has put that same path in argv[0]. One hand-off
// happens, the second is refused, and the operator gets the sentence rather
// than a process that never comes back —
// TestAFleetctlCopiedToItsHelpersNameRefusesInsteadOfLooping drives exactly
// that, from a shell.
func isSameBinary(self, path string) bool {
	if self == "" || path == "" {
		return false
	}
	if self == path {
		return true
	}
	selfInfo, err := os.Stat(self)
	if err != nil {
		return false
	}
	pathInfo, err := os.Stat(path)
	if err != nil {
		return false
	}
	return os.SameFile(selfInfo, pathInfo)
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
