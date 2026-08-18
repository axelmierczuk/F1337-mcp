//go:build !windows

package fleetctl

import (
	"fmt"
	"os"
	"syscall"
)

// execHelper replaces this process with the helper.
//
// It returns only on failure. Everything the operator's shell knows about this
// command — the pid it will signal, the process group the terminal sends
// SIGINT to, the job it will `wait` on — goes on referring to the program that
// is now drawing, because it is the same process. A child would have broken all
// three, and the end-to-end scenario notices: it records `stty -g` around a run
// it kills by pid, which with a wrapper in the way would kill the wrapper and
// read the terminal state of a view still running.
func execHelper(path string, args []string) error {
	argv := append([]string{path}, args...)
	// The path is not operator input: findHelper resolves it to a file named
	// fleet-tui in this binary's own directory, or on PATH, and there is
	// deliberately no environment variable that can redirect it. args is this
	// process's own command line, passed as argv rather than through a shell.
	if err := syscall.Exec(path, argv, os.Environ()); err != nil { //nolint:gosec // see above
		return fmt.Errorf("run %s: %w", path, err)
	}
	// Unreachable: a successful Exec does not return.
	return nil
}
