package shell

import "golang.org/x/sys/windows"

// stillActive is STILL_ACTIVE, the exit code Windows reports for a process that
// has not exited.
const stillActive = 259

// processRunning reports whether a pid names a process that is still running.
//
// It cannot be platform.ProcessExists here, and the difference is the whole
// reason this file exists. A Windows process object outlives the process while
// any handle to it is open, and its pid stays resolvable for exactly that long
// — which is deliberate in ProcessExists, whose job is to say whether a pid
// could still be confused with a later process. A test asking "did the tree
// die" would get "yes it still exists" for a process that has been terminated
// and merely not let go of, and would then fail for a reason that has nothing
// to do with the product.
//
// The exit code is the answer to the question actually being asked. A process
// whose own exit status happens to be 259 reads as running, which is a wart in
// the Windows API rather than in this check and is the safe direction to be
// wrong in: a test would wait a little longer and then fail, rather than
// passing while something survived.
func processRunning(pid int) bool {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid)) //nolint:gosec // a pid from the process under test
	if err != nil {
		// No such process object at all: it exited and nothing is holding it.
		return false
	}
	defer func() { _ = windows.CloseHandle(h) }()

	var code uint32
	if err := windows.GetExitCodeProcess(h, &code); err != nil {
		return false
	}
	return code == stillActive
}
