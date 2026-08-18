package exec

import osexec "os/exec"

// ignoreTerm has nothing to ignore on Windows: there is no SIGTERM, and the
// agent's stop path terminates the job object, which a process cannot decline.
// The helper modes that call it exist so the argv is the same on every
// platform; the tests that use them are Unix-only.
func ignoreTerm() {}

// detachFromGroup has nothing to detach from on Windows: a grandchild is in the
// agent's job object whether it likes it or not, and closing the job is what
// terminates it. The helper mode that asks for this is Unix-only.
func detachFromGroup(*osexec.Cmd) {}
