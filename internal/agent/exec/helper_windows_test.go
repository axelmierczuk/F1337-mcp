package exec

// ignoreTerm has nothing to ignore on Windows: there is no SIGTERM, and the
// agent's stop path terminates the job object, which a process cannot decline.
// The helper modes that call it exist so the argv is the same on every
// platform; the tests that use them are Unix-only.
func ignoreTerm() {}
