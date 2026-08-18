package platform

// releasePTYChildEnd has nothing to release on Windows. See the portable
// declaration: a ConPTY hands the child a pseudo-console rather than a
// descriptor the parent also holds, so there is no second end to give up, and
// the output pipe ends when the pseudo-console is closed.
func releasePTYChildEnd(PTY) error { return nil }
