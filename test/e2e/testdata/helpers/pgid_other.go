//go:build !unix

package main

// processGroup has no meaning off Unix: Windows isolates a process tree with a
// job object rather than a group, and the scenarios that read this number skip
// there. Zero, so the helper still builds on every platform the suite compiles
// it for.
func processGroup() int { return 0 }
