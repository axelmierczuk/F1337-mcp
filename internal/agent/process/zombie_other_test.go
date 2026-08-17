//go:build !linux

package process

// zombieChildPIDs has nothing to report off Linux.
//
// A zombie is a Unix concept and Windows has no equivalent — a terminated
// process without an open handle is simply gone. macOS has them, but no
// readable process table: reading one costs a sysctl walk of every process on
// the machine and a per-process status decode, which is a lot of test-only
// platform code for the second-best place to make the assertion. Linux is
// where the evidence is cheap, and CI runs there.
//
// The portable half of the guarantee is
// TestManyShortLivedStartsLeaveNothingBehind, which asserts every one of a
// hundred children reached a terminal state — which it can only do if
// something waited on it.
func zombieChildPIDs() []int { return nil }

// pidIsZombie has nothing to report off Linux either. On Windows there is no
// such state; on macOS there is, but no cheap way to read it, and the
// whole-tree kill assertion that uses it runs on all three.
func pidIsZombie(int) bool { return false }
