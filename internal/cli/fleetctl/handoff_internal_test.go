package fleetctl

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

// Finding the binary `fleetctl tui` hands the terminal to.
//
// Two places, in this order, and nothing else — see [findHelper]. What the
// order buys is that the ordinary installs need no configuration at all: `go
// install` and the fleet-tools archive both put fleetctl and its helper in one
// directory, so "next to me" answers before PATH is consulted and before
// anything an operator could get wrong is involved.

// writeHelper puts an executable file named like the helper into dir.
func writeHelper(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, exeName(helperName))
	require.NoError(t, os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755)) //nolint:gosec // a fixture standing in for an installed binary
	return path
}

// noPath is a PATH lookup that finds nothing, for the cases that must be
// answered without one.
func noPath(string) (string, error) { return "", errors.New("not on PATH") }

func TestTheHelperIsFoundNextToFleetctl(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	want := writeHelper(t, dir)
	self := filepath.Join(dir, exeName("fleetctl"))

	got, err := findHelperVia(func() (string, error) { return self, nil }, noPath)
	require.NoError(t, err)
	require.Equal(t, want, got, "the helper beside fleetctl was not the one chosen")
}

// TestTheHelperIsFoundBesideTheRealFleetctlThroughASymlink.
//
// An install that symlinks fleetctl into a bin directory — which is what a
// package manager does — leaves the helper beside the target, not beside the
// link. Answering only for the link's own directory would make `fleetctl tui`
// fail on exactly the installs that are managed rather than unpacked by hand.
func TestTheHelperIsFoundBesideTheRealFleetctlThroughASymlink(t *testing.T) {
	t.Parallel()

	installed := t.TempDir()
	want := writeHelper(t, installed)
	target := filepath.Join(installed, exeName("fleetctl"))
	require.NoError(t, os.WriteFile(target, []byte("#!/bin/sh\n"), 0o755)) //nolint:gosec // as above

	link := filepath.Join(t.TempDir(), exeName("fleetctl"))
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("this host does not allow symlinks: %v", err)
	}

	got, err := findHelperVia(func() (string, error) { return link, nil }, noPath)
	require.NoError(t, err)
	// Compared after resolving, because that is what the lookup did: macOS
	// puts the temporary directory itself behind a symlink (/var -> /private/var),
	// so the literal strings differ while naming one file.
	require.Equal(t, evaluated(t, want), evaluated(t, got))
}

// evaluated is path with every symlink on it resolved.
func evaluated(t *testing.T, path string) string {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(path)
	require.NoError(t, err)
	return resolved
}

// TestTheHelperIsFoundOnPathWhenItIsNotBesideFleetctl covers the distribution
// that splits the two across directories.
func TestTheHelperIsFoundOnPathWhenItIsNotBesideFleetctl(t *testing.T) {
	t.Parallel()

	elsewhere := writeHelper(t, t.TempDir())
	self := filepath.Join(t.TempDir(), exeName("fleetctl"))

	got, err := findHelperVia(
		func() (string, error) { return self, nil },
		func(name string) (string, error) {
			require.Equal(t, helperName, name, "something other than the helper was looked up")
			return elsewhere, nil
		})
	require.NoError(t, err)
	require.Equal(t, elsewhere, got)
}

// TestADirectoryNamedLikeTheHelperIsNotTheHelper.
//
// Anything that exists is not a binary that can be executed, and answering
// "found" for a directory turns a message naming the missing binary and the
// command that installs it into an exec failure from the operating system.
func TestADirectoryNamedLikeTheHelperIsNotTheHelper(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(dir, exeName(helperName)), 0o755))
	self := filepath.Join(dir, exeName("fleetctl"))

	_, err := findHelperVia(func() (string, error) { return self, nil }, noPath)
	require.ErrorIs(t, err, errNoHelper)
}

// TestAMissingHelperSaysWhatIsMissingAndHowToGetIt.
//
// This is the one new way `fleetctl tui` can fail, and it is a failure an
// operator meets on a workstation where `fleetctl` alone was installed. It has
// to name the binary, say where it was looked for, and give the command that
// produces it — and say that the rest of the CLI is unaffected, because the
// obvious reading of "fleetctl is missing something" is that the install is
// broken.
func TestAMissingHelperSaysWhatIsMissingAndHowToGetIt(t *testing.T) {
	t.Parallel()

	self := filepath.Join(t.TempDir(), exeName("fleetctl"))
	_, err := findHelperVia(func() (string, error) { return self, nil }, noPath)

	require.ErrorIs(t, err, errNoHelper)
	for _, want := range []string{
		helperName,
		"next to fleetctl or on PATH",
		"go install github.com/axelmierczuk/fleet-mcp/cmd/fleet-tui@latest",
		"`fleetctl list` and `fleetctl info` need nothing extra",
	} {
		require.Containsf(t, err.Error(), want, "the refusal does not say %q", want)
	}
}

// TestTheHelperIsStillLookedForWhenThisProcessCannotNameItself.
//
// os.Executable fails on hosts where /proc is not mounted, and a fleetctl that
// gave up there would be a `fleetctl tui` that cannot run on them at all —
// even with the helper on PATH, which is the case that does not depend on
// knowing where this binary is.
func TestTheHelperIsStillLookedForWhenThisProcessCannotNameItself(t *testing.T) {
	t.Parallel()

	elsewhere := writeHelper(t, t.TempDir())
	got, err := findHelperVia(
		func() (string, error) { return "", errors.New("no such thing on this host") },
		func(string) (string, error) { return elsewhere, nil })
	require.NoError(t, err)
	require.Equal(t, elsewhere, got)
}

// TestTheHelperBesideFleetctlIsPreferredToOneOnPath pins the order, which
// neither of the two tests above does.
//
// Each of them arranges for exactly one of the two places to answer — one
// passes a PATH that finds nothing, the other a directory that holds nothing —
// so both stay green with the order reversed. Only a case with a helper in both
// places says which is chosen.
//
// And the order is the part that matters. "Beside fleetctl" is the only one of
// the two that came out of the same archive, the same `make build` or the same
// `go install` as the binary doing the looking; PATH is whatever the machine
// has. Consulting PATH first would let a fleet-tui left behind by an older
// install quietly take over from the one this fleetctl shipped with, and the
// operator would see a view built by a different version of this command tree
// with nothing on screen to say so.
func TestTheHelperBesideFleetctlIsPreferredToOneOnPath(t *testing.T) {
	t.Parallel()

	installed := t.TempDir()
	want := writeHelper(t, installed)
	self := filepath.Join(installed, exeName("fleetctl"))
	stale := writeHelper(t, t.TempDir())

	got, err := findHelperVia(
		func() (string, error) { return self, nil },
		func(string) (string, error) { return stale, nil })
	require.NoError(t, err)
	require.Equal(t, want, got,
		"a helper on PATH was chosen over the one beside fleetctl, so an older install on PATH wins over the one this binary shipped with")
}

// TestTheHelperBesideTheInvokedFleetctlWinsOverTheOneBesideTheTarget pins the
// other order this lookup decides, which nothing did.
//
// A managed install is a symlink in a bin directory pointing at the unpacked
// tree, so there are two directories that can honestly be called "beside
// fleetctl", and both of the tests above arrange for exactly one of them to
// hold a helper — so both stay green whichever way round the two are tried.
// Reversing them left this package green, which is the same shape as PATH
// coming before either.
//
// The invoked path answers first. Ordinary installs have one directory and the
// two agree; when they disagree, an operator can see the directory their own
// PATH named and has no reason to know what it resolves to.
func TestTheHelperBesideTheInvokedFleetctlWinsOverTheOneBesideTheTarget(t *testing.T) {
	t.Parallel()

	unpacked := t.TempDir()
	target := filepath.Join(unpacked, exeName("fleetctl"))
	require.NoError(t, os.WriteFile(target, []byte("#!/bin/sh\n"), 0o755)) //nolint:gosec // as above
	writeHelper(t, unpacked)

	bin := t.TempDir()
	link := filepath.Join(bin, exeName("fleetctl"))
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("this host does not allow symlinks: %v", err)
	}
	want := writeHelper(t, bin)

	got, err := findHelperVia(func() (string, error) { return link, nil }, noPath)
	require.NoError(t, err)
	require.Equal(t, evaluated(t, want), evaluated(t, got),
		"the helper beside the resolved target was chosen over the one in the directory fleetctl was invoked from")
}

// TestAFleetctlUnderTheHelpersNameDoesNotExecItself.
//
// The hand-off is an exec, which is what makes this one silent: a fleetctl
// installed as fleet-tui — a rename, a copy, or a symlink made by someone who
// read "fleet-tui is fleetctl's own command tree" as "the same binary" — finds
// itself beside itself, execs itself, and does it again. Same pid, no output,
// no error, no view: `fleetctl tui` hangs on the terminal for ever, which is
// the failure this command was split out to stop. Measured before the guard
// existed: the process was still going, drawing nothing, when the test that
// started it gave up.
func TestAFleetctlUnderTheHelpersNameDoesNotExecItself(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	self := writeHelper(t, dir) // this binary, installed under the helper's name

	_, err := findHelperVia(func() (string, error) { return self, nil }, noPath)
	require.ErrorIs(t, err, errNoHelper)
	require.Contains(t, err.Error(), "this same binary", "the refusal does not say what is actually wrong")
	require.Contains(t, err.Error(), "go install github.com/axelmierczuk/fleet-mcp/cmd/fleet-tui@latest",
		"the refusal does not say how to get the real one")
}

// TestALinkToFleetctlIsNotTheHelper is the same mistake spelled the two other
// ways a packager makes it: the helper is a link to fleetctl rather than a
// binary of its own, so it is one file under two names.
func TestALinkToFleetctlIsNotTheHelper(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		link func(target, path string) error
	}{
		{"symlink", os.Symlink},
		{"hard link", os.Link},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			self := filepath.Join(dir, exeName("fleetctl"))
			require.NoError(t, os.WriteFile(self, []byte("#!/bin/sh\n"), 0o755)) //nolint:gosec // as above
			if err := tc.link(self, filepath.Join(dir, exeName(helperName))); err != nil {
				t.Skipf("this host does not allow %ss: %v", tc.name, err)
			}

			_, err := findHelperVia(func() (string, error) { return self, nil }, noPath)
			require.ErrorIs(t, err, errNoHelper)
			require.Contains(t, err.Error(), "this same binary")
		})
	}
}

// TestAHelperOnPathThatIsThisBinaryIsNotTheHelper is the same guard on the
// other place the lookup asks. A bin directory on PATH holding a fleet-tui that
// is a link to the fleetctl being run is the loop again, one step further out.
func TestAHelperOnPathThatIsThisBinaryIsNotTheHelper(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	self := filepath.Join(dir, exeName("fleetctl"))
	require.NoError(t, os.WriteFile(self, []byte("#!/bin/sh\n"), 0o755)) //nolint:gosec // as above
	onPath := filepath.Join(t.TempDir(), exeName(helperName))
	if err := os.Symlink(self, onPath); err != nil {
		t.Skipf("this host does not allow symlinks: %v", err)
	}

	_, err := findHelperVia(
		func() (string, error) { return self, nil },
		func(string) (string, error) { return onPath, nil })
	require.ErrorIs(t, err, errNoHelper)
}

// TestAHelperFoundThroughARelativePathEntryIsNotRun.
//
// With the real [exec.LookPath], because the property being pinned is one of
// its answers rather than one of ours: a match found through a relative PATH
// entry — "." among them — comes back as a path *and* an error, and this lookup
// takes only the path that arrives with no error at all. A CLI that holds the
// operator's control key and their fleet's CA does not exec whatever the
// directory they happen to be standing in contains, and `if path != ""` here
// would be exactly that.
func TestAHelperFoundThroughARelativePathEntryIsNotRun(t *testing.T) {
	// Not parallel: it moves this process's working directory and PATH.
	root := t.TempDir()
	t.Chdir(root)
	require.NoError(t, os.Mkdir(filepath.Join(root, "bin"), 0o755))
	writeHelper(t, filepath.Join(root, "bin"))
	t.Setenv("PATH", "bin")

	self := filepath.Join(t.TempDir(), exeName("fleetctl"))
	_, err := findHelperVia(func() (string, error) { return self, nil }, exec.LookPath)
	require.ErrorIs(t, err, errNoHelper,
		"a fleet-tui in the working directory was accepted as the helper")
}

// TestAFileWithoutTheExecutableBitIsNotTheHelper.
//
// The sibling of the directory case, and the other half of what
// [isExecutableFile] claims: something that exists where the helper should be
// is not the helper. A half-extracted archive or an interrupted download leaves
// exactly this — a file of the right name that cannot be run — and answering
// "found" for it replaces a refusal naming the binary and the `go install` line
// that produces it with `permission denied` from the operating system.
//
// Not on Windows, which has no such bit: there executability is the extension,
// which exeName has already applied and the directory case already covers.
func TestAFileWithoutTheExecutableBitIsNotTheHelper(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows decides executability by extension, not by a mode bit; see isExecutableFile")
	}
	t.Parallel()

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, exeName(helperName)), []byte("#!/bin/sh\n"), 0o644))
	self := filepath.Join(dir, exeName("fleetctl"))

	_, err := findHelperVia(func() (string, error) { return self, nil }, noPath)
	require.ErrorIs(t, err, errNoHelper)
}
