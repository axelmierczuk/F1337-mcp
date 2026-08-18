package fleetctl

import (
	"errors"
	"os"
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
