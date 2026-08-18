package fleetctl

import (
	"errors"
	"os"
	"path/filepath"
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
