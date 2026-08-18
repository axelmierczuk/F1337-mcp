package fleetctl_test

import (
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Which binaries are allowed to link a terminal UI.
//
// #73 was one import: `fleetctl tui` pulled in bubbletea, whose package init
// asks the terminal for its background colour and reads for up to five seconds
// waiting for an answer. Package inits run in every process that links the
// package, so `fleetctl version` paid it too — five seconds on a terminal that
// does not answer, and the operator's first keystrokes eaten along the way.
//
// test/e2e's TestNoCommandInterrogatesTheTerminalAtStartup is the behavioural
// half of the fix, and it is the one that proves the symptom is gone. This is
// the structural half, and it is what stops the symptom coming back for a
// reason nobody looked for: the defect is not "bubbletea queries the terminal",
// it is "a command that draws nothing links something that owns the terminal".
// The next dependency to probe from an init would reintroduce it in full, and
// the only thing that catches that before a release is a rule about what these
// binaries may link.
//
// A rule about imports, checked with the tool that resolves imports. Reading
// the source for import lines would answer for the file it read and not for the
// forty packages behind it, which is where this one came from — nothing in
// internal/cli/fleetctl ever named bubbletea.

// terminalUIPackages are the packages that must not reach a binary which does
// not draw.
//
// bubbletea is the one with the init. The other three are named because they
// are how it arrives and what it does: lipgloss holds the renderer whose
// package-level var runs the query, termenv makes it, and colorprofile is the
// other consumer of the same detection. Naming all four means an upgrade that
// moves the init one package sideways is still caught.
var terminalUIPackages = []string{
	"github.com/charmbracelet/bubbletea",
	"github.com/charmbracelet/lipgloss",
	"github.com/muesli/termenv",
	"github.com/charmbracelet/colorprofile",
}

// TestOnlyTheViewBinaryLinksATerminalUI.
//
// fleet-tui is the exception and the whole design: it is the one command that
// was going to take over the terminal anyway, so it is the one that may pay for
// asking the terminal about itself. Asserted rather than skipped, because a
// change that stopped it linking the view would be a `fleetctl tui` that no
// longer draws — and every other assertion here would still be green.
//
// The commands are enumerated rather than listed. A rule that named the four
// binaries that exist today would be a rule the fifth is not subject to, and
// the fifth is exactly where this comes back: nobody adding a command thinks
// they are adding a terminal query, which is how the first one arrived.
func TestOnlyTheViewBinaryLinksATerminalUI(t *testing.T) {
	t.Parallel()

	root := moduleRoot(t)
	commands := commandsOf(t, root)
	require.Contains(t, commands, viewCommand,
		"the one binary allowed to link a terminal UI is not among the commands, so the exception below asserts nothing")

	for _, command := range commands {
		t.Run(command, func(t *testing.T) {
			t.Parallel()

			deps := dependenciesOf(t, root, "./cmd/"+command)
			for _, pkg := range terminalUIPackages {
				links := slices.Contains(deps, pkg)
				if command == viewCommand {
					require.Truef(t, links,
						"%s no longer links %s, so `fleetctl tui` has nothing to hand the terminal to", command, pkg)
					continue
				}
				// Asserted with the package named rather than with the
				// dependency list compared, because the list is four hundred
				// packages long and a failure has to be readable in a CI log.
				require.Falsef(t, links,
					"%s links %s. Its package init queries the terminal and reads for five seconds "+
						"waiting for an answer, in every process, whatever subcommand was typed — which is #73. "+
						"Whatever needs it belongs behind the seam in internal/cli/fleetctl/tui.go, in cmd/%s",
					command, pkg, viewCommand)
			}
		})
	}
}

// viewCommand is the one command that may link a terminal UI.
const viewCommand = "fleet-tui"

// commandsOf is every command in this module, by the name its binary has.
func commandsOf(t *testing.T, moduleDir string) []string {
	t.Helper()

	cmd := exec.Command("go", "list", "./cmd/...")
	cmd.Dir = moduleDir
	out, err := cmd.CombinedOutput()
	require.NoErrorf(t, err, "go list ./cmd/...: %s", out)

	var commands []string
	for _, pkg := range strings.Fields(string(out)) {
		commands = append(commands, path.Base(pkg))
	}
	require.NotEmpty(t, commands, "go list ./cmd/... named no commands, so this test checked nothing")
	return commands
}

// dependenciesOf is every package the named command links, transitively.
func dependenciesOf(t *testing.T, moduleDir, pattern string) []string {
	t.Helper()

	cmd := exec.Command("go", "list", "-deps", pattern)
	cmd.Dir = moduleDir
	out, err := cmd.CombinedOutput()
	require.NoErrorf(t, err, "go list -deps %s: %s", pattern, out)

	deps := strings.Fields(string(out))
	require.NotEmptyf(t, deps, "go list -deps %s named no packages, so this test compared nothing", pattern)
	return deps
}

// moduleRoot walks up from the test's working directory to the module root, so
// that `go list` is run against this tree rather than whatever is above it.
func moduleRoot(t *testing.T) string {
	t.Helper()

	dir, err := os.Getwd()
	require.NoError(t, err)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		require.NotEqualf(t, dir, parent, "no go.mod above %s", dir)
		dir = parent
	}
}
