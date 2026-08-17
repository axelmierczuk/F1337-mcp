package mcpserver_test

import (
	"sort"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// allToolNames is the complete public surface of this MCP server: the exact
// names a client sees from tools/list, in sorted order.
//
// The fleet rebrand renamed every one of these from sandbox_* to fleet_*, which
// it could afford to do because the repo has no releases and so no shipped
// client config or published prompt refers to the old names. That stops being
// true at the first release: a tool name is the API, and renaming one silently
// breaks every stored prompt and client configuration that calls it.
//
// So this list is deliberately spelled out rather than derived from the
// registrations it checks. A test that built its expectation from the same
// source it verifies would agree with any rename, which is exactly the change
// worth failing on.
var allToolNames = []string{
	"fleet_add",
	"fleet_edit",
	"fleet_exec",
	"fleet_forward",
	"fleet_glob",
	"fleet_grep",
	"fleet_info",
	"fleet_list",
	"fleet_ls",
	"fleet_process_list",
	"fleet_process_logs",
	"fleet_process_restart",
	"fleet_process_signal",
	"fleet_process_start",
	"fleet_read",
	"fleet_remove",
	"fleet_select",
	"fleet_transfer",
	"fleet_write",
}

// TestToolsListReturnsExactlyTheNamedTools pins the whole set as a client sees
// it, in both directions: a rename or a deletion fails it, and so does a tool
// added without being listed above. The equality is on the full slice rather
// than a per-name Contains loop for that second half — a loop over the expected
// names cannot see an extra one.
func TestToolsListReturnsExactlyTheNamedTools(t *testing.T) {
	f := newFixture(t, fixtureOptions{})

	listed, err := f.session.ListTools(t.Context(), &mcp.ListToolsParams{})
	require.NoError(t, err)

	var names []string
	for _, tool := range listed.Tools {
		names = append(names, tool.Name)
	}
	sort.Strings(names)

	require.Equal(t, allToolNames, names,
		"the tool names are this server's public API; changing one breaks every client config and stored prompt that calls it")
}

// TestToolNamesDoNotRenameTheConcept guards the other half of the rebrand.
//
// "fleet" is the product; a "sandbox" is one machine in it. The rename moved
// the identifier prefix and had to leave the noun alone — including the
// per-call targeting argument that says *which* sandbox to run on. A tool does
// not act on a fleet, it acts on one member of one, so an argument named
// "fleet" there would be actively wrong.
func TestToolNamesDoNotRenameTheConcept(t *testing.T) {
	f := newFixture(t, fixtureOptions{})

	listed, err := f.session.ListTools(t.Context(), &mcp.ListToolsParams{})
	require.NoError(t, err)

	targeted := 0
	for _, tool := range listed.Tools {
		assert.NotContains(t, tool.Name, "sandbox",
			"%s: the product is fleet; no tool name should still say sandbox", tool.Name)

		input := schemaMap(t, tool.InputSchema)
		if hasProperty(input, "sandbox") {
			targeted++
		}
		assert.Falsef(t, hasProperty(input, "fleet"),
			"%s: a tool acts on one member of a fleet, not on a fleet", tool.Name)
	}

	assert.NotZero(t, targeted,
		"the per-call target is still spelled \"sandbox\"; if nothing has it, the rename ate the concept")
}
