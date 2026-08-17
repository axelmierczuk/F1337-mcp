package mcpserver_test

import (
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axelmierczuk/fleet-mcp/internal/mcpserver/selection"
)

// TestSelection_ExplicitArgumentOverridesTheStickyDefault: rule 1 beats
// rule 2, and it does so without disturbing rule 2.
func TestSelection_ExplicitArgumentOverridesTheStickyDefault(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	f.add("build-box", "build-box.internal:8722", nil)
	f.add("gpu-01", "gpu-01.internal:8722", nil)
	f.ok("sandbox_select", map[string]any{"name": "build-box"}, "")

	res := f.ok("sandbox_info", map[string]any{"sandbox": "gpu-01"}, "")
	assert.Equal(t, "gpu-01", echoOf(t, res), "the explicit argument must win")

	res = f.ok("sandbox_info", map[string]any{}, "")
	assert.Equal(t, "build-box", echoOf(t, res), "an override is for one call only")
}

// TestSelection_NoTargetIsAStructuredError, and specifically: it does not
// silently pick the only sandbox there is. A fleet grows from one to two
// without anyone revisiting the calls written while it had one member, and
// implicit targeting is how the wrong host gets written to.
func TestSelection_NoTargetIsAStructuredError(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	f.add("build-box", "build-box.internal:8722", nil)

	text := f.fails("sandbox_info", map[string]any{}, "")

	assert.Contains(t, text, "sandbox_select", "the error must name the tool that fixes it")
	assert.Contains(t, text, "build-box", "and list what is available")

	_, infoCalls, _ := f.clients.host("build-box").counts()
	assert.Zero(t, infoCalls, "resolution must fail before the handler runs, not inside it")
}

// TestSelection_EmptyFleetPointsAtEnrollment: with nothing registered, the
// answer is not "select something" but "there is nothing to select".
func TestSelection_EmptyFleetPointsAtEnrollment(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	text := f.fails("sandbox_info", map[string]any{}, "")
	assert.Contains(t, text, "none are registered")
	assert.Contains(t, text, "sandbox_add")
}

// TestSelection_SurvivesAServerRestart. The selection lives in the registry
// file, not in the process, which is the whole reason it is persisted rather
// than held in memory.
func TestSelection_SurvivesAServerRestart(t *testing.T) {
	first := newFixture(t, fixtureOptions{})
	first.add("build-box", "build-box.internal:8722", nil)
	first.add("gpu-01", "gpu-01.internal:8722", nil)
	first.ok("sandbox_select", map[string]any{"name": "gpu-01"}, "")

	// A second server over the same config directory, as if the agent CLI
	// had been restarted.
	second := newFixture(t, fixtureOptions{configDir: first.dir})

	res := second.ok("sandbox_info", map[string]any{}, "")
	assert.Equal(t, "gpu-01", echoOf(t, res), "the sticky default must outlive the process")

	out := structured[listResult](t, second.ok("sandbox_list", map[string]any{}, ""))
	require.Len(t, out.Sandboxes, 2)
	assert.Equal(t, "gpu-01", out.Sandbox)
	assert.False(t, out.Sandboxes[0].Selected)
	assert.True(t, out.Sandboxes[1].Selected)
}

// TestSelection_TwoIdentitiesAreIndependent covers the case a purely implicit
// design cannot: two clients against one registry, neither moving the other's
// target out from under it.
func TestSelection_TwoIdentitiesAreIndependent(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	f.add("build-box", "build-box.internal:8722", nil)
	f.add("gpu-01", "gpu-01.internal:8722", nil)

	f.ok("sandbox_select", map[string]any{"name": "build-box"}, "alice")
	f.ok("sandbox_select", map[string]any{"name": "gpu-01"}, "bob")

	assert.Equal(t, "build-box", echoOf(t, f.ok("sandbox_info", map[string]any{}, "alice")))
	assert.Equal(t, "gpu-01", echoOf(t, f.ok("sandbox_info", map[string]any{}, "bob")))

	// Moving one leaves the other where it was.
	f.ok("sandbox_select", map[string]any{"name": "gpu-01"}, "alice")
	assert.Equal(t, "gpu-01", echoOf(t, f.ok("sandbox_info", map[string]any{}, "alice")))
	assert.Equal(t, "gpu-01", echoOf(t, f.ok("sandbox_info", map[string]any{}, "bob")))

	// And a third client that has selected nothing gets the no-target error
	// rather than inheriting someone else's target.
	text := f.fails("sandbox_info", map[string]any{}, "carol")
	assert.Contains(t, text, "sandbox_select")
}

// TestSelection_ClientsWithDistinctImplementationNamesAreDistinct covers the
// identity that a real client supplies without knowing anything about
// fleet: the implementation name it reports at connect time.
func TestSelection_ClientsWithDistinctImplementationNamesAreDistinct(t *testing.T) {
	first := newFixture(t, fixtureOptions{clientName: "editor-a"})
	first.add("build-box", "build-box.internal:8722", nil)
	first.add("gpu-01", "gpu-01.internal:8722", nil)
	first.ok("sandbox_select", map[string]any{"name": "build-box"}, "")

	second := newFixture(t, fixtureOptions{clientName: "editor-b", configDir: first.dir})
	text := second.fails("sandbox_info", map[string]any{}, "")
	assert.Contains(t, text, "sandbox_select",
		"a different client must not inherit another's selection")

	second.ok("sandbox_select", map[string]any{"name": "gpu-01"}, "")
	assert.Equal(t, "build-box", echoOf(t, first.ok("sandbox_info", map[string]any{}, "")))
	assert.Equal(t, "gpu-01", echoOf(t, second.ok("sandbox_info", map[string]any{}, "")))
}

// TestSelection_HandleResolvesAsTheSandboxArgument: the handle sandbox_select
// mints is the spec-shaped half of the design, and it has to actually work
// when passed back.
func TestSelection_HandleResolvesAsTheSandboxArgument(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	f.add("build-box", "build-box.internal:8722", nil)
	f.add("gpu-01", "gpu-01.internal:8722", nil)

	out := structured[selectResult](t, f.ok("sandbox_select", map[string]any{"name": "gpu-01"}, ""))
	require.NotEmpty(t, out.Handle)
	assert.NotContains(t, out.Handle, "gpu-01", "the handle is opaque")
	assert.Equal(t, selection.HandleFor("gpu-01"), out.Handle)

	f.ok("sandbox_select", map[string]any{"name": "build-box"}, "")
	res := f.ok("sandbox_info", map[string]any{"sandbox": out.Handle}, "")
	assert.Equal(t, "gpu-01", echoOf(t, res), "a handle must resolve back to its sandbox")

	// A handle for a sandbox that no longer exists fails like any unknown
	// reference, with the valid names listed.
	f.ok("sandbox_remove", map[string]any{"name": "gpu-01"}, "")
	text := f.fails("sandbox_info", map[string]any{"sandbox": out.Handle}, "")
	assert.Contains(t, text, "build-box")
}

// TestSelection_StaleSelectionIsDistinctFromATypo. The model did nothing
// wrong when another client removed its target, and the fix is to re-select
// rather than to correct a name.
func TestSelection_StaleSelectionIsDistinctFromATypo(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	f.add("build-box", "build-box.internal:8722", nil)
	f.add("gpu-01", "gpu-01.internal:8722", nil)
	f.ok("sandbox_select", map[string]any{"name": "gpu-01"}, "alice")

	// Removing via a different identity leaves alice's selection dangling
	// unless removal reaches every client.
	f.ok("sandbox_remove", map[string]any{"name": "gpu-01"}, "bob")

	text := f.fails("sandbox_info", map[string]any{}, "alice")
	assert.Contains(t, text, "sandbox_select")
	assert.Contains(t, text, "build-box")

	// And with the registry edited underneath the server — the case removal
	// cannot clean up — the message says the target is gone rather than that
	// the model got the name wrong.
	f.ok("sandbox_select", map[string]any{"name": "build-box"}, "alice")
	require.NoError(t, f.fleet.Remove("build-box"))
	text = f.fails("sandbox_info", map[string]any{}, "alice")
	assert.Contains(t, text, "no longer registered")
}

// echoFixtures are arguments that make each tool succeed against the fake
// fleet, plus the sandbox its result must then echo.
//
// A tool with no entry here fails TestEcho_EveryRegisteredToolCarriesTheResolvedSandbox
// rather than being skipped. That is deliberate: a walk that quietly excuses
// the tools it cannot call proves less the more tools there are, and issues
// #22 to #26 add fourteen more. Adding a tool means adding a line here.
var echoFixtures = map[string]struct {
	args     map[string]any
	echoes   string
	targeted bool
}{
	"sandbox_list":   {args: map[string]any{}, echoes: "build-box"},
	"sandbox_select": {args: map[string]any{"name": "gpu-01"}, echoes: "gpu-01"},
	"sandbox_add":    {args: map[string]any{"name": "new-box", "address": "new-box.internal:8722"}, echoes: "new-box"},
	"sandbox_remove": {args: map[string]any{"name": "gpu-01"}, echoes: "gpu-01"},
	"sandbox_info":   {args: map[string]any{"sandbox": "build-box"}, echoes: "build-box", targeted: true},

	"sandbox_exec":  {args: map[string]any{"sandbox": "build-box", "argv": []any{"echo", "hi"}}, echoes: "build-box", targeted: true},
	"sandbox_read":  {args: map[string]any{"sandbox": "build-box", "path": "/srv/app/main.go"}, echoes: "build-box", targeted: true},
	"sandbox_write": {args: map[string]any{"sandbox": "build-box", "path": "/srv/app/main.go", "content": "package main\n"}, echoes: "build-box", targeted: true},
	"sandbox_edit":  {args: map[string]any{"sandbox": "build-box", "path": "/srv/app/main.go", "old_string": "old", "new_string": "new"}, echoes: "build-box", targeted: true},
	"sandbox_ls":    {args: map[string]any{"sandbox": "build-box", "path": "/srv/app"}, echoes: "build-box", targeted: true},
	"sandbox_glob":  {args: map[string]any{"sandbox": "build-box", "pattern": "**/*.go"}, echoes: "build-box", targeted: true},
	"sandbox_grep":  {args: map[string]any{"sandbox": "build-box", "pattern": "func main"}, echoes: "build-box", targeted: true},
	// A source that exists wherever the test binary runs: the package's own
	// directory is the working directory of a `go test` process. Nothing is
	// written on this side — the destination is on the (faked) sandbox.
	"sandbox_transfer": {args: map[string]any{
		"sandbox": "build-box", "direction": "push", "source": "server.go", "destination": "/srv/app/server.go",
	}, echoes: "build-box", targeted: true},

	"sandbox_process_start": {
		args:     map[string]any{"sandbox": "build-box", "argv": []any{"npm", "run", "dev"}, "name": "web-dev"},
		echoes:   "build-box",
		targeted: true,
	},
	"sandbox_process_list":    {args: map[string]any{"sandbox": "build-box"}, echoes: "build-box", targeted: true},
	"sandbox_process_logs":    {args: map[string]any{"sandbox": "build-box", "process_id": "proc-1"}, echoes: "build-box", targeted: true},
	"sandbox_process_signal":  {args: map[string]any{"sandbox": "build-box", "process_id": "proc-1", "graceful_stop": true}, echoes: "build-box", targeted: true},
	"sandbox_process_restart": {args: map[string]any{"sandbox": "build-box", "process_id": "proc-1"}, echoes: "build-box", targeted: true},
	"sandbox_forward":         {args: map[string]any{"sandbox": "build-box", "remote_port": 3000}, echoes: "build-box", targeted: true},
}

// TestEcho_EveryRegisteredToolCarriesTheResolvedSandbox is the walk the
// design turns on. It is driven from tools/list rather than a hand-kept list
// of what to check, so a tool added by a later milestone is covered the
// moment it is registered — including one that bypasses this package's
// helpers, which is exactly the case a per-handler convention would miss.
func TestEcho_EveryRegisteredToolCarriesTheResolvedSandbox(t *testing.T) {
	listed, err := newFixture(t, fixtureOptions{}).session.ListTools(t.Context(), &mcp.ListToolsParams{})
	require.NoError(t, err)
	require.NotEmpty(t, listed.Tools)

	// The walk is driven from tools/list, which is what makes it cover a tool
	// the moment it is registered — and is also the one thing it cannot check
	// about itself. A registration lost to a merge shortens the list, and a
	// walk over a shorter list passes without ever mentioning what is missing:
	// two milestones landing side by side each add a registerX line to the same
	// Register, and a resolution that takes one side wholesale unregisters the
	// other's tools silently. So the check runs both ways — every listed tool
	// needs a fixture, and every fixture has to have been listed.
	listedNames := map[string]bool{}
	for _, tool := range listed.Tools {
		listedNames[tool.Name] = true
	}
	for name := range echoFixtures {
		assert.Truef(t, listedNames[name],
			"%s has a fixture but is not registered: a tool that stopped being registered is a tool this walk would otherwise stop covering without saying so", name)
	}

	for _, tool := range listed.Tools {
		fixture, ok := echoFixtures[tool.Name]
		require.Truef(t, ok,
			"tool %s has no entry in echoFixtures: add arguments that make it succeed and the sandbox it must echo", tool.Name)

		t.Run(tool.Name, func(t *testing.T) {
			// A fresh fleet per tool, so a removal in one does not change
			// what the next one sees.
			f := newFixture(t, fixtureOptions{})
			f.add("build-box", "build-box.internal:8722", nil)
			f.add("gpu-01", "gpu-01.internal:8722", nil)
			f.ok("sandbox_select", map[string]any{"name": "build-box"}, "")

			res := f.ok(tool.Name, fixture.args, "")
			assert.Equal(t, fixture.echoes, echoOf(t, res),
				"the result must echo the sandbox it acted on")

			if !fixture.targeted {
				return
			}
			// A targeted tool must take the sticky default when given no
			// argument, and echo that instead.
			args := map[string]any{}
			for k, v := range fixture.args {
				if k != "sandbox" {
					args[k] = v
				}
			}
			assert.Equal(t, "build-box", echoOf(t, f.ok(tool.Name, args, "")),
				"with no explicit target, the sticky default must be used and echoed")
		})
	}
}

// TestEcho_SynthesisedCallsAlsoEcho calls every tool with arguments derived
// from its own input schema, without knowing anything about it. It catches a
// tool registered outside the helpers before anyone has written it a fixture.
func TestEcho_SynthesisedCallsAlsoEcho(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	f.add("build-box", "build-box.internal:8722", nil)
	f.ok("sandbox_select", map[string]any{"name": "build-box"}, "")

	listed, err := f.session.ListTools(t.Context(), &mcp.ListToolsParams{})
	require.NoError(t, err)

	for _, tool := range listed.Tools {
		input := schemaMap(t, tool.InputSchema)
		targeted := hasProperty(input, "sandbox")

		args := argsFromSchema(t, input)
		if targeted {
			args["sandbox"] = "build-box"
		}

		res := f.call(tool.Name, args, "")
		if res.IsError {
			// A synthesised argument can be rejected on its merits; what
			// must not happen is a *result* without an echo.
			continue
		}
		echo := echoOf(t, res)
		assert.NotEmptyf(t, echo, "tool %s returned a result with an empty sandbox echo", tool.Name)
		if targeted {
			assert.Equalf(t, "build-box", echo,
				"tool %s echoed %q, not the sandbox it was told to act on", tool.Name, echo)
		}
	}
}

// TestEcho_NoTargetedToolRunsWithoutResolution is the other half: whatever a
// targeted tool does, it cannot do it before a sandbox has been resolved.
func TestEcho_NoTargetedToolRunsWithoutResolution(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	f.add("build-box", "build-box.internal:8722", nil)
	// Deliberately nothing selected.

	listed, err := f.session.ListTools(t.Context(), &mcp.ListToolsParams{})
	require.NoError(t, err)

	checked := 0
	for _, tool := range listed.Tools {
		input := schemaMap(t, tool.InputSchema)
		if !hasProperty(input, "sandbox") {
			continue
		}
		checked++
		text := f.fails(tool.Name, argsFromSchema(t, input), "")
		assert.Containsf(t, text, "sandbox_select",
			"tool %s ran (or failed for another reason) without a resolved target", tool.Name)
	}
	assert.Positive(t, checked, "no targeted tool was found; the walk proved nothing")
}

// ---------------------------------------------------------------- helpers

// schemaMap normalises a tool schema, which arrives client-side as a
// map[string]any.
func schemaMap(t *testing.T, schema any) map[string]any {
	t.Helper()
	m, ok := schema.(map[string]any)
	require.True(t, ok, "tool schema is not an object: %T", schema)
	return m
}

func hasProperty(schema map[string]any, name string) bool {
	props, ok := schema["properties"].(map[string]any)
	if !ok {
		return false
	}
	_, ok = props[name]
	return ok
}

// argsFromSchema builds the smallest argument object an input schema accepts,
// so a tool this test has never heard of can still be called.
func argsFromSchema(t *testing.T, schema map[string]any) map[string]any {
	t.Helper()
	props, _ := schema["properties"].(map[string]any)
	required, _ := schema["required"].([]any)

	args := map[string]any{}
	for _, raw := range required {
		name, ok := raw.(string)
		if !ok {
			continue
		}
		args[name] = placeholderFor(props[name])
	}
	return args
}

func placeholderFor(property any) any {
	p, ok := property.(map[string]any)
	if !ok {
		return "placeholder"
	}
	switch schemaType(p["type"]) {
	case "integer", "number":
		return 1
	case "boolean":
		return true
	case "array":
		return []any{placeholderFor(p["items"])}
	case "object":
		return map[string]any{}
	default:
		return "placeholder"
	}
}

// schemaType picks the type to synthesise a value for.
//
// A slice or map argument is emitted as a *list* of types — ["null","array"]
// — because a nil one is valid. Reading that as a plain string produced a
// string placeholder for an array argument, which the schema validator then
// rejected before resolution could fail, so the walk proved nothing about the
// tool it thought it had covered.
func schemaType(raw any) string {
	switch t := raw.(type) {
	case string:
		return t
	case []any:
		for _, entry := range t {
			if name, ok := entry.(string); ok && name != "null" {
				return name
			}
		}
	}
	return ""
}
