package fleetctl

import (
	"errors"
	"fmt"
	"strings"

	"github.com/axelmierczuk/fleet-mcp/internal/mcpserver/selection"
)

// Which sandbox a command acts on, resolved the way every other caller
// resolves it.
//
// The order is fixed and lives in one place — internal/mcpserver/selection:
//
//  1. The explicit argument, name or handle. Always wins.
//  2. The sticky selection recorded for the caller.
//  3. Otherwise a structured error listing what is registered.
//
// This file supplies the caller identity and translates the advice; it does not
// re-implement the order. That matters more than it looks: the selection
// package deliberately has no fourth rule — a fleet of exactly one sandbox does
// not resolve implicitly — and a CLI that grew its own "obvious" shortcut would
// be the one place in the product where a command could land on a host nobody
// named. `fleetctl remove` already clears selections through the registry, so a
// removed sandbox takes this one with it.

// cliIdentity is the identity fleetctl's own sticky selection is recorded
// under.
//
// It is fleetctl's alone, and that is the point. Selections are per client
// identity — the MCP server keys them on the connecting client, so an editor
// and a terminal session hold different ones — and a CLI that borrowed some
// other client's selection would send an operator's shell to whichever host a
// model happened to be working on. The "cli:" prefix keeps it from ever
// colliding with an MCP client that calls itself fleetctl.
const cliIdentity = selection.Identity("cli:fleetctl")

// resolver opens the registry and returns the shared resolver over it.
func resolver(registryPath string) (*selection.Resolver, error) {
	fleet, err := openRegistry(registryPath)
	if err != nil {
		return nil, err
	}
	return selection.NewResolver(fleet, nil), nil
}

// resolveTarget applies the resolution order for a command, with explicit taken
// from the command's own sandbox argument (empty when it was omitted).
func resolveTarget(registryPath, explicit string) (*selection.Target, error) {
	res, err := resolver(registryPath)
	if err != nil {
		return nil, err
	}
	target, err := res.ResolveFor(cliIdentity, explicit)
	if err != nil {
		return nil, operatorAdvice(err)
	}
	return target, nil
}

// operatorAdvice rewrites the selection package's errors for a person at a
// terminal.
//
// The facts are the resolver's and are passed through unchanged — which
// sandbox, which are registered. Only the instruction changes: those errors
// name `fleet_select`, which is an MCP tool a model calls, and telling an
// operator to call a tool they have no way to invoke is worse than telling them
// nothing. Anything the resolver reports that is not one of these three is
// passed through untouched.
func operatorAdvice(err error) error {
	var noTarget *selection.NoTargetError
	if errors.As(err, &noTarget) {
		if len(noTarget.Available) == 0 {
			return errors.New("no sandbox selected, and none are enrolled; run `fleetctl enroll mint --name <name> --address <host:port>` to add one (see docs/quickstart.md)")
		}
		return fmt.Errorf("no sandbox selected. Run `fleetctl select %s` to choose one for later commands, or name it on this command. Enrolled: %s",
			noTarget.Available[0], strings.Join(noTarget.Available, ", "))
	}

	var stale *selection.StaleSelectionError
	if errors.As(err, &stale) {
		if len(stale.Available) == 0 {
			return fmt.Errorf("the selected sandbox %q is no longer enrolled, and no others are; `fleetctl list` shows the fleet", stale.Name)
		}
		return fmt.Errorf("the selected sandbox %q is no longer enrolled. Run `fleetctl select` to choose another. Enrolled: %s",
			stale.Name, strings.Join(stale.Available, ", "))
	}

	var unknown *selection.UnknownSandboxError
	if errors.As(err, &unknown) {
		if len(unknown.Available) == 0 {
			return fmt.Errorf("no sandbox named %q is enrolled, and neither is any other; `fleetctl list` shows the fleet", unknown.Ref)
		}
		return fmt.Errorf("no sandbox named %q is enrolled; the fleet holds: %s", unknown.Ref, strings.Join(unknown.Available, ", "))
	}

	return err
}
