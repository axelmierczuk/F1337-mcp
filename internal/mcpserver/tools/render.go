package tools

import (
	"fmt"
	"strings"
	"time"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/fleet-mcp/internal/cli"
	"github.com/axelmierczuk/fleet-mcp/internal/client"
	"github.com/axelmierczuk/fleet-mcp/internal/registry"
)

// Health values reported by fleet_list and fleet_info. They are short
// strings rather than an enum name because they land in model context on
// every fleet check, and "unreachable" says everything STATUS_UNREACHABLE
// does in a third of the tokens.
//
// They are defined in internal/client rather than here because fleetctl
// reports the same states to the operator, and the two must not drift.
const (
	healthServing     = client.HealthServing
	healthDegraded    = client.HealthDegraded
	healthDraining    = client.HealthDraining
	healthUnreachable = client.HealthUnreachable
	// healthUnknown means nothing has probed this sandbox yet — not that the
	// probe failed. fleet_list without refresh reports it for a sandbox no
	// call has touched since the server started.
	healthUnknown = client.HealthUnknown
)

// healthString renders a gRPC health status.
func healthString(status sandboxdv1.HealthResponse_Status) string {
	return client.HealthName(status)
}

// platformString renders a platform as "os/arch", or the empty string when
// nothing has ever reported one.
func platformString(p registry.Platform) string { return p.String() }

// The remaining renderings are shared with fleetctl, so that an operator
// comparing `fleetctl list` with fleet_list is comparing the same numbers.
func relativeTime(t time.Time, now time.Time) string { return cli.RelativeTime(t, now) }
func humanBytes(n uint64) string                     { return cli.HumanBytes(n) }
func humanDuration(d time.Duration) string           { return cli.HumanDuration(d) }

// parseLabelFilter splits a "key=value" filter, rejecting anything else with
// a message that shows the shape rather than restating that it is invalid.
func parseLabelFilter(filter string) (key, value string, err error) {
	key, value, ok := strings.Cut(filter, "=")
	key, value = strings.TrimSpace(key), strings.TrimSpace(value)
	if !ok || key == "" {
		return "", "", fmt.Errorf("label filter %q is not in key=value form, e.g. label=\"arch=arm64\"", filter)
	}
	return key, value, nil
}
