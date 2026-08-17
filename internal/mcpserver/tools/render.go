package tools

import (
	"fmt"
	"strings"
	"time"

	sandboxdv1 "github.com/axelmierczuk/sandboxd-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/sandboxd-mcp/internal/registry"
)

// Health values reported by sandbox_list and sandbox_info. They are short
// strings rather than an enum name because they land in model context on
// every fleet check, and "unreachable" says everything STATUS_UNREACHABLE
// does in a third of the tokens.
const (
	healthServing     = "serving"
	healthDegraded    = "degraded"
	healthDraining    = "draining"
	healthUnreachable = "unreachable"
	// healthUnknown means nothing has probed this sandbox yet — not that the
	// probe failed. sandbox_list without refresh reports it for a sandbox no
	// call has touched since the server started.
	healthUnknown = "unknown"
)

// healthString renders a gRPC health status.
func healthString(status sandboxdv1.HealthResponse_Status) string {
	switch status {
	case sandboxdv1.HealthResponse_STATUS_SERVING:
		return healthServing
	case sandboxdv1.HealthResponse_STATUS_DEGRADED:
		return healthDegraded
	case sandboxdv1.HealthResponse_STATUS_DRAINING:
		return healthDraining
	default:
		return healthUnknown
	}
}

// platformString renders a platform as "os/arch", or the empty string when
// nothing has ever reported one.
func platformString(p registry.Platform) string {
	switch {
	case p.OS != "" && p.Arch != "":
		return p.OS + "/" + p.Arch
	case p.OS != "":
		return p.OS
	default:
		return p.Arch
	}
}

// relativeTime renders how long ago t was, compactly. An unset time reads
// "never", which is what a sandbox that has not answered a probe deserves.
func relativeTime(t time.Time, now time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := now.Sub(t)
	if d < 0 {
		d = 0
	}
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

// humanBytes renders a byte count in the largest unit that keeps it under
// four digits. Raw byte counts of a disk are unreadable and, at three or four
// per sandbox, not cheap either.
func humanBytes(n uint64) string {
	if n == 0 {
		return ""
	}
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for v := n / unit; v >= unit && exp < 4; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTP"[exp])
}

// humanDuration renders an uptime without the sub-second noise
// time.Duration's own formatting carries.
func humanDuration(d time.Duration) string {
	if d <= 0 {
		return ""
	}
	d = d.Round(time.Second)
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	mins := int(d.Minutes()) % 60
	secs := int(d.Seconds()) % 60
	switch {
	case days > 0:
		return fmt.Sprintf("%dd%dh", days, hours)
	case hours > 0:
		return fmt.Sprintf("%dh%dm", hours, mins)
	case mins > 0:
		return fmt.Sprintf("%dm%ds", mins, secs)
	default:
		return fmt.Sprintf("%ds", secs)
	}
}

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
