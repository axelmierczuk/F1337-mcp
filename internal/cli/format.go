package cli

import (
	"fmt"
	"time"
)

// The renderings a fleet view is made of: how long ago something happened, how
// big a disk is, how long a process has been up.
//
// They live here rather than beside either caller because there are two — the
// MCP server's fleet_list and fleet_info, and fleetctl's list and info — and
// the whole point of the CLI reading the fleet through the same client the MCP
// server does is that an operator comparing the two is comparing the same
// numbers, not two roundings of them.

// RelativeTime renders how long ago t was, compactly. An unset time reads
// "never", which is what a sandbox that has not answered a probe deserves.
func RelativeTime(t time.Time, now time.Time) string {
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

// HumanBytes renders a byte count in the largest unit that keeps it under
// four digits, and an unknown quantity — zero — as the empty string. Raw byte
// counts of a disk are unreadable and, at three or four per sandbox, not cheap
// either.
func HumanBytes(n uint64) string {
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

// HumanDuration renders an uptime without the sub-second noise
// time.Duration's own formatting carries.
func HumanDuration(d time.Duration) string {
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
