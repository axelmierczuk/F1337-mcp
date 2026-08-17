package sandboxdagent_test

import (
	"encoding/xml"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axelmierczuk/fleet-mcp/internal/agent"
	"github.com/axelmierczuk/fleet-mcp/internal/cli/sandboxdagent"
)

// Rendering a unit file is a pure function of UnitParams, which is what makes
// the parts of `service install` that decide what the unit says testable
// without a service manager or root. These are those tests.

func params() sandboxdagent.UnitParams {
	return sandboxdagent.UnitParams{
		Executable:   "/usr/local/bin/sandboxd-agent",
		ConfigPath:   "/etc/sandboxd/agent.yaml",
		User:         "sandboxd",
		AllowedRoots: []string{"/home/build/workspace"},
		StateDir:     "/var/lib/sandboxd",
		LogDir:       "/var/log/sandboxd",
		RestartDelay: 5 * time.Second,
		StopTimeout:  45 * time.Second,
		Hardening:    sandboxdagent.HardeningStandard,
	}
}

// The daemon is started with the config path baked in, so it does not have to
// rediscover it as whichever account the service runs under.
func TestUnitParams_Arguments(t *testing.T) {
	assert.Equal(t, []string{"serve", "--config", "/etc/sandboxd/agent.yaml"}, params().Arguments())
}

// The single most load-bearing line in the systemd unit.
//
// systemd's default KillMode=control-group SIGTERMs every process in the
// unit's cgroup on stop — which is every background process the agent
// supervises. Without KillMode=process, `systemctl restart sandboxd-agent`
// kills every dev server the fleet is running, and an agent upgrade does it
// across the whole fleet at once.
func TestSystemdUnit_KillModeProcess(t *testing.T) {
	unit := params().SystemdUnit()
	assert.Contains(t, unit, "KillMode=process")
	assert.NotContains(t, unit, "KillMode=control-group")
	assert.NotContains(t, unit, "KillMode=mixed")
}

func TestSystemdUnit_Restart(t *testing.T) {
	unit := params().SystemdUnit()
	assert.Contains(t, unit, "Restart=on-failure")
	assert.Contains(t, unit, "RestartSec=5")
	assert.Contains(t, unit, "ExecStart=/usr/local/bin/sandboxd-agent serve --config /etc/sandboxd/agent.yaml")
	assert.Contains(t, unit, "User=sandboxd")
	assert.Contains(t, unit, "WantedBy=multi-user.target")
	assert.Contains(t, unit, "StandardOutput=journal")
	assert.Contains(t, unit, "StandardError=journal")
}

// The stop timeout has to exceed the daemon's own drain deadline, or systemd
// SIGKILLs it partway through the drain it was just asked to perform.
func TestSystemdUnit_StopTimeoutExceedsDrain(t *testing.T) {
	p := params()
	assert.Greater(t, p.StopTimeout, agent.DefaultDrainTimeout)
	assert.Contains(t, p.SystemdUnit(), "TimeoutStopSec=45")
}

func TestSystemdUnit_HardeningLevels(t *testing.T) {
	standard := params().SystemdUnit()
	assert.Contains(t, standard, "NoNewPrivileges=yes")
	assert.Contains(t, standard, "PrivateTmp=yes")
	assert.Contains(t, standard, "ProtectSystem=full")
	assert.NotContains(t, standard, "ProtectSystem=strict")
	assert.NotContains(t, standard, "ReadWritePaths=")
	// ProtectHome would break every toolchain that caches in the service
	// user's home directory, which is all of them.
	assert.NotContains(t, standard, "ProtectHome")

	p := params()
	p.Hardening = sandboxdagent.HardeningStrict
	strict := p.SystemdUnit()
	assert.Contains(t, strict, "ProtectSystem=strict")
	assert.NotContains(t, strict, "ProtectSystem=full")
	assert.Contains(t, strict, "ReadWritePaths=-/home/build/workspace /var/lib/sandboxd /var/log/sandboxd")

	p.Hardening = sandboxdagent.HardeningNone
	none := p.SystemdUnit()
	assert.NotContains(t, none, "NoNewPrivileges")
	assert.NotContains(t, none, "PrivateTmp")
	assert.NotContains(t, none, "ProtectSystem")
	// Still correct where correctness is not optional.
	assert.Contains(t, none, "KillMode=process")
}

// An allowed root that does not exist yet must not stop the service starting.
//
// systemd fails a unit's whole mount namespace when a ReadWritePaths= entry is
// absent, and a configured root that does not exist is an ordinary state on the
// default configuration: exec is on, so the roots are never handed to the jail
// and nothing checks whether they are there. systemd's "-" prefix is what
// reconciles the two. The state and log directories are created by `install`,
// so one of those missing is a real fault and is left to fail.
func TestSystemdUnit_StrictToleratesARootThatDoesNotExistYet(t *testing.T) {
	p := params()
	p.Hardening = sandboxdagent.HardeningStrict
	p.AllowedRoots = []string{"/home/build/workspace", "/srv/not-created-yet"}

	unit := p.SystemdUnit()
	assert.Contains(t, unit, "ReadWritePaths=-/home/build/workspace -/srv/not-created-yet /var/lib/sandboxd /var/log/sandboxd")

	for _, line := range strings.Split(unit, "\n") {
		if !strings.HasPrefix(line, "ReadWritePaths=") {
			continue
		}
		for _, entry := range strings.Fields(strings.TrimPrefix(line, "ReadWritePaths=")) {
			if entry == "/var/lib/sandboxd" || entry == "/var/log/sandboxd" {
				continue
			}
			assert.True(t, strings.HasPrefix(entry, "-"),
				"an allowed root must be optional to systemd, or a root created later stops the service starting: %s", entry)
		}
	}
}

// PrivateTmp is skipped when an allowed root lives under /tmp — as it does in
// the shipped example config. A private /tmp would make everything the agent
// wrote there invisible to the rest of the host and lose it on restart, which
// is a worse outcome than one missing directive.
func TestSystemdUnit_PrivateTmpSkippedWhenARootIsUnderTmp(t *testing.T) {
	for _, root := range []string{"/tmp/sandboxd", "/tmp", "/var/tmp/build"} {
		t.Run(root, func(t *testing.T) {
			p := params()
			p.AllowedRoots = []string{"/home/build/workspace", root}
			unit := p.SystemdUnit()
			assert.NotContains(t, unit, "PrivateTmp=yes")
			assert.Contains(t, unit, "PrivateTmp omitted")
		})
	}

	// A root that merely starts with the same letters is not under /tmp.
	p := params()
	p.AllowedRoots = []string{"/tmpfoo/workspace"}
	assert.Contains(t, p.SystemdUnit(), "PrivateTmp=yes")
}

// systemd splits ExecStart on whitespace, so a path with a space in it becomes
// two arguments unless it is quoted.
func TestSystemdUnit_QuotesPathsWithSpaces(t *testing.T) {
	p := params()
	p.Executable = "/opt/my tools/sandboxd-agent"
	p.ConfigPath = "/etc/my config/agent.yaml"
	assert.Contains(t, p.SystemdUnit(), `ExecStart="/opt/my tools/sandboxd-agent" serve --config "/etc/my config/agent.yaml"`)
}

// The launchd counterpart of KillMode=process. Without AbandonProcessGroup,
// launchd kills everything left in the job's process group when the job stops.
func TestLaunchdPlist_AbandonProcessGroup(t *testing.T) {
	plist := params().LaunchdPlist()
	assert.Contains(t, plist, "<key>AbandonProcessGroup</key>")
	idx := strings.Index(plist, "<key>AbandonProcessGroup</key>")
	require.Positive(t, idx)
	assert.Contains(t, plist[idx:idx+60], "<true/>")
}

func TestLaunchdPlist_IsWellFormedXML(t *testing.T) {
	plist := params().LaunchdPlist()
	// Parsing it is the check that matters: launchd silently refuses to load a
	// malformed plist, and the failure surfaces as "the service does nothing".
	require.NoError(t, xml.Unmarshal([]byte(plist), new(struct {
		XMLName xml.Name `xml:"plist"`
	})))

	assert.Contains(t, plist, "<key>Label</key>\n\t<string>sandboxd-agent</string>")
	assert.Contains(t, plist, "<string>/usr/local/bin/sandboxd-agent</string>")
	assert.Contains(t, plist, "<string>serve</string>")
	assert.Contains(t, plist, "<string>--config</string>")
	assert.Contains(t, plist, "<string>/etc/sandboxd/agent.yaml</string>")
	assert.Contains(t, plist, "<key>UserName</key>\n\t<string>sandboxd</string>")
	assert.Contains(t, plist, "<key>RunAtLoad</key>")

	// Issue #18 asks for log paths under /Library/Logs/sandboxd; LogDir is
	// what carries that on macOS.
	assert.Contains(t, plist, "<string>/var/log/sandboxd/sandboxd-agent.out.log</string>")
	assert.Contains(t, plist, "<string>/var/log/sandboxd/sandboxd-agent.err.log</string>")
}

// KeepAlive as a dict with SuccessfulExit=false restarts a failed daemon and
// leaves a deliberately stopped one alone. A bare <true/> fights `launchctl
// stop`.
func TestLaunchdPlist_KeepAliveOnFailureOnly(t *testing.T) {
	plist := params().LaunchdPlist()
	idx := strings.Index(plist, "<key>KeepAlive</key>")
	require.Positive(t, idx)
	window := plist[idx : idx+120]
	assert.Contains(t, window, "<dict>")
	assert.Contains(t, window, "<key>SuccessfulExit</key>")
	assert.Contains(t, window, "<false/>")
}

func TestLaunchdPlist_EscapesXML(t *testing.T) {
	p := params()
	p.User = `a&b<c>`
	plist := p.LaunchdPlist()
	assert.Contains(t, plist, "a&amp;b&lt;c&gt;")
	require.NoError(t, xml.Unmarshal([]byte(plist), new(struct {
		XMLName xml.Name `xml:"plist"`
	})))
}

// The Windows service is created through the SCM API rather than from a
// template, so these options are the entire configuration.
func TestServiceConfig_WindowsOptions(t *testing.T) {
	cfg := params().ServiceConfig()

	assert.Equal(t, "sandboxd-agent", cfg.Name)
	assert.Equal(t, "sandboxd", cfg.UserName)
	assert.Equal(t, []string{"serve", "--config", "/etc/sandboxd/agent.yaml"}, cfg.Arguments)
	assert.Equal(t, "/usr/local/bin/sandboxd-agent", cfg.Executable)

	assert.Equal(t, "automatic", cfg.Option["StartType"])
	assert.Equal(t, "restart", cfg.Option["OnFailure"])
	assert.Equal(t, "5s", cfg.Option["OnFailureDelayDuration"])
	assert.Equal(t, 86400, cfg.Option["OnFailureResetPeriod"])
	assert.Equal(t, false, cfg.Option["DelayedAutoStart"])

	// The POSIX unit files travel in the same options and must be the rendered
	// ones, not the library's defaults.
	assert.Equal(t, params().SystemdUnit(), cfg.Option["SystemdScript"])
	assert.Equal(t, params().LaunchdPlist(), cfg.Option["LaunchdConfig"])
}

// A fully rendered unit must contain nothing kardianos/service's template
// engine would try to expand, or install writes something other than what was
// tested here.
func TestRenderedUnitsContainNoTemplateDirectives(t *testing.T) {
	for name, out := range map[string]string{
		"systemd": params().SystemdUnit(),
		"launchd": params().LaunchdPlist(),
	} {
		t.Run(name, func(t *testing.T) {
			assert.NotContains(t, out, "{{")
			assert.NotContains(t, out, "}}")
		})
	}
}

func TestParseHardening(t *testing.T) {
	for input, want := range map[string]sandboxdagent.Hardening{
		"":         sandboxdagent.HardeningStandard,
		"standard": sandboxdagent.HardeningStandard,
		"STRICT":   sandboxdagent.HardeningStrict,
		" none ":   sandboxdagent.HardeningNone,
	} {
		got, err := sandboxdagent.ParseHardening(input)
		require.NoError(t, err, input)
		assert.Equal(t, want, got)
	}

	_, err := sandboxdagent.ParseHardening("paranoid")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "standard, strict, none")
}
