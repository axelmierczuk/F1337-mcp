package fleetagent_test

import (
	"encoding/xml"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axelmierczuk/fleet-mcp/internal/agent"
	"github.com/axelmierczuk/fleet-mcp/internal/cli/fleetagent"
)

// Rendering a unit file is a pure function of UnitParams, which is what makes
// the parts of `service install` that decide what the unit says testable
// without a service manager or root. These are those tests.

func params() fleetagent.UnitParams {
	return fleetagent.UnitParams{
		Executable:   "/usr/local/bin/fleet-agent",
		ConfigPath:   "/etc/fleet/agent.yaml",
		User:         "fleet",
		AllowedRoots: []string{"/home/build/workspace"},
		StateDir:     "/var/lib/fleet",
		LogDir:       "/var/log/fleet",
		RestartDelay: 5 * time.Second,
		StopTimeout:  45 * time.Second,
		Hardening:    fleetagent.HardeningStandard,
	}
}

// The daemon is started with the config path baked in, so it does not have to
// rediscover it as whichever account the service runs under.
func TestUnitParams_Arguments(t *testing.T) {
	assert.Equal(t, []string{"serve", "--config", "/etc/fleet/agent.yaml"}, params().Arguments())
}

// The single most load-bearing line in the systemd unit.
//
// systemd's default KillMode=control-group SIGTERMs every process in the
// unit's cgroup on stop — which is every background process the agent
// supervises. Without KillMode=process, `systemctl restart fleet-agent`
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
	assert.Contains(t, unit, "ExecStart=/usr/local/bin/fleet-agent serve --config /etc/fleet/agent.yaml")
	assert.Contains(t, unit, "User=fleet")
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
	p.Hardening = fleetagent.HardeningStrict
	strict := p.SystemdUnit()
	assert.Contains(t, strict, "ProtectSystem=strict")
	assert.NotContains(t, strict, "ProtectSystem=full")
	assert.Contains(t, strict, "ReadWritePaths=-/home/build/workspace /var/lib/fleet /var/log/fleet")

	p.Hardening = fleetagent.HardeningNone
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
	p.Hardening = fleetagent.HardeningStrict
	p.AllowedRoots = []string{"/home/build/workspace", "/srv/not-created-yet"}

	unit := p.SystemdUnit()
	assert.Contains(t, unit, "ReadWritePaths=-/home/build/workspace -/srv/not-created-yet /var/lib/fleet /var/log/fleet")

	for _, line := range strings.Split(unit, "\n") {
		if !strings.HasPrefix(line, "ReadWritePaths=") {
			continue
		}
		for _, entry := range strings.Fields(strings.TrimPrefix(line, "ReadWritePaths=")) {
			if entry == "/var/lib/fleet" || entry == "/var/log/fleet" {
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
	for _, root := range []string{"/tmp/fleet", "/tmp", "/var/tmp/build"} {
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
	p.Executable = "/opt/my tools/fleet-agent"
	p.ConfigPath = "/etc/my config/agent.yaml"
	assert.Contains(t, p.SystemdUnit(), `ExecStart="/opt/my tools/fleet-agent" serve --config "/etc/my config/agent.yaml"`)
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

	assert.Contains(t, plist, "<key>Label</key>\n\t<string>fleet-agent</string>")
	assert.Contains(t, plist, "<string>/usr/local/bin/fleet-agent</string>")
	assert.Contains(t, plist, "<string>serve</string>")
	assert.Contains(t, plist, "<string>--config</string>")
	assert.Contains(t, plist, "<string>/etc/fleet/agent.yaml</string>")
	assert.Contains(t, plist, "<key>UserName</key>\n\t<string>fleet</string>")
	assert.Contains(t, plist, "<key>RunAtLoad</key>")

	// Issue #18 asks for log paths under /Library/Logs/fleet; LogDir is
	// what carries that on macOS.
	assert.Contains(t, plist, "<string>/var/log/fleet/fleet-agent.out.log</string>")
	assert.Contains(t, plist, "<string>/var/log/fleet/fleet-agent.err.log</string>")
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

	assert.Equal(t, "fleet-agent", cfg.Name)
	assert.Equal(t, "fleet", cfg.UserName)
	assert.Equal(t, []string{"serve", "--config", "/etc/fleet/agent.yaml"}, cfg.Arguments)
	assert.Equal(t, "/usr/local/bin/fleet-agent", cfg.Executable)

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
	for input, want := range map[string]fleetagent.Hardening{
		"":         fleetagent.HardeningStandard,
		"standard": fleetagent.HardeningStandard,
		"STRICT":   fleetagent.HardeningStrict,
		" none ":   fleetagent.HardeningNone,
	} {
		got, err := fleetagent.ParseHardening(input)
		require.NoError(t, err, input)
		assert.Equal(t, want, got)
	}

	_, err := fleetagent.ParseHardening("paranoid")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "standard, strict, none")
}

// The Windows Scheduled Task is the answer to #74, and like the systemd unit
// and the launchd plist it is a pure function of UnitParams — so what an
// operator's machine would actually be given is asserted on every runner
// instead of only on a Windows one with an elevated token.
func TestScheduledTaskXML_RunsInTheOperatorsSession(t *testing.T) {
	p := params()
	p.User = `WORKSTATION\axel`
	doc := p.ScheduledTaskXML()

	// The line the whole change turns on. A service cannot have it: every
	// Windows service runs in session 0 whoever it runs as.
	assert.Contains(t, doc, "<LogonType>InteractiveToken</LogonType>")
	assert.NotContains(t, doc, "<LogonType>Password</LogonType>")
	assert.NotContains(t, doc, "<LogonType>S4U</LogonType>")

	// The agent runs every command a model asks for. It gets the operator's
	// ordinary token, not their elevated one.
	assert.Contains(t, doc, "<RunLevel>LeastPrivilege</RunLevel>")
	assert.NotContains(t, doc, "HighestAvailable")

	// Logon trigger and principal both name the account, or the task either
	// never fires or fires as somebody else.
	assert.Equal(t, 2, strings.Count(doc, "<UserId>WORKSTATION\\axel</UserId>"))
	assert.Contains(t, doc, "<LogonTrigger>")
}

// Every setting here is a Task Scheduler default that is wrong for a daemon,
// and each one produces a different flavour of "the agent stopped and nobody
// knows why".
func TestScheduledTaskXML_SettingsThatMakeItADaemon(t *testing.T) {
	doc := params().ScheduledTaskXML()

	// The default execution time limit is three days, after which Task
	// Scheduler kills the task.
	assert.Contains(t, doc, "<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>")
	// The defaults refuse to start on battery and stop when a laptop unplugs.
	// A workstation is the case this mechanism exists for.
	assert.Contains(t, doc, "<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>")
	assert.Contains(t, doc, "<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>")
	// A second logon must not start a second daemon against the same state
	// directory.
	assert.Contains(t, doc, "<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>")
	// The default priority is 7, which is below normal. The agent's children
	// are builds.
	assert.Contains(t, doc, "<Priority>5</Priority>")
	assert.NotContains(t, doc, "<Priority>7</Priority>")
	// Task Scheduler rejects a restart interval under a minute, so the 5s
	// delay the other two platforms honour is rounded up rather than rejected.
	assert.Contains(t, doc, "<Interval>PT1M</Interval>")
}

// The daemon is started with the config path baked in here too, and a config
// path with a space in it is one argument.
func TestScheduledTaskXML_Action(t *testing.T) {
	p := params()
	p.Executable = `C:\Program Files\fleet\fleet-agent.exe`
	p.ConfigPath = `C:\ProgramData\fleet\agent.yaml`
	doc := p.ScheduledTaskXML()

	assert.Contains(t, doc, `<Command>C:\Program Files\fleet\fleet-agent.exe</Command>`)
	assert.Contains(t, doc, `<Arguments>serve --config C:\ProgramData\fleet\agent.yaml</Arguments>`)

	p.ConfigPath = `C:\Program Files\fleet\agent.yaml`
	assert.Contains(t, p.ScheduledTaskXML(),
		`<Arguments>serve --config &quot;C:\Program Files\fleet\agent.yaml&quot;</Arguments>`,
		"Task Scheduler hands the arguments to CreateProcess as one string, so a path with a space has to be quoted")
}

// It has to be a document, not a string that looks like one.
func TestScheduledTaskXML_IsWellFormed(t *testing.T) {
	p := params()
	p.User = `WORK "GROUP"\a&b`
	p.Executable = `C:\tools\fleet & co\fleet-agent.exe`

	dec := xml.NewDecoder(strings.NewReader(p.ScheduledTaskXML()))
	// The document declares UTF-16 because that is what schtasks reads; the
	// renderer returns Go's UTF-8 and TaskXMLBytes does the conversion.
	dec.CharsetReader = func(_ string, input io.Reader) (io.Reader, error) { return input, nil }
	for {
		_, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
	}
}

// schtasks rejects a UTF-8 file with an error that names neither the encoding
// nor the file, so the bytes have to be right the first time.
func TestTaskXMLBytes_IsUTF16LEWithABOM(t *testing.T) {
	encoded := fleetagent.TaskXMLBytes("<a/>")
	require.Equal(t, []byte{0xFF, 0xFE, '<', 0, 'a', 0, '/', 0, '>', 0}, encoded)

	full := fleetagent.TaskXMLBytes(params().ScheduledTaskXML())
	require.Equal(t, byte(0xFF), full[0])
	require.Equal(t, byte(0xFE), full[1])
	decoded := utf16.Decode(func() []uint16 {
		units := make([]uint16, 0, (len(full)-2)/2)
		for i := 2; i+1 < len(full); i += 2 {
			units = append(units, uint16(full[i])|uint16(full[i+1])<<8)
		}
		return units
	}())
	assert.Equal(t, params().ScheduledTaskXML(), string(decoded))
}

// The Windows command-line quoting rules the <Arguments> element depends on.
func TestQuoteWindowsArgv(t *testing.T) {
	assert.Equal(t, `serve --config C:\ProgramData\fleet\agent.yaml`,
		fleetagent.QuoteWindowsArgvForTest([]string{"serve", "--config", `C:\ProgramData\fleet\agent.yaml`}))

	assert.Equal(t, `"C:\Program Files\fleet\agent.yaml"`,
		fleetagent.QuoteWindowsArgvForTest([]string{`C:\Program Files\fleet\agent.yaml`}))

	// A trailing backslash inside quotes would otherwise escape the closing
	// quote and swallow the next argument.
	assert.Equal(t, `"C:\a b\\" next`,
		fleetagent.QuoteWindowsArgvForTest([]string{`C:\a b\`, "next"}))

	// A literal quote is escaped, and the backslashes before it are doubled.
	assert.Equal(t, `"say \"hi\""`,
		fleetagent.QuoteWindowsArgvForTest([]string{`say "hi"`}))
}
