package fleetagent

import (
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/kardianos/service"
)

// The systemd and launchd renderers below use "path", not "path/filepath".
//
// A unit file and a plist are POSIX artifacts: every path inside one is
// slash-separated whatever machine wrote it. Using filepath makes the rendered
// output depend on the host's separator, which is wrong twice over — it would
// emit `\var\log\...` into a plist if the renderer ever ran on Windows, and it
// makes a pure function's result vary by GOOS, so the tests that assert what
// gets installed only assert it on some runners.

// ServiceName is the identifier the daemon is registered under with every
// platform's service manager: the systemd unit, the launchd label, and the
// Windows service name.
const ServiceName = "fleet-agent"

// Hardening selects how much the platform's service manager is asked to
// constrain the daemon.
//
// The agent's job is running arbitrary commands and writing files under its
// roots, so this is genuinely easy to overtighten: a directive that looks
// obviously correct on a daemon that serves HTTP breaks a daemon whose whole
// purpose is `go build`.
type Hardening string

const (
	// HardeningStandard is the default: the baseline issue #18 asks for, minus
	// anything that would stop a build from running.
	HardeningStandard Hardening = "standard"
	// HardeningStrict adds ProtectSystem=strict with the allowed roots as
	// ReadWritePaths. It is opt-in because a toolchain that writes outside the
	// roots — ~/.cache/go-build, ~/.npm, ~/.cargo — stops working under it
	// unless those directories are roots too.
	HardeningStrict Hardening = "strict"
	// HardeningNone emits no confinement directives.
	HardeningNone Hardening = "none"
)

// ParseHardening validates a --hardening value.
func ParseHardening(s string) (Hardening, error) {
	switch Hardening(strings.ToLower(strings.TrimSpace(s))) {
	case "", HardeningStandard:
		return HardeningStandard, nil
	case HardeningStrict:
		return HardeningStrict, nil
	case HardeningNone:
		return HardeningNone, nil
	default:
		return "", fmt.Errorf("--hardening must be one of standard, strict, none (got %q)", s)
	}
}

// UnitParams is everything that varies between installs. It is the input to
// every unit-file renderer, and is deliberately a plain value: rendering is a
// pure function of it, so the parts of `service install` that decide what the
// unit says are testable without a service manager or root.
type UnitParams struct {
	// Executable is the absolute path to the fleet-agent binary.
	Executable string
	// ConfigPath is the agent config the unit passes to `serve`.
	ConfigPath string
	// User is the account the daemon runs as. Never defaulted to a superuser:
	// every command the sandbox runs inherits this identity.
	User string
	// Group is the account's primary group. Empty means the platform default.
	Group string
	// AllowedRoots are the config's allowed roots, needed as ReadWritePaths
	// under strict hardening.
	AllowedRoots []string
	// StateDir and LogDir are created at install time and must remain
	// writable under any hardening level.
	StateDir string
	LogDir   string
	// RestartDelay is how long the service manager waits before restarting a
	// failed daemon.
	RestartDelay time.Duration
	// StopTimeout is how long the service manager waits for a graceful stop.
	// It must exceed the daemon's own drain deadline, or the drain is cut
	// short by a SIGKILL from outside.
	StopTimeout time.Duration
	// Hardening selects the confinement directive set.
	Hardening Hardening
}

// Arguments is the argv the service manager starts the daemon with.
func (p UnitParams) Arguments() []string {
	return []string{"serve", "--config", p.ConfigPath}
}

// SystemdUnit renders the complete systemd unit file.
//
// It is passed to kardianos/service as a fully expanded SystemdScript rather
// than assembled from its options, because the two directives that matter most
// here — KillMode and the hardening set — are not expressible through them.
func (p UnitParams) SystemdUnit() string {
	var b strings.Builder

	b.WriteString("[Unit]\n")
	b.WriteString("Description=fleet agent\n")
	b.WriteString("Documentation=https://github.com/axelmierczuk/fleet-mcp\n")
	b.WriteString("After=network-online.target\n")
	b.WriteString("Wants=network-online.target\n")
	b.WriteString("ConditionFileIsExecutable=" + p.Executable + "\n")

	b.WriteString("\n[Service]\n")
	b.WriteString("Type=simple\n")
	b.WriteString("ExecStart=" + quoteArgv(append([]string{p.Executable}, p.Arguments()...)) + "\n")
	if p.User != "" {
		b.WriteString("User=" + p.User + "\n")
	}
	if p.Group != "" {
		b.WriteString("Group=" + p.Group + "\n")
	}
	b.WriteString("Restart=on-failure\n")
	b.WriteString("RestartSec=" + seconds(p.RestartDelay) + "\n")

	// The load-bearing line in this file.
	//
	// systemd's default KillMode=control-group sends SIGTERM to every process
	// in the unit's cgroup on stop — which is every background process the
	// agent supervises. That turns `systemctl restart fleet-agent`, and
	// therefore every agent upgrade, into "kill every dev server in the
	// fleet". KillMode=process signals only the daemon, which is exactly the
	// ownership model the supervisor is built on.
	b.WriteString("KillMode=process\n")
	b.WriteString("KillSignal=SIGTERM\n")
	b.WriteString("TimeoutStopSec=" + seconds(p.StopTimeout) + "\n")
	b.WriteString("SendSIGKILL=yes\n")

	// Journal capture. The daemon logs to stderr with log/slog.
	b.WriteString("StandardOutput=journal\n")
	b.WriteString("StandardError=journal\n")
	b.WriteString("SyslogIdentifier=" + ServiceName + "\n")

	for _, line := range p.systemdHardening() {
		b.WriteString(line + "\n")
	}

	b.WriteString("\n[Install]\n")
	b.WriteString("WantedBy=multi-user.target\n")
	return b.String()
}

// systemdHardening returns the confinement directives for the selected level.
//
// What is deliberately absent is as considered as what is present.
// ProtectHome is not set: developer toolchains keep their caches in the
// service user's home directory, and making it inaccessible breaks `go build`
// before it breaks an attacker. PrivateDevices, RestrictAddressFamilies and
// SystemCallFilter are not set: the agent runs arbitrary programs, and every
// one of those turns an ordinary build failure into an unexplainable one.
func (p UnitParams) systemdHardening() []string {
	if p.Hardening == HardeningNone {
		return nil
	}

	lines := []string{
		"",
		"# Hardening. The agent runs arbitrary commands by design, so this is a",
		"# baseline rather than a boundary; see docs/security.md.",
		// Blocks setuid escalation from inside a sandbox command: `sudo` will
		// not work under the agent. That is the intent, not a side effect.
		"NoNewPrivileges=yes",
	}

	// PrivateTmp gives the unit its own /tmp. That is a straightforward win
	// unless an allowed root lives under /tmp — as it does in the shipped
	// example config — in which case every file the agent writes there becomes
	// invisible to the rest of the host and vanishes on restart. Silently
	// breaking a configured root is worse than skipping one directive.
	if !p.rootsUnderTmp() {
		lines = append(lines, "PrivateTmp=yes")
	} else {
		lines = append(lines, "# PrivateTmp omitted: an allowed root lives under /tmp, which a private", "# /tmp would hide from the rest of the host.")
	}

	if p.Hardening == HardeningStrict {
		lines = append(lines, "ProtectSystem=strict")
		if paths := p.readWritePaths(); len(paths) > 0 {
			lines = append(lines, "ReadWritePaths="+strings.Join(paths, " "))
		}
	} else {
		// full also makes /etc read-only, which the agent has no reason to
		// write and an escaped command has every reason to.
		lines = append(lines, "ProtectSystem=full")
	}
	return lines
}

// readWritePaths is every directory that must stay writable under
// ProtectSystem=strict: the roots the agent serves, plus its own state and
// logs.
//
// The roots carry systemd's "-" prefix, which means "ignore this one if it does
// not exist". Without it a unit naming a directory that is not there fails to
// set up its mount namespace and the service will not start at all.
//
// A configured root that does not exist is an ordinary state on a running
// agent, because on the default configuration the roots are never handed to
// the jail: exec is on, so internal/security/jail is not constructed and
// nothing ever checks whether they are there. Only an exec-disabled agent
// builds a jail, and that one refuses a missing root outright — but by then it
// has refused to start, which is a far better failure than a service that
// cannot enter its own namespace for a reason systemd states obliquely.
//
// The state and log directories are not prefixed: `install` creates them, so
// one of those missing is a real fault and worth failing on.
func (p UnitParams) readWritePaths() []string {
	seen := map[string]bool{}
	var paths []string
	add := func(path, prefix string) {
		if path == "" || seen[path] {
			return
		}
		seen[path] = true
		paths = append(paths, prefix+path)
	}
	for _, root := range p.AllowedRoots {
		add(root, "-")
	}
	add(p.StateDir, "")
	add(p.LogDir, "")
	sort.Strings(paths)
	return paths
}

func (p UnitParams) rootsUnderTmp() bool {
	for _, root := range p.AllowedRoots {
		// path.Clean, not filepath.Clean: this asks a question about a Linux
		// filesystem — is a root under /tmp — and the answer must not change
		// because the string was cleaned on a host that separates with a
		// backslash.
		clean := path.Clean(root)
		if clean == "/tmp" || clean == "/var/tmp" ||
			strings.HasPrefix(clean, "/tmp/") || strings.HasPrefix(clean, "/var/tmp/") {
			return true
		}
	}
	return false
}

// LaunchdPlist renders the complete launchd job.
func (p UnitParams) LaunchdPlist() string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString(`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` + "\n")
	b.WriteString(`<plist version="1.0">` + "\n<dict>\n")

	writeKey(&b, "Label", plistString(ServiceName))

	b.WriteString("\t<key>ProgramArguments</key>\n\t<array>\n")
	for _, arg := range append([]string{p.Executable}, p.Arguments()...) {
		b.WriteString("\t\t<string>" + escapeXML(arg) + "</string>\n")
	}
	b.WriteString("\t</array>\n")

	if p.User != "" {
		writeKey(&b, "UserName", plistString(p.User))
	}
	if p.Group != "" {
		writeKey(&b, "GroupName", plistString(p.Group))
	}

	writeKey(&b, "RunAtLoad", "<true/>")

	// KeepAlive as a dictionary rather than a bare true: SuccessfulExit=false
	// restarts the daemon when it fails and leaves it stopped when an operator
	// stopped it deliberately. A bare <true/> fights `launchctl stop`.
	b.WriteString("\t<key>KeepAlive</key>\n\t<dict>\n")
	b.WriteString("\t\t<key>SuccessfulExit</key>\n\t\t<false/>\n")
	b.WriteString("\t</dict>\n")

	// The launchd counterpart of KillMode=process. Without it, launchd kills
	// every process left in the job's process group when the job stops, which
	// is every supervised background process the agent started.
	writeKey(&b, "AbandonProcessGroup", "<true/>")

	writeKey(&b, "ProcessType", plistString("Background"))
	writeKey(&b, "ThrottleInterval", "<integer>"+seconds(p.RestartDelay)+"</integer>")
	writeKey(&b, "ExitTimeOut", "<integer>"+seconds(p.StopTimeout)+"</integer>")
	writeKey(&b, "StandardOutPath", plistString(path.Join(p.LogDir, ServiceName+".out.log")))
	writeKey(&b, "StandardErrorPath", plistString(path.Join(p.LogDir, ServiceName+".err.log")))

	b.WriteString("</dict>\n</plist>\n")
	return b.String()
}

// ServiceConfig builds the kardianos/service configuration for these
// parameters, including the per-platform options that the rendered unit files
// do not cover.
func (p UnitParams) ServiceConfig() *service.Config {
	return p.ServiceConfigWithPassword("")
}

// ServiceConfigWithPassword is ServiceConfig for a Windows service registered
// under a named account, which the SCM will not create without credentials.
//
// The password is a parameter rather than a field on UnitParams because
// UnitParams is the value that gets rendered, compared and printed — including
// into a test failure — and the one thing this password must never do is end up
// anywhere but the LSA secret the SCM stores it in. It is handed to
// CreateService and then goes out of scope.
func (p UnitParams) ServiceConfigWithPassword(password string) *service.Config {
	cfg := &service.Config{
		Name:        ServiceName,
		DisplayName: "fleet agent",
		Description: "Runs commands and serves files for a fleet over gRPC.",
		Executable:  p.Executable,
		Arguments:   p.Arguments(),
		UserName:    p.User,
		Option: service.KeyValue{
			// POSIX: fully rendered unit files, so nothing here depends on the
			// shape of the library's built-in templates.
			"SystemdScript": p.SystemdUnit(),
			"LaunchdConfig": p.LaunchdPlist(),
			"LogDirectory":  p.LogDir,

			// Windows: the service is created through the SCM API rather than
			// from a template, so these options are the whole configuration.
			"StartType":              "automatic",
			"DelayedAutoStart":       false,
			"OnFailure":              "restart",
			"OnFailureDelayDuration": p.RestartDelay.String(),
			// Reset the failure counter daily, so a service that fails once a
			// week still gets its restart rather than exhausting the actions.
			"OnFailureResetPeriod": 86400,
		},
	}
	if password != "" {
		cfg.Option["Password"] = password
	}
	return cfg
}

func writeKey(b *strings.Builder, key, value string) {
	b.WriteString("\t<key>" + key + "</key>\n\t" + value + "\n")
}

func plistString(s string) string { return "<string>" + escapeXML(s) + "</string>" }

var xmlEscaper = strings.NewReplacer(
	"&", "&amp;",
	"<", "&lt;",
	">", "&gt;",
	`"`, "&quot;",
	"'", "&apos;",
)

func escapeXML(s string) string { return xmlEscaper.Replace(s) }

// quoteArgv renders an argv for an ExecStart line, quoting any argument that
// contains whitespace. systemd splits ExecStart on whitespace, so an
// unquoted path with a space in it silently becomes two arguments.
func quoteArgv(argv []string) string {
	parts := make([]string, 0, len(argv))
	for _, arg := range argv {
		if strings.ContainsAny(arg, " \t\"") {
			arg = `"` + strings.ReplaceAll(strings.ReplaceAll(arg, `\`, `\\`), `"`, `\"`) + `"`
		}
		parts = append(parts, arg)
	}
	return strings.Join(parts, " ")
}

func seconds(d time.Duration) string {
	if d <= 0 {
		return "0"
	}
	return strconv.Itoa(int(d.Round(time.Second) / time.Second))
}

// TaskPath is the Task Scheduler path the Windows Scheduled Task registers
// under. Tasks live in a folder tree; the root folder is where an operator
// looking for it in taskschd.msc will look first.
const TaskPath = `\` + ServiceName

// ScheduledTaskXML renders the complete Task Scheduler definition for a
// logon-triggered task running in the operator's own session.
//
// This is the Windows answer to the systemd unit and the launchd job, and it is
// rendered rather than assembled for the same reason they are: what gets
// registered is then a pure function of UnitParams, so the decisions in it are
// assertable from every runner instead of only from a Windows one with an
// elevated token.
//
// The settings that are not boilerplate:
//
//   - LogonType InteractiveToken is the whole point. It runs the agent in the
//     session the operator is logged into, with their profile and their PATH,
//     and it needs no password. A service cannot do this: every Windows service
//     runs in session 0.
//   - RunLevel LeastPrivilege. The task inherits the operator's ordinary token,
//     not an elevated one. Every command the agent runs runs as them, and this
//     project's position is that handing the model an administrator is the same
//     mistake as handing it root.
//   - ExecutionTimeLimit PT0S disables the three-day default kill. A daemon is
//     not a batch job.
//   - The battery settings are inverted from the Task Scheduler defaults, which
//     refuse to start on battery and stop when a laptop unplugs. A workstation
//     is the case this mechanism exists for.
//   - Priority 5 is NORMAL_PRIORITY_CLASS. The default for a scheduled task is
//     7, which is below normal, and the agent's children are builds.
//   - MultipleInstancesPolicy IgnoreNew, so a second logon does not start a
//     second daemon against the same state directory.
func (p UnitParams) ScheduledTaskXML() string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-16"?>` + "\r\n")
	b.WriteString(`<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">` + "\r\n")

	b.WriteString("  <RegistrationInfo>\r\n")
	b.WriteString("    <Description>Runs commands and serves files for a fleet over gRPC.</Description>\r\n")
	b.WriteString("    <URI>" + escapeXML(TaskPath) + "</URI>\r\n")
	b.WriteString("  </RegistrationInfo>\r\n")

	b.WriteString("  <Triggers>\r\n")
	b.WriteString("    <LogonTrigger>\r\n")
	b.WriteString("      <Enabled>true</Enabled>\r\n")
	b.WriteString("      <UserId>" + escapeXML(p.User) + "</UserId>\r\n")
	b.WriteString("    </LogonTrigger>\r\n")
	b.WriteString("  </Triggers>\r\n")

	b.WriteString("  <Principals>\r\n")
	b.WriteString(`    <Principal id="Author">` + "\r\n")
	b.WriteString("      <UserId>" + escapeXML(p.User) + "</UserId>\r\n")
	b.WriteString("      <LogonType>InteractiveToken</LogonType>\r\n")
	b.WriteString("      <RunLevel>LeastPrivilege</RunLevel>\r\n")
	b.WriteString("    </Principal>\r\n")
	b.WriteString("  </Principals>\r\n")

	b.WriteString("  <Settings>\r\n")
	b.WriteString("    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\r\n")
	b.WriteString("    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\r\n")
	b.WriteString("    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\r\n")
	b.WriteString("    <AllowHardTerminate>true</AllowHardTerminate>\r\n")
	b.WriteString("    <StartWhenAvailable>true</StartWhenAvailable>\r\n")
	b.WriteString("    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>\r\n")
	b.WriteString("    <IdleSettings>\r\n")
	b.WriteString("      <StopOnIdleEnd>false</StopOnIdleEnd>\r\n")
	b.WriteString("      <RestartOnIdle>false</RestartOnIdle>\r\n")
	b.WriteString("    </IdleSettings>\r\n")
	b.WriteString("    <AllowStartOnDemand>true</AllowStartOnDemand>\r\n")
	b.WriteString("    <Enabled>true</Enabled>\r\n")
	b.WriteString("    <Hidden>false</Hidden>\r\n")
	b.WriteString("    <RunOnlyIfIdle>false</RunOnlyIfIdle>\r\n")
	b.WriteString("    <DisallowStartOnRemoteAppSession>false</DisallowStartOnRemoteAppSession>\r\n")
	b.WriteString("    <UseUnifiedSchedulingEngine>true</UseUnifiedSchedulingEngine>\r\n")
	b.WriteString("    <WakeToRun>false</WakeToRun>\r\n")
	b.WriteString("    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>\r\n")
	b.WriteString("    <Priority>5</Priority>\r\n")
	b.WriteString("    <RestartOnFailure>\r\n")
	// Task Scheduler rejects an interval under a minute, so the restart delay
	// the other two platforms honour to the second is rounded up to one here
	// rather than silently rejected at registration.
	b.WriteString("      <Interval>PT" + taskMinutes(p.RestartDelay) + "M</Interval>\r\n")
	b.WriteString("      <Count>3</Count>\r\n")
	b.WriteString("    </RestartOnFailure>\r\n")
	b.WriteString("  </Settings>\r\n")

	b.WriteString(`  <Actions Context="Author">` + "\r\n")
	b.WriteString("    <Exec>\r\n")
	b.WriteString("      <Command>" + escapeXML(p.Executable) + "</Command>\r\n")
	b.WriteString("      <Arguments>" + escapeXML(quoteWindowsArgv(p.Arguments())) + "</Arguments>\r\n")
	b.WriteString("    </Exec>\r\n")
	b.WriteString("  </Actions>\r\n")

	b.WriteString("</Task>\r\n")
	return b.String()
}

// taskMinutes renders a duration as whole minutes, never fewer than one.
func taskMinutes(d time.Duration) string {
	minutes := int((d + time.Minute - 1) / time.Minute)
	if minutes < 1 {
		minutes = 1
	}
	return strconv.Itoa(minutes)
}

// quoteWindowsArgv renders an argv as one command line the CRT will split back
// into the same arguments.
//
// The Task Scheduler takes the arguments as a single string and hands it to
// CreateProcess, so a config path with a space in it — `C:\Program Files\...`,
// which is where an operator will put one — becomes two arguments unless it is
// quoted here. Backslashes are only special immediately before a quote, which
// is the rule this implements and the reason a Windows path full of them can be
// quoted without escaping every one.
func quoteWindowsArgv(argv []string) string {
	parts := make([]string, 0, len(argv))
	for _, arg := range argv {
		if arg != "" && !strings.ContainsAny(arg, " \t\n\v\"") {
			parts = append(parts, arg)
			continue
		}
		var b strings.Builder
		b.WriteByte('"')
		slashes := 0
		for _, r := range arg {
			switch r {
			case '\\':
				slashes++
			case '"':
				// A quote is escaped, and every backslash run that immediately
				// precedes one has to be doubled first or the CRT reads it as
				// escaping the backslash instead.
				b.WriteString(strings.Repeat(`\`, 2*slashes+1))
				b.WriteByte('"')
				slashes = 0
			default:
				b.WriteString(strings.Repeat(`\`, slashes))
				slashes = 0
				b.WriteRune(r)
			}
		}
		// Trailing backslashes are doubled: undoubled, the last one would
		// escape the closing quote.
		b.WriteString(strings.Repeat(`\`, 2*slashes))
		b.WriteByte('"')
		parts = append(parts, b.String())
	}
	return strings.Join(parts, " ")
}

// TaskXMLBytes encodes a rendered task definition the way schtasks.exe insists
// on reading one: UTF-16, little-endian, with a byte-order mark.
//
// Not a detail worth discovering at an operator's install. schtasks rejects a
// UTF-8 file with "The task XML contains a value which is incorrectly formatted
// or out of range", which names neither the encoding nor the file, and the
// declaration at the top of the document has to agree with the bytes under it.
func TaskXMLBytes(xml string) []byte {
	units := utf16.Encode([]rune(xml))
	out := make([]byte, 0, 2+2*len(units))
	out = append(out, 0xFF, 0xFE) // BOM, little-endian
	for _, unit := range units {
		out = append(out, byte(unit), byte(unit>>8))
	}
	return out
}
