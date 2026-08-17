package fleetagent

import (
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

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
	b.WriteString("Description=sandboxd agent\n")
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
	return &service.Config{
		Name:        ServiceName,
		DisplayName: "sandboxd agent",
		Description: "Runs commands and serves files for a sandboxd fleet over mTLS gRPC.",
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
