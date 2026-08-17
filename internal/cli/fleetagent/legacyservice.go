package fleetagent

import (
	"runtime"
	"strings"

	"github.com/kardianos/service"

	"github.com/axelmierczuk/fleet-mcp/internal/cli"
)

// legacyServiceName is what [ServiceName] was before the fleet rebrand.
//
// Nothing is ever installed under it again. It is still recognised because the
// `service` subcommands address the platform's manager *by name*, and they only
// know the new one — so on a host that still carries the old registration every
// answer they give is wrong in a way that costs the operator something:
//
//   - `status` reports the service not installed while the old daemon is
//     running perfectly well beside it,
//   - `uninstall` reports there is nothing to remove and removes nothing,
//   - `install` registers a *second* service pointing at the same config and
//     the same state directory. Both start at boot, both re-adopt the same
//     supervised processes out of that directory, and both decide on their own
//     whether to restart them.
//
// The rest of the compatibility matrix — the two environment variables, the
// config directory and the directories nested inside it, the Linux service
// account — resolves the old name in code. This one cannot: removing a service
// is not something a daemon should do to a host behind the operator's back. But
// *noticing* it is, and it costs one status query on a command that already
// makes several.
const legacyServiceName = "sandboxd-agent"

// legacyServiceInstalled reports whether this host still has a service
// registered under the pre-rebrand name.
//
// It asks the same way [isInstalled] does and inherits the same bias: any
// failure to read a status reads as "not installed". A host with no service
// manager, or one this process cannot query, therefore stays silent rather than
// warning about a service that may not be there.
func legacyServiceInstalled() bool {
	svc, err := service.New(&program{}, &service.Config{
		Name:        legacyServiceName,
		DisplayName: "sandboxd agent",
		Description: "Pre-rebrand fleet agent, kept only so this one can be recognised.",
	})
	if err != nil {
		return false
	}
	return isInstalled(svc)
}

// legacyServiceNote is what to tell an operator whose host still carries a
// service under the pre-rebrand name, or "" when it does not.
//
// It takes the answer rather than asking for it. The message is the part worth
// pinning — a host with a service manager and a pre-rebrand unit registered on
// it is not something a test can arrange, and CI cannot install services at
// all (see docs/service.md → Manual verification).
func legacyServiceNote(present bool) string {
	if !present {
		return ""
	}
	var b strings.Builder
	b.WriteString("WARNING: this host still has a service registered as " + legacyServiceName + ", from\n")
	b.WriteString("         before the fleet rebrand. The `service` subcommands only know\n")
	b.WriteString("         " + ServiceName + ", so they do not stop, remove, or report on it — and\n")
	b.WriteString("         `service install` registers a second service beside it, pointing at\n")
	b.WriteString("         the same config and the same state directory.\n")
	b.WriteString("\n")
	b.WriteString("         Remove it first, with the platform's own tools:\n")
	for _, command := range legacyServiceRemoval() {
		b.WriteString("           " + command + "\n")
	}
	b.WriteString("\n")
	b.WriteString("         Full migration steps: docs/quickstart.md, \"Upgrading from sandboxd\".")
	return b.String()
}

// legacyServiceRemoval returns the commands that remove a pre-rebrand service
// on this platform. They are the ones docs/service.md prints, kept here so the
// operator is told at the moment it matters rather than only in a document
// they have already not read.
func legacyServiceRemoval() []string {
	switch runtime.GOOS {
	case "windows":
		return []string{
			"sc.exe stop " + legacyServiceName,
			"sc.exe delete " + legacyServiceName,
		}
	case "darwin":
		return []string{
			"sudo launchctl bootout system /Library/LaunchDaemons/" + legacyServiceName + ".plist",
			"sudo rm /Library/LaunchDaemons/" + legacyServiceName + ".plist",
		}
	default:
		return []string{
			"sudo systemctl disable --now " + legacyServiceName,
			"sudo rm /etc/systemd/system/" + legacyServiceName + ".service && sudo systemctl daemon-reload",
		}
	}
}

// noteLegacyService prints the pre-rebrand-service warning, when there is one
// to print.
//
// Called from every place that would otherwise give a confidently wrong answer:
// before `install` changes anything, and on the not-installed branch of
// `status` and `uninstall`.
func noteLegacyService(p *cli.Printer) {
	if note := legacyServiceNote(legacyServiceInstalled()); note != "" {
		p.Println(note)
	}
}
