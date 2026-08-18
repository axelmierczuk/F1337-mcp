package fleetagent

import (
	"fmt"
	"runtime"

	"github.com/kardianos/service"

	"github.com/axelmierczuk/fleet-mcp/internal/agent"
)

// registration is the subset of kardianos/service's Service that the `service`
// subcommands actually use.
//
// It exists so that a Windows Scheduled Task can stand in for a service manager
// registration without every subcommand growing a branch. The two mechanisms
// differ in what they can do — a task cannot host a built-in service identity,
// a service cannot reach an interactive session — and in nothing else the
// commands care about.
type registration interface {
	Install() error
	Uninstall() error
	Start() error
	Stop() error
	Restart() error
	Status() (service.Status, error)
}

// hostRegistration builds the registration `install` will write.
//
// password is the account's password, needed only by the Windows SCM and only
// for a named account. It is passed through to CreateService and stored by the
// SCM as a machine-bound LSA secret; nothing here writes it anywhere.
func hostRegistration(m Mechanism, params UnitParams, password string) (registration, error) {
	if m == MechanismTask {
		return newScheduledTask(params)
	}
	svc, err := service.New(&program{}, scmServiceConfig(params, runtime.GOOS, password))
	if err != nil {
		return nil, fmt.Errorf("prepare service definition: %w", err)
	}
	return svc, nil
}

// scmServiceConfig is the definition `install` hands the service manager.
//
// Split out from newRegistration so the one thing in it that is not already a
// pure function of UnitParams — the account, which the SCM spells differently
// from everything else on the host and differently from the Task Scheduler —
// can be asserted without a service manager. Applied here and nowhere else, so
// the account `install` prints and reasons about stays the one the operator
// typed.
func scmServiceConfig(params UnitParams, goos, password string) *service.Config {
	scm := params
	scm.User = serviceAccountName(params.User, goos)
	return scm.ServiceConfigWithPassword(password)
}

// controlRegistration and installedMechanisms are indirected so that the
// commands built on them can be driven end to end from a test.
//
// Everything `service status` decides — whether a running agent is confined,
// what to tell the operator, and what to exit with — is production code that
// only runs once something says the agent is installed and up, and nothing a
// test may do can install a service or a scheduled task: that needs root, a
// service manager, and on Windows an elevated token. Testing the judgement by
// calling the judge directly is how this repository has three times shipped a
// fix the command never reached, so the seam is here, at the host lookup, and
// the whole of the command above it is real.
//
// Same shape as internal/agent's systemConfigDir, and the same rule: assigned
// only by a test, and only for the duration of one.
//
// requireElevated is here for the same reason and with the same rule. `service
// uninstall` refuses without root or an elevated token, which is correct and is
// also why nothing on any runner had ever driven the rest of it: what uninstall
// does — walk *every* registration the host carries, and keep going when one of
// them refuses — is the behaviour an operator on a host with two of them most
// needs, and it was reachable by nothing. The gate itself stays asserted by the
// unprivileged tests, which is the half a seam here cannot weaken.
//
// newRegistration is here for the same reason, and it is what makes the rest of
// `service install` reachable at all.
//
// Everything the command decides in sequence — which registration to remove
// first, whether the daemon was running before it started, whether a failure
// left the host with nothing registered, and whether the agent it stopped is
// running again when the command returns — is production code that only runs
// once something writes a definition to a real service manager. Three audit
// rounds named that half unreachable and left it so, and every one of those
// decisions was therefore free: deleting the removal, the replacement, the
// restart or the warning each left the whole suite green.
//
// The seam is at the same place the two above are: the boundary where this
// program stops deciding and starts talking to the host. The whole of
// runServiceInstall stays real, is entered from `fleet-agent service install`,
// and would notice if it stopped calling any of this. The steps that would
// change a machine are kept out by what the scenario passes — a config whose
// state and log directories are its own, and an account whose grants are
// no-ops — not by this seam.
//
// legacyServiceInstalled joins them because a host carrying a pre-rebrand
// registration is another thing no runner has, and `install` warning about one
// before it changes anything is the difference between an operator stopping and
// an operator ending up with two daemons against one state directory.
var (
	controlRegistration    = newControlRegistration
	installedMechanisms    = hostInstalledMechanisms
	requireElevated        = requireElevation
	newRegistration        = hostRegistration
	legacyServiceInstalled = hostLegacyServiceInstalled
)

// newControlRegistration addresses an already-installed registration by name,
// for the commands that only start, stop or remove one.
func newControlRegistration(m Mechanism) (registration, error) {
	if m == MechanismTask {
		return newScheduledTask(UnitParams{})
	}
	svc, err := service.New(&program{}, minimalServiceConfig())
	if err != nil {
		return nil, fmt.Errorf("prepare service definition: %w", err)
	}
	return svc, nil
}

// hostInstalledMechanisms reports how the agent is registered on this host.
//
// It returns a list rather than one answer because a host can carry both, and
// that is not hypothetical: it is what an operator who switches mechanisms gets
// unless something removes the old one. Two registrations means two daemons
// starting against the same state directory, both re-adopting the same
// supervised processes and each deciding on its own whether to restart them —
// the same outcome docs/service.md describes for a pre-rebrand service left in
// place, from a different cause.
func hostInstalledMechanisms() []Mechanism {
	var found []Mechanism
	if svc, err := service.New(&program{}, minimalServiceConfig()); err == nil && isInstalled(svc) {
		found = append(found, MechanismService)
	}
	if scheduledTaskInstalled() {
		found = append(found, MechanismTask)
	}
	return found
}

// stateDirForStatus is where the running daemon's runtime report should be.
//
// It comes off the config when there is a loadable one, because `state_dir` is
// configurable and an agent that moved it would otherwise be reported on from
// an empty directory. A host with no readable config falls back to the default,
// which is where an installed agent's state is unless somebody changed it.
func stateDirForStatus() string {
	path, err := agent.ResolveConfigPath("")
	if err != nil {
		return agent.DefaultStateDir()
	}
	cfg, err := agent.Load(path)
	if err != nil || cfg.StateDir == "" {
		return agent.DefaultStateDir()
	}
	return cfg.StateDir
}
