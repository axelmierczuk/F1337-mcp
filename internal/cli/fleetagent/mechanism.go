package fleetagent

import (
	"fmt"
	"runtime"
	"strings"
)

// Mechanism is how the agent is registered to start on this host.
//
// Everywhere but Windows there is one answer — the platform's service manager
// — and this type is a formality. On Windows there are two, they are not
// interchangeable, and the difference is the whole of #74.
//
// A Windows service runs in session 0, which has been isolated from every
// interactive session since Vista. Under a built-in service identity it has no
// operator profile at all, so it sees none of nvm, rustup, pyenv, cargo, scoop,
// npm globals, or the credentials in %APPDATA% that git and the package
// registries read. On a developer machine that is most of PATH, and an agent
// whose entire purpose is running the commands the operator would type cannot
// run them.
//
// A logon-triggered Scheduled Task runs in the operator's own session, with
// their profile and their PATH, and needs no password. It also stops at logout,
// which is the trade.
type Mechanism string

const (
	// MechanismAuto lets install pick, which is what an operator who has never
	// heard of session 0 should get.
	MechanismAuto Mechanism = "auto"
	// MechanismService registers with the platform's service manager: systemd,
	// launchd, or the Windows SCM.
	MechanismService Mechanism = "service"
	// MechanismTask registers a logon-triggered Scheduled Task. Windows only.
	MechanismTask Mechanism = "task"
)

// ParseMechanism validates a --mechanism value.
func ParseMechanism(s string) (Mechanism, error) {
	switch Mechanism(strings.ToLower(strings.TrimSpace(s))) {
	case "", MechanismAuto:
		return MechanismAuto, nil
	case MechanismService:
		return MechanismService, nil
	case MechanismTask:
		return MechanismTask, nil
	default:
		return "", fmt.Errorf("--mechanism must be one of auto, service, task (got %q)", s)
	}
}

// Describe names the mechanism the way the output and the docs do.
func (m Mechanism) Describe() string {
	switch m {
	case MechanismTask:
		return "logon-triggered Scheduled Task"
	case MechanismService:
		if runtime.GOOS == "windows" {
			return "Windows service"
		}
		return "service manager registration"
	default:
		return string(m)
	}
}

// resolveMechanism turns --mechanism and --user into the one mechanism install
// will use, or an error naming the combination that cannot exist.
//
// goos is a parameter rather than runtime.GOOS so the rule is assertable from
// every runner rather than only from a Windows one. It is the rule, not the
// registration, that decides whether an operator ends up with a usable agent.
func resolveMechanism(requested Mechanism, goos, account string) (Mechanism, error) {
	if goos != "windows" {
		if requested == MechanismTask {
			return "", fmt.Errorf("--mechanism task is Windows-only: it registers a logon-triggered Scheduled Task, and %s has no Task Scheduler.\n\nUse --mechanism service, or leave it at auto", goos)
		}
		return MechanismService, nil
	}

	sessionZero := runsInSessionZero(account)
	switch requested {
	case MechanismService:
		return MechanismService, nil
	case MechanismTask:
		if sessionZero {
			return "", fmt.Errorf("--mechanism task cannot run as %s: a logon trigger fires when an account logs on interactively, and a built-in service identity never does.\n\nEither drop --user, so the task runs as the invoking operator, or keep %s and pass --mechanism service — accepting that the agent then runs in session 0 and cannot see any per-user toolchain",
				account, account)
		}
		return MechanismTask, nil
	default:
		// auto. A built-in service identity is a deliberate ask for a confined
		// agent, and the only mechanism that can host one is a service.
		// Everything else — which is to say every operator who did not pass
		// --user — gets their own session.
		if sessionZero {
			return MechanismService, nil
		}
		return MechanismTask, nil
	}
}

// serviceAccountName is what the platform's service manager wants the account
// spelled as.
//
// CreateService resolves a bare name against the domain, not the machine, so a
// local account has to be spelled `.\name` or the install fails on a
// domain-joined host with an error about a nonexistent account. The task
// scheduler wants the opposite — `.\name` is not a valid <UserId> — which is
// why this is applied to the service configuration only and not to the account
// the rest of `install` prints and reasons about.
//
// goos is a parameter for the same reason resolveMechanism's is: the rule
// decides whether a real install succeeds on a domain-joined host, no runner
// here has one, and a rule that only compiles on Windows is a rule only the
// Windows runner can check. Everywhere else the account is spelled as given.
func serviceAccountName(name, goos string) string {
	if goos != "windows" || name == "" || runsInSessionZero(name) {
		return name
	}
	if strings.ContainsAny(name, `\/@`) {
		return name
	}
	return `.\` + name
}

// serviceNeedsPassword reports whether the platform's service manager will
// refuse to register this account without its password.
//
// Only the Windows SCM asks, and only for a named account: it logs the account
// on with LogonUser to start the service, so it needs credentials. The built-in
// service identities have none, and a Scheduled Task with an interactive logon
// type borrows the operator's existing session rather than starting one.
func serviceNeedsPassword(m Mechanism, goos, account string) bool {
	return goos == "windows" && m == MechanismService && account != "" && !runsInSessionZero(account)
}
