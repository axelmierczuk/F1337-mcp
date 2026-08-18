package fleetagent

import (
	"fmt"
	"strings"
)

// Confinement is a way in which a running agent cannot do the job it exists
// for: the process is up, it answers health checks, and every command a model
// asks it to run either fails to find its toolchain or resolves the wrong one.
//
// It exists because `service status` used to have no vocabulary for that. A
// daemon installed as NT AUTHORITY\NetworkService reports "running" and is
// useless, and the operator finds out one failed command at a time. Status is
// the tool they ask; it should be the thing that tells them.
type Confinement struct {
	// Summary replaces "running" on the status headline.
	Summary string
	// Detail says what is wrong, in the terms an operator would use.
	Detail []string
	// RemedyIntro introduces Remedy. It varies because the remedy does: for a
	// confinement this command can name a command for, it is one line to copy;
	// for one it cannot, promising a command would be a lie.
	RemedyIntro string
	// Remedy is what to do instead. Printed verbatim, one line each.
	Remedy []string
}

// sessionZeroAccounts are the Windows built-in service identities.
//
// All three run in session 0 — as does every Windows service — but these three
// also have no operator profile: %USERPROFILE% is a service profile under
// C:\Windows\ServiceProfiles or system32\config\systemprofile, so nothing
// installed per-user is on PATH and nothing in %APPDATA% is readable. A service
// under a *named* account may still see the account's profile, which is why
// that case is decided by the probe rather than by the name.
//
// Written lowercase and matched case-insensitively: Windows account names fold,
// and an operator may well type "networkservice".
var sessionZeroAccounts = []string{
	`nt authority\networkservice`,
	`nt authority\localservice`,
	`nt authority\system`,
	"networkservice",
	"localservice",
	"localsystem",
	"system",
}

// runsInSessionZero reports whether name is a built-in Windows service identity
// — one that never logs on interactively and never has an operator profile.
func runsInSessionZero(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return false
	}
	for _, candidate := range sessionZeroAccounts {
		if name == candidate {
			return true
		}
	}
	return false
}

// confinementFor decides whether what the daemon recorded about its own
// environment describes an agent that cannot work.
//
// A pure function of the recorded facts, so the judgement can be asserted on
// every runner while the facts themselves can only be collected on Windows.
// nil means the agent has what it needs, as far as anything can tell.
func confinementFor(rep *runtimeReport) *Confinement {
	if rep == nil {
		return nil
	}

	switch {
	case rep.SessionZero && runsInSessionZero(rep.Account):
		return &Confinement{
			Summary: "running, but unusable",
			Detail: []string{
				fmt.Sprintf("This agent is running in session 0 as %s.", rep.Account),
				"Session 0 has been isolated from every interactive session since Vista, and a",
				"built-in service identity has no operator profile: nvm, rustup, pyenv, cargo,",
				"scoop, npm globals and the credentials in %APPDATA% that git and the package",
				"registries read are all invisible to it. Commands run through this agent will",
				"not find the toolchains installed on this machine.",
			},
			RemedyIntro: "Re-register it so it runs where the toolchains are:",
			Remedy: []string{
				"fleet-agent service install --mechanism task     # your session, your PATH",
				"fleet-agent service install --user DOMAIN\\name    # a service, with that account's profile",
			},
		}

	case rep.SessionZero && rep.Profile.Visibility == profileHidden:
		return &Confinement{
			Summary: "running, but unusable",
			Detail: append([]string{
				fmt.Sprintf("This agent is running in session 0 as %s, and its PATH does not reach", rep.Account),
				"the per-user toolchains installed under its own profile. A Windows service is",
				"logged on with LOGON32_LOGON_SERVICE and the account's HKCU environment is",
				"applied only if its profile is loaded, which the SCM does not guarantee.",
			}, hiddenDirsDetail(rep.Profile.Unreachable)...),
			RemedyIntro: "Re-register it so it runs where the toolchains are:",
			Remedy: []string{
				"fleet-agent service install --mechanism task     # your session, your PATH",
			},
		}

	case rep.SessionZero && isServiceProfileHome(rep.Home):
		// The one confined shape the probe cannot see, and the reason it
		// cannot: it looks for per-user installs under the home directory the
		// daemon was given, and the daemon was given the wrong one. A named
		// account whose %USERPROFILE% is a built-in service profile is not
		// running with its own profile at all — nothing under it, so the probe
		// finds nothing to look for and answers "unknown", which everywhere
		// else means "nothing to conclude" and here means "confined".
		//
		// Decided on the two facts the daemon recorded rather than on any
		// belief about when the SCM loads a profile: an ordinary account
		// running out of C:\Windows\ServiceProfiles is wrong however it got
		// there.
		return &Confinement{
			Summary: "running, but unusable",
			Detail: []string{
				fmt.Sprintf("This agent is running in session 0 as %s, and the home directory it was", rep.Account),
				fmt.Sprintf("started with is %s — a built-in service profile, not that", rep.Home),
				"account's. Its profile was never loaded, so %APPDATA%, HKCU and everything",
				"installed per-user are invisible to it whatever is on PATH.",
			},
			RemedyIntro: "Re-register it so it runs where the toolchains are:",
			Remedy: []string{
				"fleet-agent service install --mechanism task     # your session, your PATH",
			},
		}

	case rep.Profile.Visibility == profileHidden:
		return &Confinement{
			Summary: "running, but unusable",
			Detail: append([]string{
				"The PATH this agent hands the commands it runs does not reach the per-user",
				fmt.Sprintf("toolchains installed under %s, the home directory it was started with.", rep.Home),
			}, hiddenDirsDetail(rep.Profile.Unreachable)...),
			RemedyIntro: "What to do:",
			Remedy: []string{
				"Re-install so the agent runs as the account those toolchains belong to, or",
				"put the directories above on the PATH the service definition starts it with.",
			},
		}
	}
	return nil
}

// serviceProfileHomes are the profile directories Windows hands a process that
// is logged on as a service rather than as a person.
//
// Written with forward slashes and matched case-insensitively so the rule is a
// pure function of the recorded string and is assertable from every runner. The
// list is closed: these are the only directories Windows uses for the purpose,
// and none of them is ever the right answer for a named account.
var serviceProfileHomes = []string{
	`/windows/system32/config/systemprofile`,
	`/windows/serviceprofiles/localservice`,
	`/windows/serviceprofiles/networkservice`,
	`/users/default`,
}

// isServiceProfileHome reports whether home is one of those, or inside one.
func isServiceProfileHome(home string) bool {
	home = winClean(home)
	if home == "" {
		return false
	}
	for _, candidate := range serviceProfileHomes {
		if strings.HasSuffix(home, candidate) || strings.Contains(home, candidate+"/") {
			return true
		}
	}
	return false
}

// hiddenDirsDetail names the per-user directories that exist and are not
// reachable, which is the part an operator can act on.
func hiddenDirsDetail(dirs []string) []string {
	if len(dirs) == 0 {
		return nil
	}
	lines := []string{"", "Installed and not on its PATH:"}
	for _, dir := range dirs {
		lines = append(lines, "  "+dir)
	}
	return lines
}

// invokingServiceUser is the default service account on the two platforms that
// use the operator's own: macOS, which always has, and Windows, which now does.
//
// The rule and its one refusal are here rather than in either platform file so
// that both are asserted on every runner. The refusal matters more than it
// looks: `service install` needs elevation, so it is routinely run from a shell
// that is already the superuser, and "the invoking user" would then quietly
// mean "root" or "SYSTEM" — every command a model runs, as the machine's most
// privileged account, by default.
func invokingServiceUser(current string) (string, error) {
	current = strings.TrimSpace(current)
	if current == "" {
		return "", fmt.Errorf("could not determine the invoking user; pass --user with the account the agent should run as")
	}
	if runsInSessionZero(current) || strings.EqualFold(current, "root") {
		return "", fmt.Errorf("refusing to default the service account to %s: every command the agent runs would run as %s.\n\nPass --user with the account you are sitting in front of, or --user %s to accept that deliberately",
			current, current, current)
	}
	return current, nil
}
