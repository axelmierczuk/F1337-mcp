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

// networkServiceAccount is a standing, password-less, non-administrative
// built-in identity.
//
// It used to be the default, and #74 is what that cost: it runs in session 0,
// which has been isolated from every interactive session since Vista, and it
// has no operator profile — so an agent installed under it sees no nvm, no
// rustup, no pyenv, no cargo, no scoop, no npm globals, and none of the
// credentials in %APPDATA% that git and the package registries read. It stays
// available for an operator who wants a confined agent and has weighed that.
// It is no longer what somebody gets by not choosing.
const networkServiceAccount = `NT AUTHORITY\NetworkService`

// sessionZeroAccounts are the Windows built-in service identities.
//
// All three run in session 0 — as does every Windows service — but these three
// also have no operator profile: %USERPROFILE% is a service profile under
// C:\Windows\ServiceProfiles or system32\config\systemprofile, so nothing
// installed per-user is on PATH and nothing in %APPDATA% is readable. A service
// under a *named* account may still see the account's profile, which is why
// that case is decided by the probe rather than by the name.
//
// Written lowercase, without spaces, and matched through sessionZeroKey:
// Windows account names fold, an operator may well type "networkservice", and
// the same identity arrives spelled with a space and without one.
//
// The last three are the well-known SIDs themselves. They are what
// currentAccount records when LookupAccountSid cannot reach a name — a
// domain-joined host that cannot see a domain controller — and, since a report
// carries the SID beside the name, they are also the spelling that survives a
// host whose display names are not English. See reportedRunsInSessionZero.
var sessionZeroAccounts = []string{
	`ntauthority\networkservice`,
	`ntauthority\localservice`,
	`ntauthority\system`,
	// `NT AUTHORITY\LocalSystem` is how Microsoft's own documentation writes
	// the account CreateService takes as the bare word `LocalSystem`, and an
	// operator copying it in was getting a logon-triggered task for the
	// machine account, with no warning that every command would run as it.
	`ntauthority\localsystem`,
	"networkservice",
	"localservice",
	"localsystem",
	"system",
	"s-1-5-18",
	"s-1-5-19",
	"s-1-5-20",
}

// sessionZeroKey normalises an account name for comparison against
// sessionZeroAccounts: lowercased, trimmed, and with the internal spaces
// removed.
//
// The spaces are the point. One identity has two spellings and only one of them
// was ever recognised here. `NT AUTHORITY\NetworkService` is the *logon* name:
// what CreateService takes, what docs/service.md prints, what an operator
// types, and what every test in this package uses. LookupAccountSid returns the
// *display* name for the same well-known SID, and that one has a space in it —
// `NT AUTHORITY\NETWORK SERVICE`, which is also what `whoami` prints and what
// services.msc shows.
//
// runtimeReport.Account comes from LookupAccountSid by design: it records the
// account "as the platform names it — not as the service definition named it".
// So the account the *reported* agent runs as never matched this list, and the
// verdict #74 exists for — "running in session 0 as a built-in service
// identity" — could not fire for NetworkService or LocalService on any host.
// The next case caught it by its home directory and named the wrong fault
// ("its profile was never loaded", which is untrue of an account whose profile
// that is) and dropped the second remedy only that verdict offers. An agent
// whose environment left %USERPROFILE% unset was not caught at all and was
// reported as simply running.
//
// It reaches the input side too: `--user "NT AUTHORITY\NETWORK SERVICE"`,
// copied from any of the three places Windows spells it that way, resolved to
// --mechanism task — a logon trigger for an account that never logs on, which
// is the one combination resolveMechanism exists to refuse — and made install
// prompt for the password of an account that has none.
//
// The `.\` prefix is the same defect in the other spelling this codebase itself
// produces and asks for. `.\name` is how CreateService is told "this machine,
// not the domain" — serviceAccountName exists to add it, and the account prompt
// offers `DOMAIN\name, .\name, or name@domain` as the three shapes to type. So
// `.\LocalSystem` is a spelling an operator reaches by following this program's
// own instructions, and unfolded it was an ordinary named account to every rule
// built on this key: `install --user .\LocalSystem` resolved to a logon-
// triggered task for the machine account — the one combination resolveMechanism
// exists to refuse — with no warning that every command would run as SYSTEM, a
// prompt for the password of an account that has none, and a lookup in
// ensureServiceUser that a built-in identity has no entry to satisfy. #99 named
// account spelling as one of its two hypotheses for exactly this reason.
//
// Stripping it cannot promote an ordinary account: `.\admin` folds to `admin`,
// which is not on the list and is still the named account it was.
func sessionZeroKey(name string) string {
	key := strings.Map(func(r rune) rune {
		if r == ' ' {
			return -1
		}
		return r
	}, strings.ToLower(strings.TrimSpace(name)))
	return strings.TrimPrefix(key, `.\`)
}

// runsInSessionZero reports whether name is a built-in Windows service identity
// — one that never logs on interactively and never has an operator profile.
func runsInSessionZero(name string) bool {
	key := sessionZeroKey(name)
	if key == "" {
		return false
	}
	for _, candidate := range sessionZeroAccounts {
		if key == candidate {
			return true
		}
	}
	return false
}

// reportedRunsInSessionZero is the same question asked of a whole report, which
// carries two spellings of one account and only one of them holds still.
//
// rep.Account is what LookupAccountSid answered, and that is the *display* name
// of the account on the installation that answered — which Windows localises.
// The fifth audit round found this verdict unable to fire because the English
// display name has a space in it that CreateService's spelling does not; a
// German or French host does not spell it with those letters at all, so no
// amount of folding reaches it and no list of spellings can be kept complete.
// A report from such a host fell through to the named-account verdict, which
// tells the operator their agent's "profile was never loaded" — untrue of the
// account whose profile that is — and, with %USERPROFILE% unset, through that
// one too, leaving the whole point of #74 reported as plain `running`.
//
// The SID does not move: S-1-5-18, -19 and -20 are those three strings on every
// installation of Windows in every language, which is why Microsoft's own
// guidance is to compare SIDs and never names. Either answer is enough, so a
// host that could not produce a SID is judged exactly as it was before.
func reportedRunsInSessionZero(rep *runtimeReport) bool {
	return runsInSessionZero(rep.Account) || runsInSessionZero(rep.AccountSID)
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
	case rep.SessionZero && reportedRunsInSessionZero(rep):
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
