package fleetagent

import (
	"fmt"
	"path/filepath"
	"strings"
)

// windowsProfileOwner returns the profile directory name exe lives under, when
// it lives under one.
//
// usersRoot is the directory holding every account's profile — C:\Users on
// anything this century, but read from the installing operator's own
// %USERPROFILE% rather than assumed, because it is relocatable and on some
// images it is not on C:.
func windowsProfileOwner(exe, usersRoot string) (string, bool) {
	if usersRoot == "" {
		return "", false
	}
	rel, err := filepath.Rel(winClean(usersRoot), winClean(exe))
	if err != nil {
		return "", false
	}
	rel = filepath.ToSlash(rel)
	if rel == "." || strings.HasPrefix(rel, "../") || rel == ".." {
		return "", false
	}
	owner, rest, ok := strings.Cut(rel, "/")
	if !ok || rest == "" || owner == "" {
		// Directly inside C:\Users is not inside anybody's profile.
		return "", false
	}
	return owner, true
}

// winClean normalises a Windows path for comparison on any host, so the rule
// below can be asserted from a Linux runner.
func winClean(path string) string {
	return strings.ToLower(strings.TrimRight(filepath.ToSlash(strings.ReplaceAll(path, `\`, "/")), "/"))
}

// accountOwnsProfile reports whether account is plausibly the owner of a
// profile directory called profileDir.
//
// Windows does not guarantee that a profile directory is named after its
// account — a second profile for the same name gets a `name.DOMAIN` suffix, and
// a long name is truncated — so this errs towards "yes". A false yes costs the
// operator the warning below; a false no refuses an install that would have
// worked.
func accountOwnsProfile(profileDir, account string) bool {
	account = strings.ToLower(strings.TrimSpace(account))
	if i := strings.LastIndexAny(account, `\/`); i >= 0 {
		account = account[i+1:]
	}
	if before, _, ok := strings.Cut(account, "@"); ok {
		account = before
	}
	if account == "" {
		return false
	}
	profileDir = strings.ToLower(profileDir)
	if profileDir == account || strings.HasPrefix(profileDir, account+".") {
		return true
	}
	// An 8.3 short name — RUNNER~1 for runneradmin — is the same directory
	// spelled the way an inherited %TEMP% or a path built by an old tool spells
	// it. Refusing an install because the path arrived short would refuse one
	// that works, which is the failure this function leans away from.
	if base, _, ok := strings.Cut(profileDir, "~"); ok && base != "" {
		return strings.HasPrefix(account, base)
	}
	return false
}

// windowsExecutableAccessProblem reports why account will not be able to start
// the agent from exe, or "" when nothing about the path says it cannot.
//
// `service install` registers os.Executable() and never copies the binary. A
// manual download lands on the Desktop, which is inside a profile directory
// whose ACL admits its owner, SYSTEM and the administrators and nobody else —
// so registering a service there under NT AUTHORITY\NetworkService produces a
// service that installs cleanly and then fails every start with error 5, access
// denied, before a line of this program runs. install knows both halves at the
// moment it is about to do it.
func windowsExecutableAccessProblem(exe, account, usersRoot string) string {
	owner, ok := windowsProfileOwner(exe, usersRoot)
	if !ok {
		return ""
	}
	if runsInSessionZero(account) {
		return fmt.Sprintf("%s is inside %s's profile, which a built-in service identity cannot read", exe, owner)
	}
	if accountOwnsProfile(owner, account) {
		return ""
	}
	return fmt.Sprintf("%s is inside %s's profile, which %s cannot read", exe, owner, account)
}

// executableAccessIsFatal reports whether a path the service account cannot
// reach is a refusal or a warning.
//
// Windows refuses: the answer there is not a guess. A profile directory admits
// its owner, SYSTEM and the administrators and nothing else, so a path inside
// somebody else's profile is one the account will not be able to read, and the
// service manager reports that as error 5 before any of this program runs.
//
// Unix warns: access there is not decided by the mode bits alone — a
// supplementary group this code does not enumerate can grant what the bits
// appear to deny — and a wrong refusal costs an operator an install that would
// have worked.
//
// goos is a parameter for the same reason resolveMechanism's is. This decides
// whether `install` stops or continues, it lived in the two platform files as
// a bare `true` and a bare `false`, and a rule that only compiles on one host
// is a rule only that host can check.
func executableAccessIsFatal(goos string) bool { return goos == "windows" }

// executableAccessRemedy is the fix, written out as the commands that apply it.
func executableAccessRemedy(exe, goos string) []string {
	if goos == "windows" {
		return []string{
			`mkdir "C:\Program Files\fleet"`,
			fmt.Sprintf(`Copy-Item %q "C:\Program Files\fleet\fleet-agent.exe"`, exe),
			`& "C:\Program Files\fleet\fleet-agent.exe" service install`,
		}
	}
	return []string{
		fmt.Sprintf("sudo install -m 0755 %s /usr/local/bin/fleet-agent", exe),
		"sudo /usr/local/bin/fleet-agent service install",
	}
}

// executableAccessAdvice is the whole message: what is wrong, what it will
// cost, and the commands that fix it. Assembled in one place so both platforms
// word it the same way and neither can quietly stop naming the remedy.
func executableAccessAdvice(problem, exe, account, goos string) string {
	var b strings.Builder
	b.WriteString(problem)
	b.WriteString(".\n\n")
	b.WriteString("`service install` registers the binary where it is; it does not copy it. The\n")
	b.WriteString("service manager will accept this definition and then fail every start, as\n")
	b.WriteString(startFailure(goos))
	b.WriteString(", before any of this program runs.\n\n")
	b.WriteString("Install the binary somewhere " + account + " can read, and register it from there:\n")
	for _, command := range executableAccessRemedy(exe, goos) {
		b.WriteString("  " + command + "\n")
	}
	return strings.TrimRight(b.String(), "\n")
}

// startFailure is what the platform's service manager reports when it cannot
// read the binary — the string an operator will search for.
func startFailure(goos string) string {
	if goos == "windows" {
		return "error 5, access denied"
	}
	return `status=203/EXEC, or "permission denied"`
}
