package fleetagent

import (
	"fmt"
	"os"
	"os/user"
	"strings"

	"golang.org/x/sys/windows"
)

// networkServiceAccount is the built-in identity the agent is installed under
// by default.
//
// It is not LocalSystem, which is the Windows equivalent of root and is what
// the service manager uses when no account is named. NetworkService is a
// standing, password-less, non-administrative identity — the closest Windows
// gets to a dedicated system account without the installer inventing a
// password and storing it in the SCM.
const networkServiceAccount = `NT AUTHORITY\NetworkService`

// requireElevation refuses an operation that will fail partway through
// without an elevated token.
func requireElevation(action string) error {
	if isElevated() {
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		exe = "fleet-agent.exe"
	}
	return fmt.Errorf("`service %s` needs an elevated prompt: it registers a Windows service and creates directories under ProgramData.\n\nRe-run it from an elevated PowerShell:\n  Start-Process -Verb RunAs %s -ArgumentList 'service %s'",
		action, exe, action)
}

// isElevated reports whether this process holds an elevated token.
func isElevated() bool { return windows.GetCurrentProcessToken().IsElevated() }

func describeDefaultUser() string { return networkServiceAccount }

// defaultServiceUser returns the built-in non-administrative service identity.
func defaultServiceUser() (string, error) { return networkServiceAccount, nil }

// ensureServiceUser accepts the built-in service identities as they are and
// verifies that any other account actually exists.
//
// Creating a Windows account non-interactively means choosing and storing a
// password, which is a worse outcome than telling the operator to create one.
func ensureServiceUser(name string, _ bool) error {
	if name == "" {
		return fmt.Errorf("no service account resolved; pass --user")
	}
	switch strings.ToLower(name) {
	case strings.ToLower(networkServiceAccount), `nt authority\localservice`, `nt authority\system`, "localsystem":
		return nil
	}
	if _, err := user.Lookup(name); err != nil {
		return fmt.Errorf("service account %q does not resolve: %w\n\nCreate it, or pass --user with an existing account. Built-in options are %s and NT AUTHORITY\\LocalService",
			name, err, networkServiceAccount)
	}
	return nil
}

// serviceAccessByOwnership records that access on Windows is governed by ACLs
// rather than by an owner, so nothing `install` does to ownership would grant
// it. See grantServiceUserAccess.
const serviceAccessByOwnership = false

// chownToServiceUser is a no-op on Windows.
//
// Directory access is governed by ACLs rather than an owner, and the
// directories the installer creates under ProgramData inherit permissions that
// already admit the built-in service identities. An operator installing under
// a custom account must grant it access to the allowed roots itself, which is
// documented in docs/service.md.
func chownToServiceUser(string, string) error { return nil }

// grantServiceUserAccess is a no-op on Windows, for the same reason.
//
// %ProgramData%\sandboxd inherits an ACL that already admits the built-in
// service identities, and there is no Unix-style 0600 to undo: `enroll` writes
// the key with the same inherited ACL. An install under a custom account has to
// be granted access by hand — docs/service.md says so.
func grantServiceUserAccess(string, string, []string) error { return nil }
