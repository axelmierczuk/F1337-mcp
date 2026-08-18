//go:build !windows

package fleetagent

// hostVerifyServiceLogon is never reached off Windows: no other service manager
// logs an account on to start a daemon, so nothing else has a credential to
// check, and serviceNeedsPassword says so.
//
// It answers errLogonUnverifiable rather than nil so that a caller which does
// somehow reach it cannot read "no error" as "this credential is good" — the
// same rule svcuser_unix.go's readPassword follows, and for the same reason.
func hostVerifyServiceLogon(string, string) error { return errLogonUnverifiable }
