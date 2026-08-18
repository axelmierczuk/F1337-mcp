package fleetagent

import (
	"errors"
	"fmt"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modadvapi32    = windows.NewLazySystemDLL("advapi32.dll")
	procLogonUserW = modadvapi32.NewProc("LogonUserW")
)

// LOGON32_LOGON_SERVICE and LOGON32_PROVIDER_DEFAULT.
//
// Written out rather than taken from golang.org/x/sys/windows, which exports
// neither LogonUser nor its constants.
const (
	logon32LogonService    = 5
	logon32ProviderDefault = 0
)

// hostVerifyServiceLogon asks Windows the question the SCM will ask at every
// start: can this account be logged on as a service with this password.
//
// It is the same call the service control manager makes, with the same logon
// type, so its answer is the answer the machine will give — including the one
// nothing else here can find out in advance, ERROR_LOGON_TYPE_NOT_GRANTED,
// which is SeServiceLogonRight missing and which surfaces otherwise as error
// 1069 at every start of a service that installed cleanly.
//
// It creates a logon session and immediately closes it. Nothing is started
// under the token, and the password never leaves this function: the one UTF-16
// copy this process makes is zeroed before it returns.
func hostVerifyServiceLogon(account, password string) error {
	// Rather than LazyProc.Call's panic on a missing export. An installer that
	// dies here would be worse than one that registers without the check, and
	// the caller reads this as "could not check" rather than "bad credential".
	if err := procLogonUserW.Find(); err != nil {
		return fmt.Errorf("%w: %w", errLogonUnverifiable, err)
	}

	name, domain := splitServiceAccount(account)
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	var domainPtr *uint16
	if domain != "" {
		if domainPtr, err = windows.UTF16PtrFromString(domain); err != nil {
			return err
		}
	}
	// UTF16FromString, not UTF16PtrFromString, so the slice is still addressable
	// afterwards and the plaintext can be wiped the moment LogonUser is done
	// with it. It is the only copy this process makes.
	secret, err := windows.UTF16FromString(password)
	if err != nil {
		return err
	}
	defer func() {
		for i := range secret {
			secret[i] = 0
		}
	}()

	var token windows.Token
	//nolint:gosec // G103: LazyProc.Call takes ...uintptr; Win32 pointer arguments have no other form
	r1, _, callErr := procLogonUserW.Call(
		uintptr(unsafe.Pointer(namePtr)),
		uintptr(unsafe.Pointer(domainPtr)),
		uintptr(unsafe.Pointer(&secret[0])),
		logon32LogonService,
		logon32ProviderDefault,
		uintptr(unsafe.Pointer(&token)),
	)
	// LazyProc.Call is an ordinary Go function, so converting these pointers
	// inside its argument list does not pin what they point at the way the same
	// conversion would in a direct syscall. Without this the collector is free
	// to reclaim the buffers while LogonUser is reading them. Same reasoning as
	// internal/platform/group_windows.go.
	runtime.KeepAlive(namePtr)
	runtime.KeepAlive(domainPtr)
	runtime.KeepAlive(secret)

	if r1 == 0 {
		// Call always returns a non-nil lastErr — it holds a syscall.Errno,
		// which is zero when the call did not set one — so the interface being
		// non-nil says nothing. Only the code does.
		var errno syscall.Errno
		if errors.As(callErr, &errno) && errno != 0 {
			return errno
		}
		return fmt.Errorf("%w: LogonUser failed and set no error code", errLogonUnverifiable)
	}
	// The session is not wanted, only the answer.
	_ = token.Close()
	return nil
}
