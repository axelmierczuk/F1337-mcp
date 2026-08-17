package fs

// SetRenameForTest replaces the rename MovePath uses and returns a function
// restoring it.
//
// The cross-device fallback is the part of a move where a mistake loses a file,
// and the only way to reach it is a rename that fails with EXDEV — which needs
// two filesystems, something a test cannot ask a CI runner for. Injecting the
// failure is what makes that path testable at all rather than reasoned about.
func SetRenameForTest(fn func(oldpath, newpath string) error) func() {
	prev := renamePath
	renamePath = fn
	return func() { renamePath = prev }
}

// CrossDeviceErrorForTest is an error this platform recognises as "these two
// paths are on different filesystems", so a test can inject the real thing
// rather than a sentinel the production code would not match.
func CrossDeviceErrorForTest() error { return errCrossDevice }

// IsCrossDeviceForTest exposes the platform's detection, so the constant above
// is asserted to be the one the code actually looks for.
func IsCrossDeviceForTest(err error) bool { return isCrossDevice(err) }
