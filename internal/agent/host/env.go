package host

import "os"

// envPath returns the daemon's PATH, which is the only environment variable a
// toolchain probe inherits.
func envPath() string { return os.Getenv("PATH") }
