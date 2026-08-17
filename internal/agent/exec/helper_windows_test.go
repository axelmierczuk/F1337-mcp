package exec

import (
	"os"
	"time"
)

// ignoreTermHelper has nothing to ignore on Windows: there is no SIGTERM, and
// the agent's stop path terminates the job object, which a process cannot
// decline. The mode exists so the helper's argv is the same on every platform;
// the test that uses it is Unix-only.
func ignoreTermHelper() int {
	if _, err := os.Stdout.WriteString("ready\n"); err != nil {
		return 1
	}
	time.Sleep(600 * time.Second)
	return 0
}
