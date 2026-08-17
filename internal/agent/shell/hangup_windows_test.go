package shell

import "os"

// hangupSignals is empty on Windows: there is no deliverable hangup, so the
// helper that ignores one has nothing to ignore and the scenario using it
// proves nothing there. The test that runs it says so and skips.
func hangupSignals() []os.Signal { return nil }
