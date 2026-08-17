package legacypath

import "sync"

// ResetWarningsForTest clears the once-per-process deprecation state so a test
// can observe the notice for a name an earlier test already tripped.
func ResetWarningsForTest() { warned = sync.Map{} }
