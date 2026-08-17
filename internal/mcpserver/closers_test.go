package mcpserver

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Shutdown releases in the reverse of the order things were built.
//
// New registers the client pool before the tools that use it, and the
// registrar's Close joins the goroutines carrying forwarded connections over
// the pool's channels. Closing in registration order would drop every one of
// those connections with an RPC error on the way out, and would leave a
// forward's listener still accepting new ones onto a channel that had already
// gone — the accepts-and-then-drops symptom, produced by the shutdown path.
//
// This is asserted on Close rather than through a live server because the order
// is the property: a fixture that supplies its own Clients registers no pool
// closer at all, so the case that matters is the one a live test cannot reach.
func TestServerClose_ReleasesInReverseOfRegistration(t *testing.T) {
	var order []string
	s := &Server{}
	for _, name := range []string{"pool", "registrar"} {
		s.closers = append(s.closers, func() error {
			order = append(order, name)
			return nil
		})
	}

	assert.NoError(t, s.Close())
	assert.Equal(t, []string{"registrar", "pool"}, order,
		"the tools carrying connections over the pool's channels must be released before the pool is")

	// And it stays a no-op after the first call, from any number of callers.
	assert.NoError(t, s.Close())
	assert.Len(t, order, 2)
}
