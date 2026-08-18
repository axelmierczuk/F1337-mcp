// Package tui is the full-screen operator view of the fleet behind
// `fleetctl tui`: four panes — fleet, processes, logs, detail — over the same
// data every other view of the fleet reports.
//
// # This is a view, not a second implementation
//
// Nothing here opens the registry, dials an agent, or decides what "unhealthy"
// means. [Source] is the whole surface between this package and the fleet, and
// the one implementation of it that ships ([NewFleetSource]) is a thin
// projection of internal/client and internal/registry: the same pool, the same
// mTLS configuration, the same health vocabulary, the same relative times as
// `fleetctl list`. A TUI with its own idea of fleet health answers a question
// about itself rather than about the fleet, and the two views disagreeing in
// front of an operator is the most expensive bug this program could have.
//
// # Refresh is the design risk, so it is the design
//
// Polling every pane for every sandbox on a timer is the obvious thing and it
// melts a large fleet. This does two things instead.
//
// Health — the only thing that is per-sandbox — is not polled here at all. The
// pool in internal/client already keeps one background health loop per pooled
// channel, probing in parallel under a short per-sandbox deadline. The model
// reads that cache; the cache is the only thing on a schedule that talks to
// agents about health. One unreachable sandbox therefore costs one goroutine
// blocked on its own deadline and renders as unreachable, and cannot stall or
// blank the view.
//
// Everything else — the process list, the logs, the host detail — is fetched
// for the *focused* sandbox only. A twenty-machine fleet costs exactly one
// machine's worth of traffic beyond health, whichever machine the operator is
// looking at.
//
// # The model is pure
//
// [Model] holds no clients, no channels and no clock. [Model.Step] takes a
// message and returns the next model and the [Effect]s it wants performed;
// [Render] turns a model into a frame. Both are ordinary functions over values,
// which is what makes state transitions, confirmation gating, refresh
// scheduling and degradation testable without a terminal. The bubbletea
// adapter, the dispatcher that turns effects into RPCs, and the terminal
// lifecycle all live in run.go and touch no decision.
package tui
