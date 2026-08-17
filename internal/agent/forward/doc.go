// Package forward implements sandboxd.v1.ForwardService: the sandbox half of
// `ssh -L`.
//
// One RPC carries one TCP connection. The MCP server opens a local listener,
// accepts a connection on it, opens one Forward stream, and the two ends pump
// bytes between the local socket and a socket on the sandbox. There is no
// multiplexing inside a stream and no connection identifier in the protocol,
// because there is exactly one connection per stream — which is what makes
// half-close, backpressure and cancellation the transport's problem rather
// than this package's.
//
// # Loopback by default
//
// remote_host defaults to loopback, and a non-loopback target is refused
// unless the operator listed it in forward.allowed_hosts. This is the security
// property of the whole feature. An agent that will connect anywhere on
// request is a general-purpose network pivot into whatever network it sits in,
// usable by anyone who can reach the agent — and on a fleet spanning a laptop,
// a home lab and a cloud VPC, "anywhere" spans all three. Forwarding a dev
// server works identically without that capability, so nothing legitimate
// notices the restriction and nothing illegitimate gets it for free.
//
// The check resolves the requested host and requires every address it resolves
// to to be loopback. Checking the string alone would be defeated by a name
// that resolves outward, and checking one resolved address would be defeated
// by a name that resolves to several. The address that passed the check is
// then the address that gets dialed, so nothing is re-resolved in between.
//
// # Half-close
//
// Each direction ends on its own. A local client that has finished sending —
// an HTTP/1.0 request, `curl` with no keep-alive, anything that shuts down its
// write side to signal end-of-request — must still receive the response, so
// the end of the request stream closes only the write half of the sandbox-side
// socket. The reverse holds too: a sandbox-side server that closes its side
// first sends a close event, and the local end shuts down only its write half.
//
// # Goroutines
//
// One connection is two pump goroutines and one stream. A forward left open
// for hours across many connections is where those accumulate, so both pumps
// are joined before Forward returns and the sandbox-side socket is closed
// exactly once, on the way out of that join.
package forward
