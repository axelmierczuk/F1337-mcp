// Package client dials sandboxd-agent instances over mTLS gRPC, pooling
// connections and tracking health so sandbox_list can report status without a
// round trip per call.
//
// Implemented by milestone M0.
package client
