package enroll

import (
	"errors"
	"sync"
	"time"
)

// Rate limiting defaults for the enrollment endpoint. Enrollment is a rare,
// human-initiated event — an operator brings up a host and pastes a token —
// so these are generous for real use and still cut off the only unbounded,
// unauthenticated path into the control plane.
const (
	DefaultRateWindow  = time.Minute
	DefaultPerPeerRate = 10
	DefaultGlobalRate  = 60
)

// ErrRateLimited is returned when an enrollment attempt exceeds the
// configured rate.
var ErrRateLimited = errors.New("enroll: too many enrollment attempts; try again shortly")

// RateLimiter is a fixed-window counter over enrollment attempts, per calling
// host and in total.
//
// The global limit is the one that matters: per-peer counting alone is
// defeated by an attacker with more than one address, so it bounds the damage
// a single host can do while the global bound covers the rest.
type RateLimiter struct {
	window  time.Duration
	perPeer int
	global  int

	mu     sync.Mutex
	peers  map[string][]time.Time
	allHit []time.Time
}

// NewRateLimiter returns a limiter allowing perPeer attempts from any one
// address and global attempts in total within window. A non-positive limit
// disables that dimension.
func NewRateLimiter(window time.Duration, perPeer, global int) *RateLimiter {
	if window <= 0 {
		window = DefaultRateWindow
	}
	return &RateLimiter{
		window:  window,
		perPeer: perPeer,
		global:  global,
		peers:   map[string][]time.Time{},
	}
}

// Allow records an attempt from addr and reports whether it is within the
// configured limits.
func (l *RateLimiter) Allow(addr string) error {
	if l == nil {
		return nil
	}
	now := time.Now()
	cutoff := now.Add(-l.window)

	l.mu.Lock()
	defer l.mu.Unlock()

	// Sweep every peer, not just this one: otherwise a scan across many
	// addresses leaves an entry per address behind forever, and the limiter
	// meant to bound the endpoint becomes its own memory leak.
	for peerAddr, hits := range l.peers {
		if kept := after(hits, cutoff); len(kept) == 0 {
			delete(l.peers, peerAddr)
		} else {
			l.peers[peerAddr] = kept
		}
	}
	l.allHit = after(l.allHit, cutoff)

	if l.global > 0 && len(l.allHit) >= l.global {
		return ErrRateLimited
	}
	if l.perPeer > 0 && len(l.peers[addr]) >= l.perPeer {
		return ErrRateLimited
	}

	l.peers[addr] = append(l.peers[addr], now)
	l.allHit = append(l.allHit, now)
	return nil
}

// after returns the timestamps at or after cutoff, reusing the backing array.
func after(hits []time.Time, cutoff time.Time) []time.Time {
	out := hits[:0]
	for _, t := range hits {
		if t.After(cutoff) {
			out = append(out, t)
		}
	}
	return out
}
