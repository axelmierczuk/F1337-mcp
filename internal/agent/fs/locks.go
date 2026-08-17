package fs

import (
	"context"
	"strings"
	"sync"

	"github.com/axelmierczuk/sandboxd-mcp/internal/platform"
)

// pathLocks hands out one mutex per path, so two RPCs that read-modify-write
// the same file serialise instead of interleaving.
//
// The rename at the end of a write is atomic, but the sequence around it is
// not: EditFile reads a file, replaces a string, and renames the result over
// the original. Two of those running concurrently both read the same original,
// and whichever renames second silently discards the other's edit. WriteFile
// takes the same lock, so a write landing between an edit's read and its rename
// cannot be lost either.
//
// Entries are reference-counted and dropped when the last holder releases, so a
// long-lived agent editing many files does not accumulate a mutex per path it
// has ever touched.
type pathLocks struct {
	mu      sync.Mutex
	entries map[string]*pathLock
}

type pathLock struct {
	// ch is a one-slot channel rather than a sync.Mutex because acquisition has
	// to be abandonable: a caller whose RPC is cancelled while another caller
	// streams 100 MB to the same path must return, not block until the transfer
	// finishes.
	ch   chan struct{}
	refs int
}

func newPathLocks() *pathLocks {
	return &pathLocks{entries: map[string]*pathLock{}}
}

// lock acquires the lock for path, or returns ctx's error if the request is
// cancelled first. The returned function releases it.
func (l *pathLocks) lock(ctx context.Context, path string) (release func(), err error) {
	key := lockKey(path)

	l.mu.Lock()
	entry, ok := l.entries[key]
	if !ok {
		entry = &pathLock{ch: make(chan struct{}, 1)}
		l.entries[key] = entry
	}
	entry.refs++
	l.mu.Unlock()

	drop := func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		entry.refs--
		if entry.refs == 0 {
			delete(l.entries, key)
		}
	}

	select {
	case entry.ch <- struct{}{}:
	case <-ctx.Done():
		drop()
		return nil, ctx.Err()
	}

	var once sync.Once
	return func() {
		once.Do(func() {
			<-entry.ch
			drop()
		})
	}, nil
}

// lockBoth acquires the locks for two paths, for an operation with two
// endpoints.
//
// They are taken in a fixed order rather than the caller's, because two moves
// crossing — A to B and B to A at the same moment — would otherwise each hold
// what the other is waiting for. Sorting the keys means every caller queues in
// the same direction, so there is no cycle to deadlock on.
func (l *pathLocks) lockBoth(ctx context.Context, a, b string) (release func(), err error) {
	first, second := a, b
	if lockKey(second) < lockKey(first) {
		first, second = second, first
	}
	if lockKey(first) == lockKey(second) {
		// The same file under two spellings. One lock, taken once: taking it
		// twice would wait on itself forever.
		return l.lock(ctx, first)
	}

	releaseFirst, err := l.lock(ctx, first)
	if err != nil {
		return nil, err
	}
	releaseSecond, err := l.lock(ctx, second)
	if err != nil {
		releaseFirst()
		return nil, err
	}
	return func() {
		releaseSecond()
		releaseFirst()
	}, nil
}

// lockKey normalises a resolved path for use as a map key. Two spellings that
// name the same file must take the same lock, which on a case-insensitive
// filesystem means folding case — otherwise "C:\Work\a.txt" and "c:\work\a.txt"
// serialise against nothing.
func lockKey(path string) string {
	if platform.CaseInsensitivePaths {
		return strings.ToLower(path)
	}
	return path
}
