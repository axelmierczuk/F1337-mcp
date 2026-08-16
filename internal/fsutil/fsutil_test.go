package fsutil_test

import (
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axelmierczuk/sandboxd-mcp/internal/fsutil"
)

func TestWriteAtomic_CreatesAndReplaces(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.yaml")

	require.NoError(t, fsutil.WriteAtomic(path, []byte("first"), 0o600))
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "first", string(data))

	require.NoError(t, fsutil.WriteAtomic(path, []byte("second"), 0o600))
	data, err = os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "second", string(data))
}

func TestWriteAtomic_AppliesMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not meaningful on Windows")
	}
	dir := t.TempDir()

	secret := filepath.Join(dir, "key.pem")
	require.NoError(t, fsutil.WriteAtomic(secret, []byte("key"), 0o600))
	info, err := os.Stat(secret)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	public := filepath.Join(dir, "cert.pem")
	require.NoError(t, fsutil.WriteAtomic(public, []byte("cert"), 0o644))
	info, err = os.Stat(public)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o644), info.Mode().Perm())
}

// No temp file may outlive the write. They are created in the destination
// directory, so a leak litters the operator's config directory.
func TestWriteAtomic_LeavesNoTempFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.yaml")
	for i := 0; i < 5; i++ {
		require.NoError(t, fsutil.WriteAtomic(path, []byte("x"), 0o600))
	}
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Len(t, entries, 1)
	assert.Equal(t, "state.yaml", entries[0].Name())
}

// The lock is what serializes read-modify-write across processes. flock is
// held per open file description, so two goroutines that each open the lock
// file contend exactly as two processes would, which is what this exercises.
//
// Mutual exclusion is asserted with atomics rather than by guarding an
// ordinary counter: the race detector cannot see the happens-before edge that
// a kernel lock establishes, so an unsynchronized counter would be reported as
// a data race even though the lock is doing its job.
func TestLock_SerializesHolders(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.yaml")

	const holders = 16
	var (
		inside     atomic.Int32
		overlaps   atomic.Int32
		acquired   atomic.Int32
		wg         sync.WaitGroup
		holdWindow = time.Millisecond
	)
	wg.Add(holders)
	for i := 0; i < holders; i++ {
		go func() {
			defer wg.Done()
			release, err := fsutil.Lock(path)
			if err != nil {
				t.Errorf("lock: %v", err)
				return
			}
			if inside.Add(1) != 1 {
				overlaps.Add(1)
			}
			// Hold it long enough that an unenforced lock would overlap.
			time.Sleep(holdWindow)
			inside.Add(-1)
			acquired.Add(1)
			if err := release(); err != nil {
				t.Errorf("release: %v", err)
			}
		}()
	}
	wg.Wait()

	assert.EqualValues(t, holders, acquired.Load(), "every holder must eventually acquire the lock")
	assert.EqualValues(t, 0, overlaps.Load(), "no two holders may be inside the lock at once")
}

func TestLock_ReleaseIsIdempotentlySafe(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.yaml")
	release, err := fsutil.Lock(path)
	require.NoError(t, err)
	require.NoError(t, release())

	// The lock must be re-acquirable once released, or the second process to
	// want it waits forever.
	release2, err := fsutil.Lock(path)
	require.NoError(t, err)
	require.NoError(t, release2())
}

func TestLock_CreatesParentDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "dir", "state.yaml")
	release, err := fsutil.Lock(path)
	require.NoError(t, err)
	require.NoError(t, release())
	assert.DirExists(t, filepath.Dir(path))
}
