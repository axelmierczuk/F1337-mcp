//go:build unix

package fsutil

import (
	"os"
	"syscall"
)

// lockFile takes a blocking exclusive flock. flock is per open-file-
// description, so the lock is released if the process dies, which is what
// keeps a crashed CLI from wedging the registry for everyone else.
func lockFile(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
}

func unlockFile(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}
