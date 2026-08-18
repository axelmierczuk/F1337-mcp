package platform

import (
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// AwaitExit refuses on Windows rather than answering.
//
// A caller that reached for it here would be reaching for the wrong mechanism
// — there is no process group id to keep reserved, because a job object is a
// kernel object held through a handle — and the two answers it must not give
// are the ones that look like success. Blocking would answer a question nobody
// asked; nil would tell the caller its group id had been established when
// nothing had established anything, which is the whole failure the Unix
// implementation exists to prevent.
func TestAwaitExit_IsUnsupportedOnWindows(t *testing.T) {
	err := AwaitExit(os.Getpid())
	require.ErrorIs(t, err, ErrUnsupported)
	require.True(t, errors.Is(err, errors.ErrUnsupported),
		"callers are told they may test for either; see ErrUnsupported")
}
