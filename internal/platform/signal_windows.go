package platform

import "os"

// osSignal always fails on Windows. os.Process.Signal accepts only os.Kill
// there, and every other value returns "not supported by windows" after the
// caller has already assumed the signal was delivered. ProcessGroup.Signal
// implements the Windows equivalents directly.
func (s Signal) osSignal() (os.Signal, error) {
	return nil, ErrSignalUnsupported
}
