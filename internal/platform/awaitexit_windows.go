package platform

// awaitExit has no meaning on Windows, and reports so rather than pretending
// to an answer.
//
// The question it answers on Unix is "may this group id still be signalled" —
// a process group there is a number the kernel reclaims, so the leader's
// uncollected zombie is what keeps the number the group's own. Windows has
// nothing to keep: a job object is a kernel object reached through a handle,
// and [ProcessGroup] holds a handle to the leader as well, from Adopt until
// Close, so neither the job nor the leader's pid can come to name anything
// else while the group can still be asked to signal them.
//
// So no Windows caller needs this, and one that appeared would be reaching for
// the wrong mechanism. Returning [ErrUnsupported] says that; blocking until the
// process exits would answer a question nobody here is asking, and returning
// nil would tell a caller its group id had been established when nothing had
// established anything.
func awaitExit(int) error { return ErrUnsupported }
