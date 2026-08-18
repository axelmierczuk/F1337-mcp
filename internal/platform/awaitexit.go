package platform

// AwaitExit blocks until pid has exited, and leaves it there to be collected.
//
// It exists for one ordering, and the ordering is the whole of it.
//
// # A process group id is a pid
//
// kill(-pgid) names a number, and that number is a pid. The kernel keeps it
// reserved for exactly as long as some process is still attached to it: the
// leader, alive or an unreaped zombie, or any surviving member of its group.
// Once the last of those is gone the id is free, and the next process group to
// be given it belongs to somebody else — so a caller that signals a group it
// started, after collecting the leader of an emptied one, is signalling
// whatever holds that id now. On a developer's machine that is their editor or
// their build.
//
// So the signal goes out between the leader exiting and Wait collecting it.
// This call is the first half of that: the exit, reported without the
// collection that would release the id. [ProcessGroup.Sweep] is the second.
//
// # It is not a theoretical window
//
// Both halves of that were argued the other way in this repository and both
// were wrong, which #91 records:
//
//   - The window is not microseconds. os/exec's Wait does not return until the
//     output copiers do, and a grandchild that inherited the pipes holds them
//     for the whole of Cmd.WaitDelay — seconds, in precisely the case a sweep
//     exists for.
//   - The wrap happens. #82's identical call answered EPERM four times in 2400
//     runs on a loaded 12-core host, which is a signal that reached a process
//     owned by somebody else, and instrumenting it caught the id being handed
//     out again to a new session leader.
//
// Reproduced deterministically in a pid namespace, where ns_last_pid places
// the next pid exactly: reap the leader of an emptied group, hand its id to an
// unrelated session leader, make the call that used to be made — the bystander
// dies of SIGKILL. The same run shows the kernel refusing to hand out that id
// at all while the zombie is still there.
//
// Note what that says about the old ordering. Any surviving descendant pins the
// group id too, so the id could only be stale once the group had emptied: the
// call was misdirectable exactly when it had nothing to do, and killed a
// stranger's tree in exchange for nothing.
//
// # What it does not answer
//
// An error means the exit could not be established, not that the process is
// running. A caller that sweeps anyway is sending SIGKILL to a group id whose
// ownership nothing has checked, which is the call this exists to avoid; the
// two agent callers log the broken guarantee and decline to sweep.
//
// Windows returns [ErrUnsupported]. It has no equivalent question, because it
// has no process group id to keep reserved: a job object is a kernel object
// held open by a handle, and [ProcessGroup] holds one for the leader too, so a
// pid there stays the group's own until the group is closed.
func AwaitExit(pid int) error { return awaitExit(pid) }
