package platform

// GroupConfig configures a [ProcessGroup] before the child is spawned.
type GroupConfig struct {
	// Name gives the Windows job object a kernel object name, so a restarted
	// agent can reopen the same job with OpenProcessGroup and keep control of
	// a process it did not spawn in this run. Ignored on Unix, where the
	// process group id serves that purpose and needs no name.
	//
	// Names are global to the session; include the process id the agent
	// assigned, not just a service name.
	Name string

	// KillOnClose sets JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE on the Windows job,
	// so closing the last handle to it terminates every process inside.
	// Ignored on Unix.
	//
	// Choose it by what the caller owns:
	//
	//   - One-shot exec (ExecService) wants true. The agent holds the only
	//     handle for the life of the call, and the guarantee that no
	//     grandchild survives the RPC is worth more than anything else.
	//
	//   - Supervised background processes (ProcessService) want false. With it
	//     set, an agent upgrade kills every dev server in the fleet the moment
	//     the old process exits, which is precisely the failure the supervisor
	//     is designed to avoid. Pair false with a Name so the job can be
	//     reopened after the restart.
	//
	// The zero value is therefore the supervisor's setting, not exec's.
	KillOnClose bool
}

// NewProcessGroup prepares the OS mechanism that keeps a child and its
// descendants killable as a unit: a session and process group on Unix, a job
// object on Windows.
//
// The call order is fixed and the same on every platform:
//
//	g, err := platform.NewProcessGroup(platform.GroupConfig{})
//	defer g.Close()
//	g.ConfigureCommand(cmd)   // before Start: sets SysProcAttr
//	cmd.Start()
//	g.Adopt(cmd.Process)      // after Start: assigns to the job on Windows
//
// Skipping ConfigureCommand does not fail loudly — it produces a child in the
// agent's own process group, and a later Signal that would have hit the agent
// itself. Adopt detects that and leaves [ProcessGroup.Isolated] false; a
// supervisor that cares should check it.
func NewProcessGroup(cfg GroupConfig) (*ProcessGroup, error) { return newProcessGroup(cfg) }

// OpenProcessGroup returns a handle to the group of a process this agent did
// not spawn in this run — the re-adoption path after a daemon restart.
//
// The caller is responsible for having already established that pid is the
// process it thinks it is; see [SameProcess]. This call does not verify start
// identity, and a handle to a reused pid signals whatever now owns it.
//
// On Unix, name is ignored and the process group id is read from the kernel.
// On Windows, name must be the GroupConfig.Name the job was created with; when
// it is empty or the job no longer exists, the returned group falls back to
// controlling the single process, and [ProcessGroup.Isolated] reports false.
func OpenProcessGroup(pid int, name string) (*ProcessGroup, error) {
	return openProcessGroup(pid, name)
}
