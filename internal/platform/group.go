package platform

import "errors"

// ErrKillOnCloseNamedJob reports the one GroupConfig that cannot mean
// anything: a named job that also dies when its last handle closes.
//
// Name exists so a restarted agent can reopen the job with OpenProcessGroup.
// KillOnClose destroys the job, and every process in it, when the agent that
// created it exits. Asking for both is asking to re-adopt processes that the
// restart has already killed — and the killing is the part that happens. It is
// refused rather than resolved, because either resolution silently gives the
// caller the other one's behaviour.
var ErrKillOnCloseNamedJob = errors.New(
	"platform: KillOnClose with a job Name: the name exists to survive an agent restart, " +
		"and KillOnClose is what stops it surviving")

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
	// The zero value is therefore the supervisor's setting, not exec's. That
	// asymmetry is deliberate: forgetting it in exec leaks a grandchild for
	// the life of one RPC, and forgetting it in the supervisor takes down
	// every supervised process on the host at the next agent restart. The
	// cheaper mistake is the one left available.
	//
	// Setting it together with Name is refused outright; see
	// ErrKillOnCloseNamedJob.
	KillOnClose bool
}

// validate rejects configurations whose two halves contradict each other.
//
// It lives here rather than in the Windows implementation, and applies on every
// platform even though both fields are ignored on Unix, so that a caller
// developing on macOS gets the error on their own machine instead of shipping
// it to the only platform that would act on it.
func (c GroupConfig) validate() error {
	if c.KillOnClose && c.Name != "" {
		return ErrKillOnCloseNamedJob
	}
	return nil
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
func NewProcessGroup(cfg GroupConfig) (*ProcessGroup, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return newProcessGroup(cfg)
}

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
