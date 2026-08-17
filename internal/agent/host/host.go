package host

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/fleet-mcp/internal/agent"
	"github.com/axelmierczuk/fleet-mcp/internal/platform"
)

// init registers HostService with every sandboxd-agent daemon that links this
// package. See internal/cli/sandboxdagent/services.go for the import that does.
func init() {
	agent.Register("host", New)
}

// Service implements sandboxd.v1.HostService.
type Service struct {
	sandboxdv1.UnimplementedHostServiceServer

	deps   agent.Deps
	prober *Prober

	// platform is computed once at construction. None of it changes over a
	// daemon's lifetime except the hostname, which changes about as often as
	// the machine is rebuilt.
	platform *sandboxdv1.Platform
	// diskPath is the filesystem whose free space is reported, chosen from the
	// allowed roots at construction.
	diskPath string
}

// New builds the host service. It satisfies agent.Factory.
func New(deps agent.Deps) (agent.Service, error) {
	// platform.Describe never fails: a field it could not read comes back
	// empty. A host that cannot name itself is still a host that can run
	// commands, so that is reported rather than fatal.
	info := platform.Describe()
	if info.Hostname == "" {
		deps.Log.Warn("could not determine hostname")
	}
	return &Service{
		deps:   deps,
		prober: NewProber(),
		platform: &sandboxdv1.Platform{
			Os:            info.OS,
			Arch:          info.Arch,
			KernelVersion: info.KernelVersion,
			Hostname:      info.Hostname,
			PathSeparator: info.PathSeparator,
		},
		// The jail's roots, not the config's: on an exec-enabled agent the
		// config names roots that are not in force, and the filesystem worth
		// reporting free space for is the one the agent actually writes to.
		diskPath: resourceDiskPath(deps.Jail.Roots()),
	}, nil
}

// Register attaches HostService to the daemon's gRPC server.
func (s *Service) Register(r grpc.ServiceRegistrar) {
	sandboxdv1.RegisterHostServiceServer(r, s)
}

// GetHostInfo describes the host: platform, capacity, allowed roots, agent
// version, and the identity the caller is authenticated as.
//
// Toolchain probing is opt-in and bounded; everything else here is a handful
// of syscalls.
func (s *Service) GetHostInfo(ctx context.Context, req *sandboxdv1.GetHostInfoRequest) (*sandboxdv1.GetHostInfoResponse, error) {
	res, err := probeResources(s.diskPath)
	if err != nil {
		// Reported, not fatal: the figures that could be read are still worth
		// having, and the ones that could not are zero on the wire, which is
		// what the proto documents them as. Said out loud because "sandbox_info
		// reports no free disk" is otherwise an unexplainable answer.
		s.deps.Log.Warn("could not read host capacity", "disk_path", s.diskPath, "error", err)
	}

	// The principal comes from the verified client certificate, never from
	// anything in the request. Echoing it back is how a caller confirms which
	// identity it is actually using — a control plane holding two leaves and
	// reaching for the wrong one otherwise finds out at the first denied
	// operation.
	principal, _ := agent.PrincipalFromContext(ctx)

	resp := &sandboxdv1.GetHostInfoResponse{
		Platform: s.platform,
		// The effective figures, not the machine's: internal/platform narrows
		// them to any cgroup limit in force, so a container-confined agent
		// advertises what it can actually run rather than what the host has.
		// Resources.CPUQuotaLimited and MemoryLimited record which of them came
		// from a cgroup; the proto has no field for that yet.
		Resources: &sandboxdv1.Resources{
			CpuCores:             res.CPUCores,
			MemoryTotalBytes:     res.MemoryTotalBytes,
			MemoryAvailableBytes: res.MemoryAvailableBytes,
			DiskTotalBytes:       res.DiskTotalBytes,
			DiskAvailableBytes:   res.DiskAvailableBytes,
			LoadAverage_1M:       res.LoadAverage1m,
		},
		AgentVersion: s.deps.Version,
		// The jail's roots, never the config's. This field is what
		// sandbox_info and sandbox_select show the model to tell it where it
		// may write, so on an agent whose jail is off it must be empty — the
		// proto's documented "no path jail" — rather than repeating roots that
		// constrain nothing. Returning the configured list there would be the
		// model-facing version of the same lie the startup warning exists to
		// stop telling the operator.
		AllowedRoots:           s.deps.Jail.Roots(),
		StartedAt:              timestamppb.New(s.deps.StartedAt),
		AuthenticatedPrincipal: principal,
	}
	if req.GetIncludeToolchains() {
		resp.Toolchains = s.prober.Probe(ctx)
	}
	return resp, nil
}

// Health answers the liveness probe every connected MCP server runs on a
// timer.
//
// It reads three atomics and returns. No filesystem stat, no subprocess, no
// lock: multiply this call by every sandbox in a fleet and by the probe
// interval, and anything more expensive becomes a standing load on hosts whose
// actual job is running someone's build.
func (s *Service) Health(context.Context, *sandboxdv1.HealthRequest) (*sandboxdv1.HealthResponse, error) {
	state, message, running := s.deps.Status.Snapshot()
	return &sandboxdv1.HealthResponse{
		Status:           state,
		Message:          message,
		AgentVersion:     s.deps.Version,
		RunningProcesses: running,
	}, nil
}
