package host

import (
	"context"
	"os"
	"path/filepath"
	"runtime"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"

	sandboxdv1 "github.com/axelmierczuk/sandboxd-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/sandboxd-mcp/internal/agent"
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
	hostname, err := os.Hostname()
	if err != nil {
		// A host that cannot name itself is still a host that can run
		// commands, so this is reported rather than fatal.
		deps.Log.Warn("could not determine hostname", "error", err)
	}
	return &Service{
		deps:   deps,
		prober: NewProber(),
		platform: &sandboxdv1.Platform{
			Os:            runtime.GOOS,
			Arch:          runtime.GOARCH,
			KernelVersion: kernelVersion(),
			Hostname:      hostname,
			PathSeparator: string(filepath.Separator),
		},
		diskPath: resourceDiskPath(deps.Config.AllowedRoots),
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
	res := ProbeResources(s.diskPath)

	// The principal comes from the verified client certificate, never from
	// anything in the request. Echoing it back is how a caller confirms which
	// identity it is actually using — a control plane holding two leaves and
	// reaching for the wrong one otherwise finds out at the first denied
	// operation.
	principal, _ := agent.PrincipalFromContext(ctx)

	resp := &sandboxdv1.GetHostInfoResponse{
		Platform: s.platform,
		Resources: &sandboxdv1.Resources{
			CpuCores:             res.CPUCores,
			MemoryTotalBytes:     res.MemoryTotalBytes,
			MemoryAvailableBytes: res.MemoryAvailableBytes,
			DiskTotalBytes:       res.DiskTotalBytes,
			DiskAvailableBytes:   res.DiskAvailableBytes,
			LoadAverage_1M:       res.LoadAverage1m,
		},
		AgentVersion:           s.deps.Version,
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
