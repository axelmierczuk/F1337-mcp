package agent

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"google.golang.org/grpc"
)

// Deps is everything the daemon hands a service implementation. It is passed
// to a Factory once, before the listener opens.
//
// Every field is populated for every service. Jail is never nil — a --no-jail
// daemon supplies one whose Enabled reports false — so a service can call
// Resolve unconditionally instead of nil-checking on the request path.
type Deps struct {
	// Config is the loaded, validated agent configuration. Services read
	// their own section of it: exec.* for #7, process.* for #11, audit.* for
	// #17.
	Config *Config

	// Jail confines filesystem access to the configured roots. Resolve every
	// caller-supplied path through it before any syscall, and use the path it
	// returns.
	//
	// It is only ever confining on an agent with exec disabled: a caller who
	// can run commands reaches any path without FileService, so the daemon
	// hands out an unconfined jail whenever exec is on. Do not read
	// Config.AllowedRoots as an answer about what is enforced — ask this. That
	// is also what GetHostInfo reports.
	Jail Jail

	// Log is the daemon logger. Services should scope it, conventionally with
	// Log.With("service", "<name>").
	Log *slog.Logger

	// Status is the shared health state HostService.Health reports. The
	// supervisor registers its process count with it; anything that can make
	// the agent unable to serve should set a DEGRADED status on it.
	Status *Status

	// Version is the agent binary's version string, as reported by
	// GetHostInfo and Health.
	Version string

	// StartedAt is when the daemon process started, reported by GetHostInfo so
	// the control plane can detect a restart.
	StartedAt time.Time
}

// Service is one gRPC service hosted by the daemon.
//
// A service may additionally implement Shutdowner to take part in graceful
// shutdown.
type Service interface {
	// Register attaches the generated handlers to the gRPC server. It is
	// called once, before the listener opens.
	Register(grpc.ServiceRegistrar)
}

// Shutdowner is the optional half of Service: a hook run once in-flight RPCs
// have drained.
//
// The contract is narrow on purpose. Shutdown means "stop serving and flush
// your own state". It does not mean "stop the work you started": supervised
// background processes are owned by the host, not by the daemon that spawned
// them, and surviving a daemon restart is the entire reason they exist. An
// agent upgrade must not take down every dev server in the fleet.
//
// So the supervisor's Shutdown persists its process records and returns. It
// must not signal a child, and the daemon never signals one on its behalf —
// which is also why the systemd unit this repository installs sets
// KillMode=process and the launchd job sets AbandonProcessGroup.
//
// The context passed in carries the shutdown deadline. Overrunning it does not
// stop the daemon exiting.
type Shutdowner interface {
	Shutdown(context.Context) error
}

// Factory constructs a Service from the daemon's dependencies. Returning an
// error aborts startup: a service that cannot be built is a daemon that must
// not start serving as though it had been.
type Factory func(Deps) (Service, error)

// Registration is a named factory.
type Registration struct {
	Name    string
	Factory Factory
}

var services struct {
	mu      sync.Mutex
	entries map[string]Factory
}

// Register makes a service part of every sandboxd-agent daemon that imports
// its package. Call it from an init function:
//
//	func init() {
//		agent.Register("exec", func(d agent.Deps) (agent.Service, error) {
//			return &Service{jail: d.Jail, log: d.Log.With("service", "exec")}, nil
//		})
//	}
//
// The name is used for ordering and log lines, and must be unique — a
// duplicate panics at init, because two services claiming one name is a wiring
// mistake that should not survive to runtime.
func Register(name string, f Factory) {
	if name == "" {
		panic("agent: service registered with an empty name")
	}
	if f == nil {
		panic("agent: service " + name + " registered with a nil factory")
	}
	services.mu.Lock()
	defer services.mu.Unlock()
	if services.entries == nil {
		services.entries = map[string]Factory{}
	}
	if _, exists := services.entries[name]; exists {
		panic("agent: service " + name + " is registered twice")
	}
	services.entries[name] = f
}

// Registered returns every registered service, ordered by name so a daemon's
// startup is reproducible regardless of import order.
func Registered() []Registration {
	services.mu.Lock()
	defer services.mu.Unlock()

	names := make([]string, 0, len(services.entries))
	for name := range services.entries {
		names = append(names, name)
	}
	sort.Strings(names)

	out := make([]Registration, 0, len(names))
	for _, name := range names {
		out = append(out, Registration{Name: name, Factory: services.entries[name]})
	}
	return out
}

// buildServices runs every factory against deps, in the order given.
func buildServices(regs []Registration, deps Deps) ([]builtService, error) {
	built := make([]builtService, 0, len(regs))
	for _, reg := range regs {
		svc, err := reg.Factory(deps)
		if err != nil {
			return nil, fmt.Errorf("agent: build service %s: %w", reg.Name, err)
		}
		if svc == nil {
			return nil, fmt.Errorf("agent: service %s built a nil service", reg.Name)
		}
		built = append(built, builtService{name: reg.Name, svc: svc})
	}
	return built, nil
}

type builtService struct {
	name string
	svc  Service
}
