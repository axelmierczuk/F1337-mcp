// Package agent hosts the sandboxd-agent daemon: configuration, the mandatory
// mTLS gRPC server, and the lifecycle every M1 service plugs into.
//
// # Registering a service
//
// A service package registers itself from an init function and is then hosted
// by every daemon that imports it:
//
//	package exec
//
//	func init() {
//		agent.Register("exec", func(d agent.Deps) (agent.Service, error) {
//			return &Service{jail: d.Jail, log: d.Log.With("service", "exec")}, nil
//		})
//	}
//
//	// Service implements agent.Service.
//	func (s *Service) Register(r grpc.ServiceRegistrar) {
//		sandboxdv1.RegisterExecServiceServer(r, s)
//	}
//
// The daemon constructs every registered factory once, in name order, before
// it starts listening, and fails to start if any of them returns an error. The
// only wiring a new service package needs outside itself is one blank import
// in internal/cli/sandboxdagent/services.go.
//
// # What a service gets
//
// [Deps] carries the config, the path jail, a logger, the shared [Status], and
// build metadata. [PrincipalFromContext] returns the authenticated client
// certificate's common name for any RPC the daemon served, which is what an
// audit record is keyed on.
//
// # Shutdown
//
// A Service may also implement [Shutdowner] to participate in graceful
// shutdown. The contract is deliberately narrow: shutdown means "stop serving
// and flush your own state", never "kill the work you started". Background
// processes supervised by the agent outlive the daemon by design — an agent
// upgrade must not take down every dev server in the fleet — so the daemon
// never signals a child process, and neither should a Shutdowner.
package agent
