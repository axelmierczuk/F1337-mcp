package mcpserver_test

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/fleet-mcp/internal/agent"
	agentforward "github.com/axelmierczuk/fleet-mcp/internal/agent/forward"
	agenthost "github.com/axelmierczuk/fleet-mcp/internal/agent/host"
	agentprocess "github.com/axelmierczuk/fleet-mcp/internal/agent/process"
	"github.com/axelmierczuk/fleet-mcp/internal/client"
	"github.com/axelmierczuk/fleet-mcp/internal/mcpserver"
	"github.com/axelmierczuk/fleet-mcp/internal/registry"
	"github.com/axelmierczuk/fleet-mcp/internal/security/jail"
	"github.com/axelmierczuk/fleet-mcp/internal/security/policy"
)

// The process and forward tools are tested against the real agent services,
// not against a fake ProcessServiceClient.
//
// Almost everything worth asserting about these two tools lives in the gap
// between the two halves: a readiness probe that has to have actually passed
// before the tool returns, a follow that has to end at the agent's deadline
// rather than this side's, a half-close that has to survive both directions of
// a bidirectional stream. A fake client can be made to report any of those
// without any of them being true. So the agent's ProcessService and
// ForwardService are stood up in-process over bufconn, and the MCP server is
// pointed at them through the same generated clients it uses in production.

// ------------------------------------------------------------ child process

// m2HelperEnv marks a re-executed copy of this test binary as a supervised
// child rather than a test run.
//
// Named apart from exechelper_test.go's helperEnv, and dispatched apart from
// it, because the two want different things from the binary. #48's helper is
// selected in TestMain and returns an exit code; these children are supervised
// processes that outlive the call that started them, so they are entered
// through a test function and run until they are signalled. Both mechanisms
// live in one package and neither is the other's dispatcher: a child of this
// one leaves FLEET_MCP_TEST_HELPER unset, so TestMain hands it to m.Run and
// TestM2HelperChild picks it up.
const m2HelperEnv = "FLEET_MCP_M2_HELPER"

// TestM2HelperChild is the entry point of every process the process-tool tests
// supervise. It is not a test.
//
// The supervised process is another copy of this test binary because there is
// no portable alternative: `sh -c` does not exist on Windows, `sleep` is not on
// the path there, and a suite that reaches for them asserts on Unix and skips
// on the platform where process handling is least like the others. Re-executing
// this binary runs the same test everywhere against a child whose behaviour the
// test controls exactly.
func TestM2HelperChild(t *testing.T) {
	if os.Getenv(m2HelperEnv) == "" {
		t.Skip("not a test: the child-process entry point for the process-tool tests")
	}
	m2HelperMain()
}

func m2HelperMain() {
	args := os.Args[1:]
	for i, arg := range args {
		if arg == "--" {
			args = args[i+1:]
			break
		}
	}
	if len(args) == 0 {
		os.Exit(2)
	}

	switch args[0] {
	case "silent":
		// Produces nothing, ever. The bounded-follow assertion needs a process
		// that cannot be mistaken for one that is merely slow.
		time.Sleep(time.Hour)

	case "listen":
		// listen <delayMs> <port> — binds loopback after a delay, which is the
		// dev server the readiness probe exists for.
		time.Sleep(millis(args, 1))
		port := argAt(args, 2, "0")
		lis, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", port))
		if err != nil {
			fmt.Fprintln(os.Stderr, "listen failed:", err)
			os.Exit(1)
		}
		fmt.Println("listening on", lis.Addr().String())
		for {
			conn, err := lis.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}

	case "chatter":
		// chatter <count> <intervalMs> <text> — output on a schedule, then a
		// long sleep so the process is still running when the test looks.
		count, _ := strconv.Atoi(argAt(args, 1, "1"))
		interval := millis(args, 2)
		text := argAt(args, 3, "line")
		for i := range count {
			fmt.Printf("%s %d\n", text, i)
			if interval > 0 {
				time.Sleep(interval)
			}
		}
		time.Sleep(time.Hour)

	case "spew":
		// spew <count> — as fast as the pipe takes it, to outrun the ring
		// buffer so the drop markers have something to mark.
		count, _ := strconv.Atoi(argAt(args, 1, "1000"))
		for i := range count {
			fmt.Printf("spew %d %s\n", i, "................................")
		}
		time.Sleep(time.Hour)

	case "stderr":
		// stderr <text> — one line on each stream, so the rendering of the two
		// can be told apart.
		fmt.Println("on stdout")
		fmt.Fprintln(os.Stderr, argAt(args, 1, "on stderr"))
		time.Sleep(time.Hour)

	case "deaf":
		// Ignores SIGTERM, so a graceful stop has to escalate.
		//
		// It says so once the disposition is actually installed, and the test
		// waits for that line with a ready probe. Without it the test races the
		// child's own startup: fleet_process_start returns as soon as the
		// process is spawned, and a SIGTERM that arrives before this line has
		// been printed is delivered to a process still carrying the default
		// disposition, which kills it — so the stop does not escalate and the
		// test fails, on a runner slow enough, having proved nothing.
		signal.Ignore(syscall.SIGTERM, syscall.SIGINT)
		fmt.Println("ignoring SIGTERM")
		time.Sleep(time.Hour)

	case "exit":
		// exit <code> <delayMs>
		code, _ := strconv.Atoi(argAt(args, 1, "0"))
		time.Sleep(millis(args, 2))
		os.Exit(code)

	case "http":
		// http <port> <body> — the server a forward is pointed at.
		port := argAt(args, 1, "0")
		body := argAt(args, 2, "hello")
		srv := &http.Server{
			Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(body))
			}),
			ReadHeaderTimeout: 5 * time.Second,
		}
		lis, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", port))
		if err != nil {
			os.Exit(1)
		}
		fmt.Println("serving on", lis.Addr().String())
		_ = srv.Serve(lis)
	}
	os.Exit(0)
}

func argAt(args []string, i int, fallback string) string {
	if i < len(args) && args[i] != "" {
		return args[i]
	}
	return fallback
}

func millis(args []string, i int) time.Duration {
	n, err := strconv.Atoi(argAt(args, i, "0"))
	if err != nil || n <= 0 {
		return 0
	}
	return time.Duration(n) * time.Millisecond
}

// helperArgv builds the argv that re-executes this binary in helper mode.
//
// -test.timeout=0 because the children deliberately outlive the tests that
// start them: the default ten-minute panic would dump a goroutine trace into a
// supervised process's log for no reason.
func helperArgv(t *testing.T, mode string, args ...string) []string {
	t.Helper()
	exe, err := os.Executable()
	require.NoError(t, err)
	argv := []string{exe, "-test.run", "^TestM2HelperChild$", "-test.timeout", "0", "--", mode}
	return append(argv, args...)
}

// helperEnviron is the environment a supervised child needs to run as a child
// rather than as a test.
func helperEnviron() []string { return []string{m2HelperEnv + "=1"} }

// ------------------------------------------------------------- live agent

// liveAgent is a real agent service set served over bufconn.
type liveAgent struct {
	conn      *grpc.ClientConn
	stateDir  string
	auditPath string
}

type liveAgentOptions struct {
	// ringBufferLines shrinks the in-memory log ring, so a test can outrun it
	// without writing a hundred thousand lines.
	ringBufferLines int
	// maxLogBytes shrinks the on-disk log before rotation. Shrinking the ring
	// alone does not lose a line — the rotating file behind it is what makes
	// the ring's contents recoverable — so a test about dropped lines has to
	// shrink both.
	maxLogBytes int64
	// maxFollowDuration caps a follow, so the bounded-follow assertion does
	// not have to wait a minute for the agent's real default.
	maxFollowDuration time.Duration
	// gracePeriod is the default graceful-stop grace.
	gracePeriod time.Duration
	// forwardAllowedHosts are the non-loopback hosts forwarding may target.
	forwardAllowedHosts []string
	// forwardDisabled turns ForwardService off.
	forwardDisabled bool
	// socksEnabled turns SOCKS proxying on. It is off by default, exactly as it
	// is on a real agent — a fixture whose default differed from the product's
	// would be testing a posture nobody ships.
	socksEnabled bool
}

func startLiveAgent(t *testing.T, opts liveAgentOptions) *liveAgent {
	t.Helper()

	stateDir := t.TempDir()
	if opts.ringBufferLines == 0 {
		opts.ringBufferLines = 500
	}
	if opts.maxFollowDuration == 0 {
		opts.maxFollowDuration = 3 * time.Second
	}
	if opts.gracePeriod == 0 {
		opts.gracePeriod = 2 * time.Second
	}
	if opts.maxLogBytes == 0 {
		opts.maxLogBytes = 4 << 20
	}

	forwardEnabled := !opts.forwardDisabled
	cfg := &agent.Config{
		StateDir: stateDir,
		Process: agent.ProcessConfig{
			MaxConcurrent:      64,
			MaxLogBytes:        opts.maxLogBytes,
			RingBufferLines:    opts.ringBufferLines,
			DefaultGracePeriod: agent.Duration(opts.gracePeriod),
			MaxFollowDuration:  agent.Duration(opts.maxFollowDuration),
		},
		Forward: agent.ForwardConfig{
			Enabled:      &forwardEnabled,
			AllowedHosts: opts.forwardAllowedHosts,
			SocksEnabled: opts.socksEnabled,
			DialTimeout:  agent.Duration(3 * time.Second),
		},
	}

	// A real audit log in the state directory. ForwardService refuses to build
	// without one, deliberately: an agent that can be asked to reach another
	// host must not be constructible with nowhere to record that it did.
	auditLog := policy.NewAudit(policy.AuditConfig{
		Path:    filepath.Join(stateDir, "audit.jsonl"),
		Sandbox: liveSandboxName,
		Enabled: true,
	})
	t.Cleanup(func() { _ = auditLog.Close() })

	// The one concurrency limiter the daemon shares between ExecService and the
	// supervisor. It is not optional: newSupervisor refuses a nil one, because a
	// cap each service counted for itself let an agent configured for 32 run 32
	// of each.
	limiter, err := policy.New(policy.Config{Caps: policy.Caps{MaxConcurrent: cfg.Process.MaxConcurrent}})
	require.NoError(t, err)

	deps := agent.Deps{
		Config:    cfg,
		Jail:      jail.Unconfined(),
		Policy:    limiter,
		Log:       slog.New(slog.NewTextHandler(&testWriter{t: t}, &slog.HandlerOptions{Level: slog.LevelWarn})),
		Status:    agent.NewStatus(),
		Audit:     auditLog,
		Version:   "0.0.0-test",
		StartedAt: time.Now(),
	}

	procSvc, err := agentprocess.New(deps)
	require.NoError(t, err)
	fwdSvc, err := agentforward.New(deps)
	require.NoError(t, err)
	// The real HostService, so that fleet_socks reads the forward policy off the
	// agent's own configuration rather than off a fake this file could set to
	// anything. The whole of fleet_socks's refusal turns on that answer, and a
	// fixture that supplied it would be testing the tool against its own
	// opinion of what the agent said.
	hostSvc, err := agenthost.New(deps)
	require.NoError(t, err)

	lis := bufconn.Listen(1 << 20)
	// WaitForHandlers, so Stop below does not return while a handler is still
	// unwinding. Without it the teardown order is a lie: Stop returns, the audit
	// log is closed, t.TempDir starts deleting the state directory — and a
	// straggler handler writing its record reopens audit.jsonl underneath the
	// delete, which lands as "TempDir RemoveAll cleanup: directory not empty"
	// against a test that had already passed. Twice in twelve runs of the
	// forward and socks tests at -parallel 24, always a different test.
	srv := grpc.NewServer(grpc.WaitForHandlers(true))
	procSvc.Register(srv)
	fwdSvc.Register(srv)
	hostSvc.Register(srv)

	var serving sync.WaitGroup
	serving.Add(1)
	go func() {
		defer serving.Done()
		_ = srv.Serve(lis)
	}()

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)

	t.Cleanup(func() {
		// Reap first, over the connection that is about to close. Supervised
		// processes deliberately outlive the agent that spawned them — that is
		// the whole point of the supervisor — so a shutdown does not stop
		// them, and a test that fails before its own cleanup would otherwise
		// leave a sleeping child on the machine that ran the suite.
		reapEverything(t, conn)

		_ = conn.Close()
		srv.Stop()
		_ = lis.Close()
		serving.Wait()
		if sd, ok := procSvc.(agent.Shutdowner); ok {
			_ = sd.Shutdown(context.Background())
		}
	})

	return &liveAgent{conn: conn, stateDir: stateDir, auditPath: auditLog.Path()}
}

// reapEverything force-removes every process the agent is tracking.
func reapEverything(t *testing.T, conn *grpc.ClientConn) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client := sandboxdv1.NewProcessServiceClient(conn)
	list, err := client.ListProcesses(ctx, &sandboxdv1.ListProcessesRequest{})
	if err != nil {
		return
	}
	for _, p := range list.GetProcesses() {
		if _, err := client.RemoveProcess(ctx, &sandboxdv1.RemoveProcessRequest{
			ProcessId: p.GetProcessId(), Force: true, DeleteLogs: true,
		}); err != nil {
			t.Logf("reaping %s: %v", p.GetProcessId(), err)
		}
	}
}

// liveClients is a tools.Clients backed by one real agent over bufconn.
type liveClients struct {
	conn *grpc.ClientConn

	// onRemove observes the moment the pooled channel is dropped, so a test can
	// assert on what has already happened by then. Nil for every test that does
	// not care.
	onRemove func(string)
}

func (c *liveClients) Host(string, string) (sandboxdv1.HostServiceClient, error) {
	return sandboxdv1.NewHostServiceClient(c.conn), nil
}

func (c *liveClients) Exec(string, string) (sandboxdv1.ExecServiceClient, error) {
	return nil, status.Error(codes.Unimplemented, "ExecService is not part of these tests")
}

func (c *liveClients) Files(string, string) (sandboxdv1.FileServiceClient, error) {
	return nil, status.Error(codes.Unimplemented, "FileService is not part of these tests")
}

func (c *liveClients) Process(string, string) (sandboxdv1.ProcessServiceClient, error) {
	return sandboxdv1.NewProcessServiceClient(c.conn), nil
}

func (c *liveClients) Forward(string, string) (sandboxdv1.ForwardServiceClient, error) {
	return sandboxdv1.NewForwardServiceClient(c.conn), nil
}

func (c *liveClients) Health(string) (client.HealthStatus, bool) { return client.HealthStatus{}, false }

func (c *liveClients) Remove(name string) {
	if c.onRemove != nil {
		c.onRemove(name)
	}
}

// ------------------------------------------------------------- MCP fixture

// liveFixture is an MCP server whose tools reach a real agent.
type liveFixture struct {
	t       *testing.T
	agent   *liveAgent
	clients *liveClients
	server  *mcpserver.Server
	session *mcp.ClientSession
	sandbox string
}

const liveSandboxName = "m2-box"

func newLiveFixture(t *testing.T, opts liveAgentOptions) *liveFixture {
	t.Helper()

	live := startLiveAgent(t, opts)
	dir := t.TempDir()

	clients := &liveClients{conn: live.conn}
	server, err := mcpserver.New(mcpserver.Options{
		ConfigDir: dir,
		Clients:   clients,
		LogWriter: &testWriter{t: t},
		// Short, because nothing here talks to a real network. A tool that
		// waits on a probe raises its own deadline above this.
		CallTimeout: 10 * time.Second,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = server.Close() })

	fleet, err := registry.Open(filepath.Join(dir, "registry.yaml"))
	require.NoError(t, err)
	require.NoError(t, fleet.Add(registry.Sandbox{Name: liveSandboxName, Address: "bufnet:8722"}))

	const clientName = "m2-test-client"
	// The sticky selection is written straight into the registry rather than
	// made through fleet_select, which would need a HostService this fixture
	// deliberately does not serve.
	require.NoError(t, fleet.SetSelection("client:"+clientName, liveSandboxName))

	ctx := t.Context()
	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	serverSession, err := server.Connect(ctx, serverTransport)
	require.NoError(t, err)
	t.Cleanup(func() { _ = serverSession.Close() })

	mcpClient := mcp.NewClient(&mcp.Implementation{Name: clientName, Version: "1.0.0"}, nil)
	session, err := mcpClient.Connect(ctx, clientTransport, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = session.Close() })

	return &liveFixture{t: t, agent: live, clients: clients, server: server, session: session, sandbox: liveSandboxName}
}

// call invokes a tool and returns the raw result.
func (f *liveFixture) call(name string, args map[string]any) *mcp.CallToolResult {
	f.t.Helper()
	res, err := f.session.CallTool(f.t.Context(), &mcp.CallToolParams{Name: name, Arguments: args})
	require.NoError(f.t, err, "tool call must not fail at the protocol level")
	return res
}

// ok calls a tool and decodes its result, failing the test if it reported an
// error.
func liveOK[T any](f *liveFixture, name string, args map[string]any) T {
	f.t.Helper()
	res := f.call(name, args)
	require.Falsef(f.t, res.IsError, "%s reported an error: %s", name, resultText(res))
	// Every targeted tool echoes the sandbox it ran on, and every one of these
	// results goes through here — so the echo is asserted on every call in this
	// file rather than once in a test that could be deleted.
	require.Equal(f.t, f.sandbox, echoOf(f.t, res), "%s must echo the resolved sandbox", name)
	return structured[T](f.t, res)
}

// liveFails calls a tool and returns the error text, failing if it succeeded.
func (f *liveFixture) liveFails(name string, args map[string]any) string {
	f.t.Helper()
	res := f.call(name, args)
	require.Truef(f.t, res.IsError, "%s should have reported an error, got: %s", name, resultText(res))
	return resultText(res)
}

// startHelper starts a supervised child in the given helper mode.
func (f *liveFixture) startHelper(name, mode string, args ...string) map[string]any {
	f.t.Helper()
	return map[string]any{
		"name": name,
		"argv": toAnySlice(helperArgv(f.t, mode, args...)),
		"env":  toAnySlice(helperEnviron()),
	}
}

func toAnySlice(in []string) []any {
	out := make([]any, len(in))
	for i, s := range in {
		out[i] = s
	}
	return out
}

// freePort hands out a loopback port that nothing else will take, for the
// tests that have to name a port before the thing that binds it exists.
//
// The obvious implementation — bind :0, read the port, close the listener — is
// what this used to be, and it is a reserve-and-release with a window in it.
// While every test ran one at a time that window was closed by construction.
// It is not any more, and there are two ways through it: two calls racing for
// the same port, and an unrelated `Listen(":0")` elsewhere in the suite landing
// on a port a caller has reserved but not yet bound. Neither fails here — both
// fail once, on someone else's machine, in a test that reads as unrelated.
//
// So the ports come from below the ephemeral range instead of out of it. Every
// platform this suite runs on allocates :0 from a range starting at 32768
// (Linux) or 49152 (macOS, Windows), so a port under 30000 is one the kernel
// will not hand to anyone asking for "any port" — which is the whole of the
// second failure. The cursor under the mutex is the whole of the first.
//
// A port can still be held by something else on the machine, which is why each
// candidate is proved bindable before it is returned rather than assumed to be.
func freePort(t *testing.T) int {
	t.Helper()
	return freePorts.next(t)
}

// freePorts is the allocator freePort draws from, one per test binary.
var freePorts portAllocator

// freePortBase and freePortLimit bracket the range these allocators draw from:
// above the registered ports in common use and below every platform's ephemeral
// range. freePortSlice is how much of it one process takes.
//
// The slice has to be comfortably wider than the longest run of calls any one
// test makes, because the cursor wraps: a wrapped cursor re-offers ports this
// process has already finished with, which is fine for a caller and not fine
// for the test that asserts the numbers are distinct.
const (
	freePortBase  = 20000
	freePortLimit = 30000
	freePortSlice = 200
)

// portAllocator hands out ports from a slice of [freePortBase, freePortLimit)
// that it owns outright.
//
// Owning it is the point, and it is what the sentinel is for. The cursor keeps
// two goroutines in this process off one port; nothing in it keeps two
// *processes* off one, and two do run at once — `go test` in two terminals, two
// worktrees on one machine, two jobs on one self-hosted runner. Handing those
// overlapping ranges is worse than the reserve-and-release this replaced,
// because the kernel arbitrates its ephemeral range across processes and a
// private cursor arbitrates nothing. That was measured rather than imagined:
// two copies of this binary drawing from one shared range failed in three of
// six rounds — `freePort returned 22440, which is not bindable`, an explicit
// local_port already taken, and a readiness probe that passed in 355ms against
// the *other* process's listener on a port whose own child binds after 600ms.
// The last of those is the shape that matters: had it been 50ms slower it would
// have passed, having proved nothing about this process at all.
//
// So a process claims its slice the way everything here proves a port: by
// binding one, and then by not letting go. The sentinel sits on the slice's
// first port for the life of the process, so a second copy of this binary finds
// that slice taken and moves to the next one — and the claim is released by the
// kernel when the process exits, with nothing to leave behind or clean up.
type portAllocator struct {
	mu       sync.Mutex
	sentinel net.Listener
	base     int // first port after the sentinel
	limit    int
	cursor   int
}

// next returns a port in this allocator's slice that is bindable right now and
// that it has not just handed out.
//
// It claims the slice on the first call rather than at init, so a `go test`
// that never asks for a port never takes one — the supervised children in this
// file are copies of this same binary and reach m.Run, and a slice each would
// be a slice each for an hour. Every caller of freePort is a parallel test, so
// the claim also lands after the sequential descriptor-count tests have taken
// their snapshots.
func (a *portAllocator) next(t *testing.T) int {
	t.Helper()

	a.mu.Lock()
	defer a.mu.Unlock()
	if a.sentinel == nil {
		require.NoError(t, a.claim())
	}

	for range a.limit - a.base {
		port := a.cursor
		a.cursor++
		if a.cursor >= a.limit {
			a.cursor = a.base
		}
		// Proved free, not assumed: the slice is this process's, but a port in
		// it can still be held by a program that knows nothing about any of this.
		lis, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err != nil {
			continue
		}
		require.NoError(t, lis.Close())
		return port
	}
	t.Fatalf("no free port between %d and %d", a.base, a.limit)
	return 0
}

// claim takes the first slice whose sentinel port can be bound, starting from
// one chosen by process id so that two copies starting together do not both
// walk the range from the bottom.
//
// It must be called with a.mu held.
func (a *portAllocator) claim() error {
	const slices = (freePortLimit - freePortBase) / freePortSlice
	// 2^32 divided by the golden ratio: odd, so the mapping is a bijection and
	// adjacent pids — which is what two runs started seconds apart by the same
	// shell have — do not land on adjacent slices.
	const knuth = 2654435761
	first := int(uint64(os.Getpid()) * knuth % slices)

	for i := range slices {
		start := freePortBase + ((first+i)%slices)*freePortSlice
		lis, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(start)))
		if err != nil {
			continue // another copy of this binary is sitting on that slice
		}
		a.sentinel = lis
		a.base, a.limit = start+1, start+freePortSlice
		a.cursor = a.base
		return nil
	}
	return fmt.Errorf("no free port slice between %d and %d: no more than %d copies of this test binary can run at "+
		"once, and something else may be listening in that range", freePortBase, freePortLimit, slices)
}

// release gives the slice back. Only the allocators tests build for themselves
// need it; the package-level one is released when the process exits.
func (a *portAllocator) release() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.sentinel != nil {
		_ = a.sentinel.Close()
		a.sentinel = nil
	}
}

// rewind puts the next candidate back to port, for the test that has to know
// what the allocator will try next. Safe only on an allocator no other
// goroutine is using.
func (a *portAllocator) rewind(port int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.cursor = port
}

// TestFreePort_IsDistinctAndOutsideTheEphemeralRange pins the two properties
// the sweep to parallel tests actually depends on, because neither of them
// shows up as a failure here when it breaks — they show up as a port collision
// in an unrelated test, on a loaded machine, once.
//
// The bound is 32768: the lowest ephemeral floor of the three platforms this
// suite runs on (Linux; macOS and Windows start at 49152). A port below it is
// one no `Listen(":0")` anywhere else in this binary can be handed.
func TestFreePort_IsDistinctAndOutsideTheEphemeralRange(t *testing.T) {
	t.Parallel()

	const lowestEphemeralFloor = 32768
	seen := map[int]bool{}
	// Well short of freePortSlice, so the cursor cannot wrap inside one run and
	// re-offer a port this loop has already released — which would read as a
	// duplicate and would be the test's own doing.
	for range 50 {
		port := freePort(t)

		assert.Falsef(t, seen[port], "freePort handed out %d twice", port)
		seen[port] = true

		assert.Greaterf(t, port, 1023, "freePort returned %d, which is a privileged port", port)
		assert.Lessf(t, port, lowestEphemeralFloor,
			"freePort returned %d, which is inside the ephemeral range: an unrelated Listen(\":0\") "+
				"in a parallel test can be handed the same port between the reservation and the bind", port)

		// And it is free *now*, which is the only moment a caller can use it.
		lis, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		require.NoErrorf(t, err, "freePort returned %d, which is not bindable", port)
		require.NoError(t, lis.Close())
	}
}

// TestFreePort_SkipsAPortSomethingElseIsUsing is the third property, and the
// one the walk above cannot reach: the slice is this process's, but a port
// inside it can still be held by a program that knows nothing about any of
// this. Deleting the bindability check leaves the walk above green, because
// nothing on a CI runner happens to be listening between 20000 and 30000 —
// which is why this occupies a port itself rather than waiting to be unlucky.
//
// It drives an allocator of its own, which claims a slice of its own, so
// rewinding the cursor onto a chosen port cannot disturb the one every other
// parallel test in this package is drawing from.
func TestFreePort_SkipsAPortSomethingElseIsUsing(t *testing.T) {
	t.Parallel()

	own := &portAllocator{}
	t.Cleanup(own.release)

	occupied := own.next(t)
	held, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(occupied)))
	require.NoError(t, err)
	t.Cleanup(func() { _ = held.Close() })

	own.rewind(occupied)
	got := own.next(t)
	require.NotEqualf(t, occupied, got,
		"the allocator handed out %d while this test was listening on it", occupied)

	// And it moved on to one that works, rather than merely moving on.
	lis, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(got)))
	require.NoErrorf(t, err, "the port it moved on to, %d, is not bindable", got)
	require.NoError(t, lis.Close())
}

// TestFreePort_TwoAllocatorsNeverShareAPort is the cross-process half of that,
// standing in for a second copy of this binary with a second allocator: the
// sentinel is what makes the two slices disjoint, and without it two copies
// draw from one range and collide. That is not hypothetical — it is what a
// second `go test` in a second terminal does, and it broke five of this
// package's port assertions in six rounds before the sentinel existed.
func TestFreePort_TwoAllocatorsNeverShareAPort(t *testing.T) {
	t.Parallel()

	first, second := &portAllocator{}, &portAllocator{}
	t.Cleanup(first.release)
	t.Cleanup(second.release)

	seen := map[int]bool{}
	for range 50 {
		for _, a := range []*portAllocator{first, second} {
			port := a.next(t)
			assert.Falsef(t, seen[port], "two allocators both handed out %d", port)
			seen[port] = true
		}
	}
}

// eventually polls until cond holds, failing with msg if it never does.
func eventually(t *testing.T, timeout time.Duration, msg string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for %s", timeout, msg)
}
