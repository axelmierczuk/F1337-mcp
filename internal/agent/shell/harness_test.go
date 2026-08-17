package shell

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/fleet-mcp/internal/agent"
	"github.com/axelmierczuk/fleet-mcp/internal/security/policy"
)

// These drive ShellService over a real gRPC connection rather than a
// hand-rolled stream. The whole contract is about what happens on a
// bidirectional stream — keystrokes one way, terminal output the other, and a
// terminal event that has to arrive last — and a fake stream would be asserting
// on the fake.

// options are the per-test decisions about the service under test.
type options struct {
	shell   agent.ShellConfig
	exec    agent.ExecConfig
	deny    []string
	allow   []string
	audit   func(*policy.AuditConfig)
	logs    *syncBuffer
	loginTo []string
}

// enabled is the address of a bool, for the config fields whose default is
// true and which therefore cannot be a plain bool.
func enabled(v bool) *bool { return &v }

// newService builds the service with a real audit log in a temp directory, so
// every test can read back what was recorded — and so none of them can pass
// while recording nothing.
func newService(t *testing.T, opts options) *Service {
	t.Helper()

	// The daemon applies these when it loads a config file; a config built in
	// memory has to be given them, or every test would run against a service
	// that reads "shell.enabled: false" from a field nobody set.
	shellCfg, execCfg := opts.shell, opts.exec
	if shellCfg.Enabled == nil {
		shellCfg.Enabled = enabled(true)
	}
	if shellCfg.IdleTimeout <= 0 {
		shellCfg.IdleTimeout = agent.Duration(2 * time.Minute)
	}
	if execCfg.Enabled == nil {
		execCfg.Enabled = enabled(true)
	}
	cfg := &agent.Config{Shell: shellCfg, Exec: execCfg}

	auditCfg := policy.AuditConfig{
		Path:    filepath.Join(t.TempDir(), "audit.jsonl"),
		Sandbox: "test-box",
		Enabled: true,
	}
	if opts.audit != nil {
		opts.audit(&auditCfg)
	}
	auditLog := policy.NewAudit(auditCfg)
	// Released before the temp directory goes: on Windows a directory holding
	// an open handle does not delete.
	t.Cleanup(func() { _ = auditLog.Close() })

	pol, err := policy.New(policy.Config{
		Allow: opts.allow,
		Deny:  opts.deny,
		Caps:  policy.Caps{DefaultTimeout: time.Minute, MaxTimeout: time.Hour, MaxConcurrent: 8},
	})
	require.NoError(t, err)

	logs := opts.logs
	if logs == nil {
		logs = &syncBuffer{}
	}

	built, err := New(agent.Deps{
		Config: cfg,
		Policy: pol,
		Audit:  auditLog,
		// A real handler at debug, into a buffer the test can read. The audit
		// tests assert on what the daemon's own log does *not* contain, and a
		// discarded logger would make that assertion vacuous.
		Log:     slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Status:  agent.NewStatus(),
		Version: "test",
	})
	require.NoError(t, err)

	svc, ok := built.(*Service)
	require.True(t, ok)
	if len(opts.loginTo) > 0 {
		svc.loginShell = func() []string { return opts.loginTo }
	}
	return svc
}

// serve puts the service behind a real gRPC connection.
func serve(t *testing.T, svc *Service) sandboxdv1.ShellServiceClient {
	t.Helper()

	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	svc.Register(srv)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = srv.Serve(lis)
	}()

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = conn.Close()
		srv.Stop()
		_ = lis.Close()
		wg.Wait()
	})
	return sandboxdv1.NewShellServiceClient(conn)
}

// clientSession is a running session as a test drives it: a stream to type into, and
// everything the session has printed so far.
type clientSession struct {
	t      *testing.T
	stream grpc.BidiStreamingClient[sandboxdv1.ShellRequest, sandboxdv1.ShellResponse]

	opened *sandboxdv1.ShellOpened
	output *syncBuffer

	mu        sync.Mutex
	exit      *sandboxdv1.ShellExit
	streamErr error
	done      chan struct{}
}

// openSession starts a session and reads until it is open, leaving a goroutine
// collecting output.
func openSession(ctx context.Context, t *testing.T, client sandboxdv1.ShellServiceClient, open *sandboxdv1.ShellOpen) (*clientSession, error) {
	t.Helper()

	stream, err := client.Shell(ctx)
	require.NoError(t, err)
	if err := stream.Send(&sandboxdv1.ShellRequest{Event: &sandboxdv1.ShellRequest_Open{Open: open}}); err != nil {
		return nil, err
	}

	first, err := stream.Recv()
	if err != nil {
		return nil, err
	}
	opened := first.GetOpened()
	if opened == nil {
		return nil, errors.New("the first response on a shell stream was not a ShellOpened")
	}

	s := &clientSession{t: t, stream: stream, opened: opened, output: &syncBuffer{}, done: make(chan struct{})}
	go s.collect()
	return s, nil
}

// collect drains the session until it ends.
func (s *clientSession) collect() {
	defer close(s.done)
	for {
		resp, err := s.stream.Recv()
		if err != nil {
			s.mu.Lock()
			s.streamErr = err
			s.mu.Unlock()
			return
		}
		switch event := resp.GetEvent().(type) {
		case *sandboxdv1.ShellResponse_Data:
			_, _ = s.output.Write(event.Data)
		case *sandboxdv1.ShellResponse_Exit:
			s.mu.Lock()
			s.exit = event.Exit
			s.mu.Unlock()
		}
	}
}

// typed sends bytes as if the operator had typed them.
func (s *clientSession) typed(text string) error {
	return s.stream.Send(&sandboxdv1.ShellRequest{
		Event: &sandboxdv1.ShellRequest_Data{Data: []byte(text)},
	})
}

// resize sends a new window size.
func (s *clientSession) resize(columns, rows uint32) error {
	return s.stream.Send(&sandboxdv1.ShellRequest{
		Event: &sandboxdv1.ShellRequest_Resize{Resize: &sandboxdv1.ShellSize{Columns: columns, Rows: rows}},
	})
}

// printed is everything the session has produced so far.
func (s *clientSession) printed() string { return s.output.String() }

// awaitOutput waits for the session to print something containing want.
func (s *clientSession) awaitOutput(want string) {
	s.t.Helper()
	waitFor(s.t, "the session to print "+want, func() (bool, string) {
		if strings.Contains(s.printed(), want) {
			return true, ""
		}
		return false, "so far it printed: " + s.printed()
	})
}

// awaitEnd waits for the stream to finish and returns the terminal event, which
// is nil when the stream ended without one.
func (s *clientSession) awaitEnd() *sandboxdv1.ShellExit {
	s.t.Helper()
	select {
	case <-s.done:
	case <-time.After(waitTimeout):
		s.t.Fatalf("the session did not end within %s; it printed: %s", waitTimeout, s.printed())
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.exit
}

// records returns everything the service has written to its audit log.
func records(t *testing.T, svc *Service) []policy.Record {
	t.Helper()

	data, err := os.ReadFile(svc.audit.Path())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	require.NoError(t, err)

	var out []policy.Record
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var rec policy.Record
		require.NoErrorf(t, json.Unmarshal([]byte(line), &rec), "audit line is not JSON: %s", line)
		out = append(out, rec)
	}
	return out
}

// onlyRecord requires exactly one audit record and returns it. One session is
// one record, and a test that accepted "at least one" would not notice a
// duplicate on one of the four paths out of the handler.
func onlyRecord(t *testing.T, svc *Service) policy.Record {
	t.Helper()

	var got []policy.Record
	waitFor(t, "the session to reach the audit log", func() (bool, string) {
		got = records(t, svc)
		if len(got) > 0 {
			return true, ""
		}
		return false, "nothing recorded yet"
	})
	require.Lenf(t, got, 1, "expected exactly one audit record, got %d: %+v", len(got), got)
	return got[0]
}

// auditFile is the raw log, for the assertions about what is *not* in it.
func auditFile(t *testing.T, svc *Service) string {
	t.Helper()
	data, err := os.ReadFile(svc.audit.Path())
	if errors.Is(err, os.ErrNotExist) {
		return ""
	}
	require.NoError(t, err)
	return string(data)
}
