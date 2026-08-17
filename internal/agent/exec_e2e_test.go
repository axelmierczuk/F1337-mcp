package agent_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	sandboxdv1 "github.com/axelmierczuk/sandboxd-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/sandboxd-mcp/internal/agent"
	"github.com/axelmierczuk/sandboxd-mcp/internal/agent/exec"
)

// The command these tests run is this test binary, re-executed in a mode
// chosen by an environment variable. It is the one executable that is
// certain to exist on Linux, macOS and Windows alike, and it behaves the same
// on all three — where `echo` is a shell builtin on one of them and a file on
// the others.
const e2eHelperEnv = "SANDBOXD_EXEC_E2E"

func TestMain(m *testing.M) {
	switch os.Getenv(e2eHelperEnv) {
	case "":
	case "echo":
		if len(os.Args) > 1 {
			fmt.Print(strings.Join(os.Args[1:], " "))
		}
		os.Exit(0)
	default:
		fmt.Fprintln(os.Stderr, "unknown helper mode")
		os.Exit(2)
	}
	os.Exit(m.Run())
}

// ExecService end to end: over the real TLS stack, through the real
// registration seam, with the principal coming off the verified certificate
// chain rather than out of a test fixture.
//
// The exec package's own tests cover the request path in detail. What only a
// running daemon can show is that the service is reachable at all, that a
// client leaf's common name is what lands in the audit record, and that the
// stream carries chunks and then a result.
func TestExecService_EndToEnd(t *testing.T) {
	fleet := newTestFleet(t)
	cfg := fleet.agentConfig(t)
	cfg.Audit.Enabled = true
	cfg.Audit.Path = filepath.Join(t.TempDir(), "audit.jsonl")

	h := start(t, cfg, []agent.Registration{{Name: "exec", Factory: exec.New}})
	require.Equal(t, []string{"exec"}, h.server.ServiceNames())

	client := sandboxdv1.NewExecServiceClient(h.controlConn(t, fleet))
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	stream, err := client.Exec(ctx, &sandboxdv1.ExecRequest{
		Argv: []string{selfPath(t), "hello"},
		Env:  []string{"SANDBOXD_EXEC_E2E=echo"},
	})
	require.NoError(t, err)

	var stdout strings.Builder
	var result *sandboxdv1.ExecResult
	for {
		msg, recvErr := stream.Recv()
		if errors.Is(recvErr, io.EOF) {
			break
		}
		require.NoError(t, recvErr)
		if chunk := msg.GetOutput(); chunk != nil {
			require.Equal(t, sandboxdv1.Stream_STREAM_STDOUT, chunk.GetStream())
			stdout.Write(chunk.GetData())
		}
		if res := msg.GetResult(); res != nil {
			result = res
		}
	}

	require.NotNil(t, result, "the stream ends with a result")
	assert.Equal(t, int32(0), result.GetExitCode())
	assert.Equal(t, "hello", stdout.String())

	// One record, keyed on the common name in the control plane's leaf.
	require.NoError(t, h.server.Deps().Audit.Close())
	data, err := os.ReadFile(cfg.Audit.Path)
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	require.Len(t, lines, 1)

	var rec struct {
		Principal string `json:"principal"`
		RPC       string `json:"rpc"`
		Outcome   string `json:"outcome"`
	}
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &rec))
	assert.Equal(t, "sandboxd-mcp", rec.Principal,
		"the principal is the client certificate's common name, taken from the verified chain")
	assert.Equal(t, "sandboxd.v1.ExecService/Exec", rec.RPC)
	assert.Equal(t, "ok", rec.Outcome)
}

// An agent with exec disabled answers ExecService calls by naming the setting.
//
// Not Unimplemented, which reads as a version mismatch and sends an operator
// looking for the wrong problem — and not silence.
func TestExecService_DisabledAgentSaysSo(t *testing.T) {
	fleet := newTestFleet(t)
	root := t.TempDir()
	cfg := fleet.jailedConfig(t, root)

	h := start(t, cfg, []agent.Registration{{Name: "exec", Factory: exec.New}})
	require.True(t, h.server.Deps().Jail.Confined(), "exec off is the configuration where the jail is real")

	client := sandboxdv1.NewExecServiceClient(h.controlConn(t, fleet))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	stream, err := client.Exec(ctx, &sandboxdv1.ExecRequest{Argv: []string{selfPath(t)}})
	require.NoError(t, err)
	_, err = stream.Recv()
	require.Error(t, err)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	assert.Contains(t, status.Convert(err).Message(), "exec.enabled")
}

// controlConn dials the harness with the control plane's own leaf.
func (h *harness) controlConn(t *testing.T, fleet *testFleet) *grpc.ClientConn {
	t.Helper()
	certPEM, keyPEM := fleet.controlLeaf()
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)

	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(fleet.ca.CertPEM()))

	return h.rawConn(t, credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      roots,
		ServerName:   "test-agent",
		MinVersion:   tls.VersionTLS13,
	}))
}

// selfPath is the test binary, which stands in for a command that exists on
// every platform. See the exec package's helper: the same binary re-executes
// itself in a mode chosen by an environment variable.
func selfPath(t *testing.T) string {
	t.Helper()
	self, err := os.Executable()
	require.NoError(t, err)
	return self
}
