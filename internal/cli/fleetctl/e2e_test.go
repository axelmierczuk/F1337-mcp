package fleetctl_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axelmierczuk/fleet-mcp/internal/cli/fleetagent"
	"github.com/axelmierczuk/fleet-mcp/internal/cli/fleetctl"
)

// TestEndToEnd_CAInitServeMintEnrollList is the issue's first acceptance
// criterion, run for real: ca init → serve → enroll mint → an agent enrols with
// the printed command's arguments → list shows it healthy.
//
// Everything here is the shipping code path. The agent is fleet-agent's own
// enroll and serve, over a real TCP socket with a real mTLS handshake; the
// control plane is fleetctl's own serve; and the listing is `fleetctl list`,
// reading health through internal/client. The only thing the test does that an
// operator would not is run them in one process.
func TestEndToEnd_CAInitServeMintEnrollList(t *testing.T) {
	configDir := t.TempDir()
	agentDir := t.TempDir()
	t.Setenv("FLEET_CONFIG_DIR", configDir)

	// 1. A fleet CA.
	initOut, code := run(t, configDir, "ca", "init")
	require.Equal(t, 0, code, initOut)
	fingerprint := fingerprintOf(t, configDir)

	// 2. The enrollment endpoint, on loopback so the certificate it presents
	//    covers the address the agent will dial.
	controlAddr := "127.0.0.1:" + freeTCPPort(t)
	serveCtx, stopServe := context.WithCancel(context.Background())
	defer stopServe()
	serveOut := &bytes.Buffer{}
	serveDone := make(chan int, 1)
	go func() {
		serveDone <- fleetctl.MainContext(serveCtx, []string{
			"serve", "--listen", controlAddr, "--advertise", "127.0.0.1",
		}, serveOut)
	}()
	waitDialable(t, controlAddr)

	// 3. A token for a sandbox that will listen on another loopback port.
	agentAddr := "127.0.0.1:" + freeTCPPort(t)
	mintOut, code := run(t, configDir, "enroll", "mint",
		"--name", "build-box",
		"--address", agentAddr,
		"--control", controlAddr,
		"--label", "role=builder")
	require.Equal(t, 0, code, mintOut)
	token := tokenFrom(t, mintOut)

	// The generated command is what the operator would paste. Enrolling with
	// exactly the arguments it carries is what makes "directly pasteable" a
	// tested claim rather than a formatting exercise.
	command := installCommandFrom(t, mintOut)
	require.Contains(t, command, "--token "+token)
	require.Contains(t, command, "--control "+controlAddr)
	require.Contains(t, command, "--ca-fingerprint "+fingerprint)
	require.Contains(t, command, "--listen 0.0.0.0:"+portOf(t, agentAddr))

	// 4. The host joins, with the token, control address and fingerprint the
	//    mint printed — read back out of that command, not out of the flags
	//    this test passed to mint.
	agentOut := &bytes.Buffer{}
	require.Equal(t, 0, fleetagent.Main([]string{
		"enroll",
		"--token", argAfter(t, command, "--token"),
		"--control", argAfter(t, command, "--control"),
		"--ca-fingerprint", argAfter(t, command, "--ca-fingerprint"),
		"--listen", agentAddr,
		"--dir", agentDir,
	}, agentOut), agentOut.String())
	assert.Contains(t, agentOut.String(), `enrolled as "build-box"`)

	// The enrollment endpoint has done its job. Stopping it here is not
	// tidiness — it is the behaviour the docs and `serve` itself ask for.
	stopServe()
	select {
	case <-serveDone:
	case <-time.After(10 * time.Second):
		t.Fatal("fleetctl serve did not stop when its context was cancelled")
	}

	// 5. The agent daemon.
	agentCtx, stopAgent := context.WithCancel(context.Background())
	defer stopAgent()
	daemonOut := &bytes.Buffer{}
	daemonDone := make(chan int, 1)
	go func() {
		daemonDone <- fleetagent.MainContext(agentCtx, []string{
			"serve", "--config", filepath.Join(agentDir, "agent.yaml"),
		}, daemonOut)
	}()
	waitDialable(t, agentAddr)

	// 6. This workstation's own identity, which is what `list` presents to the
	//    agent.
	signOut, code := run(t, configDir, "ca", "sign", "--profile", "control")
	require.Equal(t, 0, code, signOut)

	// 7. The listing reports it healthy.
	var line struct {
		Name     string            `json:"name"`
		Address  string            `json:"address"`
		Health   string            `json:"health"`
		Platform string            `json:"platform"`
		Labels   map[string]string `json:"labels"`
	}
	require.Eventually(t, func() bool {
		out, code := run(t, configDir, "list", "--json", "--timeout", "2s")
		if code != 0 {
			return false
		}
		var doc struct {
			Sandboxes []struct {
				Name     string            `json:"name"`
				Address  string            `json:"address"`
				Health   string            `json:"health"`
				Platform string            `json:"platform"`
				Labels   map[string]string `json:"labels"`
			} `json:"sandboxes"`
		}
		if json.Unmarshal([]byte(out), &doc) != nil || len(doc.Sandboxes) != 1 {
			return false
		}
		line = doc.Sandboxes[0]
		return line.Health == "serving"
	}, 30*time.Second, 250*time.Millisecond, "the enrolled sandbox never came up healthy\nagent log:\n%s", daemonOut.String())

	assert.Equal(t, "build-box", line.Name)
	assert.Equal(t, agentAddr, line.Address)
	assert.Equal(t, map[string]string{"role": "builder"}, line.Labels)

	// 8. And `info` describes it, through the same client.
	infoOut, code := run(t, configDir, "info", "build-box", "--json", "--timeout", "5s")
	require.Equal(t, 0, code, infoOut)
	var info struct {
		Name      string `json:"name"`
		Health    string `json:"health"`
		Platform  string `json:"platform"`
		Agent     string `json:"agent"`
		Hostname  string `json:"hostname"`
		Principal string `json:"principal"`
	}
	require.NoError(t, json.Unmarshal([]byte(infoOut), &info), "info --json did not parse:\n%s", infoOut)
	assert.Equal(t, "build-box", info.Name)
	assert.Equal(t, "serving", info.Health)
	assert.NotEmpty(t, info.Platform)
	// The agent authenticated this workstation as the subject on the control
	// leaf `ca sign --profile control` just issued.
	assert.Equal(t, "fleet-mcp", info.Principal)

	// 9. The token was single-use, and the listing says so rather than still
	//    offering it as pending.
	tokens, code := run(t, configDir, "enroll", "list")
	require.Equal(t, 0, code, tokens)
	assert.Contains(t, tokens, "used")
	assert.NotContains(t, tokens, token)

	// 10. Removing it deregisters locally without touching the host.
	removeOut, code := run(t, configDir, "remove", "build-box")
	require.Equal(t, 0, code, removeOut)
	after, code := run(t, configDir, "list")
	require.Equal(t, 0, code, after)
	assert.Contains(t, after, "no sandboxes enrolled")

	stopAgent()
	select {
	case <-daemonDone:
	case <-time.After(30 * time.Second):
		t.Fatal("fleet-agent did not stop when its context was cancelled")
	}
}

// freeTCPPort asks the kernel for an unused port and gives it straight back.
// The window between is a race in principle; in practice the kernel does not
// immediately reissue a port it just handed out, and the alternative is not
// exercising a real socket at all.
func freeTCPPort(t *testing.T) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	_, port, err := net.SplitHostPort(lis.Addr().String())
	require.NoError(t, err)
	require.NoError(t, lis.Close())
	return port
}

func portOf(t *testing.T, address string) string {
	t.Helper()
	_, port, err := net.SplitHostPort(address)
	require.NoError(t, err)
	return port
}

// waitDialable blocks until something accepts on address, so a test does not
// race a listener opening.
func waitDialable(t *testing.T, address string) {
	t.Helper()
	require.Eventually(t, func() bool {
		conn, err := net.DialTimeout("tcp", address, time.Second)
		if err != nil {
			return false
		}
		_ = conn.Close()
		return true
	}, 20*time.Second, 50*time.Millisecond, "nothing ever listened on %s", address)
}

// argAfter pulls a flag's value out of the generated install command, so the
// enrollment below runs on what was printed rather than on what this test knows.
func argAfter(t *testing.T, command, flag string) string {
	t.Helper()
	fields := strings.Fields(command)
	for i, field := range fields {
		if field == flag && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	t.Fatalf("no %s in the generated command: %s", flag, command)
	return ""
}
