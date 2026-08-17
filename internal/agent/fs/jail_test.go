package fs_test

import (
	"context"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/fleet-mcp/internal/agent"
	agentfs "github.com/axelmierczuk/fleet-mcp/internal/agent/fs"
	"github.com/axelmierczuk/fleet-mcp/internal/security/jail"
)

// call names one RPC and the request that reaches outside, so every RPC in the
// service is covered by the same table rather than by whichever ones someone
// remembered.
type call struct {
	name string
	run  func(*agentfs.Service, string) error
}

func everyRPC() []call {
	ctx := context.Background()
	return []call{
		{"ReadFile", func(s *agentfs.Service, path string) error {
			return s.ReadFile(&sandboxdv1.ReadFileRequest{Path: path}, newReadStream(ctx))
		}},
		{"WriteFile", func(s *agentfs.Service, path string) error {
			return s.WriteFile(writeStreamFor(ctx, &sandboxdv1.WriteFileHeader{Path: path}, []byte("x"), 8))
		}},
		{"EditFile", func(s *agentfs.Service, path string) error {
			_, err := s.EditFile(ctx, &sandboxdv1.EditFileRequest{Path: path, OldString: "a", NewString: "b"})
			return err
		}},
		{"StatPath", func(s *agentfs.Service, path string) error {
			_, err := s.StatPath(ctx, &sandboxdv1.StatPathRequest{Path: path})
			return err
		}},
		{"ListDirectory", func(s *agentfs.Service, path string) error {
			_, err := s.ListDirectory(ctx, &sandboxdv1.ListDirectoryRequest{Path: filepath.Dir(path)})
			return err
		}},
		{"Glob", func(s *agentfs.Service, path string) error {
			_, err := s.Glob(ctx, &sandboxdv1.GlobRequest{Pattern: "*", Root: filepath.Dir(path)})
			return err
		}},
		{"Grep", func(s *agentfs.Service, path string) error {
			return s.Grep(&sandboxdv1.GrepRequest{Pattern: "x", Root: filepath.Dir(path)}, newGrepStream(ctx))
		}},
	}
}

// Every RPC refuses a path outside the allowed roots.
func TestJail_EveryRPCRefusesAPathOutsideTheRoots(t *testing.T) {
	root := tempRoot(t)
	outside := tempRoot(t)
	target := writeFile(t, filepath.Join(outside, "secret.txt"), "classified\n")
	svc := newConfined(t, root)

	for _, c := range everyRPC() {
		t.Run(c.name, func(t *testing.T) {
			err := c.run(svc, target)
			require.Error(t, err)
			assert.Equal(t, codes.PermissionDenied, status.Code(err))
			assert.Contains(t, status.Convert(err).Message(), "outside the allowed roots")
		})
	}
	assert.Equal(t, "classified\n", readBack(t, target), "and nothing outside was written to")
}

// The classic mistake this jail exists to avoid: a symlink inside the roots
// pointing out of them. Containment is checked on the resolved path, so it is
// refused.
func TestJail_RefusesASymlinkOutOfTheRoots(t *testing.T) {
	root := tempRoot(t)
	outside := tempRoot(t)
	writeFile(t, filepath.Join(outside, "secret.txt"), "classified\n")
	escape := filepath.Join(root, "escape.txt")
	requireSymlink(t, filepath.Join(outside, "secret.txt"), escape)
	svc := newConfined(t, root)

	err := svc.ReadFile(&sandboxdv1.ReadFileRequest{Path: escape}, newReadStream(context.Background()))
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))

	_, err = svc.StatPath(context.Background(), &sandboxdv1.StatPathRequest{Path: escape})
	assert.Equal(t, codes.PermissionDenied, status.Code(err))

	err = svc.WriteFile(writeStreamFor(context.Background(),
		&sandboxdv1.WriteFileHeader{Path: escape}, []byte("overwrite"), 8))
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.Equal(t, "classified\n", readBack(t, filepath.Join(outside, "secret.txt")))
}

// ".." is refused because the resolved path lands outside, not because of a
// textual check on the request — a distinction that matters, because the
// textual check is the one a symlink walks straight through.
func TestJail_RefusesTraversalOutOfTheRoots(t *testing.T) {
	root := tempRoot(t)
	svc := newConfined(t, root)

	err := svc.ReadFile(&sandboxdv1.ReadFileRequest{Path: filepath.Join(root, "..", "..", "etc", "passwd")},
		newReadStream(context.Background()))
	require.Error(t, err)
	assert.Contains(t, []codes.Code{codes.PermissionDenied, codes.NotFound}, status.Code(err))
}

// The unconfined twin. With exec enabled — the default — the daemon hands this
// service jail.Unconfined(), and there is no rejection to make. The service
// must not invent one: an operator told a path was refused by a jail that is
// not in force learns something false about their agent.
func TestJail_UnconfinedRefusesNothingAndClaimsNothing(t *testing.T) {
	root := tempRoot(t)
	outside := tempRoot(t)
	target := writeFile(t, filepath.Join(outside, "reachable.txt"), "a\n")
	svc := newUnconfined(t, root)

	for _, c := range everyRPC() {
		t.Run(c.name, func(t *testing.T) {
			err := c.run(svc, target)
			if err != nil {
				assert.NotEqual(t, codes.PermissionDenied, status.Code(err),
					"an unconfined agent has no allowed roots to refuse a path against")
				assert.NotContains(t, status.Convert(err).Message(), "allowed roots")
			}
		})
	}
	// And the write really did land, rather than being quietly dropped.
	assert.Equal(t, "x", readBack(t, target))
}

// The daemon's own wiring: the factory takes the jail from Deps and refuses to
// build without one, so a missing jail is a startup failure rather than an
// unconfined agent.
func TestNew_RequiresAJail(t *testing.T) {
	log := slog.New(slog.DiscardHandler)

	_, err := agentfs.New(agent.Deps{Log: log})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Jail")

	_, err = agentfs.New(agent.Deps{Log: log, Jail: &jail.Jail{}})
	require.Error(t, err, "an unconstructed jail refuses every path; building on one would be a dead service")

	svc, err := agentfs.New(agent.Deps{Log: log, Jail: jail.Unconfined()})
	require.NoError(t, err)
	assert.NotNil(t, svc)
}

// FileService is registered with every daemon that links this package, which is
// what the import in internal/cli/fleetagent/services.go relies on.
func TestService_IsRegisteredWithTheDaemon(t *testing.T) {
	names := make([]string, 0)
	for _, reg := range agent.Registered() {
		names = append(names, reg.Name)
	}
	assert.Contains(t, names, "fs")
}
