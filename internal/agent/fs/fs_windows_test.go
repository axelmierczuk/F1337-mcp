//go:build windows

package fs_test

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	sandboxdv1 "github.com/axelmierczuk/sandboxd-mcp/gen/go/sandboxd/v1"
)

// Windows paths are case-insensitive, so two spellings of one file are one
// file — including for the lock that serialises edits. Spelling the path
// differently must not be a way to have two edits race.
func TestWindows_CaseInsensitivePathsShareOneLock(t *testing.T) {
	root := tempRoot(t)
	path := writeFile(t, filepath.Join(root, "Shared.txt"), "alpha = 0\nbeta = 0\n")
	svc := newConfined(t, root)

	spellings := []string{path, strings.ToLower(path), strings.ToUpper(path)}
	edits := []struct{ from, to string }{
		{"alpha = 0", "alpha = 1"},
		{"beta = 0", "beta = 2"},
	}

	var wg sync.WaitGroup
	errs := make([]error, len(edits))
	start := make(chan struct{})
	for i, edit := range edits {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, errs[i] = svc.EditFile(context.Background(), &sandboxdv1.EditFileRequest{
				Path: spellings[i], OldString: edit.from, NewString: edit.to,
			})
		}()
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		require.NoError(t, err, "edit %d", i)
	}
	assert.Equal(t, "alpha = 1\nbeta = 2\n", readBack(t, path))
}

// A file read through a differently cased path is the same file.
func TestWindows_ReadsThroughACaseVariantPath(t *testing.T) {
	root := tempRoot(t)
	path := writeFile(t, filepath.Join(root, "MixedCase.txt"), "line one\r\nline two\r\n")
	svc := newConfined(t, root)

	stream := readAll(t, svc, &sandboxdv1.ReadFileRequest{Path: strings.ToLower(path)})
	assert.Equal(t, "line one\r\nline two\r\n", string(stream.content))
	assert.Equal(t, uint64(2), stream.result.GetTotalLines())
}

// Glob matches case-insensitively on Windows, because the filesystem does.
func TestWindows_GlobIsCaseInsensitive(t *testing.T) {
	root := tempRoot(t)
	writeFile(t, filepath.Join(root, "Main.GO"), "")
	svc := newConfined(t, root)

	resp := glob(t, svc, &sandboxdv1.GlobRequest{Pattern: "*.go", Root: root})
	assert.Equal(t, []string{"Main.GO"}, relative(t, root, resp.GetPaths()))
}
