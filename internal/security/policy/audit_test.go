package policy_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/axelmierczuk/sandboxd-mcp/internal/security/policy"
)

func newAudit(t *testing.T, mutate func(*policy.AuditConfig)) (*policy.Audit, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	cfg := policy.AuditConfig{Path: path, Enabled: true, MaxBytes: 1 << 20, RetainSegments: 3}
	if mutate != nil {
		mutate(&cfg)
	}
	log := policy.NewAudit(cfg)
	t.Cleanup(func() { _ = log.Close() })
	return log, cfg.Path
}

func TestAudit_WritesValidJSONL(t *testing.T) {
	log, path := newAudit(t, nil)

	exit := int32(2)
	require.NoError(t, log.Write(policy.Record{
		Principal:  "control-plane",
		RPC:        "sandboxd.v1.ExecService/Exec",
		Outcome:    policy.OutcomeOK,
		Argv:       []string{"go", "build", "./..."},
		Path:       "/usr/local/go/bin/go",
		WorkingDir: "/workspace",
		ExitCode:   &exit,
		DurationMS: 1234,
	}))
	require.NoError(t, log.Write(policy.Record{
		Principal: "control-plane",
		RPC:       "sandboxd.v1.FileService/WriteFile",
		Outcome:   policy.OutcomeOK,
		Path:      "/workspace/main.go",
		Bytes:     4096,
	}))
	require.NoError(t, log.Close())

	records := readRecords(t, path)
	require.Len(t, records, 2)

	require.Equal(t, "control-plane", records[0].Principal)
	require.Equal(t, []string{"go", "build", "./..."}, records[0].Argv)
	require.NotNil(t, records[0].ExitCode)
	require.Equal(t, int32(2), *records[0].ExitCode)
	require.False(t, records[0].Time.IsZero(), "every record is timestamped, whether or not the caller set one")

	// A write is audited with its resolved path and its size, never its
	// content: there is no field that could carry the bytes.
	require.Equal(t, "/workspace/main.go", records[1].Path)
	require.EqualValues(t, 4096, records[1].Bytes)
	require.Empty(t, records[1].Argv)
}

func TestAudit_DistinguishesNeverRanFromExitedZero(t *testing.T) {
	log, path := newAudit(t, nil)

	zero := int32(0)
	require.NoError(t, log.Write(policy.Record{Outcome: policy.OutcomeOK, ExitCode: &zero}))
	require.NoError(t, log.Write(policy.Record{Outcome: policy.OutcomeDenied}))
	require.NoError(t, log.Close())

	records := readRecords(t, path)
	require.Len(t, records, 2)
	require.NotNil(t, records[0].ExitCode)
	require.Equal(t, int32(0), *records[0].ExitCode)
	require.Nil(t, records[1].ExitCode, "a command that never ran has no exit code, which is not the same as exiting 0")
}

func TestAudit_DisabledDropsWrites(t *testing.T) {
	log, path := newAudit(t, func(c *policy.AuditConfig) { c.Enabled = false })

	require.False(t, log.Enabled())
	require.False(t, log.Required(), "a disabled log cannot be a required one")
	require.NoError(t, log.Write(policy.Record{Outcome: policy.OutcomeOK}))

	_, err := os.Stat(path)
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestAudit_RotatesAtTheCapAndRetainsTheConfiguredSegments(t *testing.T) {
	log, path := newAudit(t, func(c *policy.AuditConfig) {
		c.MaxBytes = 512
		c.RetainSegments = 2
	})

	for i := range 200 {
		require.NoError(t, log.Write(policy.Record{
			Principal: "control-plane",
			RPC:       "sandboxd.v1.ExecService/Exec",
			Outcome:   policy.OutcomeOK,
			Argv:      []string{"cmd", fmt.Sprintf("iteration-%03d", i)},
		}))
	}
	require.NoError(t, log.Close())

	// The live file plus exactly the retained segments, and nothing beyond.
	require.FileExists(t, path)
	require.FileExists(t, path+".1")
	require.FileExists(t, path+".2")
	require.NoFileExists(t, path+".3")

	for _, segment := range []string{path, path + ".1", path + ".2"} {
		info, err := os.Stat(segment)
		require.NoError(t, err)
		require.LessOrEqual(t, info.Size(), int64(512+256),
			"a segment may overshoot only by the one record that did not fit")
		require.NotEmpty(t, readRecords(t, segment), "every segment is still valid JSONL")
	}

	// The live file holds the newest records: rotation moves history aside,
	// it does not move the present.
	live := readRecords(t, path)
	require.Contains(t, live[len(live)-1].Argv[1], "iteration-199")
}

func TestAudit_RotationWithNoRetainedSegmentsIsAHardCeiling(t *testing.T) {
	log, path := newAudit(t, func(c *policy.AuditConfig) {
		c.MaxBytes = 256
		c.RetainSegments = 0
	})

	for i := range 50 {
		require.NoError(t, log.Write(policy.Record{Outcome: policy.OutcomeOK, Argv: []string{"cmd", fmt.Sprint(i)}}))
	}
	require.NoError(t, log.Close())

	require.NoFileExists(t, path+".1")
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.LessOrEqual(t, info.Size(), int64(512))
}

func TestAudit_ConcurrentWritesProduceWholeRecords(t *testing.T) {
	log, path := newAudit(t, func(c *policy.AuditConfig) {
		// Small enough that rotation happens repeatedly while the writers are
		// running — which is when a half-written or lost record would show up —
		// and retaining more segments than the run can fill, so that anything
		// missing at the end is a bug rather than the rotation doing its job.
		c.MaxBytes = 4096
		c.RetainSegments = 64
	})

	const writers, each = 8, 40
	var wg sync.WaitGroup
	for w := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range each {
				_ = log.Write(policy.Record{
					Principal: fmt.Sprintf("writer-%d", w),
					RPC:       "sandboxd.v1.ExecService/Exec",
					Outcome:   policy.OutcomeOK,
					Argv:      []string{"cmd", fmt.Sprintf("%d-%d", w, i)},
				})
			}
		}()
	}
	wg.Wait()
	require.NoError(t, log.Close())

	seen := 0
	for _, segment := range segments(t, path) {
		seen += len(readRecords(t, segment))
	}
	require.Equal(t, writers*each, seen, "no record was lost or interleaved into another")
}

func TestAudit_RequiredIsReportedToTheCaller(t *testing.T) {
	blocked := filepath.Join(t.TempDir(), "a-file")
	require.NoError(t, os.WriteFile(blocked, []byte("not a directory"), 0o600))

	log, _ := newAudit(t, func(c *policy.AuditConfig) {
		c.Path = filepath.Join(blocked, "audit.jsonl")
		c.Required = true
	})

	require.Error(t, log.Preflight(), "an unwritable path is visible at startup, not only at the first RPC")
	require.True(t, log.Required())
	require.Error(t, log.Write(policy.Record{Outcome: policy.OutcomeOK}),
		"the caller decides what to do with this; the log's job is to report it")
}

func TestAudit_RecoversWhenThePathBecomesWritable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "logs", "audit.jsonl")
	log := policy.NewAudit(policy.AuditConfig{Path: path, Enabled: true})
	t.Cleanup(func() { _ = log.Close() })

	// The directory does not exist yet; the log creates it rather than
	// requiring the operator to have done so.
	require.NoError(t, log.Write(policy.Record{Outcome: policy.OutcomeOK}))
	require.NoError(t, log.Close())
	require.Len(t, readRecords(t, path), 1)
}

func TestAudit_AppendsRatherThanTruncating(t *testing.T) {
	log, path := newAudit(t, nil)
	require.NoError(t, log.Write(policy.Record{Outcome: policy.OutcomeOK, Argv: []string{"first"}}))
	require.NoError(t, log.Close())

	// A second instance over the same file — a daemon restart — must not lose
	// what the first one recorded.
	again := policy.NewAudit(policy.AuditConfig{Path: path, Enabled: true})
	require.NoError(t, again.Write(policy.Record{Outcome: policy.OutcomeOK, Argv: []string{"second"}}))
	require.NoError(t, again.Close())

	records := readRecords(t, path)
	require.Len(t, records, 2)
	require.Equal(t, []string{"first"}, records[0].Argv)
	require.Equal(t, []string{"second"}, records[1].Argv)
}

func TestAudit_TimestampsAreUTCAndParseBack(t *testing.T) {
	log, path := newAudit(t, nil)
	before := time.Now().UTC().Add(-time.Second)
	require.NoError(t, log.Write(policy.Record{Outcome: policy.OutcomeOK}))
	require.NoError(t, log.Close())

	records := readRecords(t, path)
	require.Len(t, records, 1)
	require.WithinDuration(t, before, records[0].Time, time.Minute)
}

func segments(t *testing.T, path string) []string {
	t.Helper()
	matches, err := filepath.Glob(path + "*")
	require.NoError(t, err)
	return matches
}

func readRecords(t *testing.T, path string) []policy.Record {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)

	var out []policy.Record
	for i, line := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		if line == "" {
			continue
		}
		var rec policy.Record
		require.NoErrorf(t, json.Unmarshal([]byte(line), &rec), "%s line %d is not valid JSON: %s", path, i+1, line)
		out = append(out, rec)
	}
	return out
}
