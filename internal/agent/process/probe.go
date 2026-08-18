package process

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"time"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
)

// Readiness probing exists because "spawned" is not "usable". A dev server can
// take ten seconds to bind its port; an agent that curls it one second later
// gets a connection refused and concludes the server is broken.
//
// The rules that matter, and the reasons:
//
//   - A probe that times out is not a failure of the process. It is left
//     RUNNING and the caller is told why, because killing it would throw away
//     the logs that explain the slow start — which are the only thing that can
//     diagnose it.
//   - A process that exits during probing fails immediately, and the error says
//     it exited. "Timed out after 30s" sends the reader looking for a slow
//     start; "exited with code 1 after 200ms" sends them to the log.
//   - log_pattern observes the log stream without draining it. The matcher is
//     an ordinary subscriber on the same buffer a follower uses, so the lines
//     it reads stay readable by everyone else.
//   - HTTP probes carry their own short timeout. Without one, a hung connect
//     turns a 30-second readiness budget into an indefinite one, and the
//     StartProcess call the model is waiting on never returns.

// probeIntervalFloor is the retry interval a probe falls back to when the one
// it was handed is not a positive duration.
//
// It matches the agent's own default (supervisorConfig.probeInterval), because
// the case it covers is a probe whose interval was never chosen by anybody: a
// record hand-edited or corrupted into naming no interval at all.
const probeIntervalFloor = 250 * time.Millisecond

type probeKind int

const (
	probeNone probeKind = iota
	probeLogPattern
	probeTCPPort
	probeHTTPGet
	probeUptime
)

func (k probeKind) String() string {
	switch k {
	case probeLogPattern:
		return "log_pattern"
	case probeTCPPort:
		return "tcp_port"
	case probeHTTPGet:
		return "http_get_url"
	case probeUptime:
		return "uptime"
	case probeNone:
		return "none"
	default:
		return "unknown"
	}
}

// probeSpec is a resolved ReadyProbe: defaults applied, pattern compiled.
type probeSpec struct {
	kind       probeKind
	pattern    *regexp.Regexp
	patternSrc string
	port       uint32
	url        string
	uptime     time.Duration
	timeout    time.Duration
	interval   time.Duration
}

// describe names the probe in an error a caller reads.
func (p *probeSpec) describe() string {
	switch p.kind {
	case probeLogPattern:
		return fmt.Sprintf("log_pattern %q", p.patternSrc)
	case probeTCPPort:
		return "tcp_port " + strconv.FormatUint(uint64(p.port), 10)
	case probeHTTPGet:
		return "http_get_url " + p.url
	case probeUptime:
		return "uptime " + p.uptime.String()
	case probeNone:
		return "none"
	default:
		return "unknown"
	}
}

// probeFromProto resolves a wire ReadyProbe against the agent's defaults. It
// returns nil when no probe was configured, which is the "spawned means
// running" path.
func probeFromProto(p *sandboxdv1.ReadyProbe, defTimeout, defInterval time.Duration) (*probeSpec, error) {
	if p == nil || p.GetProbe() == nil {
		return nil, nil
	}
	spec := &probeSpec{
		timeout:  p.GetTimeout().AsDuration(),
		interval: p.GetInterval().AsDuration(),
	}
	switch probe := p.GetProbe().(type) {
	case *sandboxdv1.ReadyProbe_LogPattern:
		re, err := regexp.Compile(probe.LogPattern)
		if err != nil {
			return nil, fmt.Errorf("ready_probe.log_pattern %q is not a valid RE2 pattern: %w", probe.LogPattern, err)
		}
		spec.kind, spec.pattern, spec.patternSrc = probeLogPattern, re, probe.LogPattern
	case *sandboxdv1.ReadyProbe_TcpPort:
		if probe.TcpPort == 0 || probe.TcpPort > 65535 {
			return nil, fmt.Errorf("ready_probe.tcp_port %d is not a TCP port", probe.TcpPort)
		}
		spec.kind, spec.port = probeTCPPort, probe.TcpPort
	case *sandboxdv1.ReadyProbe_HttpGetUrl:
		if probe.HttpGetUrl == "" {
			return nil, fmt.Errorf("ready_probe.http_get_url is empty")
		}
		spec.kind, spec.url = probeHTTPGet, probe.HttpGetUrl
	case *sandboxdv1.ReadyProbe_Uptime:
		spec.kind, spec.uptime = probeUptime, probe.Uptime.AsDuration()
		if spec.uptime <= 0 {
			return nil, fmt.Errorf("ready_probe.uptime must be positive")
		}
	default:
		return nil, fmt.Errorf("ready_probe has no recognised probe set")
	}

	if spec.interval <= 0 {
		spec.interval = defInterval
	}
	if spec.timeout <= 0 {
		spec.timeout = defTimeout
		// An uptime probe whose timeout is shorter than the uptime it waits for
		// can never pass. The caller who wrote `uptime: 60s` and left the
		// timeout unset plainly meant "wait a minute", not "fail after thirty
		// seconds", so the default stretches to fit rather than contradicting
		// the only field they set.
		if spec.kind == probeUptime && spec.timeout <= spec.uptime {
			spec.timeout = spec.uptime + defTimeout
		}
	}
	return spec, nil
}

// persisted flattens the probe for the record on disk. A nil probe persists as
// nothing, which is how a re-adopted record knows it had none.
func (p *probeSpec) persisted() *persistedProbe {
	if p == nil {
		return nil
	}
	return &persistedProbe{
		Kind:       p.kind.String(),
		Pattern:    p.patternSrc,
		Port:       p.port,
		URL:        p.url,
		UptimeMS:   p.uptime.Milliseconds(),
		TimeoutMS:  p.timeout.Milliseconds(),
		IntervalMS: p.interval.Milliseconds(),
	}
}

// probeFromPersisted rebuilds a probe read off disk. A pattern that no longer
// compiles — it cannot, unless the record was hand-edited — drops the probe
// rather than failing the whole re-adoption.
//
// The defaults are applied to the timings for the same reason probeFromProto
// applies them: a probe runs a ticker, and a ticker of zero panics. A record
// that names a probe but no interval cannot be written by this agent, so it
// arrives only from an edit or a corruption — and re-adoption is now the path
// that runs it, on startup, on a goroutine whose panic takes the daemon with
// it. An agent that dies while re-adopting comes back and re-adopts the same
// record, so the failure mode is not one crash but a crash loop nothing on the
// host can break. A number the operator did not choose is a far better answer
// than that.
func probeFromPersisted(p *persistedProbe, defTimeout, defInterval time.Duration) *probeSpec {
	if p == nil {
		return nil
	}
	spec := &probeSpec{
		port:       p.Port,
		url:        p.URL,
		patternSrc: p.Pattern,
		uptime:     time.Duration(p.UptimeMS) * time.Millisecond,
		timeout:    time.Duration(p.TimeoutMS) * time.Millisecond,
		interval:   time.Duration(p.IntervalMS) * time.Millisecond,
	}
	if spec.interval <= 0 {
		spec.interval = defInterval
	}
	if spec.timeout <= 0 {
		spec.timeout = defTimeout
	}
	switch p.Kind {
	case "log_pattern":
		re, err := regexp.Compile(p.Pattern)
		if err != nil {
			return nil
		}
		spec.kind, spec.pattern = probeLogPattern, re
	case "tcp_port":
		spec.kind = probeTCPPort
	case "http_get_url":
		spec.kind = probeHTTPGet
	case "uptime":
		spec.kind = probeUptime
	default:
		return nil
	}
	return spec
}

// probeExitError reports that the process died before its probe could pass.
// The wording is load-bearing: it is what tells a reader to open the log rather
// than to raise the timeout.
type probeExitError struct {
	state    sandboxdv1.ProcessState
	exitCode int32
	signal   string
	elapsed  time.Duration
}

func (e *probeExitError) Error() string {
	switch {
	case e.signal != "":
		return fmt.Sprintf("process exited on SIG%s after %s, before its readiness probe passed",
			e.signal, e.elapsed.Round(time.Millisecond))
	default:
		return fmt.Sprintf("process exited with code %d after %s, before its readiness probe passed",
			e.exitCode, e.elapsed.Round(time.Millisecond))
	}
}

// probeTimeoutError reports that the probe did not pass in time. The process is
// still running; saying so is the difference between the caller reading the log
// and the caller concluding the process is gone.
type probeTimeoutError struct {
	probe   string
	timeout time.Duration
}

func (e *probeTimeoutError) Error() string {
	return fmt.Sprintf("readiness probe (%s) did not pass within %s; the process is still running and its logs are readable",
		e.probe, e.timeout)
}

// run blocks until the probe passes, the process exits, the timeout elapses, or
// ctx is cancelled.
//
// fromSeq is the log sequence at which the run being probed begins. Everything
// below it belongs to some earlier run of the same process and is not evidence
// about this one; see the pre-scan below and record.runFirstSeq.
//
// ctx here is the caller's, not the supervisor's: a StartProcess whose client
// disconnects stops waiting. It never stops the process, and the probe keeps
// running on the supervisor's own goroutine — see supervisor.superviseProbe.
func (p *probeSpec) run(ctx context.Context, r *record, fromSeq uint64, httpTimeout, dialTimeout time.Duration) error {
	started := time.Now()

	// The subscription is taken before the first attempt, and it carries the
	// lines already buffered. Subscribing after reading the buffer would leave
	// a gap exactly wide enough to miss the "listening on :3000" that a fast
	// process prints before the probe is set up.
	//
	// The pre-scan is bounded to this run because the buffer is not. A restart
	// keeps the process's whole log history — that is what makes the output of
	// the run that died readable afterwards — so an unbounded pre-scan matches
	// the *previous* run's announcement and reports READY before the new run
	// has printed a byte (#57). Under restart_policy: always that made
	// readiness a latch: once satisfied, satisfied for every automatic restart
	// of a service that was crash-looping.
	//
	// Only the pre-scan needs the bound. Everything arriving on the
	// subscription was appended after the snapshot, which is after the mark,
	// so it is this run's by construction.
	var subCh <-chan delivery
	if p.kind == probeLogPattern {
		existing, sub := r.buf.snapshot()
		defer r.buf.unsubscribe(sub)
		for _, line := range existing {
			if line.Seq < fromSeq {
				continue
			}
			if p.matches(line) {
				return nil
			}
		}
		subCh = sub.ch
	}

	timeout := time.NewTimer(p.timeout)
	defer timeout.Stop()
	// The floor is applied here, at the one call that panics on a bad value,
	// rather than only where the value is chosen. Both constructors already
	// refuse a non-positive interval — probeFromProto for a request, and
	// probeFromPersisted for a record read off disk — so this is unreachable
	// from either, and that is exactly why it is here: this goroutine runs on
	// the startup path for every re-adopted process, and a panic on it takes
	// the daemon down, after which the service manager restarts it, it re-reads
	// the same record and it goes down again. Every other consequence of a bad
	// interval is recoverable by an operator; this one is not.
	interval := p.interval
	if interval <= 0 {
		interval = probeIntervalFloor
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		changed, state := r.wait()
		if isTerminal(state) {
			return r.probeExit(started)
		}

		if p.kind != probeLogPattern && p.attempt(ctx, r, httpTimeout, dialTimeout) {
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timeout.C:
			// One last look at the process before blaming the clock: a process
			// that died in the final interval should be reported as dead.
			if isTerminal(r.currentState()) {
				return r.probeExit(started)
			}
			return &probeTimeoutError{probe: p.describe(), timeout: p.timeout}
		case d, ok := <-subCh:
			if !ok {
				// The buffer closed: the record is being removed.
				return fmt.Errorf("readiness probe (%s) stopped: the process record was removed", p.describe())
			}
			if p.matches(d.line) {
				return nil
			}
		case <-ticker.C:
		case <-changed:
		}
	}
}

// matches reports whether a captured line is the announcement the probe is
// waiting for.
//
// Only what the process itself said counts. The supervisor writes its own
// decisions into the same log — restarts, backoff, giving up — tagged as
// neither stdout nor stderr, and log_pattern is documented as matching a line
// on stdout or stderr. Left in, they are not merely off-contract: the note the
// supervisor writes when a probe gives up quotes the pattern that gave up, so a
// probe resumed on that process afterwards would find its own failure in the
// history and read it as success.
func (p *probeSpec) matches(line logLine) bool {
	if line.Stream == sandboxdv1.Stream_STREAM_UNSPECIFIED {
		return false
	}
	return p.pattern.MatchString(line.Text)
}

// probeExit builds the error for a process that died mid-probe.
func (r *record) probeExit(started time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return &probeExitError{
		state:    r.state,
		exitCode: r.exitCode,
		signal:   r.signalName,
		elapsed:  time.Since(started),
	}
}

// attempt performs one non-log probe. It reports readiness, never failure: a
// refused connection this second says nothing about the next one.
func (p *probeSpec) attempt(ctx context.Context, r *record, httpTimeout, dialTimeout time.Duration) bool {
	switch p.kind {
	case probeTCPPort:
		return dialLoopback(ctx, p.port, dialTimeout)
	case probeHTTPGet:
		return httpReady(ctx, p.url, httpTimeout)
	case probeUptime:
		r.mu.Lock()
		startedAt := r.startedAt
		r.mu.Unlock()
		return !startedAt.IsZero() && time.Since(startedAt) >= p.uptime
	case probeNone, probeLogPattern:
		return false
	default:
		return false
	}
}

// dialLoopback reports whether anything is accepting on the port.
//
// Both loopback addresses are tried, because a server bound to ::1 and one
// bound to 127.0.0.1 are equally ready and a probe that only knows about one of
// them fails on half the dev servers in existence.
func dialLoopback(ctx context.Context, port uint32, timeout time.Duration) bool {
	dialer := net.Dialer{Timeout: timeout}
	for _, host := range []string{"127.0.0.1", "::1"} {
		addr := net.JoinHostPort(host, strconv.FormatUint(uint64(port), 10))
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err == nil {
			_ = conn.Close()
			return true
		}
	}
	return false
}

// httpReady reports whether a GET of url comes back below 500.
//
// 404 is ready and 500 is not, which looks backwards for exactly one second:
// the question is whether the server is up, and a 404 is a server answering.
// A 500 is the one status that says the process is running but not yet able to
// serve — a framework still compiling, a connection pool not yet open.
func httpReady(ctx context.Context, url string, timeout time.Duration) bool {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false
	}
	// A client of its own, with its own timeout. http.DefaultClient has none,
	// and a probe that inherits "no timeout" is how a thirty-second readiness
	// budget becomes an indefinite hang on a connect that never completes.
	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	// Drain so the connection can be reused rather than reset on the server,
	// which otherwise shows up in the process's own log as a client error on
	// every probe interval.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	return resp.StatusCode < http.StatusInternalServerError
}
