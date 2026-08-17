package tools

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/fleet-mcp/internal/mcpserver/selection"
)

// Bounds sandbox_exec applies to its own side of the call.
const (
	// DefaultExecOutputBytes is the combined stdout and stderr the tool asks
	// for when the caller names no max_output_bytes.
	//
	// It is well under the agent's own 2 MiB ceiling on purpose. Every byte
	// here lands in the model's context, and a 2 MiB build log costs more than
	// the answer it contains is worth — where a capped one costs 128 KiB and
	// says, in the result, exactly how much was dropped and which argument
	// raises it.
	DefaultExecOutputBytes = 128 * 1024

	// maxExecBufferBytes is the hard ceiling on what one exec result may hold
	// in this process, whatever max_output_bytes was set to.
	//
	// The agent clamps output to its own configured maximum, so in the
	// ordinary case this never bites. It exists for the case where it would:
	// an agent that is misconfigured, older, or simply not the one this server
	// believes it is talking to must not be able to size this process's heap
	// by streaming at it.
	maxExecBufferBytes = 8 * 1024 * 1024

	// DefaultExecTimeout is the wall-clock limit applied when the caller names
	// none. It matches the agent's own documented default so that the limit
	// named in a timeout report is the limit that actually bit.
	DefaultExecTimeout = 120 * time.Second

	// maxExecTimeoutSeconds bounds what timeout_seconds may ask for.
	//
	// The agent has its own maximum and refuses anything above it, naming the
	// number — which is the check that matters, and this one does not try to
	// second-guess it. This exists because the deadline below is 2×timeout, and
	// time.Duration is nanoseconds in an int64: past roughly 146 years the
	// multiplication wraps negative, the context is born expired, and the model
	// is told its call "timed out — raise timeout_seconds", which is the one
	// thing that would make it worse. A week is far under that and far over
	// anything a command held open on one RPC should ask for.
	maxExecTimeoutSeconds = 7 * 24 * 60 * 60

	// execCallGrace is the slack added to the RPC deadline over the command's
	// own timeout.
	//
	// The deadline has to sit above the timeout rather than at it, or a
	// command killed on schedule loses the race to report that it was: the
	// agent needs time to signal the group, wait out the grace period, kill
	// it, and send the result. On a saturated agent the timeout also bounds
	// the wait for a process slot *before* it bounds the command, so a queued
	// call can legitimately take twice it — hence the doubling below.
	execCallGrace = 30 * time.Second
)

// registerExec adds sandbox_exec.
func registerExec(r *Registrar) {
	AddTargeted(r, &mcp.Tool{
		Name:  "sandbox_exec",
		Title: "Run a command",
		Description: "Run a command to completion on the selected sandbox and return its exit code, stdout and stderr. " +
			"argv is passed to the OS directly and is not shell-parsed unless shell is set. " +
			"A non-zero exit is a normal result carrying the output, not an error. " +
			"The call is held open until the command exits, so use sandbox_process_start for anything meant to keep running: " +
			"a dev server started here holds the stream until it times out.",
	}, r.sandboxExec)
}

// ExecArgs are the arguments to sandbox_exec.
type ExecArgs struct {
	TargetArgs
	// Argv is the executable and its arguments.
	Argv []string `json:"argv" jsonschema:"executable and arguments, e.g. [\"go\",\"test\",\"./...\"]; argv[0] is looked up in PATH and never in the working directory"`
	// WorkingDir is where the command runs.
	WorkingDir string `json:"working_dir,omitempty" jsonschema:"absolute directory on the sandbox to run in; defaults to the agent account's home directory"`
	// Env are KEY=VALUE entries applied over the agent's base environment.
	Env []string `json:"env,omitempty" jsonschema:"environment entries as KEY=VALUE, applied over the agent's base environment"`
	// TimeoutSeconds bounds the command.
	TimeoutSeconds int `json:"timeout_seconds,omitempty" jsonschema:"wall-clock limit; the process group is killed on expiry. Defaults to 120. Above the agent's maximum the call is refused"`
	// MaxOutputBytes bounds the combined output returned.
	MaxOutputBytes int64 `json:"max_output_bytes,omitempty" jsonschema:"combined stdout+stderr to return before truncating; defaults to 131072 and is clamped to the agent's own maximum"`
	// Shell runs the command through the platform shell.
	Shell bool `json:"shell,omitempty" jsonschema:"run through the platform shell (sh -c, or cmd /c on Windows) instead of exec'ing argv directly"`
	// Stdin is written to the process and the stream then closed.
	Stdin string `json:"stdin,omitempty" jsonschema:"written to the command's stdin, which is then closed"`
}

// ExecResult is the sandbox_exec result.
//
// The exit code leads, before either output stream, because it is the one
// field that decides what the rest of the result means — and a model reads the
// front of a result before it reads a screenful of build log. stdout and
// stderr stay separate fields rather than one interleaved transcript for the
// same reason: a compiler writes its diagnosis to one and its progress to the
// other, and merging them makes the model hunt for the sentence that matters.
type ExecResult struct {
	// Echo carries the sandbox that ran the command.
	Echo
	// ExitCode is the process's exit status. Meaningful unless Signal or
	// TimedOut is set.
	ExitCode int32 `json:"exit_code" jsonschema:"the command's exit status; 0 is success"`
	// Stdout is standard output, up to the cap.
	Stdout string `json:"stdout,omitempty" jsonschema:"standard output"`
	// Stderr is standard error, up to the cap.
	Stderr string `json:"stderr,omitempty" jsonschema:"standard error, kept separate from stdout"`
	// DurationMs is how long the command ran.
	DurationMs int64 `json:"duration_ms" jsonschema:"wall-clock milliseconds the command ran for"`
	// TimedOut reports that the agent killed the command for overrunning.
	TimedOut bool `json:"timed_out,omitempty" jsonschema:"true when the command was killed for exceeding its timeout"`
	// Signal names the signal that terminated the command, when one did.
	Signal string `json:"signal,omitempty" jsonschema:"signal that terminated the command, when it was signalled rather than exited"`
	// Truncation is present only when output was cut.
	Truncation *Truncation `json:"truncation,omitempty" jsonschema:"present only when output was cut short"`
	// Note states anything the fields alone would leave the model to infer.
	Note string `json:"note,omitempty" jsonschema:"what the result means when the numbers alone do not say it"`
}

func (r *Registrar) sandboxExec(ctx context.Context, _ *mcp.CallToolRequest, target *selection.Target, in ExecArgs) (ExecResult, error) {
	if len(in.Argv) == 0 || strings.TrimSpace(in.Argv[0]) == "" {
		return ExecResult{}, errors.New(`argv is required and argv[0] must name the executable, e.g. argv=["go","test","./..."]`)
	}
	if in.TimeoutSeconds < 0 {
		return ExecResult{}, fmt.Errorf("timeout_seconds is %d; it must not be negative", in.TimeoutSeconds)
	}
	if in.TimeoutSeconds > maxExecTimeoutSeconds {
		return ExecResult{}, fmt.Errorf(
			"timeout_seconds is %d, which is over the %d this tool will hold one call open for. Exec holds the RPC for the lifetime of the command; use sandbox_process_start for work meant to outlive a call",
			in.TimeoutSeconds, maxExecTimeoutSeconds)
	}
	if in.MaxOutputBytes < 0 {
		return ExecResult{}, fmt.Errorf("max_output_bytes is %d; it must not be negative", in.MaxOutputBytes)
	}

	execClient, err := r.deps.Clients.Exec(target.Name(), target.Address())
	if err != nil {
		return ExecResult{}, target.Call().Map(err)
	}

	timeout := DefaultExecTimeout
	if in.TimeoutSeconds > 0 {
		timeout = time.Duration(in.TimeoutSeconds) * time.Second
	}
	outputCap := int64(DefaultExecOutputBytes)
	if in.MaxOutputBytes > 0 {
		outputCap = in.MaxOutputBytes
	}

	// The deadline bounds the agent, not the command: the command has its own
	// timeout and the agent enforces it. This is what stops a *hung* agent —
	// one that accepted the request and then stopped answering — from holding
	// the tool call open forever.
	deadline := 2*timeout + execCallGrace
	callCtx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()

	stream, err := execClient.Exec(callCtx, &sandboxdv1.ExecRequest{
		Argv:           in.Argv,
		WorkingDir:     in.WorkingDir,
		Env:            in.Env,
		Timeout:        durationpb.New(timeout),
		MaxOutputBytes: uint64(outputCap), //nolint:gosec // checked non-negative above
		Shell:          in.Shell,
		Stdin:          []byte(in.Stdin),
	})
	if err != nil {
		return ExecResult{}, r.execError(target, in, deadline, err)
	}

	// Each stream gets the whole cap rather than half of it. Splitting the
	// budget would silently drop the tail of a command that wrote everything
	// to stderr while half the allowance sat unused on the other stream.
	bufferCap := int(min(outputCap, maxExecBufferBytes))
	stdout, stderr := newBoundedBuffer(bufferCap), newBoundedBuffer(bufferCap)

	var result *sandboxdv1.ExecResult
	for {
		msg, recvErr := stream.Recv()
		if errors.Is(recvErr, io.EOF) {
			break
		}
		if recvErr != nil {
			return ExecResult{}, r.execError(target, in, deadline, recvErr)
		}
		switch event := msg.GetEvent().(type) {
		case *sandboxdv1.ExecResponse_Output:
			// Counted and discarded past the cap rather than stopping the
			// read: a consumer that stops calling Recv stalls the agent's
			// Send, and the agent then kills the command and ends the call
			// with Aborted — throwing away the result of a command that has
			// already done its work.
			sink := stdout
			if event.Output.GetStream() == sandboxdv1.Stream_STREAM_STDERR {
				sink = stderr
			}
			_, _ = sink.Write(event.Output.GetData())
		case *sandboxdv1.ExecResponse_Result:
			result = event.Result
		}
	}

	if result == nil {
		// The stream is zero or more chunks then exactly one result, so this
		// is either an agent that ended the call without one or a stream that
		// was cut. Either way the command's fate is unknown, which is not
		// something to report as an exit status.
		return ExecResult{}, fmt.Errorf(
			"sandbox %s closed the output stream without reporting a result, so whether the command finished is unknown. It may well have run; check with sandbox_exec before retrying anything that is not safe to repeat",
			target.Name())
	}

	return renderExecResult(result, in, timeout, outputCap, int64(bufferCap), stdout, stderr), nil
}

// renderExecResult turns the terminal ExecResult and the two collected streams
// into what the model reads.
func renderExecResult(result *sandboxdv1.ExecResult, in ExecArgs, timeout time.Duration, outputCap, bufferCap int64, stdout, stderr *boundedBuffer) ExecResult {
	out := ExecResult{
		ExitCode:   result.GetExitCode(),
		Stdout:     stdout.String(),
		Stderr:     stderr.String(),
		DurationMs: result.GetDuration().AsDuration().Milliseconds(),
		TimedOut:   result.GetTimedOut(),
		Signal:     result.GetSignal(),
	}

	// The note names the cap that actually bit. Above maxExecBufferBytes the
	// caller's max_output_bytes is not the binding limit any more, and telling
	// a model to raise the argument it already raised sends it round the same
	// loop with a bigger number.
	capNote := fmt.Sprintf("Output was capped at %d bytes; raise max_output_bytes (the agent clamps it to its own maximum) or narrow the command.", outputCap)
	if outputCap > bufferCap {
		capNote = fmt.Sprintf("Output was capped at %d bytes, which is this server's own ceiling on one exec result: max_output_bytes was %d and raising it further will not lift this. Narrow the command, or redirect the output to a file on the sandbox and read it in windows.",
			bufferCap, outputCap)
	}
	out.Truncation = truncationFrom(result.GetTruncation(), capNote).
		merge(stdout.truncation(capNote)).
		merge(stderr.truncation(capNote))

	var note notes
	switch {
	case result.GetTimedOut():
		limit := "timeout_seconds"
		if in.TimeoutSeconds <= 0 {
			limit = "the default timeout_seconds"
		}
		note.add("Timed out after %s (%s) and the process group was killed. Raise timeout_seconds, or use sandbox_process_start for work meant to outlive the call.",
			timeout, limit)
	case result.GetSignaled():
		note.add("Terminated by %s rather than exiting, so exit_code is not meaningful.", signalName(result.GetSignal()))
	}
	if stdout.Len() == 0 && stderr.Len() == 0 && out.Truncation == nil {
		// Said out loud, because an empty result reads exactly like a hung
		// call — and the model's next move differs completely between the two.
		note.add("The command produced no output on either stream.")
	}
	if result.GetExitCode() != 0 && !result.GetTimedOut() && !result.GetSignaled() {
		note.add("Exit %d: the command ran and failed. This is the command's own failure, not a failure to reach the sandbox.", result.GetExitCode())
	}
	out.Note = note.String()
	return out
}

// signalName renders the signal that killed a command, for platforms and
// cases where the agent could not name one.
func signalName(signal string) string {
	if signal == "" {
		return "a signal"
	}
	return signal
}

// execError phrases a failed Exec RPC.
//
// Two of the agent's error codes arrive *after* the command has done its work
// — Internal when audit.required could not write the record, and Aborted when
// the agent gave up delivering to a caller that stopped reading — so a blanket
// "the request was rejected" would send the model to retry something that ran.
// Both are called out by name rather than folded into the central mapping,
// which is right about every other code and cannot know this one thing.
func (r *Registrar) execError(target *selection.Target, in ExecArgs, deadline time.Duration, err error) error {
	call := target.Call()
	call.Subject = "command " + firstArg(in.Argv)
	call.Timeout, call.Limit = deadline, "timeout_seconds"

	switch status.Code(err) {
	case codes.Aborted, codes.Internal:
		return fmt.Errorf("%w. This error arrives after the command has already run, so treat it as \"this may well have run\" rather than \"nothing happened\"", call.Map(err))
	default:
		return call.Map(err)
	}
}

// firstArg names the command an error is about.
func firstArg(argv []string) string {
	if len(argv) == 0 {
		return "(none)"
	}
	return argv[0]
}
