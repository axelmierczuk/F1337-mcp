package mcpserver_test

import (
	"context"
	"io"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"

	sandboxdv1 "github.com/axelmierczuk/sandboxd-mcp/gen/go/sandboxd/v1"
)

// Minimal ProcessService and ForwardService clients for the fleet-wide walks
// in selection_test.go.
//
// Those tests call every registered tool with synthesised arguments and assert
// on the echo, so they need every tool to reach its handler and come back with
// something. They are not testing what the process or forward tools do — the
// tests that are stand up the real agent services over bufconn, in
// procfwd_harness_test.go — so these answer the shape of each RPC and nothing
// more.

// fakeProcess answers the six ProcessService RPCs with one canned process.
type fakeProcess struct{}

func fakeStatus() *sandboxdv1.ProcessStatus {
	return &sandboxdv1.ProcessStatus{
		ProcessId:     "proc-1",
		Name:          "placeholder",
		Argv:          []string{"placeholder"},
		State:         sandboxdv1.ProcessState_PROCESS_STATE_RUNNING,
		Pid:           4211,
		StartedAt:     timestamppb.Now(),
		RestartPolicy: sandboxdv1.RestartPolicy_RESTART_POLICY_NEVER,
		LastLogLine:   "listening on 127.0.0.1:3000",
	}
}

func (fakeProcess) StartProcess(context.Context, *sandboxdv1.StartProcessRequest, ...grpc.CallOption) (*sandboxdv1.StartProcessResponse, error) {
	return &sandboxdv1.StartProcessResponse{Status: fakeStatus()}, nil
}

func (fakeProcess) ListProcesses(context.Context, *sandboxdv1.ListProcessesRequest, ...grpc.CallOption) (*sandboxdv1.ListProcessesResponse, error) {
	return &sandboxdv1.ListProcessesResponse{Processes: []*sandboxdv1.ProcessStatus{fakeStatus()}}, nil
}

func (fakeProcess) SignalProcess(context.Context, *sandboxdv1.SignalProcessRequest, ...grpc.CallOption) (*sandboxdv1.SignalProcessResponse, error) {
	return &sandboxdv1.SignalProcessResponse{Status: fakeStatus()}, nil
}

func (fakeProcess) RestartProcess(context.Context, *sandboxdv1.RestartProcessRequest, ...grpc.CallOption) (*sandboxdv1.RestartProcessResponse, error) {
	return &sandboxdv1.RestartProcessResponse{Status: fakeStatus()}, nil
}

func (fakeProcess) RemoveProcess(_ context.Context, req *sandboxdv1.RemoveProcessRequest, _ ...grpc.CallOption) (*sandboxdv1.RemoveProcessResponse, error) {
	return &sandboxdv1.RemoveProcessResponse{ProcessId: req.GetProcessId()}, nil
}

func (fakeProcess) GetProcessLogs(_ context.Context, _ *sandboxdv1.GetProcessLogsRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[sandboxdv1.GetProcessLogsResponse], error) {
	return &fakeLogStream{responses: []*sandboxdv1.GetProcessLogsResponse{
		{Event: &sandboxdv1.GetProcessLogsResponse_Line{Line: &sandboxdv1.LogLine{
			Stream: sandboxdv1.Stream_STREAM_STDOUT, Text: "a log line", Timestamp: timestamppb.Now(),
		}}},
		{Event: &sandboxdv1.GetProcessLogsResponse_Summary{Summary: &sandboxdv1.LogSummary{
			LinesReturned: 1, State: sandboxdv1.ProcessState_PROCESS_STATE_RUNNING,
		}}},
	}}, nil
}

// fakeLogStream replays a fixed sequence and then ends.
type fakeLogStream struct {
	grpc.ClientStream
	responses []*sandboxdv1.GetProcessLogsResponse
	next      int
}

func (s *fakeLogStream) Recv() (*sandboxdv1.GetProcessLogsResponse, error) {
	if s.next >= len(s.responses) {
		return nil, io.EOF
	}
	resp := s.responses[s.next]
	s.next++
	return resp, nil
}

// fakeForward accepts an open and reports success, which is all the preflight
// in sandbox_forward asks of it.
type fakeForward struct{}

func (fakeForward) Forward(context.Context, ...grpc.CallOption) (grpc.BidiStreamingClient[sandboxdv1.ForwardRequest, sandboxdv1.ForwardResponse], error) {
	return &fakeForwardStream{}, nil
}

type fakeForwardStream struct {
	grpc.ClientStream

	mu     sync.Mutex
	opened bool
	done   bool
}

func (s *fakeForwardStream) Send(req *sandboxdv1.ForwardRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if req.GetOpen() != nil {
		s.opened = true
	}
	return nil
}

func (s *fakeForwardStream) Recv() (*sandboxdv1.ForwardResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case !s.opened:
		return nil, io.EOF
	case s.done:
		return nil, io.EOF
	}
	s.done = true
	return &sandboxdv1.ForwardResponse{
		Event: &sandboxdv1.ForwardResponse_Opened{Opened: &sandboxdv1.ForwardOpened{
			Success: true, LocalAddress: "127.0.0.1:54321",
		}},
	}, nil
}

func (s *fakeForwardStream) CloseSend() error { return nil }
