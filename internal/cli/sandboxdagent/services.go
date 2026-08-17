package sandboxdagent

// Every gRPC service the daemon hosts is linked in here, and only here.
//
// A service package registers itself from an init function (see
// agent.Register), so joining the daemon takes exactly one line in this file
// and no change to any wiring function. That is deliberate: the M1 services
// are being built in parallel, and a shared switch statement or slice literal
// would make every one of them conflict with every other.
//
// Adding a service is one blank-import line, tagged with the issue it
// implements:
//
//	_ "github.com/axelmierczuk/fleet-mcp/internal/agent/<package>" // #<issue>, <Service>

import (
	_ "github.com/axelmierczuk/fleet-mcp/internal/agent/exec"    // #7, ExecService
	_ "github.com/axelmierczuk/fleet-mcp/internal/agent/forward" // #26, ForwardService
	_ "github.com/axelmierczuk/fleet-mcp/internal/agent/fs"      // #8–#10, FileService
	_ "github.com/axelmierczuk/fleet-mcp/internal/agent/host"    // #5, HostService
	_ "github.com/axelmierczuk/fleet-mcp/internal/agent/process" // #11–#15, ProcessService
)
