// Package process implements ProcessService: the supervisor for long-running
// background processes.
//
// Supervised processes are owned by the agent and outlive the MCP session that
// started them. The supervisor is responsible for process groups and job
// objects, readiness probing, bounded log buffering, restart policy, and
// re-adopting surviving children after an agent restart.
//
// Implemented by milestone M1.
package process
