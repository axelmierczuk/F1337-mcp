package fleetagent

// newScheduledTask builds the registration `install` writes on Windows. See
// scheduledTask in task.go for the mechanism and for why the type itself is
// not build-tagged.
func newScheduledTask(params UnitParams) (registration, error) {
	return &scheduledTask{params: params}, nil
}

// scheduledTaskInstalled reports whether a task is registered under the agent's
// name.
//
// /XML is asked for rather than a formatted listing because the answer wanted
// here is the exit code, and asking for the definition makes that exit code
// mean "the task exists" on every locale.
func scheduledTaskInstalled() bool {
	return runSchtasks("/Query", "/TN", ServiceName, "/XML", "ONE") == nil
}
