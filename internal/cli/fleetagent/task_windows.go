package fleetagent

// newScheduledTask builds the registration `install` writes on Windows. See
// scheduledTask in task.go for the mechanism and for why the type itself is
// not build-tagged.
func newScheduledTask(params UnitParams) (registration, error) {
	return &scheduledTask{params: params}, nil
}

// scheduledTaskInstalled reports whether a task is registered under the agent's
// name, for the host lookup that has no scheduledTask to ask. The query itself
// is scheduledTask.installed, so the argv is the one every runner asserts.
func scheduledTaskInstalled() bool {
	return (&scheduledTask{}).installed()
}
