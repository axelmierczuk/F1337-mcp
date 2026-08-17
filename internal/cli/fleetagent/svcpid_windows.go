package fleetagent

import (
	"golang.org/x/sys/windows/svc/mgr"
)

// servicePID queries the SCM for the service's process ID.
func servicePID() (int, bool) {
	m, err := mgr.Connect()
	if err != nil {
		return 0, false
	}
	defer func() { _ = m.Disconnect() }()

	s, err := m.OpenService(ServiceName)
	if err != nil {
		return 0, false
	}
	defer func() { _ = s.Close() }()

	status, err := s.Query()
	if err != nil || status.ProcessId == 0 {
		return 0, false
	}
	return int(status.ProcessId), true
}
