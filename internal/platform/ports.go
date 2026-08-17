package platform

import "slices"

// ListeningPorts returns the TCP ports pid has in the listening state.
//
// It is best effort, and feeds ProcessStatus.listening_ports — a hint that
// tells the model where the dev server it just started can be reached. A
// caller must not treat an empty result as proof that nothing is listening: on
// macOS the read shells out to lsof and returns nothing when lsof is absent,
// and on every platform a socket opened a millisecond after the read is
// invisible to it.
//
// The result covers pid alone, not its descendants. Supervised commands are
// frequently wrappers — `npm run dev` binds nothing and its child binds
// everything — so a supervisor that wants the useful answer should ask about
// the processes in the group, not only the leader.
//
// Ports are returned sorted and deduplicated.
func ListeningPorts(pid int) ([]uint32, error) {
	ports, err := listeningPorts(pid)
	if err != nil {
		return nil, err
	}
	slices.Sort(ports)
	return slices.Compact(ports), nil
}
