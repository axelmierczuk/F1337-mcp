package host

// probePassthrough names the variables a Windows process cannot reliably start
// without.
//
// A bare PATH is enough on Unix and is not on Windows: SystemRoot is where the
// loader finds the system DLLs, and a child launched without it fails to
// initialise — winsock in particular — before it ever reads its own arguments.
// Dropping it would not have made the probe safer, only made every toolchain on
// every Windows host report as present-but-unversioned.
//
// The list is deliberately short. It carries nothing that identifies a user or
// carries a credential, which is the reason the probe does not inherit the
// daemon's environment wholesale in the first place.
var probePassthrough = []string{
	"SystemRoot",
	"SYSTEMROOT",
	"windir",
	"COMSPEC",
	"PATHEXT",
	"NUMBER_OF_PROCESSORS",
	"PROCESSOR_ARCHITECTURE",
	"TEMP",
	"TMP",
}
