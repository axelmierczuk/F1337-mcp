package platform

import (
	"strings"

	"golang.org/x/sys/unix"
)

// kernelVersion reports the macOS product version with the Darwin kernel
// release in parentheses, for example "14.5 (23.5.0)". The product version is
// the number an operator recognises; the Darwin release is the one that
// actually predicts kernel behaviour, so both are reported.
func kernelVersion() string {
	darwin, err := unix.Sysctl("kern.osrelease")
	if err != nil {
		darwin = ""
	}
	product, err := unix.Sysctl("kern.osproductversion")
	if err != nil {
		product = ""
	}

	switch {
	case product != "" && darwin != "":
		return product + " (" + darwin + ")"
	case product != "":
		return product
	default:
		return strings.TrimSpace(darwin)
	}
}
